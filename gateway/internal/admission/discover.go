package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
)

// maxListResponseBytes bounds a tools/list response read into memory. The
// upstream is untrusted by construction, and unlike the client-facing path
// (which has http.MaxBytesReader) nothing else caps this.
const maxListResponseBytes = 8 << 20

// maxListPages bounds pagination so an upstream cannot hold the discoverer
// in a loop by always returning a nextCursor.
const maxListPages = 50

// Upstream is the subset of a routed upstream the discoverer needs. Defined
// here rather than importing internal/router so that package can depend on
// this one without a cycle.
type Upstream struct {
	Name      string
	Namespace string
	URL       string
	Client    *http.Client
	// ProtocolVersion is the upstream's configured MCP revision. Legacy
	// (2025-11-25) upstreams are skipped: reaching them requires a
	// handshaken session from translate.Pool, and their listings carry no
	// ttlMs/cacheScope (SPEC-NOTES.md:433-437). Discovering them is a
	// separate piece of work, and pretending otherwise would silently leave
	// a whole protocol version unscanned.
	ProtocolVersion string
}

// Discoverer keeps the catalog current by periodically listing each
// upstream's tools and hashing every definition.
//
// This is where rug-pull detection lives: a description that changes
// between refreshes produces a different content hash, which is a
// definition with no verdict, which the listing path then withholds until
// the control plane has judged it. The refresh interval is therefore the
// detection latency, and is worth stating plainly rather than burying.
type Discoverer struct {
	upstreams []Upstream
	gate      *Gate
	log       *slog.Logger
	interval  time.Duration
	// protocolVersion is sent on discovery requests; the gateway speaks the
	// modern revision to upstreams on its own behalf.
	protocolVersion string
}

// NativeProtocolVersion is the MCP revision Portcullis speaks natively.
const NativeProtocolVersion = "2026-07-28"

func NewDiscoverer(upstreams []Upstream, gate *Gate, log *slog.Logger, interval time.Duration) *Discoverer {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	return &Discoverer{
		upstreams:       upstreams,
		gate:            gate,
		log:             log,
		interval:        interval,
		protocolVersion: NativeProtocolVersion,
	}
}

// Run refreshes every upstream immediately, then on the configured
// interval, until ctx is done. Blocking; callers run it in a goroutine.
//
// The initial refresh is synchronous within Run so a caller that wants the
// catalog warm before serving traffic can call RefreshAll itself first.
func (d *Discoverer) Run(ctx context.Context) {
	d.RefreshAll(ctx)

	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.RefreshAll(ctx)
		}
	}
}

// RefreshAll refreshes every upstream in parallel and returns once all have
// finished (or failed).
//
// One upstream being down must not delay or block the others: a fleet is
// exactly the situation where something is always broken, and serialising
// discovery would let one slow server stall the whole catalog.
func (d *Discoverer) RefreshAll(ctx context.Context) {
	var wg sync.WaitGroup
	for _, upstream := range d.upstreams {
		if upstream.ProtocolVersion != "" && upstream.ProtocolVersion != NativeProtocolVersion {
			continue
		}
		wg.Add(1)
		go func(u Upstream) {
			defer wg.Done()
			if err := d.Refresh(ctx, u); err != nil {
				metrics.AdmissionDiscoveryFailuresTotal.WithLabelValues(u.Namespace).Inc()
				d.log.Error("admission: tool discovery failed; the catalog for this namespace is going stale",
					"upstream", u.Name, "namespace", u.Namespace, "error", err)
			}
		}(upstream)
	}
	wg.Wait()
	d.gate.InvalidateCache()
}

// Refresh lists one upstream's tools, hashes each definition, replaces that
// namespace's catalog entries, and queues anything new or changed.
func (d *Discoverer) Refresh(ctx context.Context, upstream Upstream) error {
	tools, err := d.listTools(ctx, upstream)
	if err != nil {
		return err
	}

	entries := make([]CatalogEntry, 0, len(tools))
	for _, tool := range tools {
		definition := Tool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema}
		hash, canonical, err := definition.ContentHash()
		if err != nil {
			// An unhashable definition (oversized, too deeply nested,
			// invalid schema JSON) is dropped from the catalog rather than
			// admitted unjudged: a tool we cannot even describe canonically
			// is not one we can vouch for. Logged so it is visible rather
			// than silently missing.
			d.log.Error("admission: skipping an undescribable tool definition",
				"upstream", upstream.Name, "namespace", upstream.Namespace,
				"tool", tool.Name, "error", err)
			continue
		}
		entries = append(entries, CatalogEntry{
			Namespace:     upstream.Namespace,
			ToolName:      tool.Name,
			UpstreamName:  upstream.Name,
			QualifiedName: upstream.Namespace + "." + tool.Name,
			Description:   tool.Description,
			InputSchema:   tool.InputSchema,
			ContentHash:   hash,
			Canonical:     canonical,
		})
	}

	changed := d.gate.Catalog().ReplaceNamespace(upstream.Namespace, entries)
	metrics.AdmissionCatalogTools.WithLabelValues(upstream.Namespace).Set(float64(len(entries)))

	if len(changed) > 0 {
		metrics.AdmissionScansEnqueuedTotal.WithLabelValues(upstream.Namespace).Add(float64(len(changed)))
		for _, entry := range changed {
			d.log.Info("admission: new or changed tool definition queued for scanning",
				"upstream", upstream.Name, "namespace", upstream.Namespace,
				"tool", entry.ToolName, "content_hash", entry.ContentHash)
		}
		d.gate.EnqueueScans(ctx, changed)
	}
	return nil
}

// listedTool is the part of a tools/list entry that matters here.
type listedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type listResult struct {
	Result struct {
		Tools      []listedTool `json:"tools"`
		NextCursor string       `json:"nextCursor"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// listTools performs the tools/list call, following pagination.
//
// This is the gateway acting as a client on its own behalf, not proxying:
// SPEC-NOTES.md:64-69 prescribes exactly this ("call it once per upstream at
// startup/config-load, not per client request"), and it is what makes a
// tools/call -- whose body carries no description -- judgeable at all.
func (d *Discoverer) listTools(ctx context.Context, upstream Upstream) ([]listedTool, error) {
	var all []listedTool
	cursor := ""

	for page := 0; page < maxListPages; page++ {
		body, err := d.buildListRequest(cursor)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstream.URL, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("building tools/list request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", d.protocolVersion)
		req.Header.Set("Mcp-Method", "tools/list")

		resp, err := upstream.Client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("tools/list request failed: %w", err)
		}

		payload, err := io.ReadAll(io.LimitReader(resp.Body, maxListResponseBytes))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading tools/list response: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("tools/list returned HTTP %d", resp.StatusCode)
		}

		var parsed listResult
		if err := json.Unmarshal(payload, &parsed); err != nil {
			return nil, fmt.Errorf("parsing tools/list response: %w", err)
		}
		if parsed.Error != nil {
			return nil, fmt.Errorf("tools/list rejected: %s (code %d)", parsed.Error.Message, parsed.Error.Code)
		}

		all = append(all, parsed.Result.Tools...)
		if parsed.Result.NextCursor == "" {
			return all, nil
		}
		cursor = parsed.Result.NextCursor
	}
	return nil, fmt.Errorf("tools/list did not terminate within %d pages", maxListPages)
}

func (d *Discoverer) buildListRequest(cursor string) ([]byte, error) {
	params := map[string]any{
		// Every outbound call must carry the protocol version in _meta as
		// well as the header, and the two must agree (SPEC-NOTES.md §1/§3).
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion": d.protocolVersion,
		},
	}
	if cursor != "" {
		params["cursor"] = cursor
	}
	return json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "portcullis-discover",
		"method":  "tools/list",
		"params":  params,
	})
}
