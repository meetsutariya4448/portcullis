package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/meetsutariya4448/portcullis/gateway/internal/admission"
	gwmcp "github.com/meetsutariya4448/portcullis/gateway/internal/mcp"
	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
)

// listedTool is one entry in the merged tools/list result.
type listedTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// toolsListResult mirrors a 2026-07-28 tools/list result.
//
// resultType and the caching hints are required on a complete result
// (SPEC-NOTES.md §4), and serverInfo is required on every result
// (SPEC-NOTES.md §1) -- here Portcullis is answering as a server in its own
// right rather than relaying an upstream's answer, so it identifies itself.
type toolsListResult struct {
	ResultType string         `json:"resultType"`
	Tools      []listedTool   `json:"tools"`
	TTLMs      int            `json:"ttlMs"`
	CacheScope string         `json:"cacheScope"`
	Meta       map[string]any `json:"_meta"`
}

type toolsListResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  toolsListResult `json:"result"`
}

// handleToolsList answers tools/list from the discovery catalog, filtered
// by both the policy engine and the tool-poisoning verdicts.
//
// Serving rather than proxying is what makes the gateway's
// "{namespace}.{tool}" naming discoverable at all: a client had no way to
// learn that "notes.summarize" exists, because no single upstream knows the
// namespaced name. The catalog already holds every upstream's tools with
// their namespaced names and content hashes, so merging is the natural
// answer and needs no response-body rewriting on the proxy path.
//
// Withheld tools are dropped silently. A listing that named what it was
// hiding would hand the model the pointer it was just denied; the decision
// log is where the withholding is visible.
func (s *Server) handleToolsList(w http.ResponseWriter, r *http.Request, clientID string, req gwmcp.Request, handlerStart time.Time) {
	span := trace.SpanFromContext(r.Context())

	entries := s.admission.Catalog().Entries()

	// The policy engine runs first and for free: it already answers
	// "may this client use this (namespace, tool)", and a tool the client
	// could never call has no business being advertised to its model.
	// Reusing it here also means one place decides per-client visibility.
	permitted := make([]admission.CatalogEntry, 0, len(entries))
	for _, entry := range entries {
		if allow, _ := s.authorize(clientID, entry.Namespace, entry.ToolName); allow {
			permitted = append(permitted, entry)
		}
	}

	admissionStart := time.Now()
	allowed, decisions := s.admission.AdmitListing(r.Context(), clientID, permitted)
	metrics.AdmissionLatency.WithLabelValues(string(admission.PointList)).Observe(time.Since(admissionStart).Seconds())
	for i, decision := range decisions {
		metrics.AdmissionDecisionsTotal.WithLabelValues(
			string(admission.PointList), string(decision.Outcome),
			string(decision.Reason), permitted[i].Namespace,
		).Inc()
	}

	tools := make([]listedTool, 0, len(allowed))
	for _, entry := range allowed {
		schema := entry.InputSchema
		if len(schema) == 0 {
			schema = json.RawMessage("{}")
		}
		tools = append(tools, listedTool{
			Name:        entry.QualifiedName,
			Description: entry.Description,
			InputSchema: schema,
		})
	}

	resp := toolsListResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: toolsListResult{
			ResultType: "complete",
			Tools:      tools,
			// ttlMs 0 -- immediately stale -- on purpose. This listing is a
			// security decision with a shorter useful life than any
			// upstream's own freshness hint: a verdict can land, or a
			// description can change, at any moment, and a client caching an
			// allow-list past that point would be acting on a judgement the
			// gateway has already revised. Advertising a positive TTL would
			// be claiming a guarantee this response cannot make.
			TTLMs: 0,
			// private, always: the listing is filtered per client by the
			// policy engine above, so it is not safe to share across
			// authorization contexts even when every contributing upstream
			// said "public" (SPEC-NOTES.md §4).
			CacheScope: "private",
			Meta: map[string]any{
				"io.modelcontextprotocol/serverInfo": map[string]any{
					"name":    "portcullis",
					"version": portcullisVersion,
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	withheld := len(permitted) - len(allowed)
	span.SetAttributes(
		semconv.HTTPResponseStatusCode(http.StatusOK),
		attribute.Int("portcullis.tools_list.offered", len(tools)),
		attribute.Int("portcullis.tools_list.withheld", withheld),
	)
	span.SetStatus(codes.Ok, "")

	duration := time.Since(handlerStart)
	status := strconv.Itoa(http.StatusOK)
	metrics.RequestsTotal.WithLabelValues(req.Method, toolsListNamespaceLabel, status).Inc()
	metrics.GatewayLatency.WithLabelValues(req.Method, toolsListNamespaceLabel, status).Observe(duration.Seconds())

	s.log.Info("mcp tools/list served from the discovery catalog",
		append([]any{
			"client", clientID,
			"offered", len(tools),
			"withheld", withheld,
			"catalog_size", len(entries),
			"duration_ms", duration.Milliseconds(),
		}, traceLogArgs(r.Context())...)...)
}
