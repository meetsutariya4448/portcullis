// Package translate bridges 2026-07-28 clients to unmodified 2025-11-25
// upstreams, per the "Translating 2026-07-28 clients to 2025-11-25 servers"
// section of SPEC-NOTES.md. It performs the legacy initialize/initialized
// handshake once per pooled session and holds the resulting Mcp-Session-Id
// server-side — the stateless 2026-07-28 client on the other side of the
// gateway never sees it.
//
// It deliberately does not implement InputRequiredResult/requestState
// multi-round-trip bridging (SPEC-NOTES.md item 9): that requires holding a
// legacy connection open across two unrelated client HTTP requests, which
// SPEC-NOTES.md documents as effectively impossible to do while keeping
// Portcullis itself stateless. When a legacy upstream responds with what
// looks like a server-initiated request instead of a result, Forward
// returns ErrUnsupportedMRTR.
package translate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
	"github.com/meetsutariya4448/portcullis/gateway/internal/retry"
)

// DefaultMaxPoolSize bounds how many concurrent legacy sessions Portcullis
// will hold open to a single upstream.
const DefaultMaxPoolSize = 8

// Pool is a bounded, LIFO pool of live legacy sessions to a single
// 2025-11-25 upstream. Reusing the most-recently-released session first
// (LIFO) keeps a small hot subset of sessions/connections warm instead of
// round-robining evenly across all of them.
type Pool struct {
	name    string
	url     string
	client  *http.Client
	log     *slog.Logger
	breaker *CircuitBreaker
	maxSize int

	mu   sync.Mutex
	idle []*Session // LIFO stack: idle[len(idle)-1] is the most recently released session
	live int        // sessions currently created (idle + leased), <= maxSize
}

// NewPool builds a session pool for a single legacy upstream. name is the
// upstream's configured name, used only to label the session
// reuse/creation metrics recorded in lease. client should already be
// configured with the upstream's timeout. maxSize <= 0 means "use
// DefaultMaxPoolSize."
func NewPool(name, url string, client *http.Client, log *slog.Logger, maxSize int) *Pool {
	if maxSize <= 0 {
		maxSize = DefaultMaxPoolSize
	}
	return &Pool{
		name:    name,
		url:     url,
		client:  client,
		log:     log,
		breaker: NewCircuitBreaker(),
		maxSize: maxSize,
	}
}

// WithBreakerConfig replaces the pool's circuit breaker with one built
// from cfg, and returns the pool for chaining at the NewPool call site.
// Intended to be called at most once, right after NewPool, when the
// upstream's config declares a custom circuit_breaker block; the zero
// value of BreakerConfig is a no-op (keeps the default breaker NewPool
// already built). Not safe to call concurrently with Forward.
func (p *Pool) WithBreakerConfig(cfg BreakerConfig) *Pool {
	if cfg != (BreakerConfig{}) {
		p.breaker = NewCircuitBreakerWithConfig(cfg)
	}
	return p
}

// BreakerState reports the pool's circuit breaker state, for
// metrics/observability only.
func (p *Pool) BreakerState() BreakerState {
	return p.breaker.State()
}

// Forward leases a session, forwards body to the legacy upstream over that
// session, and returns the upstream's response for the caller to relay
// unchanged (status, headers, and body). The caller must close the
// returned response's Body.
//
// The circuit breaker guards the whole attempt, including session
// establishment: a legacy upstream that's down fails at the handshake, not
// just at the forwarded call, so that failure must count too. Pool
// exhaustion is deliberately excluded from breaker accounting — it's a
// capacity signal about Portcullis's own bound, not evidence the upstream
// is unhealthy.
//
// Retry safety boundary: a caller may wrap the whole Forward call in
// retry.Do. Failures during lease() (pool exhaustion, handshake failure)
// are returned bare (retryable) — nothing has reached the upstream's tool
// yet, so a fresh Forward attempt just tries lease() again. Everything
// after a session is successfully leased is wrapped in retry.NonRetryable:
// the tool-call request may have reached (or been partially processed by)
// the upstream, and MCP tool calls are not guaranteed idempotent.
func (p *Pool) Forward(ctx context.Context, body []byte) (*http.Response, error) {
	if !p.breaker.Allow() {
		return nil, ErrCircuitOpen
	}

	sess, err := p.lease(ctx)
	if err != nil {
		if !errors.Is(err, ErrPoolExhausted) {
			p.breaker.Record(false)
		}
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		p.breaker.Record(false)
		p.discardSession()
		return nil, retry.NonRetryable(fmt.Errorf("building legacy request: %w", err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(sessionIDHeader, sess.ID)

	resp, err := p.client.Do(req)
	if err != nil {
		p.breaker.Record(false)
		p.discardSession()
		return nil, retry.NonRetryable(fmt.Errorf("legacy upstream request failed: %w", err))
	}

	unsupported, buffered, err := sniffUnsupportedMRTR(resp)
	if err != nil {
		resp.Body.Close()
		p.breaker.Record(false)
		p.discardSession()
		return nil, retry.NonRetryable(fmt.Errorf("reading legacy response: %w", err))
	}
	if unsupported {
		resp.Body.Close()
		// The upstream itself answered fine; Portcullis just doesn't
		// support this response shape. That's not an upstream-health
		// signal, so record success and keep the session.
		p.breaker.Record(true)
		p.returnSession(sess)
		p.log.Error("translate: legacy upstream sent an unsupported multi-round-trip request",
			"upstream", p.url, "session_id", sess.ID)
		return nil, retry.NonRetryable(ErrUnsupportedMRTR)
	}

	p.breaker.Record(true)
	p.returnSession(sess)
	resp.Body = io.NopCloser(bytes.NewReader(buffered))
	return resp, nil
}

// lease returns a healthy session, reusing an idle one LIFO when possible,
// health-checking it first and discarding it (and trying the next one) if
// it's dead, or establishing a brand new one via the handshake if the pool
// has spare capacity. It fails fast with ErrPoolExhausted rather than
// queuing when the pool is already at maxSize with nothing idle.
func (p *Pool) lease(ctx context.Context) (*Session, error) {
	for {
		sess := p.popIdle()
		if sess == nil {
			break
		}
		if p.healthCheck(ctx, sess) {
			metrics.LegacySessionReusedTotal.WithLabelValues(p.name).Inc()
			return sess, nil
		}
		p.log.Warn("translate: discarding dead legacy session", "upstream", p.url, "session_id", sess.ID)
		p.dropLive()
	}

	if !p.reserveLive() {
		return nil, ErrPoolExhausted
	}

	sess, err := p.handshake(ctx)
	if err != nil {
		p.dropLive()
		return nil, fmt.Errorf("establishing legacy session: %w", err)
	}
	metrics.LegacySessionCreatedTotal.WithLabelValues(p.name).Inc()
	return sess, nil
}

// returnSession returns a successfully-used session to the idle pool for
// LIFO reuse.
func (p *Pool) returnSession(sess *Session) {
	p.pushIdle(sess)
}

// discardSession drops a session whose request failed, freeing its
// capacity slot.
func (p *Pool) discardSession() {
	p.dropLive()
}

func (p *Pool) popIdle() *Session {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.idle)
	if n == 0 {
		return nil
	}
	sess := p.idle[n-1]
	p.idle = p.idle[:n-1]
	return sess
}

func (p *Pool) pushIdle(sess *Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idle = append(p.idle, sess)
}

// reserveLive reports whether there was spare capacity and, if so, claims a
// slot for a session about to be created.
func (p *Pool) reserveLive() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.live >= p.maxSize {
		return false
	}
	p.live++
	return true
}

// dropLive releases a slot previously claimed by reserveLive, or held by a
// session discarded from the idle pool.
func (p *Pool) dropLive() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.live--
}

// sniffUnsupportedMRTR reads and buffers the full response body (the
// caller must reconstruct resp.Body from the returned bytes before use) and
// reports whether the response looks like a legacy server-initiated
// request (an MRTR flow this gateway doesn't bridge) rather than an
// ordinary JSON-RPC result.
func sniffUnsupportedMRTR(resp *http.Response) (unsupported bool, body []byte, err error) {
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return false, nil, err
	}

	if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/event-stream") {
		// A legacy server may push a server-initiated request inline on an
		// SSE stream; this gateway does not parse or bridge that.
		return true, body, nil
	}

	var probe struct {
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &probe); err == nil && probe.Method != "" {
		// A "method" field on what should be a response means the legacy
		// server sent a server-initiated JSON-RPC request (sampling,
		// elicitation, roots) instead of a result.
		return true, body, nil
	}

	return false, body, nil
}
