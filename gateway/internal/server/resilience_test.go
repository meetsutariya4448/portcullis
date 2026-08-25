package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func nativeClientBody(name string) string {
	return `{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/call",
		"params": {
			"name": "` + name + `",
			"arguments": {},
			"_meta": {
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"io.modelcontextprotocol/clientCapabilities": {}
			}
		}
	}`
}

func nativeRequest(name string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(nativeClientBody(name)))
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", name)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// TestForward_RetriesPreConnectFailure proves the native path's retry
// safety boundary from the other direction of the test in
// internal/retry: a failure before any connection was established (here,
// a refused connection -- nothing listening on the target port) IS
// retried, up to the configured max_attempts.
func TestForward_RetriesPreConnectFailure(t *testing.T) {
	// Bind then immediately close: the OS won't hand this port to anyone
	// else instantly, and nothing is listening, so connecting to it fails
	// fast with connection-refused -- a clean pre-connect failure.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := l.Addr().String()
	l.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name:      "dead-upstream",
		Namespace: "dead",
		URL:       "http://" + deadAddr,
		Retry:     config.RetryPolicy{MaxAttempts: 3, BaseDelay: "1ms", MaxDelay: "2ms"},
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	before := testutil.ToFloat64(metrics.RetryAttemptsTotal.WithLabelValues("dead-upstream"))

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("dead.echo"))

	after := testutil.ToFloat64(metrics.RetryAttemptsTotal.WithLabelValues("dead-upstream"))
	if got := after - before; got != 3 {
		t.Fatalf("expected 3 forward attempts (retried up to max_attempts), got %v", got)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 after exhausting retries, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestForward_DoesNotRetryPostSendFailure proves the other half of the
// safety boundary: once the upstream has actually received the request,
// a failure must not be retried automatically, since the tool call may
// have already taken effect. Simulated by having the upstream hijack the
// connection and drop it after reading the request but before writing
// any response.
func TestForward_DoesNotRetryPostSendFailure(t *testing.T) {
	var handlerCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&handlerCalls, 1)
		_, _ = io.ReadAll(r.Body) // fully receive the request -- it was "sent"

		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server's ResponseWriter doesn't support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		conn.Close() // abruptly close without ever writing a response
	}))
	defer srv.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name:      "flaky-upstream",
		Namespace: "flaky",
		URL:       srv.URL,
		Retry:     config.RetryPolicy{MaxAttempts: 3, BaseDelay: "1ms", MaxDelay: "2ms"},
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("flaky.echo"))

	if got := atomic.LoadInt32(&handlerCalls); got != 1 {
		t.Fatalf("expected exactly 1 upstream call -- a post-send failure must not be retried -- got %d", got)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestForward_NativeBreakerOpensAfterRepeatedFailures proves the circuit
// breaker now guards the native path too (previously only translate.Pool
// had one) -- repeated connection failures trip it, after which requests
// fail fast with "circuit breaker open" instead of attempting to connect.
func TestForward_NativeBreakerOpensAfterRepeatedFailures(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := l.Addr().String()
	l.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name:      "unhealthy-upstream",
		Namespace: "unhealthy",
		URL:       "http://" + deadAddr,
		Retry:     config.RetryPolicy{MaxAttempts: 1}, // isolate breaker behavior from retry behavior
		CircuitBreaker: config.CircuitBreakerPolicy{
			Window: "1s", Cooldown: "1s", MinSamples: 2, Threshold: 0.5,
		},
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	// Trip the breaker: minSamples=2 failing requests at 100% error rate.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, nativeRequest("unhealthy.echo"))
		if rec.Code != http.StatusBadGateway {
			t.Fatalf("request %d: expected 502 (connection failure), got %d", i, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("unhealthy.echo"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 (circuit breaker open) once tripped, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "circuit breaker") {
		t.Fatalf("expected the error to mention the circuit breaker, got: %s", rec.Body.String())
	}
}

// TestForward_BulkheadBoundsNativeConcurrency proves a per-upstream
// max_concurrent actually caps how many requests can be in flight to that
// upstream at once -- the native path had no concurrency ceiling at all
// before this milestone.
func TestForward_BulkheadBoundsNativeConcurrency(t *testing.T) {
	release := make(chan struct{})
	var concurrent int32
	var maxSeen int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := atomic.AddInt32(&concurrent, 1)
		for {
			m := atomic.LoadInt32(&maxSeen)
			if c <= m {
				break
			}
			if atomic.CompareAndSwapInt32(&maxSeen, m, c) {
				break
			}
		}
		<-release
		atomic.AddInt32(&concurrent, -1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "slow-upstream", Namespace: "slow", URL: srv.URL, MaxConcurrent: 2,
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			gw.ServeHTTP(rec, nativeRequest("slow.echo"))
		}()
	}

	time.Sleep(150 * time.Millisecond) // let the requests pile up against the bulkhead
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&maxSeen); got > 2 {
		t.Fatalf("expected the bulkhead to cap concurrency at 2, observed %d simultaneous requests", got)
	}
}

// TestHandleMCP_BackpressureRejectsWhenSaturated proves the gateway-wide
// inflight bound rejects excess load with 503 + Retry-After immediately,
// rather than letting requests queue unboundedly.
func TestHandleMCP_BackpressureRejectsWhenSaturated(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "bp-upstream", Namespace: "bp", URL: srv.URL, MaxConcurrent: 100,
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 2}) // gateway-wide max_inflight = 2

	var wg sync.WaitGroup
	codes := make([]int, 3)
	var retryAfterSeen int32
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := httptest.NewRecorder()
			gw.ServeHTTP(rec, nativeRequest("bp.echo"))
			codes[i] = rec.Code
			if rec.Code == http.StatusServiceUnavailable && rec.Header().Get("Retry-After") != "" {
				atomic.AddInt32(&retryAfterSeen, 1)
			}
		}(i)
	}

	time.Sleep(150 * time.Millisecond) // let the 3 requests all attempt admission
	close(release)
	wg.Wait()

	var rejected int
	for _, c := range codes {
		if c == http.StatusServiceUnavailable {
			rejected++
		}
	}
	if rejected != 1 {
		t.Fatalf("expected exactly 1 of 3 requests rejected with max_inflight=2, got %d (codes: %v)", rejected, codes)
	}
	if atomic.LoadInt32(&retryAfterSeen) != 1 {
		t.Fatal("expected the rejected request to carry a Retry-After header")
	}
}
