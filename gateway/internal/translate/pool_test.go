package translate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeLegacyServer emulates a 2025-11-25 MCP server: it requires a valid
// Mcp-Session-Id (minted via initialize) on every non-handshake request,
// exactly like a real legacy Streamable HTTP server would.
type fakeLegacyServer struct {
	mu              sync.Mutex
	validSessions   map[string]bool
	sessionCounter  int32
	initializeCalls int32
	forwardedCalls  int32
	pingCalls       int32

	// triggerUnsupported, when true, makes forwarded (non-handshake) calls
	// respond with a server-initiated JSON-RPC request instead of a result,
	// simulating legacy sampling/elicitation/roots push.
	triggerUnsupported bool
}

func newFakeLegacyServer() *fakeLegacyServer {
	return &fakeLegacyServer{validSessions: make(map[string]bool)}
}

func (f *fakeLegacyServer) hasSession(id string) bool {
	if id == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.validSessions[id]
}

func (f *fakeLegacyServer) forgetAllSessions() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validSessions = make(map[string]bool)
}

func (f *fakeLegacyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var parsed struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &parsed)

	switch parsed.Method {
	case "initialize":
		atomic.AddInt32(&f.initializeCalls, 1)
		n := atomic.AddInt32(&f.sessionCounter, 1)
		sessionID := fmt.Sprintf("legacy-session-%d", n)
		f.mu.Lock()
		f.validSessions[sessionID] = true
		f.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", sessionID)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"portcullis-initialize","result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"fake-legacy","version":"1.0"}}}`))
		return

	case "notifications/initialized":
		if !f.hasSession(r.Header.Get("Mcp-Session-Id")) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return

	case "ping":
		atomic.AddInt32(&f.pingCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if !f.hasSession(r.Header.Get("Mcp-Session-Id")) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"portcullis-health-check","error":{"code":-32000,"message":"unknown session"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"portcullis-health-check","result":{}}`))
		return
	}

	// Any other call is a proxied client request: requires a valid session,
	// exactly like a real 2025-11-25 server.
	if !f.hasSession(r.Header.Get("Mcp-Session-Id")) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"missing or invalid Mcp-Session-Id"}}`))
		return
	}

	atomic.AddInt32(&f.forwardedCalls, 1)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if f.triggerUnsupported {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage","params":{"messages":[]}}`))
		return
	}
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"ok from legacy"}]}}`, string(parsed.ID))
}

func requestBody() []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"weather.get_forecast","arguments":{}}}`)
}

// TestPool_ForwardSucceedsWithoutCallerHandlingSession is the core proof
// requested for this feature: a caller that only ever supplies a
// stateless, session-agnostic request body gets a successful response from
// a legacy upstream that requires a valid Mcp-Session-Id on every call.
func TestPool_ForwardSucceedsWithoutCallerHandlingSession(t *testing.T) {
	fake := newFakeLegacyServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	pool := NewPool(srv.URL, srv.Client(), testLogger())

	resp, err := pool.Forward(context.Background(), requestBody())
	if err != nil {
		t.Fatalf("Forward returned error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "ok from legacy") {
		t.Fatalf("unexpected response body: %s", respBody)
	}

	if got := atomic.LoadInt32(&fake.initializeCalls); got != 1 {
		t.Fatalf("expected exactly 1 initialize call, got %d", got)
	}
	if got := atomic.LoadInt32(&fake.forwardedCalls); got != 1 {
		t.Fatalf("expected exactly 1 forwarded call, got %d", got)
	}
}

func TestPool_ReusesSessionAcrossRequests(t *testing.T) {
	fake := newFakeLegacyServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	pool := NewPool(srv.URL, srv.Client(), testLogger())

	for i := 0; i < 5; i++ {
		resp, err := pool.Forward(context.Background(), requestBody())
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
	}

	if got := atomic.LoadInt32(&fake.initializeCalls); got != 1 {
		t.Fatalf("expected the session to be reused (1 initialize call), got %d", got)
	}
	if got := atomic.LoadInt32(&fake.forwardedCalls); got != 5 {
		t.Fatalf("expected 5 forwarded calls, got %d", got)
	}
}

func TestPool_RecyclesDeadSession(t *testing.T) {
	fake := newFakeLegacyServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	pool := NewPool(srv.URL, srv.Client(), testLogger())

	resp, err := pool.Forward(context.Background(), requestBody())
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	resp.Body.Close()

	// Simulate the legacy server forgetting the session (e.g. a restart).
	fake.forgetAllSessions()

	resp2, err := pool.Forward(context.Background(), requestBody())
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	resp2.Body.Close()

	if got := atomic.LoadInt32(&fake.initializeCalls); got != 2 {
		t.Fatalf("expected the dead session to be recycled via a second initialize call, got %d", got)
	}
	if got := atomic.LoadInt32(&fake.pingCalls); got != 1 {
		t.Fatalf("expected exactly 1 health-check ping (against the now-dead session), got %d", got)
	}
}

func TestPool_ForwardReturnsErrUnsupportedMRTR(t *testing.T) {
	fake := newFakeLegacyServer()
	fake.triggerUnsupported = true
	srv := httptest.NewServer(fake)
	defer srv.Close()

	pool := NewPool(srv.URL, srv.Client(), testLogger())

	_, err := pool.Forward(context.Background(), requestBody())
	if !errors.Is(err, ErrUnsupportedMRTR) {
		t.Fatalf("expected ErrUnsupportedMRTR, got %v", err)
	}

	// The session should still be usable afterwards: an unsupported
	// response shape isn't an upstream-health failure.
	fake.triggerUnsupported = false
	resp, err := pool.Forward(context.Background(), requestBody())
	if err != nil {
		t.Fatalf("expected the session to still be usable, got error: %v", err)
	}
	resp.Body.Close()

	if got := atomic.LoadInt32(&fake.initializeCalls); got != 1 {
		t.Fatalf("expected the session from the unsupported response to be reused, got %d initialize calls", got)
	}
}

func TestPool_ExhaustionFailsFast(t *testing.T) {
	fake := newFakeLegacyServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	pool := NewPool(srv.URL, srv.Client(), testLogger())
	pool.maxSize = 1

	sess, err := pool.lease(context.Background())
	if err != nil {
		t.Fatalf("first lease failed: %v", err)
	}
	// sess is deliberately not returned yet: the pool is now at capacity
	// with nothing idle.

	if _, err := pool.lease(context.Background()); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("expected ErrPoolExhausted, got %v", err)
	}

	pool.returnSession(sess)
}

func TestPool_CircuitBreakerOpensAfterRepeatedHandshakeFailures(t *testing.T) {
	// Upstream that always 500s: every initialize attempt fails.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	pool := NewPool(srv.URL, srv.Client(), testLogger())

	var lastErr error
	for i := 0; i < defaultBreakerMinSamples; i++ {
		_, lastErr = pool.Forward(context.Background(), requestBody())
		if lastErr == nil {
			t.Fatalf("request %d: expected failure against an upstream that always 500s", i)
		}
		if errors.Is(lastErr, ErrCircuitOpen) {
			t.Fatalf("request %d: breaker tripped too early", i)
		}
	}

	_, err := pool.Forward(context.Background(), requestBody())
	if !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen after %d consecutive handshake failures, got %v", defaultBreakerMinSamples, err)
	}
}

func TestPool_PoolExhaustionDoesNotTripBreaker(t *testing.T) {
	fake := newFakeLegacyServer()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	pool := NewPool(srv.URL, srv.Client(), testLogger())
	pool.maxSize = 1

	sess, err := pool.lease(context.Background())
	if err != nil {
		t.Fatalf("first lease failed: %v", err)
	}

	for i := 0; i < defaultBreakerMinSamples+1; i++ {
		_, ferr := pool.Forward(context.Background(), requestBody())
		if !errors.Is(ferr, ErrPoolExhausted) {
			t.Fatalf("iteration %d: expected ErrPoolExhausted, got %v", i, ferr)
		}
	}

	if !pool.breaker.Allow() {
		t.Fatal("breaker should still be closed: pool exhaustion is not an upstream-health signal")
	}

	pool.returnSession(sess)
}
