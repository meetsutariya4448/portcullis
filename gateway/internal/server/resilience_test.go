package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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
	gw := New(rtr, log)

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
	gw := New(rtr, log)

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("flaky.echo"))

	if got := atomic.LoadInt32(&handlerCalls); got != 1 {
		t.Fatalf("expected exactly 1 upstream call -- a post-send failure must not be retried -- got %d", got)
	}
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", rec.Code, rec.Body.String())
	}
}
