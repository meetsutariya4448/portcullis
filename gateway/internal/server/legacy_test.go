package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// fakeLegacyUpstream is a minimal stand-in for a real, unmodified
// 2025-11-25 MCP server: it requires a valid Mcp-Session-Id, minted via the
// initialize handshake, on every other request.
type fakeLegacyUpstream struct {
	mu              sync.Mutex
	validSessions   map[string]bool
	sessionCounter  int32
	initializeCalls int32
	forwardedCalls  int32
}

func newFakeLegacyUpstream() *fakeLegacyUpstream {
	return &fakeLegacyUpstream{validSessions: make(map[string]bool)}
}

func (f *fakeLegacyUpstream) hasSession(id string) bool {
	if id == "" {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.validSessions[id]
}

func (f *fakeLegacyUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if !f.hasSession(r.Header.Get("Mcp-Session-Id")) {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"portcullis-health-check","error":{"code":-32000,"message":"unknown session"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"portcullis-health-check","result":{}}`))
		return
	}

	// Any other call is a proxied client request: this is where a real
	// 2025-11-25 server would reject a request with no session.
	if !f.hasSession(r.Header.Get("Mcp-Session-Id")) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"missing or invalid Mcp-Session-Id"}}`))
		return
	}

	atomic.AddInt32(&f.forwardedCalls, 1)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"ok from legacy"}]}}`, string(parsed.ID))
}

// TestHandleMCP_LegacyUpstream_ClientNeverHandlesSession proves the
// end-to-end path: a 2026-07-28-shaped client request, carrying no session
// concept whatsoever, succeeds against an unmodified 2025-11-25 upstream
// that requires a valid Mcp-Session-Id on every call. The gateway performs
// the handshake and holds the session itself.
func TestHandleMCP_LegacyUpstream_ClientNeverHandlesSession(t *testing.T) {
	fake := newFakeLegacyUpstream()
	upstreamSrv := httptest.NewServer(fake)
	defer upstreamSrv.Close()

	cfg := &config.Config{
		Upstreams: []config.Upstream{
			{
				Name:            "weather-legacy",
				Namespace:       "weather",
				URL:             upstreamSrv.URL,
				ProtocolVersion: "2025-11-25",
			},
		},
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New failed: %v", err)
	}
	gw := New(rtr, log)

	clientBody := `{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "tools/call",
		"params": {
			"name": "weather.get_forecast",
			"arguments": {"location": "Seattle, WA"},
			"_meta": {
				"io.modelcontextprotocol/protocolVersion": "2026-07-28",
				"io.modelcontextprotocol/clientCapabilities": {}
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(clientBody))
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "weather.get_forecast")
	req.Header.Set("Content-Type", "application/json")
	// Deliberately never set Mcp-Session-Id: a 2026-07-28 client has no
	// concept of it (SPEC-NOTES.md §2) — this is the exact thing being proven.

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from the gateway, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ok from legacy") {
		t.Fatalf("unexpected gateway response body: %s", rec.Body.String())
	}

	if got := atomic.LoadInt32(&fake.initializeCalls); got != 1 {
		t.Fatalf("expected the gateway to perform exactly 1 legacy handshake, got %d", got)
	}
	if got := atomic.LoadInt32(&fake.forwardedCalls); got != 1 {
		t.Fatalf("expected exactly 1 forwarded call to succeed against the legacy upstream, got %d", got)
	}
}
