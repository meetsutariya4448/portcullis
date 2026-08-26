package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// TestTimeout_ResponseHeaderTimeoutFiresOnHungUpstream is the timeout-
// simulation test named explicitly in the original ask: an upstream
// that accepts the connection but never writes anything back must not
// hang the request forever. Milestone 4 changed what timeout: bounds
// (from http.Client.Timeout to Transport.ResponseHeaderTimeout,
// specifically so a genuine stream could stay open past it) but never
// got a direct test proving the new mechanism actually fires on a
// non-streaming, simply-unresponsive upstream.
func TestTimeout_ResponseHeaderTimeoutFiresOnHungUpstream(t *testing.T) {
	block := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // never respond until the test says so
	}))
	// Deferred LIFO: close(block) must run before upstream.Close(), or
	// Close() blocks forever waiting for the still-parked handler
	// goroutine to notice its connection close and return.
	defer upstream.Close()
	defer close(block)

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "hung-upstream", Namespace: "hung", URL: upstream.URL,
		Timeout: "50ms",
		Retry:   config.RetryPolicy{MaxAttempts: 1},
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	start := time.Now()
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("hung.ping"))
	elapsed := time.Since(start)

	if rec.Code != http.StatusBadGateway && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 502 or 503 once ResponseHeaderTimeout fires, got %d: %s", rec.Code, rec.Body.String())
	}
	if elapsed > 2*time.Second {
		t.Fatalf("expected the ResponseHeaderTimeout (50ms) to fire quickly, took %v", elapsed)
	}
}
