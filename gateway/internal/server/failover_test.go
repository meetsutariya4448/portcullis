package server

import (
	"io"
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
	"github.com/meetsutariya4448/portcullis/gateway/internal/translate"
)

// TestForward_BreakerOpenOnPrimarySkipsInstantlyToFallback proves an
// already-open primary breaker sends zero requests to the primary --
// forwardNative's !upstream.Breaker.Allow() check returns before any
// network I/O, so failover on an open breaker costs nothing extra.
func TestForward_BreakerOpenOnPrimarySkipsInstantlyToFallback(t *testing.T) {
	var primaryCalls, fallbackCalls int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer fallback.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{
		{
			Name: "weather-primary", Namespace: "weather", URL: primary.URL,
			CircuitBreaker: config.CircuitBreakerPolicy{Window: "1m", Cooldown: "1m", MinSamples: 2, Threshold: 0.5},
		},
		{Name: "weather-fallback", Namespace: "weather", URL: fallback.URL},
	}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	group, err := rtr.Resolve("weather")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// Force the primary's breaker open deterministically, without
	// needing a real failing connection.
	for i := 0; i < 2; i++ {
		group[0].Breaker.Record(false)
	}
	if group[0].Breaker.State() != translate.StateOpen {
		t.Fatalf("expected the primary's breaker to be open before the test request, got %v", group[0].Breaker.State())
	}

	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	before := testutil.ToFloat64(metrics.UpstreamFailoverTotal.WithLabelValues("weather", "weather-primary", "weather-fallback"))

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("weather.get_forecast"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from the fallback, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&primaryCalls); got != 0 {
		t.Fatalf("expected 0 calls to the primary (breaker open), got %d", got)
	}
	if got := atomic.LoadInt32(&fallbackCalls); got != 1 {
		t.Fatalf("expected exactly 1 call to the fallback, got %d", got)
	}
	if got := testutil.ToFloat64(metrics.UpstreamFailoverTotal.WithLabelValues("weather", "weather-primary", "weather-fallback")) - before; got != 1 {
		t.Fatalf("expected UpstreamFailoverTotal to increment by 1, got %v", got)
	}
}

// TestForward_PreConnectFailureOnPrimaryFailsOverToFallback proves a
// primary that exhausts its own retry budget on pre-connect (dial)
// failures -- never having reached the network -- is safe to fail over,
// and the fallback serves the request.
func TestForward_PreConnectFailureOnPrimaryFailsOverToFallback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := l.Addr().String()
	l.Close()

	var fallbackCalls int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer fallback.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{
		{
			Name: "weather-primary", Namespace: "weather", URL: "http://" + deadAddr,
			Retry: config.RetryPolicy{MaxAttempts: 2, BaseDelay: "1ms", MaxDelay: "2ms"},
		},
		{Name: "weather-fallback", Namespace: "weather", URL: fallback.URL},
	}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("weather.get_forecast"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from the fallback, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&fallbackCalls); got != 1 {
		t.Fatalf("expected exactly 1 call to the fallback, got %d", got)
	}
}

// TestForward_PostSendFailureOnPrimaryDoesNotFailOver is the safety-
// boundary test, now proven across backends: once a request has actually
// reached the primary (or that can't be ruled out), forward must not try
// the fallback -- the primary's tool call may have already executed.
func TestForward_PostSendFailureOnPrimaryDoesNotFailOver(t *testing.T) {
	var primaryCalls, fallbackCalls int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&primaryCalls, 1)
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
	defer primary.Close()
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fallbackCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer fallback.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{
		{
			Name: "weather-primary", Namespace: "weather", URL: primary.URL,
			Retry: config.RetryPolicy{MaxAttempts: 3, BaseDelay: "1ms", MaxDelay: "2ms"},
		},
		{Name: "weather-fallback", Namespace: "weather", URL: fallback.URL},
	}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("weather.get_forecast"))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 (the primary's own failure, not a fallback result), got %d: %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&primaryCalls); got != 1 {
		t.Fatalf("expected exactly 1 call to the primary, got %d", got)
	}
	if got := atomic.LoadInt32(&fallbackCalls); got != 0 {
		t.Fatalf("expected the fallback to NEVER be attempted after a post-send failure, got %d calls", got)
	}
}

// TestForward_MixedProtocolFailoverGroup proves a native primary and a
// legacy fallback work together end-to-end: the primary is unreachable
// (pre-connect failure, safe to fail over), and the legacy fallback --
// requiring its own initialize handshake -- successfully serves the
// request.
func TestForward_MixedProtocolFailoverGroup(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := l.Addr().String()
	l.Close()

	fake := newFakeLegacyUpstream()
	legacySrv := httptest.NewServer(fake)
	defer legacySrv.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{
		{
			Name: "weather-native", Namespace: "weather", URL: "http://" + deadAddr,
			ProtocolVersion: "2026-07-28",
			Retry:           config.RetryPolicy{MaxAttempts: 1},
		},
		{
			Name: "weather-legacy", Namespace: "weather", URL: legacySrv.URL,
			ProtocolVersion: "2025-11-25",
		},
	}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("weather.get_forecast"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from the legacy fallback, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "ok from legacy") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}
