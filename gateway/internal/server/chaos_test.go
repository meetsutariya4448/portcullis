package server

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
	"github.com/meetsutariya4448/portcullis/gateway/internal/translate"
)

// TestChaos_CircuitBreakerRecoversAfterUpstreamComesBackHealthy drives a
// real upstream through healthy -> down -> breaker-open -> cooldown ->
// healthy-again -> breaker-closed via actual HTTP requests through the
// gateway, unlike translate/breaker_test.go's direct
// Allow()/Record()/State() unit tests or Milestone 4's
// Breaker.Record(false) shortcut in failover_test.go. This is the
// automated version of the scenario Milestone 7's chaos demo will
// dramatize later.
func TestChaos_CircuitBreakerRecoversAfterUpstreamComesBackHealthy(t *testing.T) {
	var healthy int32 = 1
	var calls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if atomic.LoadInt32(&healthy) == 0 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server's ResponseWriter doesn't support hijacking")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			conn.Close() // simulate a genuinely down upstream, not just an error status
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	const cooldown = 150 * time.Millisecond
	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "chaos-upstream", Namespace: "chaos", URL: upstream.URL,
		Retry: config.RetryPolicy{MaxAttempts: 1}, // isolate breaker transitions from within-request retries
		CircuitBreaker: config.CircuitBreakerPolicy{
			Window: "200ms", Cooldown: "150ms", MinSamples: 2, Threshold: 0.5,
		},
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	group, err := rtr.Resolve("chaos")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	breaker := group[0].Breaker

	// 1. Healthy: an ordinary request succeeds, breaker starts closed.
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("chaos.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("step 1 (healthy): expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if breaker.State() != translate.StateClosed {
		t.Fatalf("step 1: expected the breaker closed, got %v", breaker.State())
	}

	// 2. Flip down: send failing requests until the breaker opens (the
	// prior healthy request already contributed one success sample to
	// the window, so exactly how many failures it takes to cross
	// Threshold isn't pinned here -- only that it does, within a few).
	atomic.StoreInt32(&healthy, 0)
	opened := false
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, nativeRequest("chaos.ping"))
		if rec.Code != http.StatusBadGateway && rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("step 2 (down, request %d): expected 502 or 503, got %d: %s", i, rec.Code, rec.Body.String())
		}
		if breaker.State() == translate.StateOpen {
			opened = true
			break
		}
	}
	if !opened {
		t.Fatal("step 2: expected the breaker to open after repeated failures")
	}

	// 3. Still down, breaker open: the next request must fail fast
	// (503, circuit breaker open) WITHOUT ever reaching the upstream.
	callsBeforeOpenCheck := atomic.LoadInt32(&calls)
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("chaos.ping"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("step 3 (breaker open): expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := atomic.LoadInt32(&calls); got != callsBeforeOpenCheck {
		t.Fatalf("step 3: expected the open breaker to prevent any call to the upstream, got %d new calls", got-callsBeforeOpenCheck)
	}

	// 4. Wait past cooldown, then flip healthy again.
	time.Sleep(cooldown + 50*time.Millisecond)
	atomic.StoreInt32(&healthy, 1)

	// 5. The next request is the half-open trial and must succeed,
	// closing the breaker.
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("chaos.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("step 5 (half-open trial): expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if breaker.State() != translate.StateClosed {
		t.Fatalf("step 5: expected the breaker closed after a successful half-open trial, got %v", breaker.State())
	}

	// 6. Fully recovered: subsequent requests succeed normally, no
	// further trial gating.
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("chaos.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("step 6 (recovered): expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
