package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
	"github.com/meetsutariya4448/portcullis/gateway/internal/policy"
	"github.com/meetsutariya4448/portcullis/gateway/internal/quota"
	"github.com/meetsutariya4448/portcullis/gateway/internal/ratelimit"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// sumCounterVec totals every time series currently registered under cv,
// across every label combination -- used to prove a metric's total
// count matches an independently-known number of events, without having
// to enumerate every label combination a concurrent test produced.
func sumCounterVec(cv *prometheus.CounterVec) float64 {
	ch := make(chan prometheus.Metric, 64)
	go func() {
		cv.Collect(ch)
		close(ch)
	}()
	var total float64
	for m := range ch {
		var pb dto.Metric
		_ = m.Write(&pb)
		total += pb.GetCounter().GetValue()
	}
	return total
}

// TestLoad_ConcurrentMultiFeatureTraffic hits a gateway with auth,
// policy, rate limiting, and quota all enabled simultaneously under
// real concurrency -- every existing integration test up to this point
// exercises one feature (or one interaction) at a time. This is where a
// race between two gates touching shared state, or a metric that gets
// double-counted or dropped under concurrent access, would actually
// surface -- exactly what go test -race exists to catch, and exactly
// what a single-goroutine test structurally cannot.
func TestLoad_ConcurrentMultiFeatureTraffic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "load-upstream", Namespace: "load", URL: upstream.URL, MaxConcurrent: 500,
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}

	authenticator := auth.New([]auth.Client{
		{ID: "acme", APIKeys: []string{"acme-key"}},
		{ID: "globex", APIKeys: []string{"globex-key"}},
	})
	// Only acme is allowed; globex is authenticated but denied --
	// exercises the 403 path under concurrency too.
	pol := policy.New([]policy.Rule{
		{Client: "acme", Namespace: "load", Tools: []string{"*"}, Effect: "allow"},
	})
	limiter := ratelimit.NewLimiter(1000, 50) // generous, but low enough that a 300-request burst can trip it
	quotaTracker := quota.NewTracker(1000, 100000)

	gw := New(Options{
		Router:        rtr,
		Log:           log,
		MaxInflight:   1000,
		Authenticator: authenticator,
		Policy:        pol,
		RateLimiter:   limiter,
		QuotaTracker:  quotaTracker,
	})

	const perCategory = 100
	type category struct {
		name      string
		apiKey    string // "" means no key at all
		wantCodes map[int]bool
	}
	categories := []category{
		{name: "valid-allowed", apiKey: "acme-key", wantCodes: map[int]bool{http.StatusOK: true, http.StatusTooManyRequests: true}},
		{name: "valid-denied", apiKey: "globex-key", wantCodes: map[int]bool{http.StatusForbidden: true, http.StatusTooManyRequests: true}},
		{name: "invalid-key", apiKey: "not-a-real-key", wantCodes: map[int]bool{http.StatusUnauthorized: true}},
	}

	requestsBefore := sumCounterVec(metrics.RequestsTotal)

	var wg sync.WaitGroup
	var mu sync.Mutex
	codesByCategory := make(map[string][]int, len(categories))
	// Pre-populate every key before any goroutine starts: a concurrent
	// map WRITE from the main goroutine (adding a new key for the next
	// category) racing against a worker goroutine's guarded append to a
	// DIFFERENT key is still a race -- Go maps aren't safe for
	// concurrent access at all, key collision or not, since insertion
	// can trigger a shared rehash. mu only protects appends from racing
	// each other, not from this.
	for _, cat := range categories {
		codesByCategory[cat.name] = make([]int, 0, perCategory)
	}

	for _, cat := range categories {
		cat := cat
		for i := 0; i < perCategory; i++ {
			wg.Add(1)
			go func(cat category) {
				defer wg.Done()
				req := nativeRequest("load.ping")
				if cat.apiKey != "" {
					req.Header.Set(apiKeyHeader, cat.apiKey)
				}
				rec := httptest.NewRecorder()
				gw.ServeHTTP(rec, req)

				mu.Lock()
				codesByCategory[cat.name] = append(codesByCategory[cat.name], rec.Code)
				mu.Unlock()
			}(cat)
		}
	}
	wg.Wait()

	totalRequests := 0
	for _, cat := range categories {
		codes := codesByCategory[cat.name]
		if len(codes) != perCategory {
			t.Fatalf("category %q: expected %d responses, got %d", cat.name, perCategory, len(codes))
		}
		totalRequests += len(codes)
		for _, code := range codes {
			if !cat.wantCodes[code] {
				t.Fatalf("category %q: unexpected status code %d (allowed: %v)", cat.name, code, cat.wantCodes)
			}
		}
	}

	// invalid-key requests never touch the rate limiter (auth rejects
	// them first), so this category's outcome is fully deterministic
	// regardless of concurrent load from the other two categories.
	for _, code := range codesByCategory["invalid-key"] {
		if code != http.StatusUnauthorized {
			t.Fatalf("expected every invalid-key request to get 401 deterministically, got %d", code)
		}
	}

	requestsAfter := sumCounterVec(metrics.RequestsTotal)
	if got := requestsAfter - requestsBefore; got != float64(totalRequests) {
		t.Fatalf("expected portcullis_requests_total to increase by exactly %d (one per request, no double-count or drop under concurrency), got %v", totalRequests, got)
	}

	if t.Failed() {
		fmt.Println("codesByCategory:", codesByCategory)
	}
}
