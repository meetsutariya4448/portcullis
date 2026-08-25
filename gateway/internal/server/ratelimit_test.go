package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/ratelimit"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// rateLimitTestGateway builds a gateway pointed at a trivial upstream that
// always returns 200, with the given Limiter (nil means rate limiting is
// disabled).
func rateLimitTestGateway(t *testing.T, limiter *ratelimit.Limiter) *Server {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "echo-upstream", Namespace: "echo", URL: upstream.URL,
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	return New(Options{Router: rtr, Log: log, MaxInflight: 100, RateLimiter: limiter})
}

func TestHandleMCP_NoRateLimiterConfigured_AllowsUnboundedRequests(t *testing.T) {
	gw := rateLimitTestGateway(t, nil)
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, nativeRequest("echo.ping"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 with no rate limiter configured, got %d", i, rec.Code)
		}
	}
}

func TestHandleMCP_RateLimitAllowsWithinBurst(t *testing.T) {
	gw := rateLimitTestGateway(t, ratelimit.NewLimiter(1, 3))
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, nativeRequest("echo.ping"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 within the burst of 3, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleMCP_RateLimitRejectsOnceBurstExhausted(t *testing.T) {
	gw := rateLimitTestGateway(t, ratelimit.NewLimiter(1, 1))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the first request to be allowed, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once the burst is exhausted, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected the rejected request to carry a Retry-After header")
	}
}

// TestHandleMCP_RateLimitTracksClientsIndependently proves each
// authenticated client gets its own bucket -- one client exhausting its
// limit must not affect another client's requests.
func TestHandleMCP_RateLimitTracksClientsIndependently(t *testing.T) {
	authenticator := auth.New([]auth.Client{
		{ID: "acme", APIKeys: []string{"acme-key"}},
		{ID: "globex", APIKeys: []string{"globex-key"}},
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "echo-upstream", Namespace: "echo", URL: upstream.URL,
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{
		Router:        rtr,
		Log:           log,
		MaxInflight:   100,
		Authenticator: authenticator,
		RateLimiter:   ratelimit.NewLimiter(1, 1),
	})

	acmeReq := nativeRequest("echo.ping")
	acmeReq.Header.Set(apiKeyHeader, "acme-key")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, acmeReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected acme's first request to be allowed, got %d", rec.Code)
	}

	globexReq := nativeRequest("echo.ping")
	globexReq.Header.Set(apiKeyHeader, "globex-key")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, globexReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected globex's first request to be allowed despite acme exhausting its own bucket, got %d", rec.Code)
	}
}
