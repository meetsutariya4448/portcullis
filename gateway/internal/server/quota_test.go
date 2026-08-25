package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/quota"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// quotaTestGateway builds a gateway pointed at a trivial upstream that
// always returns 200, with the given Tracker (nil means quota tracking is
// disabled).
func quotaTestGateway(t *testing.T, tracker *quota.Tracker) *Server {
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
	return New(Options{Router: rtr, Log: log, MaxInflight: 100, QuotaTracker: tracker})
}

func TestHandleMCP_NoQuotaTrackerConfigured_AllowsUnboundedRequests(t *testing.T) {
	gw := quotaTestGateway(t, nil)
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, nativeRequest("echo.ping"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 with no quota tracker configured, got %d", i, rec.Code)
		}
	}
}

func TestHandleMCP_QuotaAllowsWithinMax(t *testing.T) {
	gw := quotaTestGateway(t, quota.NewTracker(time.Hour, 3))
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, nativeRequest("echo.ping"))
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 within quota max=3, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleMCP_QuotaRejectsOnceMaxExhausted(t *testing.T) {
	gw := quotaTestGateway(t, quota.NewTracker(time.Hour, 1))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected the first request to be allowed, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once quota is exhausted, got %d: %s", rec.Code, rec.Body.String())
	}
}
