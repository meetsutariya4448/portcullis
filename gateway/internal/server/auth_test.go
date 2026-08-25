package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// authTestGateway builds a gateway pointed at a trivial upstream that
// always returns 200, with the given Authenticator (nil means auth
// disabled). Shared setup for every test in this file.
func authTestGateway(t *testing.T, authenticator *auth.Authenticator) *Server {
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
	return New(Options{Router: rtr, Log: log, MaxInflight: 100, Authenticator: authenticator})
}

// TestHandleMCP_AuthDisabled_AllowsRequestWithNoKey is the backward-
// compatibility guarantee: a Server built with no Authenticator (the
// zero value of Options.Authenticator, matching a config with no auth:
// block) behaves exactly like every pre-Milestone-2 deployment -- no key
// required at all.
func TestHandleMCP_AuthDisabled_AllowsRequestWithNoKey(t *testing.T) {
	gw := authTestGateway(t, nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with auth disabled and no key presented, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_AuthEnabled_RejectsMissingKey(t *testing.T) {
	gw := authTestGateway(t, auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"acme-key"}}}))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping")) // no X-Portcullis-Api-Key header set
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a missing key, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_AuthEnabled_RejectsInvalidKey(t *testing.T) {
	gw := authTestGateway(t, auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"acme-key"}}}))
	req := nativeRequest("echo.ping")
	req.Header.Set(apiKeyHeader, "not-the-right-key")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an invalid key, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_AuthEnabled_AllowsValidKey(t *testing.T) {
	gw := authTestGateway(t, auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"acme-key"}}}))
	req := nativeRequest("echo.ping")
	req.Header.Set(apiKeyHeader, "acme-key")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a valid key, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_AuthEnabled_RejectsRevokedClient(t *testing.T) {
	gw := authTestGateway(t, auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"acme-key"}, Revoked: true}}))
	req := nativeRequest("echo.ping")
	req.Header.Set(apiKeyHeader, "acme-key")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a revoked client, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_AuthEnabled_RejectsExpiredClient(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	gw := authTestGateway(t, auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"acme-key"}, ExpiresAt: &past}}))
	req := nativeRequest("echo.ping")
	req.Header.Set(apiKeyHeader, "acme-key")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an expired client, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleMCP_AuthEnabled_RotationAcceptsOldAndNewKey proves rotation
// works end-to-end through the actual gateway, not just at the auth
// package's unit-test level: both keys authenticate successfully while
// both are listed.
func TestHandleMCP_AuthEnabled_RotationAcceptsOldAndNewKey(t *testing.T) {
	gw := authTestGateway(t, auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"old-key", "new-key"}}}))
	for _, key := range []string{"old-key", "new-key"} {
		req := nativeRequest("echo.ping")
		req.Header.Set(apiKeyHeader, key)
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("key %q: expected 200, got %d: %s", key, rec.Code, rec.Body.String())
		}
	}
}
