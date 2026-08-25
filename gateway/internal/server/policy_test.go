package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/policy"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// policyTestGateway builds a gateway pointed at a trivial upstream that
// always returns 200, with the given Policy (nil means the authorization
// gate is skipped entirely). Auth is left disabled so clientID is always
// "" here — policy rules in these tests match on client "*".
func policyTestGateway(t *testing.T, pol *policy.Policy) *Server {
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
	return New(Options{Router: rtr, Log: log, MaxInflight: 100, Policy: pol})
}

func TestHandleMCP_NoPolicyConfigured_AllowsRequest(t *testing.T) {
	gw := policyTestGateway(t, nil)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with no policy configured, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_PolicyAllowsMatchingRule(t *testing.T) {
	gw := policyTestGateway(t, policy.New([]policy.Rule{
		{Client: "*", Namespace: "echo", Tools: []string{"ping"}, Effect: "allow"},
	}))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for a matching allow rule, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_PolicyDeniesMatchingDenyRule(t *testing.T) {
	gw := policyTestGateway(t, policy.New([]policy.Rule{
		{Client: "*", Namespace: "echo", Tools: []string{"ping"}, Effect: "deny"},
	}))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a matching deny rule, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleMCP_PolicyDeniesWhenNothingMatches(t *testing.T) {
	gw := policyTestGateway(t, policy.New([]policy.Rule{
		{Client: "*", Namespace: "other-namespace", Tools: []string{"*"}, Effect: "allow"},
	}))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when no rule matches (default deny), got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestHandleMCP_PolicyGatesBeforeRouting proves the authorization decision
// is made from the request's own namespace/tool, not deferred until after
// a (possibly expensive) upstream resolution -- a denied call to a
// namespace with no configured upstream still gets 403, not a routing
// error, when a rule explicitly denies it.
func TestHandleMCP_PolicyGatesBeforeRouting(t *testing.T) {
	gw := policyTestGateway(t, policy.New([]policy.Rule{
		{Client: "*", Namespace: "nonexistent", Tools: []string{"*"}, Effect: "deny"},
	}))
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("nonexistent.whatever"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from the policy gate itself, got %d: %s", rec.Code, rec.Body.String())
	}
}
