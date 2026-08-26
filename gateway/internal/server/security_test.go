package server

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// TestSecurity_APIKeyNeverReachesTelemetry is a security-regression test
// locking in a property that was previously just "true by not having
// written the bug": Milestone 3's span attributes were deliberately
// designed to carry only portcullis.client_id, never the API key itself
// (see server.go's handleMCP -- span.SetAttributes only ever receives
// clientID, the resolved identity, not the credential that produced it).
// This proves it, rather than continuing to rely on code review holding
// forever: sends a real API key through a real authenticated request,
// then searches every exported span's attributes/events AND the log
// output for that exact key string.
func TestSecurity_APIKeyNeverReachesTelemetry(t *testing.T) {
	exporter := installTestTracing(t)

	const apiKey = "super-secret-acme-key-should-never-leak-anywhere"
	authenticator := auth.New([]auth.Client{{ID: "acme", APIKeys: []string{apiKey}}})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "security-upstream", Namespace: "security", URL: upstream.URL,
	}}}

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))

	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100, Authenticator: authenticator})

	req := nativeRequest("security.ping")
	req.Header.Set(apiKeyHeader, apiKey)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if strings.Contains(logBuf.String(), apiKey) {
		t.Fatalf("API key leaked into log output:\n%s", logBuf.String())
	}

	for _, span := range exporter.GetSpans() {
		for _, attr := range span.Attributes {
			if strings.Contains(attr.Value.Emit(), apiKey) {
				t.Fatalf("API key leaked into span %q attribute %q = %q", span.Name, attr.Key, attr.Value.Emit())
			}
		}
		for _, ev := range span.Events {
			for _, attr := range ev.Attributes {
				if strings.Contains(attr.Value.Emit(), apiKey) {
					t.Fatalf("API key leaked into span %q event %q attribute %q = %q", span.Name, ev.Name, attr.Key, attr.Value.Emit())
				}
			}
		}
	}
}

// TestSecurity_RejectedAuthAttemptDoesNotLeakPresentedKey covers the
// mirror case: an INVALID key presented by a caller must not leak into
// telemetry either, even though the request is rejected. authRejectReason
// only ever returns a fixed reason string (missing/invalid/revoked/
// expired), never echoing the presented credential -- this locks that in.
func TestSecurity_RejectedAuthAttemptDoesNotLeakPresentedKey(t *testing.T) {
	exporter := installTestTracing(t)

	const presentedKey = "wrong-key-that-was-guessed-by-an-attacker"
	authenticator := auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"the-real-key"}}})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "security-upstream-2", Namespace: "security2", URL: upstream.URL,
	}}}

	var logBuf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logBuf, nil))

	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100, Authenticator: authenticator})

	req := nativeRequest("security2.ping")
	req.Header.Set(apiKeyHeader, presentedKey)
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	if strings.Contains(logBuf.String(), presentedKey) {
		t.Fatalf("presented (wrong) API key leaked into log output:\n%s", logBuf.String())
	}
	for _, span := range exporter.GetSpans() {
		for _, attr := range span.Attributes {
			if strings.Contains(attr.Value.Emit(), presentedKey) {
				t.Fatalf("presented (wrong) API key leaked into span %q attribute %q", span.Name, attr.Key)
			}
		}
	}
}
