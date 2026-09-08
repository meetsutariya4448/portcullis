package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// TestSecurity_GatewayAPIKeyIsNeverForwardedUpstream is the regression test
// for a real leak: copyHeaders relayed every inbound header, so
// X-Portcullis-Api-Key -- the gateway's own edge credential -- was handed
// to every upstream in the fleet. Any of them, including the untrusted
// third-party servers this gateway exists to sit in front of, could replay
// it to impersonate that client at the gateway.
//
// TestSecurity_APIKeyNeverReachesTelemetry covers logs and spans; this
// covers the wire, which is where it actually escaped.
func TestSecurity_GatewayAPIKeyIsNeverForwardedUpstream(t *testing.T) {
	const apiKey = "super-secret-acme-key-should-never-leave-the-gateway"

	var mu sync.Mutex
	var seen http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Header.Clone()
		mu.Unlock()
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
		Router: rtr, Log: log, MaxInflight: 100,
		Authenticator: auth.New([]auth.Client{{ID: "acme", APIKeys: []string{apiKey}}}),
	})

	req := nativeRequest("echo.ping")
	req.Header.Set(apiKeyHeader, apiKey)
	// An Authorization header IS meant for the upstream -- that is the whole
	// reason Portcullis uses a header of its own -- so it must still arrive.
	req.Header.Set("Authorization", "Bearer upstream-token")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if got := seen.Get(apiKeyHeader); got != "" {
		t.Errorf("%s was forwarded upstream with value %q", apiKeyHeader, got)
	}
	for name, values := range seen {
		for _, v := range values {
			if strings.Contains(v, apiKey) {
				t.Errorf("the gateway API key leaked upstream in header %q = %q", name, v)
			}
		}
	}
	if got := seen.Get("Authorization"); got != "Bearer upstream-token" {
		t.Errorf("Authorization = %q, want it forwarded unchanged for the upstream", got)
	}
}

func TestCopyHeaders_DoesNotMutateTheSourceHeaders(t *testing.T) {
	// The earlier implementation deleted hop-by-hop headers from src in
	// place, mutating the caller's inbound request headers -- visible to
	// everything later in the pipeline and to every retry reusing the map.
	src := http.Header{}
	src.Set("Connection", "keep-alive")
	src.Set("Content-Type", "application/json")
	src.Set(apiKeyHeader, "secret")

	copyHeaders(http.Header{}, src)

	if src.Get("Connection") == "" {
		t.Error("copyHeaders deleted a header from its source")
	}
	if src.Get(apiKeyHeader) == "" {
		t.Error("copyHeaders deleted the API key from its source")
	}
}

func TestCopyHeaders_StripsHopByHopAndTheEdgeCredential(t *testing.T) {
	src := http.Header{}
	src.Set("Content-Type", "application/json")
	src.Set("X-Custom", "keep me")
	for _, h := range hopByHopHeaders {
		src.Set(h, "drop me")
	}
	// Header names are case-insensitive; a client sending an odd casing
	// must not slip the credential past the filter.
	src.Set("x-portcullis-api-key", "secret")

	dst := http.Header{}
	copyHeaders(dst, src)

	for _, h := range hopByHopHeaders {
		if dst.Get(h) != "" {
			t.Errorf("hop-by-hop header %q was forwarded", h)
		}
	}
	if dst.Get(apiKeyHeader) != "" {
		t.Error("the edge credential was forwarded despite lowercase spelling")
	}
	if dst.Get("X-Custom") != "keep me" || dst.Get("Content-Type") != "application/json" {
		t.Error("an ordinary header was dropped")
	}
}

// TestMetrics_ToolNamesCannotMintUnboundedSeries is the regression test for
// a memory-exhaustion vector: the request metrics were labeled by the
// client-supplied tool name, so N distinct names produced N counters and N
// histograms with nothing capping them.
func TestMetrics_ToolNamesCannotMintUnboundedSeries(t *testing.T) {
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
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	before := countSeries(t, metrics.RequestsTotal)
	for i := 0; i < 50; i++ {
		gw.ServeHTTP(httptest.NewRecorder(), nativeRequest("echo.tool"+strings.Repeat("x", i)))
		// Unroutable namespaces are the other half of the vector.
		gw.ServeHTTP(httptest.NewRecorder(), nativeRequest("ghost"+strings.Repeat("y", i)+".tool"))
	}
	added := countSeries(t, metrics.RequestsTotal) - before

	// 100 distinct client-supplied names may add at most the routed
	// namespace and the "unrouted" bucket, times the statuses they produce.
	if added > 4 {
		t.Fatalf("100 distinct tool names added %d time series; the label is still unbounded", added)
	}
}

func countSeries(t *testing.T, collector prometheus.Collector) int {
	t.Helper()
	ch := make(chan prometheus.Metric, 4096)
	go func() {
		collector.Collect(ch)
		close(ch)
	}()
	n := 0
	for range ch {
		n++
	}
	return n
}

func TestMetricNamespace_CollapsesUnroutableNames(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "echo-upstream", Namespace: "echo", URL: upstream.URL,
	}}}
	rtr, err := router.New(cfg, discardLogger())
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	s := New(Options{Router: rtr, Log: discardLogger(), MaxInflight: 10})

	for _, tc := range []struct{ in, want string }{
		{"echo.ping", "echo"},
		{"echo.anything-at-all", "echo"},
		{"nosuchnamespace.tool", unroutedNamespaceLabel},
		{"not-namespace-qualified", unroutedNamespaceLabel},
		{"", unroutedNamespaceLabel},
	} {
		if got := s.metricNamespace(tc.in); got != tc.want {
			t.Errorf("metricNamespace(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
