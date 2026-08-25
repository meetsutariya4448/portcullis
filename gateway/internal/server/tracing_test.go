package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

// OpenTelemetry's global otel.Tracer(...) — which server.go's package-level
// tracer var calls exactly once, at package init — resolves through a
// one-time delegate: the FIRST otel.SetTracerProvider call after init
// upgrades that delegate to a concrete provider, and later
// SetTracerProvider calls stop affecting it. So tests can't each install
// their own TracerProvider the way a fresh-process test normally would;
// instead, install exactly one real provider/exporter for the whole test
// binary (via sync.Once) and Reset the shared exporter before each test.
var (
	tracingSetupOnce sync.Once
	tracingExporter  *tracetest.InMemoryExporter
)

// installTestTracing returns the process-wide in-memory span exporter,
// resetting it first so a test only sees spans from its own request.
func installTestTracing(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	tracingSetupOnce.Do(func() {
		tracingExporter = tracetest.NewInMemoryExporter()
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithSyncer(tracingExporter),
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
		)
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.TraceContext{})
	})
	tracingExporter.Reset()
	return tracingExporter
}

func TestHandleMCP_SuccessfulRequest_ProducesOkSpan(t *testing.T) {
	exporter := installTestTracing(t)
	gw := policyTestGateway(t, nil) // echo upstream in namespace "echo", no policy

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	spans := exporter.GetSpans()
	var handleSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "mcp.handle" {
			handleSpan = &spans[i]
		}
	}
	if handleSpan == nil {
		t.Fatalf("expected an \"mcp.handle\" span, got spans: %v", spanNames(spans))
	}
	if handleSpan.Status.Code != codes.Ok {
		t.Fatalf("expected codes.Ok, got %v (%s)", handleSpan.Status.Code, handleSpan.Status.Description)
	}
	assertHasAttribute(t, handleSpan.Attributes, "mcp.namespace", "echo")
}

// TestHandleMCP_RejectedRequest_ProducesErrorSpan is the error-context
// test: it proves a rejection marks the *mcp.handle* span itself as
// codes.Error (with the matching HTTP status code attribute), not merely
// that a span exists at all -- the happy-path test above wouldn't catch
// an instrumentation bug that left every rejection path unmarked, since
// writeGatewayError/writeJSONRPCError are the only places that set
// span status and this is the only way to prove they're actually wired
// to the request's real span (via r.Context(), after r.WithContext).
func TestHandleMCP_RejectedRequest_ProducesErrorSpan(t *testing.T) {
	exporter := installTestTracing(t)
	authenticator := auth.New([]auth.Client{{ID: "acme", APIKeys: []string{"acme-key"}}})
	gw := authTestGateway(t, authenticator)

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("echo.ping")) // no API key header set
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	spans := exporter.GetSpans()
	var handleSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "mcp.handle" {
			handleSpan = &spans[i]
		}
	}
	if handleSpan == nil {
		t.Fatalf("expected an \"mcp.handle\" span, got spans: %v", spanNames(spans))
	}
	if handleSpan.Status.Code != codes.Error {
		t.Fatalf("expected codes.Error for a rejected request, got %v", handleSpan.Status.Code)
	}
	assertHasAttribute(t, handleSpan.Attributes, "http.response.status_code", int64(http.StatusUnauthorized))
}

// TestHandleMCP_PropagatesIncomingTraceparentToUpstream is the
// end-to-end propagation test: it proves Portcullis extracts an incoming
// traceparent (rather than starting a disconnected new trace) AND
// injects that same trace onto the outbound request to the upstream --
// i.e. genuine distributed tracing across the proxy boundary, not just
// local span generation. A wiring mistake in either half (missing
// Extract, or a transport that isn't otelhttp-wrapped) would make this
// fail while the two tests above could still pass.
func TestHandleMCP_PropagatesIncomingTraceparentToUpstream(t *testing.T) {
	exporter := installTestTracing(t)

	var capturedTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedTraceparent = r.Header.Get("traceparent")
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
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	// W3C spec's own example IDs (used verbatim in the tracecontext spec)
	// -- a fixed, known trace/span ID this test can assert against.
	const incomingTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const incomingSpanID = "00f067aa0ba902b7"
	req := nativeRequest("echo.ping")
	req.Header.Set("traceparent", "00-"+incomingTraceID+"-"+incomingSpanID+"-01")

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if capturedTraceparent == "" {
		t.Fatal("expected the upstream to receive a traceparent header, got none")
	}
	if !containsTraceID(capturedTraceparent, incomingTraceID) {
		t.Fatalf("expected the outbound traceparent to carry the incoming trace ID %q, got %q", incomingTraceID, capturedTraceparent)
	}

	spans := exporter.GetSpans()
	var handleSpan *tracetest.SpanStub
	for i := range spans {
		if spans[i].Name == "mcp.handle" {
			handleSpan = &spans[i]
		}
	}
	if handleSpan == nil {
		t.Fatalf("expected an \"mcp.handle\" span, got spans: %v", spanNames(spans))
	}
	if got := handleSpan.SpanContext.TraceID().String(); got != incomingTraceID {
		t.Fatalf("expected mcp.handle's span to share the incoming trace ID %q, got %q -- extraction did not happen", incomingTraceID, got)
	}
}

func containsTraceID(traceparent, traceID string) bool {
	// traceparent format: "{version}-{trace-id}-{parent-id}-{flags}"
	return len(traceparent) >= 2+len(traceID) && traceparent[3:3+len(traceID)] == traceID
}

func spanNames(spans tracetest.SpanStubs) []string {
	names := make([]string, len(spans))
	for i, s := range spans {
		names[i] = s.Name
	}
	return names
}

func assertHasAttribute(t *testing.T, attrs []attribute.KeyValue, key string, want any) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) != key {
			continue
		}
		switch w := want.(type) {
		case string:
			if a.Value.AsString() != w {
				t.Fatalf("attribute %q: expected %q, got %q", key, w, a.Value.AsString())
			}
		case int64:
			if a.Value.AsInt64() != w {
				t.Fatalf("attribute %q: expected %d, got %d", key, w, a.Value.AsInt64())
			}
		default:
			t.Fatalf("unsupported want type for attribute %q", key)
		}
		return
	}
	t.Fatalf("expected attribute %q to be set, attributes: %v", key, attrs)
}
