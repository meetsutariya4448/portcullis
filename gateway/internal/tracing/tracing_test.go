package tracing

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
)

// resetGlobalTracing restores OpenTelemetry's global tracer provider and
// propagator after a test that calls BuildProvider with tracing enabled
// — otherwise one test's global state would leak into every test that
// runs after it in the same process.
func resetGlobalTracing(t *testing.T) {
	t.Helper()
	prevTP := otel.GetTracerProvider()
	prevProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
}

func TestBuildProvider_DisabledReturnsNilWithoutError(t *testing.T) {
	tp, err := BuildProvider(context.Background(), config.Tracing{Enabled: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tp != nil {
		t.Fatal("expected a nil provider when tracing is disabled")
	}
}

func TestBuildProvider_EnabledReturnsProvider(t *testing.T) {
	resetGlobalTracing(t)
	tp, err := BuildProvider(context.Background(), config.Tracing{
		Enabled:      true,
		OTLPEndpoint: "localhost:4318",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tp == nil {
		t.Fatal("expected a non-nil provider when tracing is enabled")
	}
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
}

// TestBuildProvider_DefaultSampleRatioSamplesEverything proves the
// zero-value SampleRatio (meaning "default to 1.0") actually results in
// every span being sampled, not just that SampleRatioOrDefault reports
// 1.0 in isolation.
func TestBuildProvider_DefaultSampleRatioSamplesEverything(t *testing.T) {
	resetGlobalTracing(t)
	tp, err := BuildProvider(context.Background(), config.Tracing{
		Enabled:      true,
		OTLPEndpoint: "localhost:4318",
		// SampleRatio deliberately left at its zero value.
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	_, span := tp.Tracer("test").Start(context.Background(), "test-span")
	defer span.End()
	if !span.SpanContext().IsSampled() {
		t.Fatal("expected a span to be sampled when SampleRatio defaults to 1.0")
	}
}
