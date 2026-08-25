// Package tracing builds Portcullis's OpenTelemetry TracerProvider from
// config and installs it as the process-wide default.
package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
)

// BuildProvider constructs a TracerProvider from cfg and installs it (and
// a W3C tracecontext propagator) as OpenTelemetry's process-wide default
// via otel.SetTracerProvider/otel.SetTextMapPropagator.
//
// When cfg.Enabled is false, this returns (nil, nil) and touches nothing
// global: every otel.Tracer(...) call elsewhere in the gateway then
// returns OpenTelemetry's built-in no-op tracer, so instrumented code
// needs no "is tracing on" branching of its own — this is the same
// nil-means-off posture as every other Milestone 2 gate.
//
// The caller is responsible for calling Shutdown on the returned
// provider (if non-nil) to flush any buffered spans before the process
// exits.
func BuildProvider(ctx context.Context, cfg config.Tracing) (*sdktrace.TracerProvider, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("tracing: building OTLP exporter: %w", err)
	}

	res := resource.NewWithAttributes(semconv.SchemaURL,
		semconv.ServiceName(cfg.ServiceNameOrDefault()),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRatioOrDefault())),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp, nil
}
