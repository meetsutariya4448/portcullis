// Package metrics defines Portcullis's Prometheus instrumentation.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// RequestsTotal counts proxied requests by method, tool, and outcome status.
	RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_requests_total",
		Help: "Total MCP requests proxied by Portcullis.",
	}, []string{"method", "tool", "status"})

	// GatewayLatency measures Portcullis's own per-request overhead —
	// header validation, routing, and marshaling — excluding time spent
	// waiting on the upstream round trip.
	GatewayLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "portcullis_gateway_latency_seconds",
		Help:    "Gateway-only overhead per request, excluding upstream round-trip time.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "tool", "status"})

	// RetryAttemptsTotal counts every forward attempt made (including the
	// first), per upstream. attempts_total minus RequestsTotal's request
	// count for the same upstream is how many extra attempts retries cost.
	RetryAttemptsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_retry_attempts_total",
		Help: "Total forward attempts made per upstream, including the first attempt of each request.",
	}, []string{"upstream"})
)

func init() {
	prometheus.MustRegister(
		RequestsTotal,
		GatewayLatency,
		RetryAttemptsTotal,
	)
}
