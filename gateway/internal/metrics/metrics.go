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
)

func init() {
	prometheus.MustRegister(RequestsTotal, GatewayLatency)
}
