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

	// CircuitBreakerState is the per-upstream breaker state
	// (0=closed, 1=open, 2=half_open — translate.BreakerState's values),
	// updated on every Allow()/Record() call. This is what a chaos-demo
	// dashboard graphs to show the closed->open->half_open->closed
	// lifecycle live.
	CircuitBreakerState = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "portcullis_circuit_breaker_state",
		Help: "Per-upstream circuit breaker state: 0=closed, 1=open, 2=half_open.",
	}, []string{"upstream"})

	// RetryAttemptsTotal counts every forward attempt made (including the
	// first), per upstream. attempts_total minus RequestsTotal's request
	// count for the same upstream is how many extra attempts retries cost.
	RetryAttemptsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_retry_attempts_total",
		Help: "Total forward attempts made per upstream, including the first attempt of each request.",
	}, []string{"upstream"})

	// BulkheadInflight is the current number of in-flight native-path
	// requests holding a bulkhead slot for an upstream.
	BulkheadInflight = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "portcullis_bulkhead_inflight",
		Help: "Current in-flight native-path requests holding a bulkhead slot, per upstream.",
	}, []string{"upstream"})

	// BulkheadWaitSeconds measures how long a request waited to acquire a
	// bulkhead slot. Near-zero under normal load; a rising p99 here is the
	// leading indicator that an upstream's max_concurrent is undersized
	// (or the upstream itself is slow) before it turns into rejected
	// requests or gateway-wide backpressure.
	BulkheadWaitSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "portcullis_bulkhead_wait_seconds",
		Help:    "Time spent waiting to acquire a per-upstream bulkhead slot.",
		Buckets: prometheus.DefBuckets,
	}, []string{"upstream"})

	// InflightRequests is the current number of /mcp requests being
	// handled gateway-wide, gated by the backpressure semaphore.
	InflightRequests = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "portcullis_inflight_requests",
		Help: "Current in-flight /mcp requests gateway-wide.",
	})

	// BackpressureRejectedTotal counts requests rejected with 503 because
	// the gateway-wide max_inflight bound was already saturated.
	BackpressureRejectedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "portcullis_backpressure_rejected_total",
		Help: "Total requests rejected because the gateway-wide inflight bound was saturated.",
	})

	// AuthRejectedTotal counts requests rejected at the gateway-edge
	// authentication gate, by reason (missing/invalid/revoked/expired).
	AuthRejectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_auth_rejected_total",
		Help: "Total requests rejected by gateway-edge authentication, by reason.",
	}, []string{"reason"})

	// PolicyDeniedTotal counts requests denied by the policy engine, by
	// client and namespace (not by tool — that would make the label set
	// unbounded for a fleet with many tools).
	PolicyDeniedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_policy_denied_total",
		Help: "Total requests denied by the policy engine, by client and namespace.",
	}, []string{"client", "namespace"})
)

func init() {
	prometheus.MustRegister(
		RequestsTotal,
		GatewayLatency,
		CircuitBreakerState,
		RetryAttemptsTotal,
		BulkheadInflight,
		BulkheadWaitSeconds,
		InflightRequests,
		BackpressureRejectedTotal,
		AuthRejectedTotal,
		PolicyDeniedTotal,
	)
}
