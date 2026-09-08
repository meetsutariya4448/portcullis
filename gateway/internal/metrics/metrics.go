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

	// RateLimitRejectedTotal counts requests rejected because a client
	// exceeded its token-bucket rate limit.
	RateLimitRejectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_rate_limit_rejected_total",
		Help: "Total requests rejected because the client exceeded its rate limit.",
	}, []string{"client"})

	// QuotaRejectedTotal counts requests rejected because a client
	// exceeded its sliding-window quota.
	QuotaRejectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_quota_rejected_total",
		Help: "Total requests rejected because the client exceeded its quota.",
	}, []string{"client"})

	// AdmissionDecisionsTotal counts tool-poisoning admission decisions by
	// enforcement point (list/call), outcome (allow/deny) and reason.
	//
	// Labeled by namespace rather than by tool: tool names come from
	// upstream servers and are unbounded, so using one as a label value
	// would let an upstream grow this metric without limit. Same reasoning
	// as PolicyDeniedTotal above.
	AdmissionDecisionsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_admission_decisions_total",
		Help: "Tool-poisoning admission decisions, by enforcement point, outcome and reason.",
	}, []string{"point", "outcome", "reason", "namespace"})

	// AdmissionLatency measures the admission gate's own cost: catalog
	// lookup plus verdict lookup, which is a cache hit in the steady state.
	//
	// Reported separately from GatewayLatency so the claim that enforcement
	// is effectively free stays falsifiable -- the added cost is visible on
	// its own rather than folded into the headline overhead figure.
	AdmissionLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "portcullis_admission_latency_seconds",
		Help: "Time spent in the tool-poisoning admission gate, per request.",
		// Finer-grained than DefBuckets at the low end: a cache hit should
		// land in microseconds, and DefBuckets' 5ms floor would hide the
		// difference between "free" and "not free".
		Buckets: []float64{0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5},
	}, []string{"point"})

	// AdmissionCatalogTools is the number of tools currently discovered
	// from upstream listings, per namespace. A namespace that drops to zero
	// means discovery is failing for that upstream.
	AdmissionCatalogTools = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "portcullis_admission_catalog_tools",
		Help: "Tools currently discovered from upstream listings, per namespace.",
	}, []string{"namespace"})

	// AdmissionScansEnqueuedTotal counts tool definitions queued for the
	// control plane to scan. A persistently rising counter alongside a
	// rising unknown_hash decision count means the worker is not keeping up
	// (or is not running).
	AdmissionScansEnqueuedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_admission_scans_enqueued_total",
		Help: "Tool definitions enqueued for out-of-band scanning, per namespace.",
	}, []string{"namespace"})

	// AdmissionDiscoveryFailuresTotal counts failed upstream tool-list
	// refreshes. While this rises, the catalog is going stale and a
	// rug-pull would go unnoticed.
	AdmissionDiscoveryFailuresTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_admission_discovery_failures_total",
		Help: "Failed upstream tool-list discovery refreshes, per namespace.",
	}, []string{"namespace"})

	// UpstreamLatency measures pure upstream round-trip time — the
	// forward() call's duration, excluding Portcullis's own header
	// parsing/routing/marshaling overhead (that's GatewayLatency's job).
	UpstreamLatency = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "portcullis_upstream_latency_seconds",
		Help:    "Upstream round-trip time per request, excluding gateway-only overhead.",
		Buckets: prometheus.DefBuckets,
	}, []string{"upstream", "status"})

	// BulkheadRejectedTotal counts requests rejected because a per-upstream
	// bulkhead slot could not be acquired (distinct from every other
	// forward failure — see forwardNative).
	BulkheadRejectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_bulkhead_rejected_total",
		Help: "Total requests rejected because a per-upstream bulkhead slot could not be acquired.",
	}, []string{"upstream"})

	// LegacySessionReusedTotal counts legacy-upstream forward attempts
	// that reused an already-established session from the pool, rather
	// than paying the initialize/initialized handshake cost again.
	LegacySessionReusedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_legacy_session_reused_total",
		Help: "Total legacy-upstream forwards that reused a pooled session.",
	}, []string{"upstream"})

	// LegacySessionCreatedTotal counts legacy-upstream forward attempts
	// that established a brand new session via the handshake. Together
	// with LegacySessionReusedTotal this gives the pool's session reuse
	// rate: reused / (reused + created).
	LegacySessionCreatedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_legacy_session_created_total",
		Help: "Total legacy-upstream forwards that established a brand new session via the handshake.",
	}, []string{"upstream"})

	// StreamingResponsesTotal counts responses relayed via the
	// flush-per-chunk streaming copy loop (Content-Type: text/event-stream)
	// rather than the default buffered copy.
	StreamingResponsesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_streaming_responses_total",
		Help: "Total upstream responses relayed as a streaming (SSE) response.",
	}, []string{"upstream"})

	// UpstreamFailoverTotal counts requests that moved from one backend
	// to the next within a namespace's failover group, by namespace and
	// the (from, to) backend names.
	UpstreamFailoverTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "portcullis_upstream_failover_total",
		Help: "Total requests that failed over from one backend to the next within a namespace's failover group.",
	}, []string{"namespace", "from", "to"})
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
		RateLimitRejectedTotal,
		QuotaRejectedTotal,
		AdmissionDecisionsTotal,
		AdmissionLatency,
		AdmissionCatalogTools,
		AdmissionScansEnqueuedTotal,
		AdmissionDiscoveryFailuresTotal,
		UpstreamLatency,
		BulkheadRejectedTotal,
		LegacySessionReusedTotal,
		LegacySessionCreatedTotal,
		StreamingResponsesTotal,
		UpstreamFailoverTotal,
	)
}
