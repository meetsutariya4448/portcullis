// Package server implements Portcullis's HTTP surface: the single /mcp
// data-plane endpoint plus /healthz and /metrics.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	gwmcp "github.com/meetsutariya4448/portcullis/gateway/internal/mcp"
	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
	"github.com/meetsutariya4448/portcullis/gateway/internal/policy"
	"github.com/meetsutariya4448/portcullis/gateway/internal/quota"
	"github.com/meetsutariya4448/portcullis/gateway/internal/ratelimit"
	"github.com/meetsutariya4448/portcullis/gateway/internal/retry"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
	"github.com/meetsutariya4448/portcullis/gateway/internal/translate"
)

// maxBodyBytes bounds how much of a request body Portcullis will read into
// memory before rejecting the request.
const maxBodyBytes = 10 << 20 // 10MiB

// apiKeyHeader carries the gateway-edge API key. Deliberately not
// "Authorization": that header (if a client sends one) is meant for the
// upstream MCP server and is forwarded through unchanged by copyHeaders —
// Portcullis's own auth needs a header of its own so the two never collide.
const apiKeyHeader = "X-Portcullis-Api-Key"

// tracer is Portcullis's tracer for the request pipeline. When no
// TracerProvider has been installed (tracing disabled — see
// internal/tracing), otel.Tracer returns OpenTelemetry's built-in no-op
// implementation, so every call site below needs no "is tracing on"
// branching of its own.
var tracer = otel.Tracer("portcullis/server")

// hopByHopHeaders are stripped when forwarding a request or response, per
// RFC 9110's hop-by-hop header list — they describe this specific
// connection, not the message, and must not be blindly relayed.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Options bundles Server's dependencies. Introduced in Milestone 2 instead
// of growing New's positional parameter list further (it was already at
// 3 after Milestone 1); more traffic-control dependencies land here as
// later Milestone 2 commits add them.
type Options struct {
	Router      *router.Router
	Log         *slog.Logger
	MaxInflight int
	// Authenticator is optional. nil means gateway-edge authentication is
	// disabled and every request is allowed through unauthenticated —
	// today's behavior, unchanged, for a config with no auth: block.
	Authenticator *auth.Authenticator
	// Policy is optional. nil means the authorization gate is skipped
	// entirely — equivalent to (but cheaper than) a Policy with zero
	// rules, which also allows everything.
	Policy *policy.Policy
	// RateLimiter is optional. nil means no client is ever rate-limited —
	// today's behavior, unchanged, for a config with no rate_limit: block.
	RateLimiter *ratelimit.Limiter
	// QuotaTracker is optional. nil means no client is ever quota-limited
	// — today's behavior, unchanged, for a config with no quota: block.
	QuotaTracker *quota.Tracker
}

// Server holds the dependencies shared by all handlers.
type Server struct {
	router        *router.Router
	log           *slog.Logger
	mux           *http.ServeMux
	authenticator *auth.Authenticator
	policy        *policy.Policy
	rateLimiter   *ratelimit.Limiter
	quotaTracker  *quota.Tracker

	// inflightSem bounds total concurrent /mcp handling gateway-wide —
	// backpressure. A request that can't immediately acquire a slot is
	// rejected with 503 + Retry-After rather than queuing unboundedly.
	inflightSem chan struct{}
}

// New builds a Server and registers its routes.
func New(opts Options) *Server {
	maxInflight := opts.MaxInflight
	if maxInflight <= 0 {
		maxInflight = 1
	}
	s := &Server{
		router:        opts.Router,
		log:           opts.Log,
		mux:           http.NewServeMux(),
		authenticator: opts.Authenticator,
		policy:        opts.Policy,
		rateLimiter:   opts.RateLimiter,
		quotaTracker:  opts.QuotaTracker,
		inflightSem:   make(chan struct{}, maxInflight),
	}
	s.mux.HandleFunc("POST /mcp", s.handleMCP)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)
	s.mux.Handle("GET /metrics", promhttp.Handler())
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// authenticate resolves the caller's identity from the apiKeyHeader. When
// no Authenticator is configured (auth disabled, or no auth: block in
// config at all), every request is allowed through with an empty
// clientID — today's behavior, unchanged.
func (s *Server) authenticate(r *http.Request) (clientID string, err error) {
	if s.authenticator == nil {
		return "", nil
	}
	client, err := s.authenticator.Authenticate(r.Header.Get(apiKeyHeader))
	if err != nil {
		return "", err
	}
	return client.ID, nil
}

// authorize decides whether clientID may call tool in namespace. When no
// Policy is configured, every request is allowed through — today's
// behavior, unchanged, for a config with no policy: block.
func (s *Server) authorize(clientID, namespace, tool string) (allow bool, reason string) {
	if s.policy == nil {
		return true, ""
	}
	return s.policy.Evaluate(clientID, namespace, tool)
}

// authRejectReason maps an auth error to a stable, low-cardinality metric
// label.
func authRejectReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrMissingKey):
		return "missing"
	case errors.Is(err, auth.ErrInvalidKey):
		return "invalid"
	case errors.Is(err, auth.ErrRevoked):
		return "revoked"
	case errors.Is(err, auth.ErrExpired):
		return "expired"
	default:
		return "unknown"
	}
}

// handleMCP is the single stateless data-plane endpoint: validate headers
// against the body, resolve the target upstream from the tool namespace,
// forward the request unchanged, and return the response unchanged.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	handlerStart := time.Now()

	// Extract any incoming traceparent before starting our own span, so a
	// caller that's already tracing this call joins the same trace instead
	// of Portcullis silently starting a disconnected one. otelhttp's
	// outbound transport (see router.New) injects a traceparent on the way
	// to the upstream using the same global propagator, so a request that
	// arrives already-traced stays in one trace end to end. Reassigning
	// r's context (rather than threading a separate ctx variable) means
	// every r.Context() call below -- including inside
	// writeGatewayError/writeJSONRPCError, which aren't otherwise touched
	// -- sees the active span with no further call-site changes.
	ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	ctx, span := tracer.Start(ctx, "mcp.handle", trace.WithAttributes(
		semconv.HTTPRequestMethodPost,
		semconv.HTTPRoute("/mcp"),
	))
	r = r.WithContext(ctx)
	defer span.End()

	select {
	case s.inflightSem <- struct{}{}:
	default:
		metrics.BackpressureRejectedTotal.Inc()
		w.Header().Set("Retry-After", "1")
		s.writeGatewayError(w, r, "", "", http.StatusServiceUnavailable, nil, "gateway at capacity, try again shortly", handlerStart, nil)
		return
	}
	metrics.InflightRequests.Inc()
	defer func() {
		metrics.InflightRequests.Dec()
		<-s.inflightSem
	}()

	clientID, err := s.authenticate(r)
	if err != nil {
		metrics.AuthRejectedTotal.WithLabelValues(authRejectReason(err)).Inc()
		s.writeGatewayError(w, r, "", "", http.StatusUnauthorized, nil, err.Error(), handlerStart, err)
		return
	}
	span.SetAttributes(attribute.String("portcullis.client_id", clientID))

	if s.rateLimiter != nil && !s.rateLimiter.Allow(clientID) {
		metrics.RateLimitRejectedTotal.WithLabelValues(clientID).Inc()
		w.Header().Set("Retry-After", "1")
		s.writeGatewayError(w, r, "", "", http.StatusTooManyRequests, nil, "rate limit exceeded", handlerStart, nil)
		return
	}

	if s.quotaTracker != nil && !s.quotaTracker.Allow(clientID) {
		metrics.QuotaRejectedTotal.WithLabelValues(clientID).Inc()
		s.writeGatewayError(w, r, "", "", http.StatusTooManyRequests, nil, "quota exceeded", handlerStart, nil)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		s.writeGatewayError(w, r, "", "", http.StatusRequestEntityTooLarge, nil, "request body too large or unreadable", handlerStart, err)
		return
	}

	var req gwmcp.Request
	if err := json.Unmarshal(body, &req); err != nil {
		s.writeGatewayError(w, r, "", "", http.StatusBadRequest, nil, "request body is not valid JSON-RPC", handlerStart, err)
		return
	}

	headers := gwmcp.Headers{
		ProtocolVersion: r.Header.Get("MCP-Protocol-Version"),
		Method:          r.Header.Get("Mcp-Method"),
		Name:            r.Header.Get("Mcp-Name"),
	}

	if err := gwmcp.ValidateHeaders(headers, &req); err != nil {
		resp := gwmcp.NewHeaderMismatchResponse(req.ID, err)
		s.writeJSONRPCError(w, r, req.Method, headers.Name, http.StatusBadRequest, resp, handlerStart)
		return
	}

	namespace, tool, ok := router.SplitName(headers.Name)
	if !ok {
		s.writeGatewayError(w, r, req.Method, headers.Name, http.StatusBadGateway, req.ID,
			"request is not namespace-qualified (\"{namespace}.{tool}\"); Portcullis cannot route it", handlerStart, nil)
		return
	}
	span.SetAttributes(
		semconv.RPCMethod(req.Method),
		attribute.String("mcp.tool", headers.Name),
		attribute.String("mcp.namespace", namespace),
	)

	if allow, reason := s.authorize(clientID, namespace, tool); !allow {
		metrics.PolicyDeniedTotal.WithLabelValues(clientID, namespace).Inc()
		s.writeGatewayError(w, r, req.Method, headers.Name, http.StatusForbidden, req.ID, reason, handlerStart, nil)
		return
	}

	upstream, err := s.router.Resolve(namespace)
	if err != nil {
		s.writeGatewayError(w, r, req.Method, headers.Name, http.StatusBadGateway, req.ID, err.Error(), handlerStart, err)
		return
	}
	span.SetAttributes(attribute.String("portcullis.upstream", upstream.Name))

	preUpstream := time.Since(handlerStart)

	upstreamStart := time.Now()
	forwardCtx, forwardSpan := tracer.Start(r.Context(), "portcullis.forward",
		trace.WithAttributes(attribute.String("portcullis.upstream", upstream.Name)))
	resp, err := s.forward(forwardCtx, upstream, body, r.Header)
	upstreamDuration := time.Since(upstreamStart)
	if err != nil {
		httpStatus, message := translateForwardError(err)
		forwardSpan.SetStatus(codes.Error, message)
		forwardSpan.End()
		metrics.UpstreamLatency.WithLabelValues(upstream.Name, strconv.Itoa(httpStatus)).Observe(upstreamDuration.Seconds())
		s.writeGatewayError(w, r, req.Method, headers.Name, httpStatus, req.ID, message, handlerStart, err)
		return
	}
	forwardSpan.End()
	defer resp.Body.Close()

	postStart := time.Now()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, copyErr := io.Copy(w, resp.Body)
	postUpstream := time.Since(postStart)

	gatewayOverhead := preUpstream + postUpstream
	status := strconv.Itoa(resp.StatusCode)
	metrics.RequestsTotal.WithLabelValues(req.Method, headers.Name, status).Inc()
	metrics.GatewayLatency.WithLabelValues(req.Method, headers.Name, status).Observe(gatewayOverhead.Seconds())
	metrics.UpstreamLatency.WithLabelValues(upstream.Name, status).Observe(upstreamDuration.Seconds())
	span.SetAttributes(semconv.HTTPResponseStatusCode(resp.StatusCode))

	totalDuration := time.Since(handlerStart)
	logArgs := append([]any{
		"method", req.Method,
		"tool", headers.Name,
		"upstream", upstream.Name,
		"client", clientID,
		"duration_ms", totalDuration.Milliseconds(),
		"status", resp.StatusCode,
		"upstream_duration_ms", upstreamDuration.Milliseconds(),
	}, traceLogArgs(r.Context())...)
	if copyErr != nil {
		span.SetStatus(codes.Error, copyErr.Error())
		s.log.Error("mcp request: failed writing response body", append(logArgs, "error", copyErr)...)
		return
	}
	span.SetStatus(codes.Ok, "")
	s.log.Info("mcp request", logArgs...)
}

// traceLogArgs returns slog key/value pairs correlating a log line with
// its trace, or nil when ctx carries no valid (i.e. tracing is disabled
// or sampled-out) span context -- the concrete link between "structured
// logs" and "OTel tracing."
func traceLogArgs(ctx context.Context) []any {
	sc := trace.SpanFromContext(ctx).SpanContext()
	if !sc.IsValid() {
		return nil
	}
	return []any{"trace_id", sc.TraceID().String(), "span_id", sc.SpanID().String()}
}

// forward dispatches to the legacy or native forward path and wraps the
// whole attempt in upstream's retry policy. retry.Do re-invokes fn from
// scratch on a retryable failure — for the legacy path that means a fresh
// Pool.Forward call (which itself starts with a fresh session lease and a
// fresh breaker.Allow() check); for the native path, forwardNative
// likewise re-checks the breaker and bulkhead on every attempt. Neither
// path's Allow() check is done once up front — each retry attempt gets an
// independent, current admission decision.
func (s *Server) forward(ctx context.Context, upstream *router.Upstream, body []byte, headers http.Header) (*http.Response, error) {
	var resp *http.Response
	err := retry.Do(ctx, upstream.RetryConfig, func(attempt int) error {
		metrics.RetryAttemptsTotal.WithLabelValues(upstream.Name).Inc()
		trace.SpanFromContext(ctx).AddEvent("attempt", trace.WithAttributes(attribute.Int("attempt", attempt)))

		var attemptErr error
		if upstream.LegacyPool != nil {
			resp, attemptErr = upstream.LegacyPool.Forward(ctx, body)
		} else {
			resp, attemptErr = s.forwardNative(ctx, upstream, body, headers)
		}
		return attemptErr
	})
	return resp, err
}

// forwardNative sends body directly to a native (2026-07-28) upstream,
// guarded by that upstream's circuit breaker and bulkhead. Mirrors the
// breaker/error-wrapping pattern translate.Pool.Forward already uses for
// the legacy path: a failure before the request reached the upstream
// (breaker open, bulkhead wait canceled, a pre-connect dial failure) is
// returned bare so retry.Do may retry it; anything after the request was
// handed to the upstream is wrapped in retry.NonRetryable.
func (s *Server) forwardNative(ctx context.Context, upstream *router.Upstream, body []byte, headers http.Header) (*http.Response, error) {
	if !upstream.Breaker.Allow() {
		return nil, retry.NonRetryable(translate.ErrCircuitOpen)
	}

	waitStart := time.Now()
	if err := upstream.Bulkhead.Acquire(ctx); err != nil {
		metrics.BulkheadRejectedTotal.WithLabelValues(upstream.Name).Inc()
		return nil, retry.NonRetryable(err)
	}
	metrics.BulkheadWaitSeconds.WithLabelValues(upstream.Name).Observe(time.Since(waitStart).Seconds())
	metrics.BulkheadInflight.WithLabelValues(upstream.Name).Inc()
	defer func() {
		metrics.BulkheadInflight.WithLabelValues(upstream.Name).Dec()
		upstream.Bulkhead.Release()
	}()

	probeCtx, connEstablished := retry.WithConnProbe(ctx)
	outReq, err := http.NewRequestWithContext(probeCtx, http.MethodPost, upstream.URL, bytes.NewReader(body))
	if err != nil {
		upstream.Breaker.Record(false)
		return nil, retry.NonRetryable(err)
	}
	copyHeaders(outReq.Header, headers)

	resp, err := upstream.Client.Do(outReq)
	if err != nil {
		upstream.Breaker.Record(false)
		metrics.CircuitBreakerState.WithLabelValues(upstream.Name).Set(float64(upstream.Breaker.State()))
		if connEstablished() {
			// The request reached the upstream (or we can't prove it
			// didn't) -- not safe to retry automatically.
			return nil, retry.NonRetryable(err)
		}
		return nil, err // pre-connect failure: safe to retry
	}
	upstream.Breaker.Record(true)
	metrics.CircuitBreakerState.WithLabelValues(upstream.Name).Set(float64(upstream.Breaker.State()))
	return resp, nil
}

// writeJSONRPCError writes a fully-formed JSON-RPC error response (e.g. a
// HeaderMismatch) and records logging/metrics for it.
func (s *Server) writeJSONRPCError(w http.ResponseWriter, r *http.Request, method, tool string, httpStatus int, resp gwmcp.ErrorResponse, handlerStart time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(resp)

	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(semconv.HTTPResponseStatusCode(httpStatus))
	span.SetStatus(codes.Error, resp.Error.Message)

	duration := time.Since(handlerStart)
	status := strconv.Itoa(httpStatus)
	metrics.RequestsTotal.WithLabelValues(method, tool, status).Inc()
	metrics.GatewayLatency.WithLabelValues(method, tool, status).Observe(duration.Seconds())
	logArgs := append([]any{
		"method", method,
		"tool", tool,
		"duration_ms", duration.Milliseconds(),
		"status", httpStatus,
		"error_code", resp.Error.Code,
		"error_message", resp.Error.Message,
	}, traceLogArgs(r.Context())...)
	s.log.Warn("mcp request rejected", logArgs...)
}

// writeGatewayError writes a generic JSON-RPC error response for failures
// that aren't header/body mismatches (bad JSON, unroutable request,
// unreachable upstream) and records logging/metrics for it.
func (s *Server) writeGatewayError(w http.ResponseWriter, r *http.Request, method, tool string, httpStatus int, id json.RawMessage, message string, handlerStart time.Time, cause error) {
	resp := gwmcp.ErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: gwmcp.RPCError{
			Code:    -32000,
			Message: message,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(resp)

	span := trace.SpanFromContext(r.Context())
	span.SetAttributes(semconv.HTTPResponseStatusCode(httpStatus))
	span.SetStatus(codes.Error, message)

	duration := time.Since(handlerStart)
	status := strconv.Itoa(httpStatus)
	metrics.RequestsTotal.WithLabelValues(method, tool, status).Inc()
	metrics.GatewayLatency.WithLabelValues(method, tool, status).Observe(duration.Seconds())
	logArgs := append([]any{
		"method", method,
		"tool", tool,
		"duration_ms", duration.Milliseconds(),
		"status", httpStatus,
		"message", message,
	}, traceLogArgs(r.Context())...)
	if cause != nil {
		logArgs = append(logArgs, "error", cause)
	}
	s.log.Error("mcp request failed", logArgs...)
}

// translateForwardError maps an error from a legacy upstream forward
// (package translate) or a direct upstream call to the HTTP status and
// message Portcullis should return to the client.
func translateForwardError(err error) (httpStatus int, message string) {
	switch {
	case errors.Is(err, translate.ErrUnsupportedMRTR):
		return http.StatusNotImplemented, "legacy upstream requires a multi-round-trip flow (sampling/elicitation/roots) that this gateway does not bridge"
	case errors.Is(err, translate.ErrCircuitOpen):
		return http.StatusServiceUnavailable, "upstream circuit breaker is open"
	case errors.Is(err, translate.ErrPoolExhausted):
		return http.StatusServiceUnavailable, "legacy session pool exhausted"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		// A request whose context ended while waiting -- on a retry backoff
		// delay, on a bulkhead slot, or the client disconnecting mid-request.
		return http.StatusServiceUnavailable, "request canceled or timed out waiting for upstream capacity"
	default:
		return http.StatusBadGateway, "upstream request failed"
	}
}

// copyHeaders copies all headers from src to dst except hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	for _, h := range hopByHopHeaders {
		src.Del(h)
	}
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
