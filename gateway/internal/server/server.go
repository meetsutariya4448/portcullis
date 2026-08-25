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

	gwmcp "github.com/meetsutariya4448/portcullis/gateway/internal/mcp"
	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
	"github.com/meetsutariya4448/portcullis/gateway/internal/retry"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
	"github.com/meetsutariya4448/portcullis/gateway/internal/translate"
)

// maxBodyBytes bounds how much of a request body Portcullis will read into
// memory before rejecting the request.
const maxBodyBytes = 10 << 20 // 10MiB

// hopByHopHeaders are stripped when forwarding a request or response, per
// RFC 9110's hop-by-hop header list — they describe this specific
// connection, not the message, and must not be blindly relayed.
var hopByHopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Server holds the dependencies shared by all handlers.
type Server struct {
	router *router.Router
	log    *slog.Logger
	mux    *http.ServeMux

	// inflightSem bounds total concurrent /mcp handling gateway-wide —
	// backpressure. A request that can't immediately acquire a slot is
	// rejected with 503 + Retry-After rather than queuing unboundedly.
	inflightSem chan struct{}
}

// New builds a Server and registers its routes. maxInflight bounds total
// concurrent /mcp requests gateway-wide; pass config.MaxInflightOrDefault().
func New(rtr *router.Router, log *slog.Logger, maxInflight int) *Server {
	if maxInflight <= 0 {
		maxInflight = 1
	}
	s := &Server{router: rtr, log: log, mux: http.NewServeMux(), inflightSem: make(chan struct{}, maxInflight)}
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

// handleMCP is the single stateless data-plane endpoint: validate headers
// against the body, resolve the target upstream from the tool namespace,
// forward the request unchanged, and return the response unchanged.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	handlerStart := time.Now()

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

	namespace, _, ok := router.SplitName(headers.Name)
	if !ok {
		s.writeGatewayError(w, r, req.Method, headers.Name, http.StatusBadGateway, req.ID,
			"request is not namespace-qualified (\"{namespace}.{tool}\"); Portcullis cannot route it", handlerStart, nil)
		return
	}

	upstream, err := s.router.Resolve(namespace)
	if err != nil {
		s.writeGatewayError(w, r, req.Method, headers.Name, http.StatusBadGateway, req.ID, err.Error(), handlerStart, err)
		return
	}

	preUpstream := time.Since(handlerStart)

	upstreamStart := time.Now()
	resp, err := s.forward(r.Context(), upstream, body, r.Header)
	upstreamDuration := time.Since(upstreamStart)
	if err != nil {
		httpStatus, message := translateForwardError(err)
		s.writeGatewayError(w, r, req.Method, headers.Name, httpStatus, req.ID, message, handlerStart, err)
		return
	}
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

	totalDuration := time.Since(handlerStart)
	logArgs := []any{
		"method", req.Method,
		"tool", headers.Name,
		"upstream", upstream.Name,
		"duration_ms", totalDuration.Milliseconds(),
		"status", resp.StatusCode,
		"upstream_duration_ms", upstreamDuration.Milliseconds(),
	}
	if copyErr != nil {
		s.log.Error("mcp request: failed writing response body", append(logArgs, "error", copyErr)...)
		return
	}
	s.log.Info("mcp request", logArgs...)
}

// forward dispatches to the legacy or native forward path and wraps the
// whole attempt in upstream's retry policy. retry.Do re-invokes fn from
// scratch on a retryable failure — for the legacy path that means a fresh
// Pool.Forward call (which itself starts with a fresh session lease); for
// the native path, forwardNative re-dials from scratch. Neither path
// decides retryability once up front — each attempt's own outcome decides
// whether the next attempt happens.
func (s *Server) forward(ctx context.Context, upstream *router.Upstream, body []byte, headers http.Header) (*http.Response, error) {
	var resp *http.Response
	err := retry.Do(ctx, upstream.RetryConfig, func(attempt int) error {
		metrics.RetryAttemptsTotal.WithLabelValues(upstream.Name).Inc()

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
// guarded by that upstream's bulkhead. A failure before the request
// reached the upstream (bulkhead wait canceled, a pre-connect dial
// failure) is returned bare so retry.Do may retry it; anything after the
// request was handed to the upstream is wrapped in retry.NonRetryable --
// MCP tool calls are not guaranteed idempotent, so a failure that might
// mean the upstream already started processing the call must never be
// retried automatically.
func (s *Server) forwardNative(ctx context.Context, upstream *router.Upstream, body []byte, headers http.Header) (*http.Response, error) {
	waitStart := time.Now()
	if err := upstream.Bulkhead.Acquire(ctx); err != nil {
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
		return nil, retry.NonRetryable(err)
	}
	copyHeaders(outReq.Header, headers)

	resp, err := upstream.Client.Do(outReq)
	if err != nil {
		if connEstablished() {
			// The request reached the upstream (or we can't prove it
			// didn't) -- not safe to retry automatically.
			return nil, retry.NonRetryable(err)
		}
		return nil, err // pre-connect failure: safe to retry
	}
	return resp, nil
}

// writeJSONRPCError writes a fully-formed JSON-RPC error response (e.g. a
// HeaderMismatch) and records logging/metrics for it.
func (s *Server) writeJSONRPCError(w http.ResponseWriter, r *http.Request, method, tool string, httpStatus int, resp gwmcp.ErrorResponse, handlerStart time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(resp)

	duration := time.Since(handlerStart)
	status := strconv.Itoa(httpStatus)
	metrics.RequestsTotal.WithLabelValues(method, tool, status).Inc()
	metrics.GatewayLatency.WithLabelValues(method, tool, status).Observe(duration.Seconds())
	s.log.Warn("mcp request rejected",
		"method", method,
		"tool", tool,
		"duration_ms", duration.Milliseconds(),
		"status", httpStatus,
		"error_code", resp.Error.Code,
		"error_message", resp.Error.Message,
	)
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

	duration := time.Since(handlerStart)
	status := strconv.Itoa(httpStatus)
	metrics.RequestsTotal.WithLabelValues(method, tool, status).Inc()
	metrics.GatewayLatency.WithLabelValues(method, tool, status).Observe(duration.Seconds())
	logArgs := []any{
		"method", method,
		"tool", tool,
		"duration_ms", duration.Milliseconds(),
		"status", httpStatus,
		"message", message,
	}
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
