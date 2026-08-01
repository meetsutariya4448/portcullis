// Package server implements Portcullis's HTTP surface: the single /mcp
// data-plane endpoint plus /healthz and /metrics.
package server

import (
	"bytes"
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
}

// New builds a Server and registers its routes.
func New(rtr *router.Router, log *slog.Logger) *Server {
	s := &Server{router: rtr, log: log, mux: http.NewServeMux()}
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
	var resp *http.Response
	if upstream.LegacyPool != nil {
		resp, err = upstream.LegacyPool.Forward(r.Context(), body)
	} else {
		var outReq *http.Request
		outReq, err = http.NewRequestWithContext(r.Context(), http.MethodPost, upstream.URL, bytes.NewReader(body))
		if err == nil {
			copyHeaders(outReq.Header, r.Header)
			resp, err = upstream.Client.Do(outReq)
		}
	}
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
