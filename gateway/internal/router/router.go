// Package router resolves a namespaced tool/resource/prompt name to a
// configured upstream and holds that upstream's pooled HTTP client.
package router

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/retry"
	"github.com/meetsutariya4448/portcullis/gateway/internal/translate"
)

// maxIdleConnsPerUpstream bounds the pooled idle connections kept open to
// a single upstream, per config.Config.validate.
const maxIdleConnsPerUpstream = 32

// Upstream pairs a configured upstream with its own connection-pooled HTTP
// client and timeout, per SPEC-NOTES.md §1: "One upstream connection pool
// per configured upstream, with a per-upstream timeout."
//
// LegacyPool is non-nil only when ProtocolVersion is translate.LegacyProtocolVersion
// (2025-11-25): requests to that upstream go through the session-pool shim
// in package translate instead of Client directly.
//
// Breaker and Bulkhead protect the NATIVE forward path (server.go wraps
// upstream.Client.Do with them). Legacy upstreams keep using LegacyPool's
// own internal breaker and its MaxPoolSize-bounded concurrency instead —
// Breaker/Bulkhead are still constructed for a legacy Upstream (so the
// zero value is never nil) but the server never exercises them on that
// path, since forwarding always goes through LegacyPool.Forward.
type Upstream struct {
	Name            string
	Namespace       string
	URL             string
	ProtocolVersion string
	Client          *http.Client
	LegacyPool      *translate.Pool
	Breaker         *translate.CircuitBreaker
	Bulkhead        bulkhead
	RetryConfig     retry.Config
}

// Router maps a tool/resource/prompt namespace to its upstream.
type Router struct {
	upstreams map[string]*Upstream
}

// New builds a Router from the loaded config, constructing one pooled
// *http.Client, a circuit breaker, and a bulkhead per upstream (see the
// Upstream doc comment for which path actually uses the breaker/bulkhead),
// and — for upstreams declaring protocol_version: "2025-11-25" — a
// translate.Pool that performs the legacy handshake and holds sessions on
// the client's behalf.
func New(cfg *config.Config, log *slog.Logger) (*Router, error) {
	upstreams := make(map[string]*Upstream, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		timeout, err := u.TimeoutDuration()
		if err != nil {
			return nil, err
		}
		breakerCfg, err := breakerConfigFrom(u.CircuitBreaker)
		if err != nil {
			return nil, err
		}
		retryCfg, err := retryConfigFrom(u.Retry)
		if err != nil {
			return nil, err
		}

		transport := &http.Transport{
			MaxIdleConnsPerHost: maxIdleConnsPerUpstream,
			IdleConnTimeout:     90 * time.Second,
			// Wraps the same dialer net/http would use by default
			// (DialContext left nil) — behavior is unchanged, but now
			// a successful dial is observable via retry.WithConnProbe,
			// which is what lets the native forward path retry a
			// pre-connect failure while never retrying a request that
			// actually reached the upstream.
			DialContext: retry.ProbeDialContext((&net.Dialer{}).DialContext),
			// ResponseHeaderTimeout (not http.Client.Timeout — see
			// below) bounds only how long we wait for the upstream to
			// start responding.
			ResponseHeaderTimeout: timeout,
		}
		client := &http.Client{
			// Deliberately no Timeout here: http.Client.Timeout bounds
			// the ENTIRE request including body-read time, which would
			// kill a legitimate long-lived streaming response (e.g. a
			// subscriptions/listen SSE stream) after `timeout` elapses
			// regardless of whether the upstream is healthy. Once
			// headers arrive within ResponseHeaderTimeout above, a
			// response — streamed or not — is now bounded only by the
			// client's own connection lifetime (r.Context(), canceled
			// when the client disconnects) and, on shutdown, the
			// graceful-drain timeout. This also fixes a latent issue for
			// ordinary large non-streaming responses, which previously
			// could be killed mid-transfer by a healthy-but-slow
			// upstream even though it had already started responding.
			//
			// otelhttp.NewTransport wraps the dial-probed transport one
			// layer further: it starts a client-side span per real
			// outbound call and injects the active trace context as a
			// traceparent header, via whatever propagator
			// internal/tracing installed globally (a no-op when tracing
			// is disabled). One wrapping point here instruments BOTH
			// the native forward path (upstream.Client.Do) and the
			// legacy path (translate.Pool is handed this same client),
			// so an upstream that's also instrumented joins the same
			// trace across the proxy boundary either way.
			Transport: otelhttp.NewTransport(transport),
		}
		upstream := &Upstream{
			Name:            u.Name,
			Namespace:       u.Namespace,
			URL:             u.URL,
			ProtocolVersion: u.ProtocolVersion,
			Client:          client,
			Breaker:         translate.NewCircuitBreakerWithConfig(breakerCfg),
			Bulkhead:        newBulkhead(u.MaxConcurrentOrDefault()),
			RetryConfig:     retryCfg,
		}
		if u.ProtocolVersion == translate.LegacyProtocolVersion {
			upstream.LegacyPool = translate.NewPool(u.Name, u.URL, client, log, u.MaxPoolSize).WithBreakerConfig(breakerCfg)
		}
		upstreams[u.Namespace] = upstream
	}
	return &Router{upstreams: upstreams}, nil
}

// breakerConfigFrom converts a config.CircuitBreakerPolicy (string
// durations, YAML-facing) into a translate.BreakerConfig (parsed
// durations). config.Config.validate already checked these parse cleanly
// at load time; errors here would only occur if New is called with a
// config that skipped validation.
func breakerConfigFrom(p config.CircuitBreakerPolicy) (translate.BreakerConfig, error) {
	window, err := p.WindowDuration()
	if err != nil {
		return translate.BreakerConfig{}, err
	}
	cooldown, err := p.CooldownDuration()
	if err != nil {
		return translate.BreakerConfig{}, err
	}
	return translate.BreakerConfig{
		Window:     window,
		MinSamples: p.MinSamples,
		Threshold:  p.Threshold,
		Cooldown:   cooldown,
	}, nil
}

// retryConfigFrom converts a config.RetryPolicy (string durations,
// YAML-facing) into a retry.Config (parsed durations). config.Config.validate
// already checked these parse cleanly at load time; errors here would only
// occur if New is called with a config that skipped validation.
func retryConfigFrom(p config.RetryPolicy) (retry.Config, error) {
	baseDelay, err := p.BaseDelayDuration()
	if err != nil {
		return retry.Config{}, err
	}
	maxDelay, err := p.MaxDelayDuration()
	if err != nil {
		return retry.Config{}, err
	}
	return retry.Config{
		MaxAttempts: p.MaxAttempts,
		BaseDelay:   baseDelay,
		MaxDelay:    maxDelay,
	}, nil
}

// SplitName splits a "{namespace}.{tool}" name into its namespace and tool
// parts. It returns ok=false if name has no namespace separator.
func SplitName(name string) (namespace, tool string, ok bool) {
	i := strings.Index(name, ".")
	if i <= 0 || i == len(name)-1 {
		return "", "", false
	}
	return name[:i], name[i+1:], true
}

// Resolve looks up the upstream registered for namespace.
func (r *Router) Resolve(namespace string) (*Upstream, error) {
	u, ok := r.upstreams[namespace]
	if !ok {
		return nil, fmt.Errorf("no upstream configured for namespace %q", namespace)
	}
	return u, nil
}
