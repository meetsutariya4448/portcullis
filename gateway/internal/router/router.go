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
type Upstream struct {
	Name            string
	Namespace       string
	URL             string
	ProtocolVersion string
	Client          *http.Client
	LegacyPool      *translate.Pool
	RetryConfig     retry.Config
}

// Router maps a tool/resource/prompt namespace to its upstream.
type Router struct {
	upstreams map[string]*Upstream
}

// New builds a Router from the loaded config, constructing one pooled
// *http.Client per upstream, and — for upstreams declaring
// protocol_version: "2025-11-25" — a translate.Pool that performs the
// legacy handshake and holds sessions on the client's behalf.
func New(cfg *config.Config, log *slog.Logger) (*Router, error) {
	upstreams := make(map[string]*Upstream, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		timeout, err := u.TimeoutDuration()
		if err != nil {
			return nil, err
		}
		retryCfg, err := retryConfigFrom(u.Retry)
		if err != nil {
			return nil, err
		}

		client := &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: maxIdleConnsPerUpstream,
				IdleConnTimeout:     90 * time.Second,
				// Wraps the same dialer net/http would use by default
				// (DialContext left nil) — behavior is unchanged, but now
				// a successful dial is observable via retry.WithConnProbe,
				// which is what lets the native forward path retry a
				// pre-connect failure while never retrying a request that
				// actually reached the upstream.
				DialContext: retry.ProbeDialContext((&net.Dialer{}).DialContext),
			},
		}
		upstream := &Upstream{
			Name:            u.Name,
			Namespace:       u.Namespace,
			URL:             u.URL,
			ProtocolVersion: u.ProtocolVersion,
			Client:          client,
			RetryConfig:     retryCfg,
		}
		if u.ProtocolVersion == translate.LegacyProtocolVersion {
			upstream.LegacyPool = translate.NewPool(u.URL, client, log, u.MaxPoolSize)
		}
		upstreams[u.Namespace] = upstream
	}
	return &Router{upstreams: upstreams}, nil
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
