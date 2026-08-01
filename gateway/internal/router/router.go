// Package router resolves a namespaced tool/resource/prompt name to a
// configured upstream and holds that upstream's pooled HTTP client.
package router

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
)

// maxIdleConnsPerUpstream bounds the pooled idle connections kept open to
// a single upstream, per config.Config.validate.
const maxIdleConnsPerUpstream = 32

// Upstream pairs a configured upstream with its own connection-pooled HTTP
// client and timeout, per SPEC-NOTES.md §1: "One upstream connection pool
// per configured upstream, with a per-upstream timeout."
type Upstream struct {
	Name            string
	Namespace       string
	URL             string
	ProtocolVersion string
	Client          *http.Client
}

// Router maps a tool/resource/prompt namespace to its upstream.
type Router struct {
	upstreams map[string]*Upstream
}

// New builds a Router from the loaded config, constructing one pooled
// *http.Client per upstream.
func New(cfg *config.Config) (*Router, error) {
	upstreams := make(map[string]*Upstream, len(cfg.Upstreams))
	for _, u := range cfg.Upstreams {
		timeout, err := u.TimeoutDuration()
		if err != nil {
			return nil, err
		}
		upstreams[u.Namespace] = &Upstream{
			Name:            u.Name,
			Namespace:       u.Namespace,
			URL:             u.URL,
			ProtocolVersion: u.ProtocolVersion,
			Client: &http.Client{
				Timeout: timeout,
				Transport: &http.Transport{
					MaxIdleConnsPerHost: maxIdleConnsPerUpstream,
					IdleConnTimeout:     90 * time.Second,
				},
			},
		}
	}
	return &Router{upstreams: upstreams}, nil
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
