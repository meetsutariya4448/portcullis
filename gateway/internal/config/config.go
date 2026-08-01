// Package config loads the upstream fleet definition Portcullis routes to.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// defaultUpstreamTimeout is applied to an upstream that doesn't set its own
// "timeout" in the config file.
const defaultUpstreamTimeout = 30 * time.Second

// Upstream is one MCP server Portcullis can route to.
type Upstream struct {
	Name            string `yaml:"name"`
	Namespace       string `yaml:"namespace"`
	URL             string `yaml:"url"`
	ProtocolVersion string `yaml:"protocol_version"`
	// Timeout is the per-upstream HTTP client timeout. Optional; defaults to
	// defaultUpstreamTimeout if empty. Accepts any value time.ParseDuration
	// understands, e.g. "30s".
	Timeout string `yaml:"timeout"`
}

// TimeoutDuration returns the parsed per-upstream timeout, falling back to
// defaultUpstreamTimeout when Timeout is unset.
func (u Upstream) TimeoutDuration() (time.Duration, error) {
	if u.Timeout == "" {
		return defaultUpstreamTimeout, nil
	}
	d, err := time.ParseDuration(u.Timeout)
	if err != nil {
		return 0, fmt.Errorf("upstream %q: invalid timeout %q: %w", u.Name, u.Timeout, err)
	}
	return d, nil
}

// Config is the top-level YAML config: the fleet of upstreams Portcullis
// proxies to.
type Config struct {
	Upstreams []Upstream `yaml:"upstreams"`
}

// Load reads and parses the upstream fleet config from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %q: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	seen := make(map[string]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.Name == "" {
			return fmt.Errorf("upstream has no name")
		}
		if u.Namespace == "" {
			return fmt.Errorf("upstream %q: namespace is required", u.Name)
		}
		if u.URL == "" {
			return fmt.Errorf("upstream %q: url is required", u.Name)
		}
		if seen[u.Namespace] {
			return fmt.Errorf("duplicate upstream namespace %q", u.Namespace)
		}
		seen[u.Namespace] = true
		if _, err := u.TimeoutDuration(); err != nil {
			return err
		}
	}
	return nil
}
