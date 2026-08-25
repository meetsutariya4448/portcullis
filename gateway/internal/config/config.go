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

// defaultMaxConcurrent bounds concurrent in-flight requests to an upstream
// on the native forward path when max_concurrent is unset. Legacy
// upstreams don't use this — MaxPoolSize already bounds their concurrency.
const defaultMaxConcurrent = 256

// defaultMaxInflight bounds total concurrent /mcp requests gateway-wide
// when max_inflight is unset at the top level.
const defaultMaxInflight = 1000

// RetryPolicy configures per-upstream retry behavior for forward attempts
// that fail before any side effect could have reached the upstream (see
// internal/retry's safety boundary, applied at the actual call sites).
// The zero value means "use internal/retry.DefaultConfig" for every field;
// an explicit MaxAttempts of 1 disables retries for an upstream an
// operator knows is unsafe to retry.
type RetryPolicy struct {
	MaxAttempts int    `yaml:"max_attempts"`
	BaseDelay   string `yaml:"base_delay"`
	MaxDelay    string `yaml:"max_delay"`
}

// BaseDelayDuration parses BaseDelay, returning (0, nil) when unset so the
// caller can substitute its own default.
func (r RetryPolicy) BaseDelayDuration() (time.Duration, error) {
	if r.BaseDelay == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(r.BaseDelay)
	if err != nil {
		return 0, fmt.Errorf("invalid retry.base_delay %q: %w", r.BaseDelay, err)
	}
	return d, nil
}

// MaxDelayDuration parses MaxDelay, returning (0, nil) when unset so the
// caller can substitute its own default.
func (r RetryPolicy) MaxDelayDuration() (time.Duration, error) {
	if r.MaxDelay == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(r.MaxDelay)
	if err != nil {
		return 0, fmt.Errorf("invalid retry.max_delay %q: %w", r.MaxDelay, err)
	}
	return d, nil
}

// CircuitBreakerPolicy configures per-upstream circuit-breaker tuning. The
// zero value means "use the translate package default" for every field.
type CircuitBreakerPolicy struct {
	Window     string  `yaml:"window"`
	MinSamples int     `yaml:"min_samples"`
	Threshold  float64 `yaml:"threshold"`
	Cooldown   string  `yaml:"cooldown"`
}

// WindowDuration parses Window, returning (0, nil) when unset so the
// caller can substitute its own default.
func (c CircuitBreakerPolicy) WindowDuration() (time.Duration, error) {
	if c.Window == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.Window)
	if err != nil {
		return 0, fmt.Errorf("invalid circuit_breaker.window %q: %w", c.Window, err)
	}
	return d, nil
}

// CooldownDuration parses Cooldown, returning (0, nil) when unset so the
// caller can substitute its own default.
func (c CircuitBreakerPolicy) CooldownDuration() (time.Duration, error) {
	if c.Cooldown == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.Cooldown)
	if err != nil {
		return 0, fmt.Errorf("invalid circuit_breaker.cooldown %q: %w", c.Cooldown, err)
	}
	return d, nil
}

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
	// MaxPoolSize overrides translate.DefaultMaxPoolSize for this upstream's
	// legacy session pool (only meaningful when ProtocolVersion is
	// translate.LegacyProtocolVersion). Zero means "use the default." This
	// exists because the default (8) is sized for production, not for a
	// benchmark run at 50+ concurrent requests against a single upstream.
	MaxPoolSize int `yaml:"max_pool_size"`
	// MaxConcurrent bounds concurrent in-flight requests to this upstream
	// on the native forward path (bulkhead isolation). Zero means "use
	// defaultMaxConcurrent." Not consulted for legacy upstreams —
	// MaxPoolSize already serves this role there.
	MaxConcurrent  int                  `yaml:"max_concurrent"`
	Retry          RetryPolicy          `yaml:"retry"`
	CircuitBreaker CircuitBreakerPolicy `yaml:"circuit_breaker"`
}

// MaxConcurrentOrDefault returns MaxConcurrent, falling back to
// defaultMaxConcurrent when unset.
func (u Upstream) MaxConcurrentOrDefault() int {
	if u.MaxConcurrent <= 0 {
		return defaultMaxConcurrent
	}
	return u.MaxConcurrent
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
	// MaxInflight bounds total concurrent /mcp requests gateway-wide
	// (backpressure). Zero means "use defaultMaxInflight."
	MaxInflight int `yaml:"max_inflight"`
}

// MaxInflightOrDefault returns MaxInflight, falling back to
// defaultMaxInflight when unset.
func (c Config) MaxInflightOrDefault() int {
	if c.MaxInflight <= 0 {
		return defaultMaxInflight
	}
	return c.MaxInflight
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
		if u.MaxPoolSize < 0 {
			return fmt.Errorf("upstream %q: max_pool_size must be >= 0, got %d", u.Name, u.MaxPoolSize)
		}
		if u.MaxConcurrent < 0 {
			return fmt.Errorf("upstream %q: max_concurrent must be >= 0, got %d", u.Name, u.MaxConcurrent)
		}
		if u.Retry.MaxAttempts < 0 {
			return fmt.Errorf("upstream %q: retry.max_attempts must be >= 0, got %d", u.Name, u.Retry.MaxAttempts)
		}
		if _, err := u.Retry.BaseDelayDuration(); err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		if _, err := u.Retry.MaxDelayDuration(); err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		if u.CircuitBreaker.MinSamples < 0 {
			return fmt.Errorf("upstream %q: circuit_breaker.min_samples must be >= 0, got %d", u.Name, u.CircuitBreaker.MinSamples)
		}
		if u.CircuitBreaker.Threshold < 0 || u.CircuitBreaker.Threshold > 1 {
			return fmt.Errorf("upstream %q: circuit_breaker.threshold must be in [0,1], got %v", u.Name, u.CircuitBreaker.Threshold)
		}
		if _, err := u.CircuitBreaker.WindowDuration(); err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
		if _, err := u.CircuitBreaker.CooldownDuration(); err != nil {
			return fmt.Errorf("upstream %q: %w", u.Name, err)
		}
	}
	if c.MaxInflight < 0 {
		return fmt.Errorf("max_inflight must be >= 0, got %d", c.MaxInflight)
	}
	return nil
}
