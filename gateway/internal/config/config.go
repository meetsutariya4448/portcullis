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

// AuthClient is one caller Portcullis recognizes: a client identity plus
// the API key(s) that authenticate as it. APIKeys is a list deliberately
// — key rotation is just "list the old and new key together for a
// while," no separate rotation mechanism needed. Each entry in APIKeys
// may be a literal or a "${SECRET:NAME}" reference (see
// internal/secret) — expansion happens where the Authenticator is built,
// not here, so this package stays free of a dependency on internal/secret.
type AuthClient struct {
	ClientID string   `yaml:"client_id"`
	APIKeys  []string `yaml:"api_keys"`
	// ExpiresAt is RFC3339; empty means the credential never expires.
	ExpiresAt string `yaml:"expires_at"`
	Revoked   bool   `yaml:"revoked"`
}

// ExpiresAtTime parses ExpiresAt, returning (nil, nil) when unset.
func (a AuthClient) ExpiresAtTime() (*time.Time, error) {
	if a.ExpiresAt == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, a.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("client %q: invalid expires_at %q: %w", a.ClientID, a.ExpiresAt, err)
	}
	return &t, nil
}

// Auth configures gateway-edge API-key authentication (a separate
// concern from MCP's own protocol-level OAuth — see internal/auth's
// package doc). Enabled defaults to false: an absent or disabled `auth:`
// block means every request is allowed through unauthenticated, today's
// behavior, unchanged, for any config that doesn't opt in.
type Auth struct {
	Enabled bool         `yaml:"enabled"`
	Clients []AuthClient `yaml:"clients"`
}

// PolicyRule is one authorization rule: Client and Namespace match a
// literal value or "*" (any); Tools matches if the target tool is listed
// or Tools contains "*". Effect must be "allow" or "deny".
type PolicyRule struct {
	Client    string   `yaml:"client"`
	Namespace string   `yaml:"namespace"`
	Tools     []string `yaml:"tools"`
	Effect    string   `yaml:"effect"`
}

// Policy configures the (client, namespace, tool) authorization gate. An
// empty Rules list means "no policy configured" — every request is
// allowed through, today's behavior, unchanged, for any config that
// doesn't opt in. Once Rules is non-empty, evaluation is first-match-wins
// and anything no rule matches is denied — see internal/policy.
type Policy struct {
	Rules []PolicyRule `yaml:"rules"`
}

// RateLimit configures the gateway-wide per-client token-bucket rate
// limiter. Enabled defaults to false: an absent or disabled
// `rate_limit:` block means no client is ever rate-limited, today's
// behavior, unchanged, for any config that doesn't opt in. Every client
// (keyed by its authenticated client ID, or "" if auth is disabled) gets
// its own bucket at the same RequestsPerSecond/Burst — see
// internal/ratelimit.
type RateLimit struct {
	Enabled           bool    `yaml:"enabled"`
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

// Quota configures the gateway-wide per-client sliding-window request
// quota — a longer-horizon sibling to RateLimit (hours/days rather than
// per-second). Enabled defaults to false: an absent or disabled `quota:`
// block means no client is ever quota-limited, today's behavior,
// unchanged, for any config that doesn't opt in. See internal/quota.
type Quota struct {
	Enabled     bool   `yaml:"enabled"`
	MaxRequests int    `yaml:"max_requests"`
	Window      string `yaml:"window"`
}

// WindowDuration parses Window, returning (0, nil) when unset so the
// caller can distinguish "unset" from "invalid."
func (q Quota) WindowDuration() (time.Duration, error) {
	if q.Window == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(q.Window)
	if err != nil {
		return 0, fmt.Errorf("invalid quota.window %q: %w", q.Window, err)
	}
	return d, nil
}

// defaultTracingServiceName is used for the OTel resource's service.name
// attribute when Tracing.ServiceName is unset.
const defaultTracingServiceName = "portcullis"

// Tracing configures OpenTelemetry distributed tracing. Enabled defaults
// to false: an absent or disabled `tracing:` block means zero tracing
// overhead and no global tracer provider is ever installed, today's
// behavior, unchanged, for any config that doesn't opt in. SampleRatio's
// zero value means "sample everything" (ratio 1.0) — same zero-sentinel
// convention as CircuitBreakerPolicy.Threshold. See internal/tracing.
type Tracing struct {
	Enabled      bool    `yaml:"enabled"`
	OTLPEndpoint string  `yaml:"otlp_endpoint"`
	SampleRatio  float64 `yaml:"sample_ratio"`
	ServiceName  string  `yaml:"service_name"`
}

// SampleRatioOrDefault returns SampleRatio, falling back to 1.0 (always
// sample) when unset.
func (t Tracing) SampleRatioOrDefault() float64 {
	if t.SampleRatio <= 0 {
		return 1.0
	}
	return t.SampleRatio
}

// ServiceNameOrDefault returns ServiceName, falling back to
// defaultTracingServiceName when unset.
func (t Tracing) ServiceNameOrDefault() string {
	if t.ServiceName == "" {
		return defaultTracingServiceName
	}
	return t.ServiceName
}

// Upstream is one MCP server Portcullis can route to.
type Upstream struct {
	Name            string `yaml:"name"`
	Namespace       string `yaml:"namespace"`
	URL             string `yaml:"url"`
	ProtocolVersion string `yaml:"protocol_version"`
	// Timeout bounds how long Portcullis waits for this upstream to start
	// responding (Transport.ResponseHeaderTimeout) — NOT the whole
	// request/response cycle. A response that starts within Timeout,
	// including a long-lived streaming one, is then bounded only by the
	// client's own connection lifetime, not by this value. Optional;
	// defaults to defaultUpstreamTimeout if empty. Accepts any value
	// time.ParseDuration understands, e.g. "30s".
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
	MaxInflight int       `yaml:"max_inflight"`
	Auth        Auth      `yaml:"auth"`
	Policy      Policy    `yaml:"policy"`
	RateLimit   RateLimit `yaml:"rate_limit"`
	Quota       Quota     `yaml:"quota"`
	Tracing     Tracing   `yaml:"tracing"`
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
	// Multiple entries MAY share a Namespace -- that's an ordered
	// failover group, first entry primary (see router.New). Name must
	// still be unique across the whole config: it's the label on every
	// per-upstream metric, and now the only thing distinguishing
	// same-namespace group members from each other.
	seenNames := make(map[string]bool, len(c.Upstreams))
	for _, u := range c.Upstreams {
		if u.Name == "" {
			return fmt.Errorf("upstream has no name")
		}
		if seenNames[u.Name] {
			return fmt.Errorf("duplicate upstream name %q", u.Name)
		}
		seenNames[u.Name] = true
		if u.Namespace == "" {
			return fmt.Errorf("upstream %q: namespace is required", u.Name)
		}
		if u.URL == "" {
			return fmt.Errorf("upstream %q: url is required", u.Name)
		}
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
	if err := c.Auth.validate(); err != nil {
		return err
	}
	if err := c.Policy.validate(); err != nil {
		return err
	}
	if err := c.RateLimit.validate(); err != nil {
		return err
	}
	if err := c.Quota.validate(); err != nil {
		return err
	}
	if err := c.Tracing.validate(); err != nil {
		return err
	}
	return nil
}

func (t Tracing) validate() error {
	if t.SampleRatio < 0 || t.SampleRatio > 1 {
		return fmt.Errorf("tracing: sample_ratio must be in [0,1], got %v", t.SampleRatio)
	}
	if t.Enabled && t.OTLPEndpoint == "" {
		return fmt.Errorf("tracing: otlp_endpoint is required when tracing is enabled")
	}
	return nil
}

func (q Quota) validate() error {
	if q.MaxRequests < 0 {
		return fmt.Errorf("quota: max_requests must be >= 0, got %d", q.MaxRequests)
	}
	d, err := q.WindowDuration()
	if err != nil {
		return err
	}
	if q.Enabled {
		if q.MaxRequests <= 0 {
			return fmt.Errorf("quota: max_requests must be > 0 when quota is enabled")
		}
		if q.Window == "" {
			return fmt.Errorf("quota: window is required when quota is enabled")
		}
		if d <= 0 {
			return fmt.Errorf("quota: window must be > 0 when quota is enabled")
		}
	}
	return nil
}

func (r RateLimit) validate() error {
	if r.RequestsPerSecond < 0 {
		return fmt.Errorf("rate_limit: requests_per_second must be >= 0, got %v", r.RequestsPerSecond)
	}
	if r.Burst < 0 {
		return fmt.Errorf("rate_limit: burst must be >= 0, got %d", r.Burst)
	}
	if r.Enabled && r.RequestsPerSecond <= 0 {
		return fmt.Errorf("rate_limit: requests_per_second must be > 0 when rate_limit is enabled")
	}
	if r.Enabled && r.Burst <= 0 {
		return fmt.Errorf("rate_limit: burst must be > 0 when rate_limit is enabled")
	}
	return nil
}

func (p Policy) validate() error {
	for i, r := range p.Rules {
		if r.Client == "" {
			return fmt.Errorf("policy: rule %d: client is required (use \"*\" to match any client)", i)
		}
		if r.Namespace == "" {
			return fmt.Errorf("policy: rule %d: namespace is required (use \"*\" to match any namespace)", i)
		}
		if len(r.Tools) == 0 {
			return fmt.Errorf("policy: rule %d: tools is required (use [\"*\"] to match any tool)", i)
		}
		for _, tool := range r.Tools {
			if tool == "" {
				return fmt.Errorf("policy: rule %d: tools contains an empty entry", i)
			}
		}
		if r.Effect != "allow" && r.Effect != "deny" {
			return fmt.Errorf("policy: rule %d: effect must be \"allow\" or \"deny\", got %q", i, r.Effect)
		}
	}
	return nil
}

func (a Auth) validate() error {
	seenKeys := make(map[string]string, len(a.Clients)) // api key -> owning client_id
	seenIDs := make(map[string]bool, len(a.Clients))
	for _, client := range a.Clients {
		if client.ClientID == "" {
			return fmt.Errorf("auth: a client has no client_id")
		}
		if seenIDs[client.ClientID] {
			return fmt.Errorf("auth: duplicate client_id %q", client.ClientID)
		}
		seenIDs[client.ClientID] = true
		if a.Enabled && len(client.APIKeys) == 0 {
			return fmt.Errorf("auth: client %q has no api_keys", client.ClientID)
		}
		for _, key := range client.APIKeys {
			if key == "" {
				return fmt.Errorf("auth: client %q has an empty api key", client.ClientID)
			}
			if owner, ok := seenKeys[key]; ok {
				return fmt.Errorf("auth: api key reused by both %q and %q -- keys must be unique per client", owner, client.ClientID)
			}
			seenKeys[key] = client.ClientID
		}
		if _, err := client.ExpiresAtTime(); err != nil {
			return err
		}
	}
	return nil
}
