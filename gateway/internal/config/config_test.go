package config

import (
	"strings"
	"testing"
	"time"
)

func TestUpstream_TimeoutDuration_DefaultsWhenUnset(t *testing.T) {
	u := Upstream{Name: "x"}
	d, err := u.TimeoutDuration()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d != defaultUpstreamTimeout {
		t.Fatalf("expected default %v, got %v", defaultUpstreamTimeout, d)
	}
}

func TestUpstream_TimeoutDuration_InvalidReturnsError(t *testing.T) {
	u := Upstream{Name: "x", Timeout: "not-a-duration"}
	if _, err := u.TimeoutDuration(); err == nil {
		t.Fatal("expected an error for an invalid timeout string")
	}
}

func TestRetryPolicy_DurationParsing(t *testing.T) {
	unset := RetryPolicy{}
	if d, err := unset.BaseDelayDuration(); err != nil || d != 0 {
		t.Fatalf("expected (0, nil) for unset BaseDelay, got (%v, %v)", d, err)
	}
	if d, err := unset.MaxDelayDuration(); err != nil || d != 0 {
		t.Fatalf("expected (0, nil) for unset MaxDelay, got (%v, %v)", d, err)
	}

	set := RetryPolicy{BaseDelay: "50ms", MaxDelay: "1s"}
	if d, err := set.BaseDelayDuration(); err != nil || d != 50*time.Millisecond {
		t.Fatalf("expected 50ms, got (%v, %v)", d, err)
	}
	if d, err := set.MaxDelayDuration(); err != nil || d != time.Second {
		t.Fatalf("expected 1s, got (%v, %v)", d, err)
	}

	bad := RetryPolicy{BaseDelay: "banana"}
	if _, err := bad.BaseDelayDuration(); err == nil {
		t.Fatal("expected an error for an invalid base_delay")
	}
}

func validConfig() *Config {
	return &Config{Upstreams: []Upstream{
		{Name: "weather", Namespace: "weather", URL: "http://localhost:9001/mcp"},
	}}
}

func TestConfig_Validate_AcceptsValidConfig(t *testing.T) {
	if err := validConfig().validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestUpstream_MaxConcurrentOrDefault(t *testing.T) {
	if got := (Upstream{}).MaxConcurrentOrDefault(); got != defaultMaxConcurrent {
		t.Fatalf("expected default %d, got %d", defaultMaxConcurrent, got)
	}
	if got := (Upstream{MaxConcurrent: 10}).MaxConcurrentOrDefault(); got != 10 {
		t.Fatalf("expected 10, got %d", got)
	}
}

func TestConfig_MaxInflightOrDefault(t *testing.T) {
	if got := (Config{}).MaxInflightOrDefault(); got != defaultMaxInflight {
		t.Fatalf("expected default %d, got %d", defaultMaxInflight, got)
	}
	if got := (Config{MaxInflight: 50}).MaxInflightOrDefault(); got != 50 {
		t.Fatalf("expected 50, got %d", got)
	}
}

func TestConfig_Validate_RejectsNegativeMaxConcurrent(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].MaxConcurrent = -1
	assertValidateError(t, cfg, "max_concurrent")
}

func TestConfig_Validate_RejectsNegativeMaxInflight(t *testing.T) {
	cfg := validConfig()
	cfg.MaxInflight = -1
	assertValidateError(t, cfg, "max_inflight")
}

func TestConfig_Validate_RejectsNegativeRetryMaxAttempts(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].Retry.MaxAttempts = -1
	assertValidateError(t, cfg, "retry.max_attempts")
}

func TestConfig_Validate_RejectsInvalidRetryBaseDelay(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].Retry.BaseDelay = "not-a-duration"
	assertValidateError(t, cfg, "base_delay")
}

func TestConfig_Validate_RejectsInvalidRetryMaxDelay(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].Retry.MaxDelay = "not-a-duration"
	assertValidateError(t, cfg, "max_delay")
}

func TestCircuitBreakerPolicy_DurationParsing(t *testing.T) {
	unset := CircuitBreakerPolicy{}
	if d, err := unset.WindowDuration(); err != nil || d != 0 {
		t.Fatalf("expected (0, nil) for unset Window, got (%v, %v)", d, err)
	}
	if d, err := unset.CooldownDuration(); err != nil || d != 0 {
		t.Fatalf("expected (0, nil) for unset Cooldown, got (%v, %v)", d, err)
	}

	bad := CircuitBreakerPolicy{Cooldown: "not-a-duration"}
	if _, err := bad.CooldownDuration(); err == nil {
		t.Fatal("expected an error for an invalid cooldown")
	}
}

func TestConfig_Validate_RejectsNegativeMinSamples(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].CircuitBreaker.MinSamples = -1
	assertValidateError(t, cfg, "min_samples")
}

func TestConfig_Validate_RejectsOutOfRangeThreshold(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].CircuitBreaker.Threshold = 1.5
	assertValidateError(t, cfg, "threshold")

	cfg2 := validConfig()
	cfg2.Upstreams[0].CircuitBreaker.Threshold = -0.1
	assertValidateError(t, cfg2, "threshold")
}

func TestConfig_Validate_AcceptsZeroThresholdAsUnset(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].CircuitBreaker.Threshold = 0
	if err := cfg.validate(); err != nil {
		t.Fatalf("threshold=0 (unset sentinel) should be valid, got: %v", err)
	}
}

func TestConfig_Validate_RejectsInvalidBreakerWindow(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].CircuitBreaker.Window = "not-a-duration"
	assertValidateError(t, cfg, "window")
}

func TestConfig_Validate_RejectsInvalidBreakerCooldown(t *testing.T) {
	cfg := validConfig()
	cfg.Upstreams[0].CircuitBreaker.Cooldown = "not-a-duration"
	assertValidateError(t, cfg, "cooldown")
}

func TestAuthClient_ExpiresAtTime(t *testing.T) {
	unset := AuthClient{ClientID: "x"}
	got, err := unset.ExpiresAtTime()
	if err != nil || got != nil {
		t.Fatalf("expected (nil, nil) for unset ExpiresAt, got (%v, %v)", got, err)
	}

	set := AuthClient{ClientID: "x", ExpiresAt: "2027-01-01T00:00:00Z"}
	got, err = set.ExpiresAtTime()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil || got.Year() != 2027 {
		t.Fatalf("expected a parsed 2027 timestamp, got %v", got)
	}

	bad := AuthClient{ClientID: "x", ExpiresAt: "not-a-timestamp"}
	if _, err := bad.ExpiresAtTime(); err == nil {
		t.Fatal("expected an error for an invalid expires_at")
	}
}

func TestConfig_Validate_AcceptsConfigWithNoAuthBlock(t *testing.T) {
	// Backward compatibility: existing configs with no `auth:` block at
	// all must keep validating and behaving exactly as before this
	// milestone.
	if err := validConfig().validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_RejectsAuthClientWithNoID(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.Clients = []AuthClient{{APIKeys: []string{"key1"}}}
	assertValidateError(t, cfg, "client_id")
}

func TestConfig_Validate_RejectsDuplicateClientID(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.Clients = []AuthClient{
		{ClientID: "acme", APIKeys: []string{"key1"}},
		{ClientID: "acme", APIKeys: []string{"key2"}},
	}
	assertValidateError(t, cfg, "duplicate client_id")
}

func TestConfig_Validate_RejectsEnabledClientWithNoKeys(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Clients = []AuthClient{{ClientID: "acme"}}
	assertValidateError(t, cfg, "no api_keys")
}

func TestConfig_Validate_AllowsDisabledClientWithNoKeys(t *testing.T) {
	// A client entry can exist in config (e.g. staged ahead of enabling
	// auth) without keys as long as auth isn't actually enabled yet.
	cfg := validConfig()
	cfg.Auth.Enabled = false
	cfg.Auth.Clients = []AuthClient{{ClientID: "acme"}}
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_RejectsDuplicateAPIKeyAcrossClients(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.Clients = []AuthClient{
		{ClientID: "acme", APIKeys: []string{"shared-key"}},
		{ClientID: "globex", APIKeys: []string{"shared-key"}},
	}
	assertValidateError(t, cfg, "reused")
}

func TestConfig_Validate_RejectsInvalidExpiresAt(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.Clients = []AuthClient{{ClientID: "acme", APIKeys: []string{"key1"}, ExpiresAt: "not-a-timestamp"}}
	assertValidateError(t, cfg, "expires_at")
}

func TestConfig_Validate_AcceptsKeyRotationTwoKeysSameClient(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.Enabled = true
	cfg.Auth.Clients = []AuthClient{{ClientID: "acme", APIKeys: []string{"old-key", "new-key"}}}
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_AcceptsConfigWithNoPolicyBlock(t *testing.T) {
	// Backward compatibility: an absent `policy:` block means every
	// request is allowed through, unchanged, for any config that doesn't
	// opt in.
	if err := validConfig().validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfig_Validate_RejectsPolicyRuleWithNoClient(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Rules = []PolicyRule{{Namespace: "weather", Tools: []string{"*"}, Effect: "allow"}}
	assertValidateError(t, cfg, "client is required")
}

func TestConfig_Validate_RejectsPolicyRuleWithNoNamespace(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Rules = []PolicyRule{{Client: "acme", Tools: []string{"*"}, Effect: "allow"}}
	assertValidateError(t, cfg, "namespace is required")
}

func TestConfig_Validate_RejectsPolicyRuleWithNoTools(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Rules = []PolicyRule{{Client: "acme", Namespace: "weather", Effect: "allow"}}
	assertValidateError(t, cfg, "tools is required")
}

func TestConfig_Validate_RejectsPolicyRuleWithEmptyToolEntry(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Rules = []PolicyRule{{Client: "acme", Namespace: "weather", Tools: []string{""}, Effect: "allow"}}
	assertValidateError(t, cfg, "empty entry")
}

func TestConfig_Validate_RejectsPolicyRuleWithInvalidEffect(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Rules = []PolicyRule{{Client: "acme", Namespace: "weather", Tools: []string{"*"}, Effect: "maybe"}}
	assertValidateError(t, cfg, "effect must be")
}

func TestConfig_Validate_AcceptsWellFormedPolicyRule(t *testing.T) {
	cfg := validConfig()
	cfg.Policy.Rules = []PolicyRule{{Client: "*", Namespace: "*", Tools: []string{"*"}, Effect: "allow"}}
	if err := cfg.validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertValidateError(t *testing.T, cfg *Config, wantSubstring string) {
	t.Helper()
	err := cfg.validate()
	if err == nil {
		t.Fatalf("expected a validation error containing %q, got nil", wantSubstring)
	}
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Fatalf("expected error containing %q, got: %v", wantSubstring, err)
	}
}
