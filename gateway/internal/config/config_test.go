package config

import (
	"strings"
	"testing"
	"time"
)

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
