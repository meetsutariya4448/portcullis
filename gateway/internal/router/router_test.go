package router

import (
	"io"
	"log/slog"
	"testing"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestResolve_SingleEntryNamespace_ReturnsSingleElementGroup(t *testing.T) {
	cfg := &config.Config{Upstreams: []config.Upstream{
		{Name: "weather", Namespace: "weather", URL: "http://localhost:9001/mcp"},
	}}
	r, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	group, err := r.Resolve("weather")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(group) != 1 {
		t.Fatalf("expected a single-element group, got %d", len(group))
	}
	if group[0].Name != "weather" {
		t.Fatalf("expected the sole entry to be %q, got %q", "weather", group[0].Name)
	}
}

// TestResolve_SharedNamespace_ReturnsGroupInConfigOrder proves multiple
// entries sharing a namespace form one ordered failover group, primary
// (first-listed) first -- list position as priority, the same
// first-match-wins convention already established by policy.Policy.
func TestResolve_SharedNamespace_ReturnsGroupInConfigOrder(t *testing.T) {
	cfg := &config.Config{Upstreams: []config.Upstream{
		{Name: "weather-primary", Namespace: "weather", URL: "http://localhost:9001/mcp"},
		{Name: "weather-fallback-1", Namespace: "weather", URL: "http://localhost:9002/mcp"},
		{Name: "weather-fallback-2", Namespace: "weather", URL: "http://localhost:9003/mcp"},
	}}
	r, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	group, err := r.Resolve("weather")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantOrder := []string{"weather-primary", "weather-fallback-1", "weather-fallback-2"}
	if len(group) != len(wantOrder) {
		t.Fatalf("expected a %d-element group, got %d", len(wantOrder), len(group))
	}
	for i, wantName := range wantOrder {
		if group[i].Name != wantName {
			t.Fatalf("group[%d]: expected %q, got %q", i, wantName, group[i].Name)
		}
	}
}

// TestResolve_SharedNamespace_MembersHaveIndependentState proves each
// group member gets its own breaker/bulkhead/client -- failover only
// makes sense if a fallback's health state is independent of the
// primary's.
func TestResolve_SharedNamespace_MembersHaveIndependentState(t *testing.T) {
	cfg := &config.Config{Upstreams: []config.Upstream{
		{Name: "weather-primary", Namespace: "weather", URL: "http://localhost:9001/mcp"},
		{Name: "weather-fallback", Namespace: "weather", URL: "http://localhost:9002/mcp"},
	}}
	r, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	group, err := r.Resolve("weather")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if group[0].Breaker == group[1].Breaker {
		t.Fatal("expected each group member to have its own circuit breaker")
	}
	if group[0].Bulkhead == group[1].Bulkhead {
		t.Fatal("expected each group member to have its own bulkhead")
	}
	if group[0].Client == group[1].Client {
		t.Fatal("expected each group member to have its own HTTP client")
	}
}

func TestResolve_UnknownNamespace_ReturnsError(t *testing.T) {
	cfg := &config.Config{Upstreams: []config.Upstream{
		{Name: "weather", Namespace: "weather", URL: "http://localhost:9001/mcp"},
	}}
	r, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := r.Resolve("nonexistent"); err == nil {
		t.Fatal("expected an error for an unconfigured namespace")
	}
}

// TestResolve_MixedProtocolFailoverGroup proves a failover group can mix
// a native primary with a legacy fallback (or vice versa) -- each member
// keeps its own full config surface, including protocol_version.
func TestResolve_MixedProtocolFailoverGroup(t *testing.T) {
	cfg := &config.Config{Upstreams: []config.Upstream{
		{Name: "weather-native", Namespace: "weather", URL: "http://localhost:9001/mcp", ProtocolVersion: "2026-07-28"},
		{Name: "weather-legacy", Namespace: "weather", URL: "http://localhost:9002/mcp", ProtocolVersion: "2025-11-25"},
	}}
	r, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	group, err := r.Resolve("weather")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if group[0].LegacyPool != nil {
		t.Fatal("expected the native primary to have no LegacyPool")
	}
	if group[1].LegacyPool == nil {
		t.Fatal("expected the legacy fallback to have a LegacyPool")
	}
}
