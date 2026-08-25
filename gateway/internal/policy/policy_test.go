package policy

import "testing"

func TestEvaluate_NoRulesAllowsEverything(t *testing.T) {
	p := New(nil)
	allow, _ := p.Evaluate("any-client", "any-namespace", "any-tool")
	if !allow {
		t.Fatal("expected allow with no rules configured")
	}
}

func TestEvaluate_RulesConfiguredButNothingMatches_Denies(t *testing.T) {
	p := New([]Rule{
		{Client: "acme", Namespace: "weather", Tools: []string{"get_forecast"}, Effect: "allow"},
	})
	allow, reason := p.Evaluate("other-client", "weather", "get_forecast")
	if allow {
		t.Fatalf("expected deny for a client with no matching rule, got allow (%s)", reason)
	}
}

func TestEvaluate_ExactMatchAllows(t *testing.T) {
	p := New([]Rule{
		{Client: "acme", Namespace: "weather", Tools: []string{"get_forecast"}, Effect: "allow"},
	})
	allow, _ := p.Evaluate("acme", "weather", "get_forecast")
	if !allow {
		t.Fatal("expected allow for an exact-match rule")
	}
}

func TestEvaluate_ExactMatchDenies(t *testing.T) {
	p := New([]Rule{
		{Client: "acme", Namespace: "weather", Tools: []string{"get_forecast"}, Effect: "deny"},
	})
	allow, _ := p.Evaluate("acme", "weather", "get_forecast")
	if allow {
		t.Fatal("expected deny for an exact-match deny rule")
	}
}

func TestEvaluate_WildcardClientMatchesAnyClient(t *testing.T) {
	p := New([]Rule{
		{Client: "*", Namespace: "weather", Tools: []string{"get_forecast"}, Effect: "allow"},
	})
	allow, _ := p.Evaluate("whoever", "weather", "get_forecast")
	if !allow {
		t.Fatal("expected the wildcard client rule to match any client")
	}
}

func TestEvaluate_WildcardNamespaceMatchesAnyNamespace(t *testing.T) {
	p := New([]Rule{
		{Client: "acme", Namespace: "*", Tools: []string{"get_forecast"}, Effect: "allow"},
	})
	allow, _ := p.Evaluate("acme", "whatever-namespace", "get_forecast")
	if !allow {
		t.Fatal("expected the wildcard namespace rule to match any namespace")
	}
}

func TestEvaluate_WildcardToolMatchesAnyTool(t *testing.T) {
	p := New([]Rule{
		{Client: "acme", Namespace: "weather", Tools: []string{"*"}, Effect: "allow"},
	})
	allow, _ := p.Evaluate("acme", "weather", "whatever_tool")
	if !allow {
		t.Fatal("expected the wildcard tools entry to match any tool")
	}
}

// TestEvaluate_FirstMatchWins proves that once a rule matches, later rules
// are never consulted — an earlier deny rule shadows a later allow rule
// for the same (client, namespace, tool), and vice versa.
func TestEvaluate_FirstMatchWins(t *testing.T) {
	p := New([]Rule{
		{Client: "acme", Namespace: "weather", Tools: []string{"get_forecast"}, Effect: "deny"},
		{Client: "*", Namespace: "weather", Tools: []string{"get_forecast"}, Effect: "allow"},
	})
	allow, _ := p.Evaluate("acme", "weather", "get_forecast")
	if allow {
		t.Fatal("expected the first (deny) rule to win over the later, broader allow rule")
	}

	// A different client never matches the first rule, so it falls
	// through to the second, broader allow rule.
	allow, _ = p.Evaluate("someone-else", "weather", "get_forecast")
	if !allow {
		t.Fatal("expected the second rule to allow a client the first rule doesn't mention")
	}
}

func TestEvaluate_ToolListWithMultipleEntries(t *testing.T) {
	p := New([]Rule{
		{Client: "acme", Namespace: "weather", Tools: []string{"get_forecast", "get_alerts"}, Effect: "allow"},
	})
	for _, tool := range []string{"get_forecast", "get_alerts"} {
		allow, _ := p.Evaluate("acme", "weather", tool)
		if !allow {
			t.Fatalf("expected %q to be allowed by the multi-tool rule", tool)
		}
	}
	allow, _ := p.Evaluate("acme", "weather", "delete_everything")
	if allow {
		t.Fatal("expected a tool not listed in the rule to fall through to default deny")
	}
}
