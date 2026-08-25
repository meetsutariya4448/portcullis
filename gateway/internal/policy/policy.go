// Package policy implements Portcullis's authorization gate: given a
// caller's identity and the (namespace, tool) it's trying to call, decide
// whether the request is allowed through.
//
// This is a separate concern from internal/auth: auth answers "who is
// this," policy answers "is this client allowed to call this tool."
package policy

// Rule is one authorization rule. Client and Namespace match a literal
// value or "*" (any); Tools matches if the target tool is listed or
// Tools contains "*". Effect is "allow" or "deny".
type Rule struct {
	Client    string
	Namespace string
	Tools     []string
	Effect    string
}

// Policy evaluates an ordered list of rules, first-match-wins.
type Policy struct {
	rules []Rule
}

// New builds a Policy from rules, preserving their order — Evaluate stops
// at the first rule that matches.
func New(rules []Rule) *Policy {
	return &Policy{rules: rules}
}

// Evaluate decides whether clientID may call tool in namespace.
//
// No rules configured at all means "allow everything" — a deployment that
// hasn't opted into the policy engine behaves exactly as it did before
// this feature existed. Once at least one rule exists, the first matching
// rule wins; if nothing matches, the request is denied — an operator who
// starts writing rules is defining an allowlist, and a request nothing
// mentions should not silently fall through as allowed.
func (p *Policy) Evaluate(clientID, namespace, tool string) (allow bool, reason string) {
	if len(p.rules) == 0 {
		return true, "no policy rules configured"
	}
	for _, r := range p.rules {
		if !matches(r.Client, clientID) {
			continue
		}
		if !matches(r.Namespace, namespace) {
			continue
		}
		if !matchesAny(r.Tools, tool) {
			continue
		}
		if r.Effect == "allow" {
			return true, "allowed by policy rule"
		}
		return false, "denied by policy rule"
	}
	return false, "no policy rule matched (default deny)"
}

func matches(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

func matchesAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if matches(p, value) {
			return true
		}
	}
	return false
}
