// Package secret resolves credential references so they don't have to sit
// in plaintext YAML. Deliberately minimal: one interface, one default
// implementation, one expansion helper — no external vault dependency,
// consistent with Portcullis's "focused systems identity."
package secret

import (
	"fmt"
	"os"
	"strings"
)

// Provider resolves a named secret to its value.
type Provider interface {
	Resolve(name string) (string, error)
}

// EnvProvider resolves secrets from environment variables. The default
// Provider — no external dependency required to use secret references at
// all.
type EnvProvider struct{}

// Resolve looks up name as an environment variable.
func (EnvProvider) Resolve(name string) (string, error) {
	v, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("secret: environment variable %q is not set", name)
	}
	return v, nil
}

const (
	refPrefix = "${SECRET:"
	refSuffix = "}"
)

// Expand resolves s via p if s has the form "${SECRET:NAME}"; any other
// string — including the empty string — passes through unchanged as a
// literal. This is the one indirection point in config: an operator
// chooses per-value whether something is a secret reference or a literal,
// so config.example.yaml and the bench configs can keep using plaintext
// dev values without needing real secrets or a provider at all.
func Expand(s string, p Provider) (string, error) {
	if !strings.HasPrefix(s, refPrefix) || !strings.HasSuffix(s, refSuffix) {
		return s, nil
	}
	name := strings.TrimSuffix(strings.TrimPrefix(s, refPrefix), refSuffix)
	if name == "" {
		return "", fmt.Errorf("secret: empty name in reference %q", s)
	}
	return p.Resolve(name)
}
