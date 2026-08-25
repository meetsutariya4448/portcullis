// Package auth resolves a caller's presented API key to a recognized
// client identity. This is gateway-edge authentication — a separate
// concern from MCP's own protocol-level OAuth authorization framework
// (SEP-2577, SPEC-NOTES.md §9), which governs the client<->upstream-server
// relationship and is untouched here. Auth answers "who is calling
// Portcullis," the same question any API gateway asks at its perimeter.
package auth

import (
	"crypto/subtle"
	"errors"
	"time"
)

// Client is a caller Portcullis recognizes. APIKeys is plural
// deliberately: that plurality IS key rotation — list the old and new key
// together during a rotation window, then remove the old one once
// callers have migrated, with no gap where the client is unauthenticatable.
type Client struct {
	ID        string
	APIKeys   []string
	ExpiresAt *time.Time
	Revoked   bool
}

var (
	// ErrMissingKey is returned when no API key was presented at all.
	ErrMissingKey = errors.New("auth: no API key presented")
	// ErrInvalidKey is returned when the presented key matches no client.
	ErrInvalidKey = errors.New("auth: API key not recognized")
	// ErrRevoked is returned when the matched client has been revoked.
	ErrRevoked = errors.New("auth: client revoked")
	// ErrExpired is returned when the matched client's credential has expired.
	ErrExpired = errors.New("auth: client credential expired")
)

// Authenticator resolves a presented API key to a Client. Built once from
// config and never mutated afterward, so it's safe for concurrent use
// without its own locking.
type Authenticator struct {
	clients []Client
}

// New builds an Authenticator from the configured clients.
func New(clients []Client) *Authenticator {
	return &Authenticator{clients: clients}
}

// Authenticate resolves apiKey to a Client. Key comparison is
// constant-time (crypto/subtle) — this is a real security boundary
// (an early-exit byte-by-byte comparison would let an attacker infer a
// valid key one byte at a time from response timing), not just a map
// lookup that happens to also check equality.
func (a *Authenticator) Authenticate(apiKey string) (*Client, error) {
	if apiKey == "" {
		return nil, ErrMissingKey
	}
	for i := range a.clients {
		c := &a.clients[i]
		for _, k := range c.APIKeys {
			if len(k) != len(apiKey) {
				continue // ConstantTimeCompare requires equal-length inputs
			}
			if subtle.ConstantTimeCompare([]byte(k), []byte(apiKey)) == 1 {
				if c.Revoked {
					return nil, ErrRevoked
				}
				if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
					return nil, ErrExpired
				}
				return c, nil
			}
		}
	}
	return nil, ErrInvalidKey
}
