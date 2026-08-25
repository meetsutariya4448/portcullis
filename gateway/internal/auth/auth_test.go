package auth

import (
	"errors"
	"testing"
	"time"
)

func TestAuthenticate_MissingKey(t *testing.T) {
	a := New([]Client{{ID: "acme", APIKeys: []string{"key1"}}})
	_, err := a.Authenticate("")
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("expected ErrMissingKey, got %v", err)
	}
}

func TestAuthenticate_UnrecognizedKey(t *testing.T) {
	a := New([]Client{{ID: "acme", APIKeys: []string{"key1"}}})
	_, err := a.Authenticate("not-a-real-key")
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestAuthenticate_ValidKeyResolvesClient(t *testing.T) {
	a := New([]Client{{ID: "acme", APIKeys: []string{"key1"}}})
	c, err := a.Authenticate("key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID != "acme" {
		t.Fatalf("expected client %q, got %q", "acme", c.ID)
	}
}

func TestAuthenticate_RotationAcceptsBothOldAndNewKey(t *testing.T) {
	a := New([]Client{{ID: "acme", APIKeys: []string{"old-key", "new-key"}}})
	for _, key := range []string{"old-key", "new-key"} {
		c, err := a.Authenticate(key)
		if err != nil {
			t.Fatalf("key %q: unexpected error: %v", key, err)
		}
		if c.ID != "acme" {
			t.Fatalf("key %q: expected client %q, got %q", key, "acme", c.ID)
		}
	}
}

func TestAuthenticate_RevokedClientRejected(t *testing.T) {
	a := New([]Client{{ID: "acme", APIKeys: []string{"key1"}, Revoked: true}})
	_, err := a.Authenticate("key1")
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("expected ErrRevoked, got %v", err)
	}
}

func TestAuthenticate_ExpiredClientRejected(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	a := New([]Client{{ID: "acme", APIKeys: []string{"key1"}, ExpiresAt: &past}})
	_, err := a.Authenticate("key1")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestAuthenticate_FutureExpiryStillValid(t *testing.T) {
	future := time.Now().Add(time.Hour)
	a := New([]Client{{ID: "acme", APIKeys: []string{"key1"}, ExpiresAt: &future}})
	c, err := a.Authenticate("key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID != "acme" {
		t.Fatalf("expected client %q, got %q", "acme", c.ID)
	}
}

func TestAuthenticate_DifferentLengthKeyNeverMatches(t *testing.T) {
	// Regression guard for the length-guard in Authenticate: a key that's
	// a prefix (or any different length) of a real key must not match.
	a := New([]Client{{ID: "acme", APIKeys: []string{"a-fairly-long-key"}}})
	_, err := a.Authenticate("a-fairly-long-ke")
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey for a truncated key, got %v", err)
	}
}

func TestAuthenticate_MultipleClientsDistinguished(t *testing.T) {
	a := New([]Client{
		{ID: "acme", APIKeys: []string{"acme-key"}},
		{ID: "globex", APIKeys: []string{"globex-key"}},
	})
	c, err := a.Authenticate("globex-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID != "globex" {
		t.Fatalf("expected client %q, got %q", "globex", c.ID)
	}
}
