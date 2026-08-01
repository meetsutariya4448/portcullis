package translate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// LegacyProtocolVersion is the only legacy protocol version this shim
// speaks. Per SPEC-NOTES.md's "Translating 2026-07-28 clients to
// 2025-11-25 servers" section, item 1: a 2025-11-25 server expects an
// initialize/notifications/initialized handshake before anything else,
// scoped to a connection; Portcullis performs it on the upstream's behalf
// and never exposes it to the client.
const LegacyProtocolVersion = "2025-11-25"

const (
	handshakeClientName    = "portcullis"
	handshakeClientVersion = "0.1.0"
)

// sessionIDHeader is the header a 2025-11-25 Streamable HTTP server mints a
// session on and expects echoed on every subsequent request, per
// SPEC-NOTES.md's "Translating" section, item 2.
const sessionIDHeader = "Mcp-Session-Id"

// Session is a leased legacy Mcp-Session-Id, established once via the
// initialize/initialized handshake and reused across proxied requests. The
// client that ultimately triggered a request over this session never sees
// it.
type Session struct {
	ID         string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

type rpcErrorEnvelope struct {
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// handshake performs the legacy initialize / notifications/initialized
// exchange against the upstream and returns the session it establishes.
func (p *Pool) handshake(ctx context.Context) (*Session, error) {
	initBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "portcullis-initialize",
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": LegacyProtocolVersion,
			"capabilities":    map[string]any{},
			"clientInfo": map[string]any{
				"name":    handshakeClientName,
				"version": handshakeClientVersion,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("encoding initialize request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(initBody))
	if err != nil {
		return nil, fmt.Errorf("building initialize request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("initialize request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading initialize response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("initialize failed: upstream returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var envelope rpcErrorEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return nil, fmt.Errorf("parsing initialize response: %w", err)
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("initialize rejected: %s (code %d)", envelope.Error.Message, envelope.Error.Code)
	}

	sessionID := resp.Header.Get(sessionIDHeader)
	if sessionID == "" {
		return nil, fmt.Errorf("legacy upstream did not return an %s header on initialize", sessionIDHeader)
	}

	if err := p.sendInitialized(ctx, sessionID); err != nil {
		return nil, err
	}

	now := time.Now()
	p.log.Info("translate: established legacy session", "upstream", p.url, "session_id", sessionID)
	return &Session{ID: sessionID, CreatedAt: now, LastUsedAt: now}, nil
}

// sendInitialized completes the handshake with the notifications/initialized
// notification, which carries no id and expects no JSON-RPC response.
func (p *Pool) sendInitialized(ctx context.Context, sessionID string) error {
	body := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building initialized notification: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(sessionIDHeader, sessionID)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("initialized notification failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("initialized notification: upstream returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// healthCheck sends a lightweight JSON-RPC ping over sess and reports
// whether the session is still usable. Legacy (pre-2026-07-28) servers
// support "ping"; it was removed only in 2026-07-28 (SPEC-NOTES.md §7).
func (p *Pool) healthCheck(ctx context.Context, sess *Session) bool {
	body := []byte(`{"jsonrpc":"2.0","id":"portcullis-health-check","method":"ping"}`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set(sessionIDHeader, sess.ID)

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	var envelope rpcErrorEnvelope
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return false
	}
	return envelope.Error == nil
}
