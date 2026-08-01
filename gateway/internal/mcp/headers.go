// Package mcp implements wire-level primitives for the MCP 2026-07-28
// Streamable HTTP transport, as documented in SPEC-NOTES.md.
package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// metaProtocolVersionKey is the _meta key carrying the per-request protocol
// version, per SPEC-NOTES.md §1 (basic/index §General fields).
const metaProtocolVersionKey = "io.modelcontextprotocol/protocolVersion"

// HeaderMismatchCode is the JSON-RPC error code the 2026-07-28 spec defines
// for header/body validation failures (SPEC-NOTES.md §3, streamable-http
// §Server Validation).
const HeaderMismatchCode = -32020

// methodsRequiringName is the set of methods for which the Mcp-Name header
// is required, per SPEC-NOTES.md §3.
var methodsRequiringName = map[string]bool{
	"tools/call":     true,
	"resources/read": true,
	"prompts/get":    true,
}

// base64SentinelPrefix and base64SentinelSuffix mark a header value as
// Base64-encoded per SPEC-NOTES.md §3 (streamable-http §Value Encoding).
const (
	base64SentinelPrefix = "=?base64?"
	base64SentinelSuffix = "?="
)

// Request is the minimal JSON-RPC request shape needed for header
// validation and namespace routing. It intentionally does not model the
// full MCP schema — Portcullis forwards request bodies unchanged and only
// needs to read a few fields out of them.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  RequestParams   `json:"params"`
}

// RequestParams is the subset of params fields relevant to header
// validation and routing.
type RequestParams struct {
	Name string                     `json:"name,omitempty"`
	URI  string                     `json:"uri,omitempty"`
	Meta map[string]json.RawMessage `json:"_meta,omitempty"`
}

// Headers holds the MCP-defined HTTP headers carried on a Streamable HTTP
// POST request (SPEC-NOTES.md §3).
type Headers struct {
	ProtocolVersion string
	Method          string
	Name            string
}

// HeaderMismatchError is returned by ValidateHeaders when a required header
// is missing or disagrees with the request body. Its Error() text is meant
// for the JSON-RPC error response's "message" field.
type HeaderMismatchError struct {
	msg string
}

func (e *HeaderMismatchError) Error() string { return e.msg }

func mismatch(format string, args ...any) *HeaderMismatchError {
	return &HeaderMismatchError{msg: fmt.Sprintf(format, args...)}
}

// ValidateHeaders checks that MCP-Protocol-Version, Mcp-Method, and Mcp-Name
// agree with the parsed JSON-RPC request body, per SPEC-NOTES.md §3
// (streamable-http §Server Validation): a required header that is missing,
// or a header value that disagrees with the body, MUST be rejected with a
// HeaderMismatch error. Mcp-Name is only required for tools/call,
// resources/read, and prompts/get.
func ValidateHeaders(h Headers, req *Request) error {
	if h.ProtocolVersion == "" {
		return mismatch("missing required header: MCP-Protocol-Version")
	}
	bodyVersion, err := metaString(req.Params.Meta, metaProtocolVersionKey)
	if err != nil {
		return mismatch("request body _meta.%s: %v", metaProtocolVersionKey, err)
	}
	if bodyVersion == "" {
		return mismatch("request body is missing required _meta.%s", metaProtocolVersionKey)
	}
	if h.ProtocolVersion != bodyVersion {
		return mismatch("MCP-Protocol-Version header %q does not match body value %q", h.ProtocolVersion, bodyVersion)
	}

	if h.Method == "" {
		return mismatch("missing required header: Mcp-Method")
	}
	decodedMethod, err := decodeHeaderValue(h.Method)
	if err != nil {
		return mismatch("Mcp-Method header: %v", err)
	}
	if decodedMethod != req.Method {
		return mismatch("Mcp-Method header %q does not match body method %q", decodedMethod, req.Method)
	}

	if methodsRequiringName[req.Method] {
		bodyName := req.Params.Name
		if req.Method == "resources/read" {
			bodyName = req.Params.URI
		}
		if h.Name == "" {
			return mismatch("missing required header: Mcp-Name (required for %s)", req.Method)
		}
		decodedName, err := decodeHeaderValue(h.Name)
		if err != nil {
			return mismatch("Mcp-Name header: %v", err)
		}
		if decodedName != bodyName {
			return mismatch("Mcp-Name header value %q does not match body value %q", decodedName, bodyName)
		}
	}

	return nil
}

// decodeHeaderValue reverses the Base64 sentinel encoding described in
// SPEC-NOTES.md §3, returning the value unchanged if it isn't sentinel-wrapped.
func decodeHeaderValue(v string) (string, error) {
	if !strings.HasPrefix(v, base64SentinelPrefix) || !strings.HasSuffix(v, base64SentinelSuffix) {
		return v, nil
	}
	encoded := strings.TrimSuffix(strings.TrimPrefix(v, base64SentinelPrefix), base64SentinelSuffix)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid base64 sentinel value: %w", err)
	}
	return string(decoded), nil
}

// metaString extracts a JSON string value from a raw _meta map.
func metaString(meta map[string]json.RawMessage, key string) (string, error) {
	raw, ok := meta[key]
	if !ok {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%s is not a string: %w", key, err)
	}
	return s, nil
}
