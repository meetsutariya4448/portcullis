package mcp

import (
	"encoding/json"
	"testing"
)

// FuzzDecodeHeaderValue fuzzes decodeHeaderValue, which reverses the
// Base64 sentinel encoding on every Mcp-Method/Mcp-Name header value --
// untrusted attacker input on every single request, before any auth
// check runs. The only invariant fuzzing can check here is "never
// panics" -- there's no correctness oracle beyond that for arbitrary
// input.
func FuzzDecodeHeaderValue(f *testing.F) {
	seeds := []string{
		"",
		"tools/call",
		"=?base64?" + "?=",
		"=?base64?SGVsbG8=?=",
		"=?base64?not-valid-base64!!!?=",
		base64SentinelPrefix,
		base64SentinelSuffix,
		base64SentinelPrefix + base64SentinelSuffix,
		"=?base64?" + string([]byte{0xff, 0xfe, 0x00}) + "?=",
		"weather.get_forecast",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = decodeHeaderValue(s)
	})
}

// FuzzValidateHeaders fuzzes ValidateHeaders against a Request parsed
// from fuzzed JSON bytes -- the actual shape of an attacker-controlled
// request: three header strings plus a JSON body, exactly what
// handleMCP hands to this function on every POST. Only checks for
// panics; header/body mismatch is expected and correctly-handled
// behavior, not a fuzz failure.
func FuzzValidateHeaders(f *testing.F) {
	type seed struct {
		protocolVersion, method, name string
		body                          string
	}
	seeds := []seed{
		{
			protocolVersion: "2026-07-28", method: "tools/call", name: "get_forecast",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_forecast","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		},
		{
			protocolVersion: "", method: "", name: "",
			body: `{}`,
		},
		{
			protocolVersion: "2026-07-28", method: "resources/read", name: "file:///x",
			body: `{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///x","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		},
		{
			protocolVersion: "2026-07-28", method: "tools/call", name: "=?base64?bad?=",
			body: `{"jsonrpc":"2.0","method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`,
		},
		{
			protocolVersion: "x", method: "y", name: "z",
			body: `not json at all`,
		},
		{
			protocolVersion: "x", method: "y", name: "z",
			body: `[1,2,3]`,
		},
		{
			protocolVersion: "x", method: "y", name: "z",
			body: ``,
		},
	}
	for _, s := range seeds {
		f.Add(s.protocolVersion, s.method, s.name, s.body)
	}
	f.Fuzz(func(t *testing.T, protocolVersion, method, name, body string) {
		var req Request
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			// Malformed JSON is outside ValidateHeaders' contract (the
			// caller is responsible for successfully unmarshaling
			// first) -- nothing to fuzz here beyond confirming
			// json.Unmarshal itself doesn't panic on adversarial bytes,
			// which the standard library already guarantees.
			return
		}
		h := Headers{ProtocolVersion: protocolVersion, Method: method, Name: name}
		_ = ValidateHeaders(h, &req)
	})
}
