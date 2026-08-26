package server

import (
	"encoding/json"
	"strings"
	"testing"

	gwmcp "github.com/meetsutariya4448/portcullis/gateway/internal/mcp"
)

// FuzzRequestUnmarshal fuzzes the exact parsing step handleMCP performs
// on every request body before any auth/policy/rate-limit gate runs:
// json.Unmarshal into gwmcp.Request. The body is fully attacker-controlled
// (bounded only by maxBodyBytes, enforced separately via
// http.MaxBytesReader before this ever runs) -- the only invariant here
// is "never panics."
func FuzzRequestUnmarshal(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","_meta":{}}}`,
		``,
		`not json`,
		`[1,2,3]`,
		`"a string"`,
		`123`,
		`null`,
		`{}`,
		`{"id": null}`,
		`{"id": {"nested": {"deeply": {"a": {"b": {"c": 1}}}}}}`,
		strings.Repeat(`{"a":`, 1000) + `1` + strings.Repeat(`}`, 1000),
		string([]byte{0xff, 0xfe, 0x00, 0x01}),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","_meta":{"io.modelcontextprotocol/protocolVersion":123}}}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		var req gwmcp.Request
		_ = json.Unmarshal([]byte(body), &req)
	})
}
