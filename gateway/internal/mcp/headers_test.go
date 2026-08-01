package mcp

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func metaWithVersion(version string) map[string]json.RawMessage {
	return map[string]json.RawMessage{
		metaProtocolVersionKey: json.RawMessage(`"` + version + `"`),
	}
}

func TestValidateHeaders_Agreement(t *testing.T) {
	tests := []struct {
		name string
		h    Headers
		req  *Request
	}{
		{
			name: "tools/call matches on name",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "tools/call",
				Name:            "weather.get_forecast",
			},
			req: &Request{
				Method: "tools/call",
				Params: RequestParams{
					Name: "weather.get_forecast",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "resources/read matches on uri",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "resources/read",
				Name:            "file:///projects/myapp/config.json",
			},
			req: &Request{
				Method: "resources/read",
				Params: RequestParams{
					URI:  "file:///projects/myapp/config.json",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "prompts/get matches on name",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "prompts/get",
				Name:            "summarize",
			},
			req: &Request{
				Method: "prompts/get",
				Params: RequestParams{
					Name: "summarize",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "method not requiring Mcp-Name needs no name header",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "server/discover",
			},
			req: &Request{
				Method: "server/discover",
				Params: RequestParams{
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "Base64 sentinel encoded name decodes and matches",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "tools/call",
				Name:            base64SentinelPrefix + base64.StdEncoding.EncodeToString([]byte("Hello, 世界")) + base64SentinelSuffix,
			},
			req: &Request{
				Method: "tools/call",
				Params: RequestParams{
					Name: "Hello, 世界",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateHeaders(tt.h, tt.req); err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

func TestValidateHeaders_Disagreement(t *testing.T) {
	tests := []struct {
		name string
		h    Headers
		req  *Request
	}{
		{
			name: "protocol version header does not match body",
			h: Headers{
				ProtocolVersion: "2025-11-25",
				Method:          "tools/call",
				Name:            "weather.get_forecast",
			},
			req: &Request{
				Method: "tools/call",
				Params: RequestParams{
					Name: "weather.get_forecast",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "Mcp-Method header does not match body method",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "tools/list",
				Name:            "weather.get_forecast",
			},
			req: &Request{
				Method: "tools/call",
				Params: RequestParams{
					Name: "weather.get_forecast",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "Mcp-Name header does not match body params.name",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "tools/call",
				Name:            "weather.get_forecast",
			},
			req: &Request{
				Method: "tools/call",
				Params: RequestParams{
					Name: "weather.get_current_conditions",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "Mcp-Name header does not match body params.uri for resources/read",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "resources/read",
				Name:            "file:///a.json",
			},
			req: &Request{
				Method: "resources/read",
				Params: RequestParams{
					URI:  "file:///b.json",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
		{
			name: "invalid base64 sentinel value",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "tools/call",
				Name:            base64SentinelPrefix + "not-valid-base64!!!" + base64SentinelSuffix,
			},
			req: &Request{
				Method: "tools/call",
				Params: RequestParams{
					Name: "weather.get_forecast",
					Meta: metaWithVersion("2026-07-28"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaders(tt.h, tt.req)
			if err == nil {
				t.Fatal("expected a HeaderMismatch error, got nil")
			}
			if _, ok := err.(*HeaderMismatchError); !ok {
				t.Fatalf("expected *HeaderMismatchError, got %T", err)
			}
		})
	}
}

func TestValidateHeaders_MissingHeaders(t *testing.T) {
	baseReq := func() *Request {
		return &Request{
			Method: "tools/call",
			Params: RequestParams{
				Name: "weather.get_forecast",
				Meta: metaWithVersion("2026-07-28"),
			},
		}
	}

	tests := []struct {
		name string
		h    Headers
		req  *Request
	}{
		{
			name: "missing MCP-Protocol-Version header",
			h: Headers{
				Method: "tools/call",
				Name:   "weather.get_forecast",
			},
			req: baseReq(),
		},
		{
			name: "missing Mcp-Method header",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Name:            "weather.get_forecast",
			},
			req: baseReq(),
		},
		{
			name: "missing Mcp-Name header on tools/call",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "tools/call",
			},
			req: baseReq(),
		},
		{
			name: "body missing required _meta.protocolVersion",
			h: Headers{
				ProtocolVersion: "2026-07-28",
				Method:          "tools/call",
				Name:            "weather.get_forecast",
			},
			req: &Request{
				Method: "tools/call",
				Params: RequestParams{
					Name: "weather.get_forecast",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHeaders(tt.h, tt.req)
			if err == nil {
				t.Fatal("expected a HeaderMismatch error, got nil")
			}
			if !strings.Contains(err.Error(), "missing required") {
				t.Fatalf("expected a missing-header message, got: %v", err)
			}
		})
	}
}

func TestValidateHeaders_MethodsNotRequiringName(t *testing.T) {
	// tools/list, prompts/list, resources/list, and server/discover do not
	// carry a Mcp-Name header per SPEC-NOTES.md §3, even though Mcp-Method
	// and MCP-Protocol-Version are still required.
	methods := []string{"tools/list", "prompts/list", "resources/list", "server/discover"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			h := Headers{
				ProtocolVersion: "2026-07-28",
				Method:          method,
			}
			req := &Request{
				Method: method,
				Params: RequestParams{
					Meta: metaWithVersion("2026-07-28"),
				},
			}
			if err := ValidateHeaders(h, req); err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}
