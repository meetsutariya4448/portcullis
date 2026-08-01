package mcp

import "encoding/json"

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrorResponse is a JSON-RPC 2.0 error response.
type ErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Error   RPCError        `json:"error"`
}

// NewHeaderMismatchResponse builds the JSON-RPC error response body for a
// HeaderMismatch failure (SPEC-NOTES.md §3), echoing the request ID when one
// could be parsed.
func NewHeaderMismatchResponse(id json.RawMessage, err error) ErrorResponse {
	return ErrorResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: RPCError{
			Code:    HeaderMismatchCode,
			Message: err.Error(),
		},
	}
}
