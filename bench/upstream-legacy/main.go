// Command upstream-legacy is a trivial 2025-11-25 MCP server with a single
// "echo" tool, used only as a near-constant-time benchmark fixture for
// measuring Portcullis's legacy session-pool translation overhead. It
// implements just enough of the legacy Streamable HTTP shape to be a
// realistic target for gateway/internal/translate: an initialize handshake
// that mints an Mcp-Session-Id, and rejection of any other call that
// doesn't carry a still-valid one. It is not a spec-conformant
// implementation otherwise.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

type request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
}

var (
	mu       sync.RWMutex
	sessions = make(map[string]bool)
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9102"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /mcp", handleMCP)

	log.Printf("bench upstream-legacy (2025-11-25) listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req request
	_ = json.Unmarshal(body, &req)

	switch req.Method {
	case "initialize":
		id := newSessionID()
		mu.Lock()
		sessions[id] = true
		mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"bench-upstream-legacy","version":"1.0"}}}`, string(req.ID))
		return

	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
		return

	case "ping":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, string(req.ID))
		return
	}

	sessionID := r.Header.Get("Mcp-Session-Id")
	mu.RLock()
	valid := sessions[sessionID]
	mu.RUnlock()
	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"missing or invalid Mcp-Session-Id"}}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"echo"}]}}`, string(req.ID))
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
