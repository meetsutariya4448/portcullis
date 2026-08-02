// Command upstream-native is a trivial 2026-07-28 MCP server with a single
// "echo" tool, used only as a near-constant-time benchmark fixture for
// measuring gateway overhead. It is not a spec-conformant implementation —
// it does no header/body validation of its own — because for this purpose
// it only needs to be fast and its response time needs to be stable, not
// correct in the general case.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

type request struct {
	ID json.RawMessage `json:"id"`
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9101"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("POST /mcp", handleMCP)

	log.Printf("bench upstream-native (2026-07-28) listening on :%s", port)
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
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"complete","content":[{"type":"text","text":"echo"}],"ttlMs":0,"cacheScope":"private","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"bench-upstream-native","version":"1.0"}}}}`, string(req.ID))
}
