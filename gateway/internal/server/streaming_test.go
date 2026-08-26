package server

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/metrics"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
)

func TestIsEventStream(t *testing.T) {
	cases := map[string]bool{
		"text/event-stream":                true,
		"text/event-stream; charset=utf-8": true,
		"TEXT/EVENT-STREAM":                true,
		"  text/event-stream  ":            true,
		"application/json":                 false,
		"":                                 false,
		"text/plain":                       false,
	}
	for ct, want := range cases {
		if got := isEventStream(ct); got != want {
			t.Errorf("isEventStream(%q) = %v, want %v", ct, got, want)
		}
	}
}

// TestStreamCopy_StopsWhenContextCanceled proves streamCopy doesn't hang
// on a blocked read once ctx is canceled -- mirroring how net/http
// actually behaves in production: canceling a request's context closes
// the underlying connection, unblocking any in-progress Read on the
// response body with an error. Simulated here by closing the pipe with
// ctx's error the moment ctx.Done() fires, since io.Pipe itself has no
// context awareness of its own.
func TestStreamCopy_StopsWhenContextCanceled(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-ctx.Done()
		pr.CloseWithError(ctx.Err())
	}()

	rec := httptest.NewRecorder()
	done := make(chan error, 1)
	go func() {
		done <- streamCopy(ctx, rec, pr)
	}()

	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("streamCopy did not stop after context cancellation")
	}
}

func TestStreamCopy_RelaysDataAndFlushes(t *testing.T) {
	rec := httptest.NewRecorder()
	src := strings.NewReader("data: hello\n\ndata: world\n\n")
	if err := streamCopy(context.Background(), rec, src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rec.Flushed {
		t.Error("expected the response writer to have been flushed")
	}
	if got := rec.Body.String(); got != "data: hello\n\ndata: world\n\n" {
		t.Fatalf("unexpected body: %q", got)
	}
}

// readLineWithTimeout reads one line from r, failing the test if none
// arrives within timeout -- used to prove a read genuinely would have
// hung (i.e. the gateway was buffering) rather than letting a stuck test
// block until Go's default 10-minute test timeout.
func readLineWithTimeout(t *testing.T, r *bufio.Reader, timeout time.Duration) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("read failed: %v", res.err)
		}
		return res.line
	case <-time.After(timeout):
		t.Fatal("timed out waiting for a line -- response appears to be buffered rather than streamed")
		return ""
	}
}

// TestHandleMCP_StreamsSSEResponseIncrementally is the real end-to-end
// proof: a fake upstream sends one SSE event, then blocks on a channel
// before sending a second. If the gateway buffered the whole response
// before relaying anything (the old default-io.Copy behavior for a
// response the handler doesn't finish writing until it's complete),
// reading the first event here would hang until the channel is released
// -- but the release only happens AFTER this test successfully reads the
// first event, so a hang here means buffering, not streaming.
func TestHandleMCP_StreamsSSEResponseIncrementally(t *testing.T) {
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		_, _ = w.Write([]byte("data: first\n\n"))
		flusher.Flush()

		<-release

		_, _ = w.Write([]byte("data: second\n\n"))
		flusher.Flush()
	}))
	defer upstream.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "sse-upstream", Namespace: "sse", URL: upstream.URL,
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	before := testutil.ToFloat64(metrics.StreamingResponsesTotal.WithLabelValues("sse-upstream"))

	req, err := http.NewRequest(http.MethodPost, gwSrv.URL+"/mcp", strings.NewReader(nativeClientBody("sse.ping")))
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "sse.ping")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Fatalf("expected X-Accel-Buffering: no, got %q", got)
	}

	reader := bufio.NewReader(resp.Body)

	// Each SSE frame is "data: ...\n\n" -- two lines (the data line and
	// its blank terminator). Read both for the first frame before
	// asserting, so the second ReadString call below can only be
	// satisfied by data the upstream hasn't sent yet.
	firstLine := readLineWithTimeout(t, reader, 2*time.Second)
	if !strings.Contains(firstLine, "first") {
		t.Fatalf("expected the first line to contain \"first\", got %q", firstLine)
	}
	readLineWithTimeout(t, reader, 2*time.Second) // the blank line terminating the first frame

	close(release)

	secondLine := readLineWithTimeout(t, reader, 2*time.Second)
	if !strings.Contains(secondLine, "second") {
		t.Fatalf("expected the second line to contain \"second\", got %q", secondLine)
	}

	if got := testutil.ToFloat64(metrics.StreamingResponsesTotal.WithLabelValues("sse-upstream")) - before; got != 1 {
		t.Fatalf("expected StreamingResponsesTotal to increment by 1, got %v", got)
	}
}

// TestHandleMCP_NonStreamingResponseUnaffected proves an ordinary JSON
// response still goes through the plain io.Copy path -- streaming
// detection doesn't accidentally kick in for the common case.
func TestHandleMCP_NonStreamingResponseUnaffected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	cfg := &config.Config{Upstreams: []config.Upstream{{
		Name: "json-upstream", Namespace: "json", URL: upstream.URL,
	}}}
	log := discardLogger()
	rtr, err := router.New(cfg, log)
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	gw := New(Options{Router: rtr, Log: log, MaxInflight: 100})

	before := testutil.ToFloat64(metrics.StreamingResponsesTotal.WithLabelValues("json-upstream"))

	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, nativeRequest("json.ping"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Accel-Buffering"); got != "" {
		t.Fatalf("expected no X-Accel-Buffering header on a non-streaming response, got %q", got)
	}
	if got := testutil.ToFloat64(metrics.StreamingResponsesTotal.WithLabelValues("json-upstream")) - before; got != 0 {
		t.Fatalf("expected StreamingResponsesTotal unchanged for a non-streaming response, got %v", got)
	}
}
