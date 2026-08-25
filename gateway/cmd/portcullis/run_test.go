package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRun_DrainsInFlightRequestInsteadOfKillingIt proves the actual
// graceful-shutdown behavior: a request already being handled when the
// shutdown signal fires gets to finish successfully, and run only returns
// after that drain completes.
func TestRun_DrainsInFlightRequestInsteadOfKillingIt(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	handlerCompleted := make(chan struct{})

	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseHandler
		w.WriteHeader(http.StatusOK)
		close(handlerCompleted)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpServer := &http.Server{Handler: mux}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- run(ctx, cancel, httpServer, listener, 2*time.Second, testLogger())
	}()

	// Fire the slow request, wait for the handler to actually be running,
	// then trigger shutdown while it's still in flight.
	clientDone := make(chan error, 1)
	go func() {
		resp, err := http.Get("http://" + listener.Addr().String() + "/slow")
		if err == nil {
			resp.Body.Close()
		}
		clientDone <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("handler never started")
	}

	cancel() // simulates the shutdown signal firing mid-request

	// The handler must still be allowed to finish -- release it only after
	// shutdown has begun, proving Shutdown() is draining, not killing.
	time.Sleep(20 * time.Millisecond)
	close(releaseHandler)

	select {
	case <-handlerCompleted:
	case <-time.After(time.Second):
		t.Fatal("in-flight handler was killed instead of allowed to complete")
	}

	if err := <-clientDone; err != nil {
		t.Fatalf("client request failed instead of completing cleanly: %v", err)
	}

	select {
	case err := <-runDone:
		if err != nil {
			t.Fatalf("expected a clean shutdown, got: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after the drain completed")
	}
}

// TestRun_ShutdownTimeoutIsEnforced proves the drain window is actually
// bounded: a handler that outlives shutdownTimeout causes run to return an
// error rather than waiting forever.
func TestRun_ShutdownTimeoutIsEnforced(t *testing.T) {
	requestStarted := make(chan struct{})
	blockForever := make(chan struct{}) // deliberately never closed

	mux := http.NewServeMux()
	mux.HandleFunc("/hang", func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-blockForever
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpServer := &http.Server{Handler: mux}

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- run(ctx, cancel, httpServer, listener, 50*time.Millisecond, testLogger())
	}()

	go func() {
		resp, err := http.Get("http://" + listener.Addr().String() + "/hang")
		if err == nil {
			resp.Body.Close()
		}
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("handler never started")
	}

	cancel()

	select {
	case err := <-runDone:
		if err == nil {
			t.Fatal("expected run to return an error when the drain window is exceeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return even after the shutdown timeout should have elapsed")
	}
}
