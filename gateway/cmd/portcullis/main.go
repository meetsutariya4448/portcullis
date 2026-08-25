// Command portcullis runs the stateless MCP gateway data plane.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
	"github.com/meetsutariya4448/portcullis/gateway/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the upstream fleet YAML config")
	addr := flag.String("addr", ":8080", "address to listen on")
	shutdownTimeout := flag.Duration("shutdown-timeout", 15*time.Second, "how long to wait for in-flight requests to finish during a graceful shutdown")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("failed to load config", "error", err, "path", *configPath)
		os.Exit(1)
	}

	rtr, err := router.New(cfg, log)
	if err != nil {
		log.Error("failed to build router", "error", err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Error("failed to bind", "addr", *addr, "error", err)
		os.Exit(1)
	}

	srv := server.New(rtr, log, cfg.MaxInflightOrDefault())
	httpServer := &http.Server{Handler: srv}

	// First SIGINT/SIGTERM triggers a graceful drain (in run, below);
	// calling stop as soon as that starts un-registers the handler so a
	// SECOND signal falls through to the Go runtime's default behavior
	// (immediate exit) — the standard "ask nicely once, then just kill it"
	// pattern.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("portcullis starting", "addr", listener.Addr().String(), "upstreams", len(cfg.Upstreams), "max_inflight", cfg.MaxInflightOrDefault())
	if err := run(ctx, stop, httpServer, listener, *shutdownTimeout, log); err != nil {
		os.Exit(1)
	}
}

// run serves httpServer on listener until either it exits on its own (an
// operational failure once already listening) or ctx is done (a shutdown
// signal), in which case it drains in-flight requests via Shutdown within
// shutdownTimeout. Split out from main so graceful shutdown is testable
// without spawning a real process or OS signal.
func run(ctx context.Context, stop context.CancelFunc, httpServer *http.Server, listener net.Listener, shutdownTimeout time.Duration, log *slog.Logger) error {
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- httpServer.Serve(listener)
	}()

	select {
	case err := <-serveErrCh:
		if err != nil && err != http.ErrServerClosed {
			log.Error("server exited", "error", err)
			return err
		}
		return nil
	case <-ctx.Done():
		stop()
		log.Info("shutdown signal received, draining in-flight requests", "timeout", shutdownTimeout.String())

		drainCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(drainCtx); err != nil {
			log.Error("graceful shutdown did not complete within the timeout", "error", err)
			return err
		}
		log.Info("shutdown complete")
		return nil
	}
}
