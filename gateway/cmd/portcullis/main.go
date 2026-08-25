// Command portcullis runs the stateless MCP gateway data plane.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/meetsutariya4448/portcullis/gateway/internal/auth"
	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/policy"
	"github.com/meetsutariya4448/portcullis/gateway/internal/quota"
	"github.com/meetsutariya4448/portcullis/gateway/internal/ratelimit"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
	"github.com/meetsutariya4448/portcullis/gateway/internal/secret"
	"github.com/meetsutariya4448/portcullis/gateway/internal/server"
	"github.com/meetsutariya4448/portcullis/gateway/internal/tracing"
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

	authenticator, err := buildAuthenticator(cfg.Auth)
	if err != nil {
		log.Error("failed to build authenticator", "error", err)
		os.Exit(1)
	}

	pol := buildPolicy(cfg.Policy)
	limiter := buildRateLimiter(cfg.RateLimit)
	quotaTracker, err := buildQuotaTracker(cfg.Quota)
	if err != nil {
		log.Error("failed to build quota tracker", "error", err)
		os.Exit(1)
	}

	tracerProvider, err := tracing.BuildProvider(context.Background(), cfg.Tracing)
	if err != nil {
		log.Error("failed to build tracer provider", "error", err)
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Error("failed to bind", "addr", *addr, "error", err)
		os.Exit(1)
	}

	srv := server.New(server.Options{
		Router:        rtr,
		Log:           log,
		MaxInflight:   cfg.MaxInflightOrDefault(),
		Authenticator: authenticator,
		Policy:        pol,
		RateLimiter:   limiter,
		QuotaTracker:  quotaTracker,
	})
	httpServer := &http.Server{Handler: srv}

	// First SIGINT/SIGTERM triggers a graceful drain (in run, below);
	// calling stop as soon as that starts un-registers the handler so a
	// SECOND signal falls through to the Go runtime's default behavior
	// (immediate exit) — the standard "ask nicely once, then just kill it"
	// pattern.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Info("portcullis starting", "addr", listener.Addr().String(), "upstreams", len(cfg.Upstreams), "max_inflight", cfg.MaxInflightOrDefault(), "auth_enabled", cfg.Auth.Enabled, "policy_rules", len(cfg.Policy.Rules), "rate_limit_enabled", cfg.RateLimit.Enabled, "quota_enabled", cfg.Quota.Enabled, "tracing_enabled", cfg.Tracing.Enabled)
	runErr := run(ctx, stop, httpServer, listener, *shutdownTimeout, log)

	if tracerProvider != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := tracerProvider.Shutdown(shutdownCtx); err != nil {
			log.Error("failed to flush trace exporter", "error", err)
		}
		cancel()
	}

	if runErr != nil {
		os.Exit(1)
	}
}

// buildAuthenticator constructs an auth.Authenticator from cfg, expanding
// each configured API key through secret.Expand (env-var-backed by
// default — see internal/secret) so keys don't have to sit in plaintext
// YAML; a value with no "${SECRET:...}" wrapper passes through as a
// literal, so local-dev configs work without a real provider. Returns
// (nil, nil) when auth is disabled: the server's auth gate treats a nil
// Authenticator as "authentication off," today's behavior, unchanged.
func buildAuthenticator(cfg config.Auth) (*auth.Authenticator, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	provider := secret.EnvProvider{}
	clients := make([]auth.Client, 0, len(cfg.Clients))
	for _, c := range cfg.Clients {
		keys := make([]string, 0, len(c.APIKeys))
		for _, k := range c.APIKeys {
			resolved, err := secret.Expand(k, provider)
			if err != nil {
				return nil, fmt.Errorf("client %q: resolving api key: %w", c.ClientID, err)
			}
			keys = append(keys, resolved)
		}
		expiresAt, err := c.ExpiresAtTime()
		if err != nil {
			return nil, err
		}
		clients = append(clients, auth.Client{
			ID:        c.ClientID,
			APIKeys:   keys,
			ExpiresAt: expiresAt,
			Revoked:   c.Revoked,
		})
	}
	return auth.New(clients), nil
}

// buildPolicy constructs a policy.Policy from cfg. An empty Rules list
// (no policy: block, or one present with no rules) still returns a
// non-nil Policy — Evaluate treats zero rules as "allow everything," so
// this needs no special-casing the way buildAuthenticator's disabled
// case does.
func buildPolicy(cfg config.Policy) *policy.Policy {
	rules := make([]policy.Rule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		rules = append(rules, policy.Rule{
			Client:    r.Client,
			Namespace: r.Namespace,
			Tools:     r.Tools,
			Effect:    r.Effect,
		})
	}
	return policy.New(rules)
}

// buildRateLimiter constructs a ratelimit.Limiter from cfg. Returns nil
// when rate limiting is disabled: the server's rate-limit gate treats a
// nil Limiter as "off," today's behavior, unchanged.
func buildRateLimiter(cfg config.RateLimit) *ratelimit.Limiter {
	if !cfg.Enabled {
		return nil
	}
	return ratelimit.NewLimiter(cfg.RequestsPerSecond, cfg.Burst)
}

// buildQuotaTracker constructs a quota.Tracker from cfg. Returns (nil,
// nil) when quota is disabled: the server's quota gate treats a nil
// Tracker as "off," today's behavior, unchanged.
func buildQuotaTracker(cfg config.Quota) (*quota.Tracker, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	window, err := cfg.WindowDuration()
	if err != nil {
		return nil, err
	}
	return quota.NewTracker(window, cfg.MaxRequests), nil
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
