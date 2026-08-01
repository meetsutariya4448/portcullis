// Command portcullis runs the stateless MCP gateway data plane.
package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/meetsutariya4448/portcullis/gateway/internal/config"
	"github.com/meetsutariya4448/portcullis/gateway/internal/router"
	"github.com/meetsutariya4448/portcullis/gateway/internal/server"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the upstream fleet YAML config")
	addr := flag.String("addr", ":8080", "address to listen on")
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

	srv := server.New(rtr, log)

	log.Info("portcullis starting", "addr", *addr, "upstreams", len(cfg.Upstreams))
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Error("server exited", "error", err)
		os.Exit(1)
	}
}
