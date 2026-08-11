# Portcullis

A stateless MCP gateway: proxies between MCP clients and a fleet of MCP
servers, bridging legacy-protocol upstreams transparently and detecting
tool-poisoning attacks in tool descriptions. Built in Go (data plane) and
Python (control plane) — see [ARCHITECTURE.md](ARCHITECTURE.md) for why.

**Status:** the gateway data plane, legacy-protocol translation shim, and
the three-layer tool-poisoning scanner are implemented and tested. Policy
enforcement (acting on a scanner verdict) and wiring the scanner into the
live gateway request path are **not built yet** — see
[What's not implemented](#whats-not-implemented).

## What's implemented

- **Stateless `2026-07-28` gateway** (`gateway/`) — a single `POST /mcp`
  endpoint, `GET /healthz`, `GET /metrics`. Validates `MCP-Protocol-Version`
  / `Mcp-Method` / `Mcp-Name` headers against the request body and rejects
  disagreement with the spec-defined `-32020 HeaderMismatch` error.
  Namespace-based routing (`{namespace}.{tool}`) to configured upstreams,
  each with its own connection pool. Prometheus metrics
  (`portcullis_requests_total`, `portcullis_gateway_latency_seconds` —
  gateway-only overhead, excluding upstream round-trip time) and
  structured `slog` logging on every request. Holds no session state
  anywhere.
- **Legacy `2025-11-25` translation** (`gateway/internal/translate`) — lets
  an unmodified legacy upstream sit behind the same stateless gateway.
  Performs the `initialize`/`initialized` handshake once per pooled
  session and holds `Mcp-Session-Id` server-side; the `2026-07-28` client
  on the other end never sees it. Bounded LIFO session pool, health-checked
  on lease, per-upstream circuit breaker (opens at 50% error rate over a
  10s sliding window). Multi-round-trip requests
  (`InputRequiredResult`/`requestState`) are explicitly out of scope —
  bridging those isn't compatible with staying stateless — and fail loudly
  (`ErrUnsupportedMRTR`) rather than hanging or guessing.
- **Three-layer tool-poisoning scanner** (`control/scanner/`) — rules →
  local embedding similarity → LLM classifier, short-circuiting on a
  confident result from a cheaper layer. Layer 3's `evidence_span` is
  verified as a literal substring of the input description and rejected
  outright (never repaired) if it isn't. See
  [Measured results](#measured-results) below.

Full architecture and request-flow detail: [ARCHITECTURE.md](ARCHITECTURE.md).
Protocol details are sourced from the published `2026-07-28` spec, not
recollection: [SPEC-NOTES.md](SPEC-NOTES.md).

## What's not implemented

- **Policy enforcement.** The scanner produces a verdict; nothing acts on
  it (allow/block/log/alert). No policy engine exists.
- **Scanner ↔ gateway integration.** The scanner is a standalone Python
  component with its own test suite and eval harness — the Go gateway
  does not call it. Nothing in `gateway/` references the scanner today.
- **Production deployment.** `docker-compose.yml` is a local dev stack;
  there's no Kubernetes/Helm config, CI deploy pipeline, or image registry
  publishing.

## Quickstart

```sh
# Dev stack (postgres/pgvector, redis — provisioned ahead of need, see
# ARCHITECTURE.md: nothing that runs today actually connects to either yet)
docker compose up -d

# Gateway: build + test
cd gateway && go build ./... && go test ./...
cd gateway && go run ./cmd/portcullis -config config.example.yaml

# Scanner: install deps + run tests
cd control && pip install -e . && python3 -m pytest scanner

# Scanner eval against the labeled corpus (needs ANTHROPIC_API_KEY;
# layer 2 runs locally, no key needed for that layer)
cd control && python3 evals/run_eval.py

# Gateway overhead benchmark (needs Docker + `hey`: brew install hey)
./bench/run_bench.sh
```

## Measured results

These are real, measured numbers, not targets — both source files caveat
their own methodology in detail and should be read before quoting a
number out of context.

**Scanner cascade** (139-row labeled corpus; provenance in
[control/evals/corpus/README.md](control/evals/corpus/README.md); full
methodology, per-attack-class breakdown, and cost in
[control/evals/REPORT.md](control/evals/REPORT.md)):

| | precision | recall | F1 |
|---|---|---|---|
| Layer 1 (rules) | 1.000 | 0.737 | 0.848 |
| Layer 2 (embeddings, leave-one-out) | 1.000 | 0.947 | 0.973 |
| Layer 3 (LLM) | 0.926 | 0.658 | 0.769 |
| **Full cascade** | **1.000** | **0.947** | **0.973** |

Caveat that matters: layer 2's recall drops to **0.000** when the scored
sample's entire seed family (not just itself) is excluded from the index —
most of its apparent recall is retrieving a near-identical sibling, not
generalizing to an unfamiliar attack. The cascade inherits this: recall
falls to 0.842 under that stricter indexing, with detection shifting onto
layers 1 and 3. Both numbers are reported side by side in REPORT.md, not
just the flattering one. Cascade LLM invocation rate is 2.9% of rows
(~$0.50 per 1,000 tools scanned) under the leave-one-out numbers above.

**Gateway overhead**, single instance, median of 3 warmed-up runs on an
Apple M2 (8 cores) — full method and caveats in
[bench/results.md](bench/results.md):

| Upstream | Added p50 | Added p99 |
|---|---:|---:|
| native (`2026-07-28`) | +1.30ms | +35.00ms |
| legacy (`2025-11-25`, translated) | +3.10ms | +16.60ms |

3-instance scaling is **explicitly not reported**: even with per-container
CPU limits, 3 gateway instances + nginx + upstreams + the load generator
contend for cores on this 8-core test machine, and the benchmark's own
contention check drops the measurement rather than publish a number the
hardware can't actually support.

## Repo layout

```
gateway/               Go data plane
  cmd/portcullis/       entrypoint
  internal/mcp/         header/body validation, HeaderMismatch
  internal/router/      namespace -> upstream resolution
  internal/translate/   legacy 2025-11-25 session-pool shim + circuit breaker
  internal/server/      POST /mcp, /healthz, /metrics
  internal/metrics/     Prometheus instrumentation
control/               Python control plane
  scanner/               three-layer tool-poisoning detection cascade
  evals/                 labeled corpus + run_eval.py + REPORT.md
bench/                 gateway overhead benchmark (docker-compose "bench" profile)
docker-compose.yml     local dev stack (postgres/pgvector, redis) + bench profile
SPEC-NOTES.md          sourced MCP 2026-07-28 protocol reference
ARCHITECTURE.md        request-flow and component detail
```

## Commit convention

Small, scoped commits. Conventional Commits prefixes: `feat`, `fix`,
`docs`, `chore`, `refactor`, `test`.
