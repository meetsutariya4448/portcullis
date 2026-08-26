# Portcullis

A stateless MCP gateway: proxies between MCP clients and a fleet of MCP
servers, bridging legacy-protocol upstreams transparently and detecting
tool-poisoning attacks in tool descriptions. Built in Go (data plane) and
Python (control plane) — see [ARCHITECTURE.md](ARCHITECTURE.md) for why.

**Status:** the gateway data plane is a production-shaped resilient
proxy — retries with a real safety boundary, circuit breaking, bulkhead
isolation, backpressure, graceful shutdown, gateway-edge auth, a
`(client, namespace, tool)` policy engine, rate limiting, quotas,
OpenTelemetry tracing, SSE streaming, and ordered upstream failover are
all implemented and tested. The legacy-protocol translation shim and the
three-layer tool-poisoning scanner are implemented and tested too. Two
things are still explicitly **not** wired up — see
[What's not implemented](#whats-not-implemented): the scanner's verdict
isn't consumed by anything yet, and there's no production deployment
tooling.

## What's implemented

- **Stateless `2026-07-28` gateway** (`gateway/`) — a single `POST /mcp`
  endpoint, `GET /healthz`, `GET /metrics`. Validates `MCP-Protocol-Version`
  / `Mcp-Method` / `Mcp-Name` headers against the request body and rejects
  disagreement with the spec-defined `-32020 HeaderMismatch` error.
  Namespace-based routing (`{namespace}.{tool}`) to configured upstreams.
  Holds no session state anywhere.
- **Resilience** (`internal/retry`, `router`, `translate`) — bounded
  exponential backoff with a real retry-safety boundary: a request that
  may have already reached an upstream is never retried, against the
  same backend or a failover target, while a failure provably local (an
  open circuit breaker, a pre-connect dial failure) is safely retried or
  failed over. Per-upstream circuit breaker on both the native and
  legacy paths, per-upstream bulkhead concurrency isolation,
  gateway-wide backpressure (`max_inflight`, 503 + `Retry-After`), and
  graceful shutdown that drains in-flight requests before exiting.
- **Traffic control & multi-tenancy** (`internal/auth`, `policy`,
  `ratelimit`, `quota`, `secret`) — gateway-edge API-key authentication
  with rotation/revocation and `${SECRET:NAME}` indirection, a
  `(client, namespace, tool)` authorization policy engine (first-match-
  wins, allow-when-unconfigured), per-client token-bucket rate limiting,
  and a sliding-window request quota. All off by default — an
  unconfigured deployment behaves exactly as it did before any of this
  existed.
- **Observability** (`internal/tracing`, `metrics`) — OpenTelemetry
  distributed tracing (a span per request plus a child span per upstream
  forward attempt, W3C `traceparent` extraction/injection so a trace
  continues across the proxy boundary in both directions, an optional
  local Jaeger instance under docker-compose's `observability` profile)
  and Prometheus metrics covering requests, latency, retries,
  circuit-breaker state, bulkhead/backpressure rejections, auth/policy/
  rate-limit/quota rejections, legacy session reuse, streaming
  responses, and upstream failover.
- **Streaming + failover** (`internal/server`, `router`) — SSE
  (`text/event-stream`) responses are relayed with a flush-per-chunk
  copy loop instead of being buffered, treating client disconnection as
  the cancellation signal. A namespace may map to an ordered group of
  upstreams; the gateway fails over to the next one on a failure proven
  safe to retry elsewhere, via the same retry-safety boundary as
  same-backend retries.
- **Legacy `2025-11-25` translation** (`internal/translate`) — lets an
  unmodified legacy upstream sit behind the same stateless gateway.
  Performs the `initialize`/`initialized` handshake once per pooled
  session and holds `Mcp-Session-Id` server-side; the `2026-07-28`
  client on the other end never sees it. Bounded LIFO session pool,
  health-checked on lease. Multi-round-trip requests
  (`InputRequiredResult`/`requestState`) are explicitly out of scope —
  bridging those isn't compatible with staying stateless — and fail
  loudly (`ErrUnsupportedMRTR`) rather than hanging or guessing.
- **Three-layer tool-poisoning scanner** (`control/scanner/`) — rules →
  local embedding similarity → LLM classifier, short-circuiting on a
  confident result from a cheaper layer. Layer 3's `evidence_span` is
  verified as a literal substring of the input description and rejected
  outright (never repaired) if it isn't. See
  [Measured results](#measured-results) below.
- **Test pyramid and live measurement** — `go test -race` as the
  standing bar since the first commit, Go native fuzz tests against
  every untrusted-input parser (protocol headers, JSON-RPC bodies,
  secret syntax, namespace splitting), an end-to-end circuit-breaker
  recovery test against a real toggled upstream, a concurrent
  multi-feature load test (auth + policy + rate limit + quota under
  ~300 concurrent goroutines), and a security regression test proving
  API keys never reach a trace span or log line — plus a real benchmark
  sweep and a live terminal chaos demo, see
  [Chaos demo](#chaos-demo) and [Measured results](#measured-results).

Full architecture and request-flow detail: [ARCHITECTURE.md](ARCHITECTURE.md).
Protocol details are sourced from the published `2026-07-28` spec, not
recollection: [SPEC-NOTES.md](SPEC-NOTES.md).

## What's not implemented

- **Scanner verdict isn't enforced anywhere.** The scanner produces a
  verdict (`malicious`/`benign`/`uncertain`); nothing consumes it yet.
  The gateway's own policy engine (above) authorizes calls by
  client/namespace/tool — a separate, orthogonal concern from acting on
  a scanner's tool-poisoning verdict, which nothing does yet.
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

# Concurrency sweep (1/10/100/500/1000) + resource usage + session reuse
./bench/run_concurrency_sweep.sh

# Live-timed circuit-breaker recovery (stops/starts a real upstream container)
./bench/run_chaos_bench.sh
```

## Chaos demo

`./bench/chaos_demo.sh` (needs Docker) is a live terminal dashboard: it
brings up the gateway and a real upstream, then in real time — a
redrawn-in-place panel, not scrolling logs — shows the circuit breaker
sitting CLOSED, injects an actual failure (`docker compose stop` on the
upstream, not a simulated one), and watches it open, hold through its
cooldown, probe recovery via a HALF_OPEN trial, and close again once the
upstream comes back. The committed, reproducible timing numbers this is
illustrating are in [Measured results](#measured-results) below and in
[bench/results.md](bench/results.md) (`bench/run_chaos_bench.sh`) — this
script is meant to be watched, not archived.

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
| native (`2026-07-28`) | +0.80ms | +101.40ms |
| legacy (`2025-11-25`, translated) | +5.90ms | +40.70ms |

3-instance scaling is **explicitly not reported**: even with per-container
CPU limits, 3 gateway instances + nginx + upstreams + the load generator
contend for cores on this 8-core test machine, and the benchmark's own
contention check drops the measurement rather than publish a number the
hardware can't actually support.

**Concurrency sweep, resource usage, and live chaos timing** (same
machine, single gateway instance; full tables in
[bench/results.md](bench/results.md)):

- Legacy session reuse across a full 1–1000-concurrency sweep:
  **100.0%** (391,450 sessions reused, 64 created).
- Live circuit-breaker recovery against a real stopped/restarted
  upstream container, at the config's real (default) tuning: breaker
  opened **1s** after the outage began, recovered **5s** after the
  upstream came back (**6s** total) — see [Chaos demo](#chaos-demo) to
  watch this live instead of reading it.
- At concurrency ≥100, the native and legacy paths show two different,
  both-intentional backpressure mechanisms under real load: the native
  path's default bulkhead (256 slots) queues excess requests rather than
  rejecting them (rising latency, zero non-200s); the legacy path's
  session pool (`max_pool_size: 64` in the bench config) rejects outright
  once exhausted (real `503`s). Neither is tuned away — both are reported
  as the actual finding.

## Repo layout

```
gateway/               Go data plane
  cmd/portcullis/       entrypoint
  internal/mcp/         header/body validation, HeaderMismatch
  internal/router/      namespace -> upstream (or failover group) resolution
  internal/translate/   legacy 2025-11-25 session-pool shim + circuit breaker
  internal/retry/       bounded backoff + the retry-safety-boundary primitive
  internal/auth/        gateway-edge API-key authentication
  internal/policy/      (client, namespace, tool) authorization
  internal/ratelimit/   per-client token-bucket rate limiting
  internal/quota/       per-client sliding-window quota
  internal/secret/      ${SECRET:NAME} indirection
  internal/tracing/     OpenTelemetry TracerProvider setup
  internal/server/      POST /mcp, /healthz, /metrics
  internal/metrics/     Prometheus instrumentation
control/               Python control plane
  scanner/               three-layer tool-poisoning detection cascade
  evals/                 labeled corpus + run_eval.py + REPORT.md
bench/                 benchmarks + live demos (docker-compose "bench" profile)
  run_bench.sh            gateway overhead, 1 vs. 3 instances
  run_concurrency_sweep.sh  1/10/100/500/1000 concurrency + resource usage
  run_chaos_bench.sh      live-timed circuit-breaker recovery (measure-and-exit)
  chaos_demo.sh           live terminal dashboard (watch-and-narrate)
  lib.sh                  shared helpers (median/hey-parsing/machine-spec)
docker-compose.yml     local dev stack (postgres/pgvector, redis) + bench and
                       observability (Jaeger) profiles
SPEC-NOTES.md          sourced MCP 2026-07-28 protocol reference
ARCHITECTURE.md        request-flow and component detail
```

## Commit convention

Small, scoped commits. Conventional Commits prefixes: `feat`, `fix`,
`docs`, `chore`, `refactor`, `test`.
