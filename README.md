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
three-layer tool-poisoning scanner are implemented and tested too, and the
scanner's verdicts are now **enforced** by the gateway: a tool whose
description the scanner classified as an attack is denied before the
upstream is contacted, and a server that swaps a cleared description for a
poisoned one is re-assessed rather than grandfathered. See
[Tool-poisoning admission](#tool-poisoning-admission).

Verdicts are enforced at both points that matter: a poisoned tool is
withheld from `tools/list` so its description never reaches the model, and
denied at `tools/call` so it never executes. What remains explicitly
**not** done is listed under
[What's not implemented](#whats-not-implemented).

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
- **Tool-poisoning admission** (`gateway/internal/admission`) — the
  scanner's verdicts, enforced. A background discoverer lists each
  upstream's tools, hashes every `(name, description, inputSchema)`, and
  queues anything unscanned; the Python worker
  (`control/app/worker.py`) runs the cascade out of band and writes
  verdicts to Postgres. The request path does a cached lookup, never a
  model call. Verdicts are keyed by content hash, so a changed description
  is a different verdict — see
  [Tool-poisoning admission](#tool-poisoning-admission).
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

- **A full eval run under the current harness.** The harness was rebuilt
  around a held-out split and per-run fingerprinting, but re-running it
  needs `ANTHROPIC_API_KEY`. Only the local layers have been measured under
  it — see [Measured results](#measured-results), where the superseded
  figures are retracted rather than restated.
- **Per-principal listings.** The discoverer lists with the gateway's own
  credentials, so a server that varies its tool list by authenticated
  principal (permitted by SPEC-NOTES.md §2) is modelled as a single list.
  The policy engine still filters the merged listing per client.
- **Admission for `resources/read` and `prompts/get`.** Both are
  name-bearing, but a tool-poisoning verdict is about a tool definition;
  covering them needs verdicts the scanner does not produce.
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
# layer 2 runs locally, no key needed for that layer). Writes
# evals/results/<fingerprint>/ and, for a full run, regenerates REPORT.md.
cd control && python3 evals/run_eval.py
cd control && python3 evals/run_eval.py --skip-llm   # local layers only

# Tool-poisoning admission: schema, then the out-of-band scanning worker
docker compose up -d postgres
psql "$PORTCULLIS_ADMISSION_DATABASE_URL" -f control/migrations/001_admission.sql
cd control && python3 -m app.run_worker --once   # or omit --once to poll

# Gateway overhead benchmark (needs Docker + `hey`: brew install hey)
./bench/run_bench.sh

# Concurrency sweep (1/10/100/500/1000) + resource usage + session reuse
./bench/run_concurrency_sweep.sh

# Live-timed circuit-breaker recovery (stops/starts a real upstream container)
./bench/run_chaos_bench.sh
```

## Tool-poisoning admission

The scanner's verdicts decide which tools a client may call.

**Nothing is scanned on the request path.** Layer 3 measures p50 ~3s; the
gateway's own overhead budget is under a millisecond. So the work is split:

```
                 (out of band, every refresh_interval)
gateway --tools/list--> upstream        gateway --enqueue--> scan_queue
        <--definitions--                                          |
        hash each (name, description, inputSchema)                |
                                                        control/app/worker.py
                                                          runs the cascade
                                                                  |
                                                           tool_verdicts
                                                                  |
client --tools/call--> gateway --cached lookup--> verdict --> allow | 403
```

The gateway reads `tool_verdicts`; the worker reads `scan_queue`. Neither
process calls the other — the database is the entire interface
(`control/migrations/001_admission.sql`).

**Verdicts are keyed by content hash**, not by tool name. The hash covers
the tool's name, description and input schema — everything a model reads —
so a server that serves a benign description, gets cleared, then swaps in a
poisoned one produces a *different* key and does not inherit the old
verdict. Rows are never updated in place, so a tool's verdict history is
just the rows sharing its name:

```
     hash     |  verdict  | produced_by
--------------+-----------+-------------
 6e1cd9ed033a | benign    | layer2
 db413fc7cbe1 | malicious | layer1        <- after the description was swapped
```

The canonical form the hash is taken over is specified identically in Go
(`gateway/internal/admission/hash.go`) and Python
(`control/app/hashing.py`), with shared golden vectors in
[testdata/tool_hash_vectors.json](testdata/tool_hash_vectors.json) asserted
from both. If they ever diverge the worker refuses to scan rather than
filing a verdict under a key the gateway will never read.

**Outcomes** (`admission:` in `gateway/config.example.yaml`):

| Verdict | `tools/list` | `tools/call` | Configurable |
|---|---|---|---|
| `benign` | listed | allow | no |
| `malicious` | **withheld** | **deny** (403, JSON-RPC `-32001`) | no |
| `uncertain`, `layer3_failure` | withheld | deny | `on_uncertain` |
| no verdict for the current hash | **withheld** | allow + warn | `on_unknown` |
| verdict store unreachable | withheld | last-known verdict, else allow + error log | `on_unavailable` |

Withholding an unscanned description from listings is what closes the
obvious bypass: a server that mutates its description on every listing
keeps the content hash perpetually new, so a verdict never applies to what
it is currently serving. Calls fail open by default so a fresh deployment
stays usable before the first scan lands; listings do not, because that is
where the attack actually lands.

`malicious` and `benign` are deliberately not configurable: an operator who
wants monitor mode turns the gate off rather than configuring it into
reporting enforcement it isn't doing. A scan that failed is never recorded
as `benign` — an outage is not a clean bill of health.

**Decision logs** carry the evidence needed to act on a denial: which tool,
which exact content hash, which verdict and attack class, and the eval-run
fingerprint that characterizes how good that judgement is.

```sql
 point | tool_name  | decision |    reason    |     hash     |  verdict  |   fingerprint
-------+------------+----------+--------------+--------------+-----------+------------------
 call  | summarize  | allow    | benign       | 6e1cd9ed033a | benign    | 6cdd4785936c4da9
 call  | exfiltrate | deny     | malicious    | c14d8cd807d0 | malicious | 6cdd4785936c4da9
 call  | summarize  | allow    | unknown_hash | db413fc7cbe1 |           |
```

**Measured cost** — the request path does a cached lookup, never a model
call. Added p50 is ~0.2ms with a warm cache and ~0.3ms with the cache
disabled entirely (every request re-reading Postgres); the gate's own
histogram puts the mean at 0.17ms in that worst case, with 38% of requests
under 100µs. Full method, caveats and the second run in
[bench/results.md](bench/results.md#tool-poisoning-admission-overhead).

Metrics: `portcullis_admission_decisions_total{point,outcome,reason,namespace}`,
`portcullis_admission_latency_seconds{point}` (reported separately from the
headline gateway overhead so the cost of enforcement stays falsifiable),
`portcullis_admission_catalog_tools`, `portcullis_admission_scans_enqueued_total`,
`portcullis_admission_discovery_failures_total`.

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

> **These figures are superseded and are not being restated here.** They
> were produced by harness v1, which scored malicious rows against a
> row- or family-excluded layer-2 index while scoring benign rows against
> the *full* index — so precision and recall inside each row came from two
> different configurations, and the F1 over them described neither. The
> bolded "full cascade" row was additionally the leave-one-out
> configuration without saying so, sitting beside a layer-3 row measured
> under different conditions.
>
> The harness has been rebuilt around a held-out split
> (`control/evals/split.py`): one layer-2 index, built from train-split
> attacks only, and every number computed over held-out rows that are not
> in it. Every run now carries a fingerprint over its corpus, split,
> model, thresholds, embedder and library versions, and writes
> machine-readable artifacts to `control/evals/results/<fingerprint>/`.
>
> **Re-running the full eval needs `ANTHROPIC_API_KEY` and has not been
> done yet**, so no cascade or layer-3 figure is quoted above. The
> local-only layers have been measured under the new configuration
> (fingerprint `6cdd4785936c4da9`, marked `partial: true` because layer 3
> was skipped):
>
> | | precision | recall | F1 | n (held-out) |
> |---|---|---|---|---|
> | Layer 1 (rules) | 1.000 | 0.850 | 0.919 | 62 |
> | Layer 2 (embeddings, held-out index) | n/a (no positives) | 0.000 | n/a | 62 |
>
> Layer 2's held-out recall of **0.000** is the finding the old 0.947
> concealed: against seed families absent from its index it retrieves
> nothing, which the leave-one-seed-family-out diagnostic had already
> hinted at. Quote a number from this project only together with the run
> fingerprint it came from.

The superseded harness-v1 report is still in
[control/evals/REPORT.md](control/evals/REPORT.md) for provenance; it is
labelled there rather than deleted.

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
