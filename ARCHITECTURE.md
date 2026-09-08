# Architecture

## Overview

Portcullis sits between MCP clients and a fleet of MCP servers. Clients
always speak the current MCP `2026-07-28` transport to Portcullis; upstream
servers may speak that same version natively, or the older `2025-11-25`
version. Portcullis is stateless: it holds no client session state itself,
and it presents the same stateless-by-default `2026-07-28` contract to
every client regardless of what a given upstream actually requires. Where
that requires state on the upstream side (a legacy `Mcp-Session-Id`),
Portcullis owns and hides that state internally rather than pushing it
onto the client. See [SPEC-NOTES.md](SPEC-NOTES.md) for the protocol
details this is built against, all sourced from the published spec.

The system is split into two independently-versioned pieces — see
[CLAUDE.md](CLAUDE.md) for the "why Go / why Python" reasoning. They still
do not call each other: the two halves are joined by a **shared Postgres
database**, not by an RPC. The gateway reads verdicts and writes a scan
queue; the control plane reads that queue and writes verdicts. This keeps
the scanner off the request path entirely — a ~3s layer-3 call can never
land on a request the gateway is holding open — while making its verdicts
enforceable. See **Tool-poisoning admission** below.

## Data Plane

`gateway/`, Go, stdlib `net/http` only (no MCP SDK). Three HTTP endpoints
(`gateway/internal/server`):

- `POST /mcp` — the actual proxy
- `GET /healthz`
- `GET /metrics` — Prometheus, via `promhttp`

Request flow for `POST /mcp`:

1. **Header/body validation** (`gateway/internal/mcp`) — parses and
   cross-checks `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name`
   against the request body. A disagreement is rejected with the
   spec-defined JSON-RPC error `-32020 HeaderMismatch`
   (`gwmcp.HeaderMismatchCode`), not silently resolved one way or another.
2. **Namespace routing** (`gateway/internal/router`) — resolves the
   `{namespace}.{tool}`-style name to a configured `Upstream`, each with
   its own pooled `http.Client` and per-upstream timeout (one connection
   pool per upstream, never shared).
3. **Forwarding**, one of two paths depending on the upstream's configured
   `protocol_version`:
   - **Native (`2026-07-28`)**: forwarded to the upstream unchanged,
     directly over the upstream's own `http.Client`.
   - **Legacy (`2025-11-25`)**: leased from that upstream's session pool
     instead — see **Translation shim** below. The inbound stateless
     request is mapped onto a leased, already-handshaken legacy session;
     the client never sees a session ID.
4. Response forwarded back, hop-by-hop headers (`Connection`,
   `Transfer-Encoding`, etc., per RFC 9110) stripped in both directions.

Every request emits `portcullis_requests_total{method,tool,status}` and
`portcullis_gateway_latency_seconds{method,tool,status}` — the latter
measures Portcullis's own overhead only (header validation, routing,
marshaling), explicitly excluding time spent waiting on the upstream, so
it isolates the gateway's cost from the upstream's. Structured `slog`
logging on every request records method, tool, upstream, duration, and
status.

**Translation shim** (`gateway/internal/translate`): bridges a stateless
`2026-07-28` client to an unmodified `2025-11-25` upstream. Performs the
legacy `initialize`/`initialized` handshake once per pooled connection and
holds the resulting `Mcp-Session-Id` server-side; health-checks a session
on lease and recycles dead ones; bounded, LIFO pool (keeps connections
warm); per-upstream circuit breaker opening at a 50% error rate over a
10-second sliding window (10 one-second buckets). It deliberately does
**not** implement `InputRequiredResult`/`requestState` multi-round-trip
bridging — that requires holding a legacy connection open across two
unrelated client HTTP requests, which isn't compatible with Portcullis
staying stateless. A legacy upstream that responds with what looks like a
server-initiated mid-flow request instead of a result produces
`ErrUnsupportedMRTR` rather than silently hanging or guessing.

The gateway holds **no session state**, anywhere — statelessness is a
correctness property (any instance can serve any request), not just an
implementation detail, which is what makes `bench/`'s no-sticky-sessions
round-robin topology valid in the first place.

## Control Plane

`control/scanner/`, Python. A three-layer detection cascade for
tool-poisoning attacks in MCP tool descriptions — deterministic rules,
then embedding similarity, then an LLM classifier — short-circuiting on a
confident result from a cheaper layer before paying for a more expensive
one. See `control/scanner/cascade.py` for the orchestration and
`control/evals/REPORT.md` for measured precision/recall/cost.

1. **Layer 1 — `layer1_rules.py`**: regex/heuristic rules over the tool
   description (imperative instructions aimed at the model, references to
   other tools by name, base64 blobs, URLs, unicode homoglyphs/hidden
   characters, sensitive-path references, coercive language). Zero cost.
   Only short-circuits the cascade on a confident **malicious** verdict —
   a confident **benign** verdict alone is not trusted (see the fix
   documented in `cascade.py`'s comments: "zero rules matched" is absence
   of evidence, not evidence of absence).
2. **Layer 2 — `layer2_similarity.py`**: embeds the description locally
   (`sentence-transformers`, `all-MiniLM-L6-v2`, no API key/cost) and
   scores it by cosine similarity against a known-attack corpus, backed by
   pgvector (HNSW, cosine) in production or an in-memory store for
   tests/small runs. Only reached if layer 1 didn't already short-circuit
   malicious, and — since the fix above — also runs before the cascade
   will accept a "benign" verdict from layer 1 alone.
3. **Layer 3 — `layer3_llm.py`**: Claude (`claude-opus-5`) structured-output
   classifier, reached only if layers 1–2 didn't resolve it. Its
   `evidence_span` field is verified programmatically as a literal
   substring of the input description (`span in description`); if it
   isn't, the verdict is rejected outright — never repaired — and counted
   as a layer-3 failure. This is the project's central design decision for
   this layer: an unfalsifiable "trust me" verdict is worse than no
   verdict.

**Invoked out of band, never on the request path.** `control/app/worker.py`
drains the `scan_queue` table the gateway writes, runs `Cascade.classify`
unchanged, and writes rows to `tool_verdicts`. It is also exercised by its
own test suite (`control/scanner/tests/`, `control/app/tests/`) and the
offline eval harness (`control/evals/run_eval.py`) against a labeled
corpus (`control/evals/corpus/`, provenance in
`control/evals/corpus/README.md`).

Layer 2's production index is seeded from the corpus's **train split only**,
via the same `control/evals/split.py` the eval harness uses — so the
published held-out quality numbers describe the classifier that is actually
running, not a differently-indexed one.

## Tool-poisoning admission

`gateway/internal/admission`, Go. Three pieces:

- **Discoverer** — on startup and every `refresh_interval`, calls
  `tools/list` against each upstream on the gateway's own behalf
  (SPEC-NOTES.md §1 prescribes exactly this: "once per upstream at
  startup/config-load, not per client request"), hashes every
  `(name, description, inputSchema)`, and replaces that namespace's catalog
  entries. Definitions that are new or whose hash changed are enqueued for
  scanning. **This is the rug-pull detector**, and `refresh_interval` is its
  detection latency.
- **Catalog** — the discovered tools, indexed by `{namespace}.{tool}`. It
  exists because a `tools/call` body carries no description at all
  (SPEC-NOTES.md §3): without an out-of-band catalog there is nothing to
  judge a call against.
- **Gate** — the request-path decision: catalog lookup, verdict lookup
  behind a bounded TTL cache, policy evaluation. No network call, no model
  call. Placed in `handleMCP` after the policy gate and before routing, so a
  denied call costs no routing work and the upstream is never contacted.
  Measured at ~0.2ms added p50 warm, ~0.3ms with the cache disabled — see
  [bench/results.md](bench/results.md#tool-poisoning-admission-overhead).

`tools/list` is **served** by the gateway rather than proxied: it carries no
`Mcp-Name`, so it has no namespace to route to, and no single upstream
knows the namespaced names clients use. The catalog already holds every
upstream's tools under `{namespace}.{tool}`, so the merged listing comes
from there, filtered by both the policy engine and the verdicts. That is
also the enforcement point that matters most — tool poisoning lands when a
model reads a description, so withholding beats blocking the later call.
Legacy `2025-11-25` upstreams are discovered through `translate.Pool`,
which owns their handshake and session.

Verdicts are keyed by `(namespace, tool_name, content_hash)` and rows are
never updated in place, so a tool's verdict history falls out of the schema
rather than needing to be recorded separately. The canonical form the hash
covers is specified identically in `gateway/internal/admission/hash.go` and
`control/app/hashing.py`, with shared golden vectors asserted from both
languages — the failure mode that contract prevents (verdicts filed under
keys the gateway never reads, so enforcement silently does nothing while
every dashboard looks healthy) is invisible to any single-language test.

`internal/admission` is the one place the data plane takes a non-stdlib
dependency beyond its existing set: `jackc/pgx` for the verdict store. The
alternative — an HTTP hop to the Python control plane on the request path —
would put a Python process's availability and latency in front of every
proxied call, which is what this whole design exists to avoid.

## Data Flow

**Native upstream (`2026-07-28`):**

```
client → POST /mcp → [header/body validation] → [namespace routing]
       → upstream (direct, pooled client) → response → client
```

**Legacy upstream (`2025-11-25`):**

```
client → POST /mcp → [header/body validation] → [namespace routing]
       → [translate.Pool: lease a handshaken session, health-check it]
       → upstream (with Mcp-Session-Id the client never saw)
       → response → [release session back to pool] → client
```

In both cases the client-facing contract is identical and stateless; only
what happens between routing and the upstream response differs.

## Deployment

No production deployment story yet — this section describes what actually
exists, not a target architecture.

- `docker-compose.yml` (repo root): a local dev stack — `postgres`
  (`pgvector/pgvector:pg16`) and `redis`. Postgres is now exercised: it
  holds the admission schema (`control/migrations/001_admission.sql`) that
  joins the two halves. Layer 2's `PgVectorStore`
  (`control/scanner/layer2_similarity.py`) is real, working code for a
  pgvector-backed attack index, but every eval run so far
  (`control/evals/run_eval.py`) has used its in-memory store instead —
  `PgVectorStore`/`connect()` have no test coverage and have never been
  run against this Postgres container. Redis has no consumer at all yet.
  Both are provisioned ahead of need. Host ports are remapped (`15432`,
  `16379`) to avoid clashing with services a dev machine may already be
  running.
- A separate, non-default `bench` Compose profile
  (`docker compose --profile bench up`, or `bench/run_bench.sh`, which
  drives it) stands up a native upstream, a legacy upstream, one solo
  gateway instance, three gateway instances behind an nginx round-robin
  (no sticky sessions — see the statelessness note above), all with
  explicit per-container CPU limits so the benchmark's own measurements
  aren't confounded by host resource contention. See
  [bench/results.md](bench/results.md) for what it measured and its
  documented limitations on an 8-core test machine.
- No Kubernetes/Helm/systemd/CI-deploy config exists yet, and no image
  registry publishing.
