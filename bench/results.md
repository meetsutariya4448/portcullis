# Portcullis gateway overhead benchmark

> **These numbers are machine-specific.** They reflect this exact host's
> CPU, memory, kernel, and Docker networking stack. Each scenario is the
> median of 3 warmed-up repetitions (min–max spread reported
> alongside), not a single run -- but still one machine, one point in
> time. Do not treat these as portable performance claims — re-run this
> script on your own target hardware before relying on them.

Generated: 2026-08-25T04:25:51Z

## Milestone 1 (resilience core) note

This run measures the gateway **after** Milestone 1 added retries, native
bulkhead isolation, an improved circuit breaker (native + legacy), graceful
shutdown, and backpressure — all of which add some per-request bookkeeping
(a semaphore acquire/release, breaker Allow/Record, a retry.Do wrapper) even
on the successful, non-retried, non-saturated path. The added-latency
numbers below reflect that real cost.

**Read the baseline column with extra caution on this run specifically.**
Docker Desktop had just been freshly restarted immediately before this
benchmark ran, and was given only ~10–50s to report ready before the
build+bench started — the VM was likely not fully warmed up. That shows up
as baseline noise that has nothing to do with Portcullis: native
direct-to-upstream p50 came in at 6.30ms here, versus ~1.4–1.7ms in prior
(pre-Milestone-1) runs on the same host, even though the baseline path
never touches any gateway code Milestone 1 changed. The *added-latency*
deltas below are still the real, honestly-measured numbers from this run —
per the project's standing rule, they are not re-run or smoothed to look
better — but a controlled run on an already-warm Docker instance would be
a fairer read of Milestone 1's true steady-state overhead. That controlled
run, when done, will be recorded as an additional dated result below, not
a replacement for this one.

**3-instance scaling is explicitly excluded from this run's numbers**,
same as every prior run on this 8-core host: the CPU-contention check in
`bench/run_bench.sh` tripped for both upstreams (see the dropped rows in
Results and Added Latency below), so no 3-instance figure is reported —
not because it wasn't measured, but because what was measured was
contention on this machine, not Portcullis's own scaling behavior.

## Machine

| Field | Value |
|---|---|
| CPU | Apple M2 |
| Cores | 8 |
| RAM | 8.0 GB |
| OS | macOS 26.5 |

## Method

- Tool: [`hey`](https://github.com/rakyll/hey)
- 5000 requests, 50 concurrent, one `tools/call` per request
- Each scenario: a discarded 500-request warmup, then
  5000 requests, repeated 3 times. Reported figures are the
  MEDIAN of the 3 reps; the Results table also shows the min–max
  spread. A single run's p99 is dominated by outliers at this sample
  size -- median-of-3 is the stable signal, not a single-shot number.
- Every bench container (upstream-native, upstream-legacy, gateway-solo,
  gateway-a/b/c, nginx-bench) is CPU-limited to 1.0 core in
  docker-compose.yml. This host has 8 cores total; the
  3-gateway-instance scenario runs up to 5 of these containers
  concurrently (3 gateways + nginx + 1 upstream) alongside `hey` itself
  and Docker Desktop's own VM overhead, all on the same physical cores.
  Without an explicit limit, docker compose lets every container burst
  across all cores, which was masking true per-request overhead behind
  scheduler contention (a previous run of this script showed 3-instance
  throughput LOWER than 1-instance -- physically impossible for a
  correctly-scaling proxy, and the signature of CPU starvation, not
  architecture).
- Native upstream speaks 2026-07-28 directly; legacy upstream speaks
  2025-11-25 and is bridged through `gateway/internal/translate`'s
  session pool
- Same request body and MCP headers sent to every target, so only
  "is the gateway in the path" varies — except the legacy baseline,
  which must supply `Mcp-Session-Id` itself since a real 2025-11-25
  server requires one and a 2026-07-28 client has no concept of one to
  give it. That's the thing being measured, not an artifact.
- **3-instance scaling is only reported if it doesn't show contention.**
  If median throughput through 3 instances is lower than through 1
  instance, or median p50 is higher, that scenario's result is DROPPED
  from the tables below rather than reported as a scaling measurement --
  see the note where it would otherwise appear.

## Exact hey commands

```
# native-baseline
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/native-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ native.echo http://localhost:9101/mcp 

# native-1-instance
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/native-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ native.echo http://localhost:8081/mcp 

# native-3-instances
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/native-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ native.echo http://localhost:8090/mcp 

# legacy-baseline
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo -H Mcp-Session-Id:\ e7919c3a686a44bde14d8dd6d968e143 http://localhost:9102/mcp 

# legacy-1-instance
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo http://localhost:8081/mcp 

# legacy-3-instances
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo http://localhost:8090/mcp 

```

## Results

| Scenario | Target | p50 ms (min–max) | p95 (ms) | p99 ms (min–max) | req/s | Non-200 responses |
|---|---|---|---:|---|---:|---|
| direct to upstream (baseline) | native | 6.30 (4.00–6.90) | 31.60 | 47.60 (40.60–123.00) | 4317.3924 | none |
| through 1 gateway instance | native | 7.10 (4.30–7.60) | 54.30 | 149.00 (59.50–172.60) | 3034.5321 | none |
| through 3 gateway instances | native | *dropped -- CPU contention on this 8-core host, not a scaling measurement* | | | | |
| direct to upstream (baseline) | legacy | 1.80 (1.60–2.30) | 3.40 | 30.20 (14.60–45.10) | 21868.0410 | none |
| through 1 gateway instance | legacy | 7.70 (5.90–8.50) | 60.70 | 70.90 (68.10–133.80) | 3086.2027 | none |
| through 3 gateway instances | legacy | *dropped -- CPU contention on this 8-core host, not a scaling measurement* | | | | |

## Added latency (gateway − baseline, median of 3 reps)

| Upstream | Topology | Added p50 latency (ms) | Added p99 latency (ms) |
|---|---|---:|---:|
| native | 1 gateway instance | 0.80 | 101.40 |
| native | 3 gateway instances | *dropped -- CPU contention, not measurable on this hardware* | |
| legacy | 1 gateway instance | 5.90 | 40.70 |
| legacy | 3 gateway instances | *dropped -- CPU contention, not measurable on this hardware* | |

p50 is reported alongside p99 here deliberately: at 5000 requests,
p50 (median of the per-rep medians) is the stable signal, while p99 can
still be noisy even after median-of-3 averaging -- see the spread
columns in Results above.

**Multi-instance scaling is not measurable on this 8-core host.**
Single-gateway-instance overhead above is real and was measured cleanly;
the 3-instance topology on this machine hits CPU contention (3 gateways
+ nginx + upstreams + `hey` + Docker Desktop overhead competing for
8 physical cores) before it demonstrates anything about
Portcullis's own scaling behavior. Re-run on a host with more cores (or
one dedicated to this benchmark, with `hey` running from a separate
machine) to get a real multi-instance measurement. Raw per-rep data for
the dropped scenario(s) is still saved under `bench/.raw/` if you want
to inspect it anyway -- it's just not reported as a scaling result.

**These numbers are machine-specific.** Re-run on your own hardware before drawing conclusions.

---

## Milestone 6 (concurrency sweep, resource usage, circuit-breaker timing)

Generated: 2026-08-26T03:51:01Z

This section is **appended**, not a replacement for the Milestone 1
section above (same standing rule: a new, honestly-caveated run gets
recorded as a new section, not used to quietly overwrite an older one).
It answers the parts of the original benchmark ask the Milestone 1 run
didn't cover: concurrency scaling (1/10/100/500/1000), gateway memory/CPU
under load, legacy session reuse rate, and live circuit-breaker
recovery timing. Machine is the same 8-core Apple M2 as above, this
time on an already-warmed Docker Desktop instance (no cold-VM caveat).

Produced by two new scripts, `bench/run_concurrency_sweep.sh` and
`bench/run_chaos_bench.sh` (both reuse `bench/lib.sh`, extracted from
`run_bench.sh` in this same pass so the three scripts share one copy of
the median/hey-parsing logic instead of three that could drift). Raw
per-level data is under `bench/.raw/`, same transparency precedent as
the Milestone 1 section.

**Methodology difference from Milestone 1's run:** each concurrency
level runs for a fixed 10s **duration** (`hey -z`) rather than a fixed
request count -- this keeps total sweep wall-clock cost predictable
regardless of how many requests a given concurrency level manages to
complete (a fixed compute-time budget per data point), 2 reps per level,
median reported. Only the 1-gateway-instance topology is swept, not the
3-instance/nginx cluster -- that topology already showed CPU contention
in the Milestone 1 run at a single concurrency point (50), and adding a
concurrency sweep on top of a topology already known to be
contention-bound on this host wouldn't produce a meaningful result.

**One real bug found and fixed while building this**: the first sweep
run reported "n/a" for every memory/CPU sample -- `docker stats` was
being pointed at a literal `gateway-solo` container name, but Compose
(no `container_name:` override in `docker-compose.yml`) actually names
it `portcullis-gateway-solo-1`. Fixed by resolving the real container ID
via `docker compose ps -q gateway-solo` instead of guessing the name,
verified against a live container, then the full sweep was re-run. The
first (broken) run's numbers were discarded entirely, not partially
reused -- this section reflects only the corrected run.

### Concurrency sweep

<!-- sweep table below is bench/.raw/concurrency-sweep.md, generated verbatim -->

| Concurrency | Target | p50 (ms) | p95 (ms) | req/s | Non-200 | gateway-solo mem / cpu |
|---:|---|---:|---:|---:|---|---|
| 1 | native baseline | 0.15 | 0.30 | 6049.56 | none | n/a |
| 1 | native via gateway | 0.30 | 0.45 | 2918.38 | none | 9.73MiB / 3.826GiB 49.85%; 10.3MiB / 3.826GiB 51.51% |
| 1 | legacy baseline | 0.20 | 0.20 | 6409.05 | none | n/a |
| 1 | legacy via gateway | 0.40 | 0.50 | 2296.88 | none | 10.16MiB / 3.826GiB 63.63%; 10.52MiB / 3.826GiB 62.91% |
| 10 | native baseline | 0.40 | 0.60 | 23185.9 | none | n/a |
| 10 | native via gateway | 0.70 | 1.30 | 8781.77 | none | 12.9MiB / 3.826GiB 108.75%; 12.77MiB / 3.826GiB 107.59% |
| 10 | legacy baseline | 0.40 | 0.60 | 22135.2 | none | n/a |
| 10 | legacy via gateway | 0.85 | 1.60 | 6833.65 | none | 13.43MiB / 3.826GiB 106.77%; 13.31MiB / 3.826GiB 108.57% |
| 100 | native baseline | 2.60 | 4.50 | 30967.7 | none | n/a |
| 100 | native via gateway | 11.50 | 141.25 | 3488.71 | none | 30.3MiB / 3.826GiB 104.78%; 33.46MiB / 3.826GiB 105.95% |
| 100 | legacy baseline | 2.55 | 5.30 | 27453.2 | none | n/a |
| 100 | legacy via gateway | 6.80 | 62.85 | 6406.71 | [503] 258 responses [503] 294 responses | 31.46MiB / 3.826GiB 104.64%; 32.4MiB / 3.826GiB 104.83% |
| 500 | native baseline | 13.30 | 54.85 | 25178.7 | none | n/a |
| 500 | native via gateway | 245.50 | 988.50 | 2218.29 | none | 85.44MiB / 3.826GiB 107.58%; 96.83MiB / 3.826GiB 97.72% |
| 500 | legacy baseline | 14.05 | 56.55 | 23264.8 | none | n/a |
| 500 | legacy via gateway | 74.15 | 111.90 | 7579.03 | [503] 47960 responses [503] 48081 responses | 89.39MiB / 3.826GiB 103.72%; 98.86MiB / 3.826GiB 105.20% |
| 1000 | native baseline | 34.15 | 81.95 | 21588.4 | none | n/a |
| 1000 | native via gateway | 839.40 | 1903.05 | 1831.66 | none | 153.8MiB / 3.826GiB 104.30%; 158.9MiB / 3.826GiB 100.38% |
| 1000 | legacy baseline | 43.75 | 89.90 | 20027.4 | none | n/a |
| 1000 | legacy via gateway | 99.75 | 196.25 | 9327.67 | [503] 80317 responses [503] 84183 responses | 146.7MiB / 3.826GiB 103.94%; 161.2MiB / 3.826GiB 102.98% |

`gateway-solo mem / cpu` is one raw `docker stats --no-stream` sample
per rep (2 per row), taken partway through that rep's 10s window --
"n/a" for baseline rows since those hit the upstream containers
directly, not the gateway. CPU% is relative to the 1.0-core limit
`docker-compose.yml` sets for every bench container (per the Milestone 1
section's own note), so ~100-108% means the gateway container is
essentially saturating its single allotted core at concurrency ≥10, not
that something is wrong.

**Two genuinely different backpressure mechanisms show up at high
concurrency, and the numbers reflect that honestly rather than being
smoothed over:**

- **Native path: queuing, not rejection.** No non-200 responses at any
  concurrency level, but p50/p95 both climb sharply past c=100 (839ms
  p50 at c=1000, vs. 34ms for the direct-upstream baseline at the same
  concurrency) — consistent with `MaxConcurrent`'s default bulkhead size
  (256, see `internal/config`'s `defaultMaxConcurrent`) being well below
  the swept concurrency levels: requests beyond 256 in flight queue for
  a bulkhead slot (blocking, bounded by the request's own context) rather
  than being turned away. This is the gateway absorbing load at the cost
  of latency, exactly as the bulkhead was designed to do — the bench
  config doesn't override `max_concurrent`, so this is out-of-the-box
  default behavior, not a tuned-for-the-demo number.
- **Legacy path: outright rejection.** Real `503` responses start
  appearing at c=100 (258-294 per 10s rep) and become the majority of
  traffic at c≥500 (~48-84k of each rep's completed requests) — the
  legacy session pool's `max_pool_size: 64` (set in
  `bench/configs/gateway.yaml` specifically for this benchmark's
  concurrency, per that file's own comment) is far below concurrency
  100+, so `ErrPoolExhausted` fires and the gateway fails fast with 503
  rather than queue. This is a deliberate, previously-documented design
  choice (`translate.Pool.Forward`'s doc comment: pool exhaustion is
  excluded from breaker accounting because it's a capacity signal about
  Portcullis's own bound, not the upstream's health) showing up exactly
  as designed under real load.

### Legacy session reuse

Sessions reused: 391,450. Sessions newly created: 64. **Reuse rate:
100.0%** (`portcullis_legacy_session_reused_total` /
`_created_total`, scraped from `gateway-solo`'s own `/metrics` before
and after the full sweep). The 64 created sessions are essentially the
pool filling up once at the very start of the run (`max_pool_size: 64`)
— every one of the following ~391k legacy-path forwards across the
entire sweep reused an already-established session rather than paying
the `initialize`/`notifications/initialized` handshake again.

### Circuit-breaker recovery timing (live, gateway-solo + upstream-native)

Measured against `bench/configs/gateway.yaml`'s real circuit-breaker
tuning (no `circuit_breaker:` block present, so this exercises
`internal/translate`'s documented defaults: 10s window, 5 min samples,
50% threshold, 5s cooldown), via an actual `docker compose stop`/`start`
on `upstream-native` — not a simulated failure. This is the live,
wall-clock-timed counterpart to `gateway/internal/server/chaos_test.go`
(Milestone 5), which proves the state machine transitions correctly
using short, test-only windows; this measures what that transition
actually costs in real time against real (default) production tuning.

| Phase | Wall-clock time |
|---|---:|
| Outage start → breaker opens (fast 503) | 1s |
| Upstream restarted → first successful response | 5s |
| **Total: outage start → fully recovered** | **6s** |

The breaker opened after just **2 client-facing requests** — faster
than the 5-sample minimum might suggest, because each client-facing
request that fails pre-connect is itself retried internally (this bench
config leaves `retry:` unset, so `internal/retry.DefaultConfig`'s 3
attempts apply), and **every retry attempt independently records a
breaker failure** (`forwardNative` calls `Breaker.Record(false)` on each
failed `Do()`, not once per client-facing request). 2 requests × up to 3
attempts each comfortably clears the 5-sample/50%-threshold bar within
the first second.

Recovery took 5s after the upstream came back — matching the configured
5s cooldown almost exactly (the small remainder is the polling interval
plus the half-open trial's own round trip). Full observed status
timeline:

```
t+0s  502  upstream request failed
t+1s  503  upstream circuit breaker is open
t+1s  503  upstream circuit breaker is open
t+1s  503  upstream circuit breaker is open
t+2s  503  upstream circuit breaker is open
t+2s  503  upstream circuit breaker is open
t+2s  503  upstream circuit breaker is open
t+3s  503  upstream circuit breaker is open
t+3s  503  upstream circuit breaker is open
t+4s  503  upstream circuit breaker is open
t+4s  503  upstream circuit breaker is open
t+5s  503  upstream circuit breaker is open
t+5s  503  upstream circuit breaker is open
t+5s  503  upstream circuit breaker is open
t+6s  503  upstream circuit breaker is open
t+6s  200  result: "echo"
```

This is the shape of graceful degradation a real client would
experience during an actual upstream outage: one slow failed attempt
(502, the request that triggers detection), then immediate, cheap 503s
for the full cooldown window (no wasted connection attempts against a
known-dead upstream), then a clean recovery the moment the upstream is
healthy again and the half-open trial succeeds. Full raw timeline (every
probe, with response bodies): `bench/.raw/chaos-timeline.log`.

### AI scanner (control plane) latency and cost

Already measured, sourced, and reported in full in
[`control/evals/REPORT.md`](../control/evals/REPORT.md) — not re-run
here, since doing so would mean fresh Anthropic API spend to reproduce
numbers that are already rigorous and honestly caveated (see that
report's own methodology/limitations section, including why it is
explicitly *not* a held-out test set). Headline figures, full cascade,
leave-one-out layer-2 indexing (139-row corpus, 101 benign / 38
malicious):

| | Value |
|---|---|
| Precision / Recall / F1 | 1.000 / 0.947 / 0.973 |
| End-to-end latency (p50 / p95) | 12.67ms / 22.77ms |
| Estimated cost per 1,000 tools scanned | $0.50 |
| LLM (layer 3) invocation rate | 2.9% (4/139 rows) |

See the linked report for the leave-one-seed-family-out comparison
(the closer proxy for generalization to a genuinely unfamiliar attack,
which scores lower — reported as a finding, not resolved away by
picking the more flattering number), per-layer breakdowns, and the full
methodology.

**These numbers are machine-specific.** Re-run on your own hardware before drawing conclusions.
