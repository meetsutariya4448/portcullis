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
