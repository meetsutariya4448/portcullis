# Portcullis gateway overhead benchmark

## Known measurement problems

This run has three known methodology problems that make the multi-instance
numbers below unusable, and make the raw p99 figures untrustworthy even for
the single-instance scenarios. They are documented here rather than quietly
fixed in place -- the numbers below are kept exactly as this run measured
them.

1. **Negative added p99 latency for native (-2.70ms) is impossible.** A
   proxy cannot be faster than a direct connection to the same upstream.
   The baseline p99 (21.90ms) is 13x its p50 (1.70ms) -- p99 here is being
   set by a handful of outlier requests, not by the actual per-request
   work being measured.
2. **Throughput drops from 1 to 3 gateway instances (13317.5683 ->
   6942.0770 req/s) and p50 rises (2.90ms -> 6.40ms).** 3 gateway
   instances + nginx + 2 upstreams + `hey` are all sharing one 8-core
   machine with no CPU limits set on any container. This measures CPU
   contention on this host, not Portcullis's ability to scale.
3. **No warmup, single run, no repeats.** Every figure below comes from
   one 5000-request run with no discarded warmup beforehand. There is no
   way to distinguish real signal from single-run noise at this sample
   size, particularly at p99.

**What to trust from this run:** only the single-instance p50 deltas --
native +1.20ms (2.90ms - 1.70ms), legacy +1.60ms (3.40ms - 1.80ms), read
directly off the Results table below. Everything else here -- any
3-instance number, any p99 figure, and the "Added latency" table's p99
column -- should be treated as unreliable, not as evidence about
Portcullis's real overhead or scaling behavior. Multi-instance scaling was
**not measurable** with this methodology on this hardware.

> **These numbers are machine-specific.** They reflect this exact host's
> CPU, memory, kernel, and Docker networking stack, run once, with no
> statistical repeats. Do not treat them as portable performance claims —
> re-run this script on your own target hardware before relying on them.

Generated: 2026-08-02T22:05:36Z

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
- Native upstream speaks 2026-07-28 directly; legacy upstream speaks
  2025-11-25 and is bridged through `gateway/internal/translate`'s
  session pool
- Same request body and MCP headers sent to every target, so only
  "is the gateway in the path" varies — except the legacy baseline,
  which must supply `Mcp-Session-Id` itself since a real 2025-11-25
  server requires one and a 2026-07-28 client has no concept of one to
  give it. That's the thing being measured, not an artifact.

## Exact hey commands

```
# native-baseline
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/native-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ native.echo http://localhost:9101/mcp 

# native-1-instance
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/native-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ native.echo http://localhost:8081/mcp 

# native-3-instances
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/native-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ native.echo http://localhost:8090/mcp 

# legacy-baseline
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo -H Mcp-Session-Id:\ ae968eb55d93c44fcaf7179f8503e48b http://localhost:9102/mcp 

# legacy-1-instance
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo http://localhost:8081/mcp 

# legacy-3-instances
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo http://localhost:8090/mcp 

```

## Results

| Scenario | Target | p50 (ms) | p95 (ms) | p99 (ms) | req/s | Non-200 responses |
|---|---|---:|---:|---:|---:|---|
| direct to upstream (baseline) | native | 1.70 | 3.40 | 21.90 | 23192.6006 | none |
| through 1 gateway instance | native | 2.90 | 7.80 | 19.20 | 13317.5683 | none |
| through 3 gateway instances | native | 6.40 | 13.10 | 20.60 | 6942.0770 | none |
| direct to upstream (baseline) | legacy | 1.80 | 4.90 | 10.00 | 22102.3335 | none |
| through 1 gateway instance | legacy | 3.40 | 7.70 | 15.20 | 12348.3367 | none |
| through 3 gateway instances | legacy | 6.90 | 14.10 | 19.30 | 6505.7075 | none |

## Added latency (gateway p99 − baseline p99)

| Upstream | Topology | Added p99 latency (ms) |
|---|---|---:|
| native | 1 gateway instance | -2.70 |
| native | 3 gateway instances | -1.30 |
| legacy | 1 gateway instance | 5.20 |
| legacy | 3 gateway instances | 9.30 |

**These numbers are machine-specific.** Re-run on your own hardware before drawing conclusions.
