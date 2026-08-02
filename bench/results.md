# Portcullis gateway overhead benchmark

> **These numbers are machine-specific.** They reflect this exact host's
> CPU, memory, kernel, and Docker networking stack, run once, with no
> statistical repeats. Do not treat them as portable performance claims —
> re-run this script on your own target hardware before relying on them.

Generated: 2026-08-02T21:10:08Z

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
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo -H Mcp-Session-Id:\ 9d89af4e67f3456fe80eea747ba53768 http://localhost:9102/mcp 

# legacy-1-instance
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo http://localhost:8081/mcp 

# legacy-3-instances
hey -n 5000 -c 50 -m POST -T application/json -D /Users/meetsutariya/Desktop/portcullis/bench/.raw/legacy-body.json -H MCP-Protocol-Version:\ 2026-07-28 -H Mcp-Method:\ tools/call -H Mcp-Name:\ legacy.echo http://localhost:8090/mcp 

```

## Results

| Scenario | Target | p50 (ms) | p95 (ms) | p99 (ms) | req/s | Non-200 responses |
|---|---|---:|---:|---:|---:|---|
| direct to upstream (baseline) | native | 2.10 | 10.70 | 31.60 | 13045.8974 | none |
| through 1 gateway instance | native | 3.80 | 15.80 | 55.70 | 8651.2699 | none |
| through 3 gateway instances | native | 6.90 | 26.80 | 78.20 | 4878.1571 | none |
| direct to upstream (baseline) | legacy | 2.00 | 5.30 | 16.20 | 19655.3597 | none |
| through 1 gateway instance | legacy | 4.00 | 12.00 | 36.20 | 9562.3824 | none |
| through 3 gateway instances | legacy | 7.30 | 19.10 | 38.50 | 5525.0847 | none |

## Added latency (gateway p99 − baseline p99)

| Upstream | Topology | Added p99 latency (ms) |
|---|---|---:|
| native | 1 gateway instance | 24.10 |
| native | 3 gateway instances | 46.60 |
| legacy | 1 gateway instance | 20.00 |
| legacy | 3 gateway instances | 22.30 |

**These numbers are machine-specific.** Re-run on your own hardware before drawing conclusions.
