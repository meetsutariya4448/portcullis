# Portcullis

A stateless MCP gateway in Go that proxies between MCP clients and a fleet of MCP
servers, with protocol translation for legacy servers, tool-poisoning detection, and
policy enforcement.

## Two-language split

- `gateway/` (Go): the data plane. Every proxied MCP request passes through it, so it
  needs to be fast and low-overhead — Go's runtime and standard-library `net/http`
  fit that better than a scripting-language stack would.
- `control/` (Python): the control plane. Tool-poisoning scanning and eval work
  benefit from Python's ML/NLP ecosystem far more than they'd benefit from raw request
  latency, so it's kept out of the data plane entirely.

## Protocol details come from the spec, never from memory

The MCP `2026-07-28` revision postdates this assistant's training data and changed
core protocol mechanics (handshake removal, session removal, routing headers,
multi-round-trip requests, and more). Any claim about wire behavior must be sourced
from the fetched spec — see [SPEC-NOTES.md](SPEC-NOTES.md) — and never asserted from
recollection. If SPEC-NOTES.md doesn't cover a needed detail, fetch the relevant
`https://modelcontextprotocol.io/specification/2026-07-28/...` page before writing
code that depends on it.

## Commit convention

Small, scoped commits. Conventional Commits prefixes: `feat`, `fix`, `docs`, `chore`,
`refactor`, `test`.
