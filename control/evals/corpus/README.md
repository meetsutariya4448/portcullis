# Tool-poisoning detector corpus: provenance

`corpus.jsonl` is a labeled corpus for evaluating a tool-poisoning detector.
**139 rows**: 101 benign, 38 malicious. Every row is one MCP tool definition
(`name`, `description`, `input_schema`) with `label`, `attack_class`,
`source`, and `derivation`.

This document exists because the corpus is only useful if its provenance is
trustworthy: the recall/precision numbers a detector gets on this corpus are
meaningless if the same model that's being evaluated also wrote the attacks
it's being evaluated against. Every row below traces to something that
either (a) a live, real MCP server returned over the wire, or (b) a named,
dated, third-party security disclosure — never to this assistant's own idea
of what an attack "should" look like.

Reproduce the whole corpus with:

```
python3 harvest_registry.py --target 100 --out harvest_log.jsonl --samples-out harvest_samples.jsonl
python3 generate_variants.py
python3 build_corpus.py
```

---

## 1. Benign (101 rows, `derivation: original`)

**What they are:** real tool definitions (`name`, `description`,
`inputSchema`) pulled live from real MCP servers' own `tools/list` response,
via `harvest_registry.py`.

**Why it took a live client, not just the registry:** the public MCP
registry (`https://registry.modelcontextprotocol.io`) turned out to catalog
*servers*, not *tools* — confirmed by reading both its `ServerDetail` JSON
schema (no `tools` or `inputSchema` field) and its own OpenAPI spec
(`docs/reference/api/openapi.yaml`, six endpoints total, none returning
per-tool data; its own `description` field literally reads "metadata about
MCP servers"). So `harvest_registry.py`:

1. Pages `GET https://registry.modelcontextprotocol.io/v0.1/servers?version=latest`
   for the server list (pagination via `metadata.nextCursor`).
2. For each server with a `streamable-http` remote, speaks just enough MCP
   (`initialize` → `notifications/initialized` → `tools/list`) to pull its
   real, live tool definitions.
3. Takes up to 3 tools per server (`MAX_TOOLS_PER_SERVER`), so the 101
   samples span many servers rather than being dominated by one large one.

**Attrition (documented, not hidden):** 179 servers were looked at to reach
101 samples from 36 servers:

| Outcome | Count |
|---|---:|
| `ok` (yielded tools) | 36 |
| `skipped_no_streamable_http_remote` | 45 |
| `error:initialize` — `403 Forbidden` | 48 |
| `error:initialize` — `401 Unauthorized` | 41 |
| `error:initialize` — DNS failure | 7 |
| `error:initialize` — other (bad redirect, malformed URL) | 2 |

The dominant failure mode (401/403, 89 of 98 `initialize` errors) is real:
most hosted MCP servers in the registry require OAuth or an API key, which
this script deliberately doesn't attempt to obtain — it only harvests from
servers that answer an anonymous `initialize`. The full attempt log
(one JSON object per server, success or failure) is in
`harvest_log.jsonl`; the raw harvested samples before corpus assembly are in
`harvest_samples.jsonl`.

**Scope decisions, and why:**
- Only `streamable-http` remotes were attempted — not `stdio` packages
  (would mean executing arbitrary third-party code to harvest a
  description) and not `sse` remotes (the older dual-endpoint transport;
  not implemented here).
- `source` for each benign row is the server's own remote URL (where the
  `tools/list` response actually came from), not the registry listing URL —
  the registry only pointed at it.

---

## 2. Attack seeds (11 rows, `derivation: original`, in `seeds.json`)

**What they are:** MCP tool definitions reproduced from published
tool-poisoning disclosures — in most cases copied verbatim (including the
original authors' own typos) from the primary source's code or paper table,
not paraphrased or reimagined.

| id | attack_class | tool name | source |
|---|---|---|---|
| IJ-01 | instruction_injection | `add` | [Invariant Labs — mcp-injection-experiments, direct-poisoning.py](https://github.com/invariantlabs-ai/mcp-injection-experiments/blob/main/direct-poisoning.py) |
| IJ-02 | instruction_injection | `get_current_time` | [MCPTox (Wang et al., AAAI 2026), Table 1](https://arxiv.org/abs/2508.14925) |
| IJ-03 | instruction_injection | `security_check` | [MCPTox, Table 1 / Figure 2](https://arxiv.org/abs/2508.14925) |
| TS-01 | tool_shadowing | `add` (→ `send_email`) | [Invariant Labs — mcp-injection-experiments, shadowing.py](https://github.com/invariantlabs-ai/mcp-injection-experiments/blob/main/shadowing.py) |
| TS-02 | tool_shadowing | `daily_quote` (→ `transaction_processor`) | [Elastic Security Labs — MCP Tools: Attack Vectors and Defense Recommendations](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations) |
| CSR-01 | cross_server_reference | `get_fact_of_the_day` (→ `mcp_whatsapp send_message`) | [Invariant Labs — mcp-injection-experiments, whatsapp-takeover.py](https://github.com/invariantlabs-ai/mcp-injection-experiments/blob/main/whatsapp-takeover.py) |
| CSR-02 | cross_server_reference | `get_random_engineering_fact` (→ `create_issue`) | [stevengonsalvez/mcp-ethicalhacks, src/server.ts](https://github.com/stevengonsalvez/mcp-ethicalhacks/blob/main/src/server.ts) |
| EVP-01 | exfiltration_via_parameter | `format_python_code` | [Elastic Security Labs, same article as TS-02](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations) |
| EVP-02 | exfiltration_via_parameter | `get_filesystem_metadata` | [stevengonsalvez/mcp-ethicalhacks, src/server.ts](https://github.com/stevengonsalvez/mcp-ethicalhacks/blob/main/src/server.ts) |
| EVP-03 | exfiltration_via_parameter | `get_weather_forecast` | [stevengonsalvez/mcp-ethicalhacks, src/server.ts](https://github.com/stevengonsalvez/mcp-ethicalhacks/blob/main/src/server.ts) |
| EVP-04 | exfiltration_via_parameter | `send_email` | [MCPTox, Table 1](https://arxiv.org/abs/2508.14925) |

Full text, exact per-field provenance notes, and what was reproduced
verbatim vs. reasonably completed (e.g. a schema the source didn't publish
explicitly) are in `seeds.json`, one `source_note` per entry.

### Primary disclosure

[Invariant Labs, "MCP Security Notification: Tool Poisoning Attacks"](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
(Luca Beurer-Kellner & Marc Fischer, April 1, 2025) coined "Tool Poisoning
Attack" and is the origin of IJ-01, TS-01, and CSR-01, via the companion
repo above. Everything else traces to independent, later, published work
that documents the same phenomenon with its own examples.

### What was found but deliberately excluded, and why

Not every disclosed MCP attack fits a corpus that classifies on
`(name, description, input_schema)` alone — some published attacks are real
but live in a different layer of the protocol:

- **`postmark-mcp` npm supply-chain incident** (Sept 2025, real, widely
  reported — [Socket/Snyk writeup](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)):
  the malicious version silently BCC'd every sent email to an
  attacker address via one added line of **server-side implementation**
  code. Its tool description was an unmodified copy of the legitimate
  Postmark tool's description — nothing to reproduce at the description
  layer; including it would mean labeling a benign-looking description
  "malicious" with no textual signal a description-based detector could
  ever learn from.
- **`YassWorks/Malicious-MCP-Server`**: a real PoC, but its attack abuses
  MCP *sampling* (the server asks the client's LLM to run a
  server-supplied prompt at call time) — the payload lives in a
  dynamically-constructed sampling prompt, not in the tool's static
  `description`, again outside this corpus's schema.
- **GitHub MCP issue-injection case** (`ukend0464/pacman` issue #1, via
  [Invariant Labs' GitHub MCP disclosure](https://invariantlabs.ai/blog/mcp-github-vulnerability)):
  the injected instructions lived in the *content of a GitHub issue*
  returned by a tool call, not in any tool's own description — indirect
  prompt injection via tool *output*, a related but distinct attack surface
  from tool poisoning.

None of these were used as seeds. No `[NO SOURCE FOUND]` case arose for any
of the four requested attack classes — each had at least one (usually
several) independently published, reproducible example.

---

## 3. Variants (27 rows, `derivation: variant_of:<seed_id>`, via `generate_variants.py`)

**What they are:** mechanical, code-only transformations of the 11 seeds
above. No LLM was involved in generating variant text — `generate_variants.py`
does pure string/dict manipulation:

| Transform | What it does | Applies to |
|---|---|---|
| `rename_tool` | Swaps the tool's own `name` for a fixed synonym (e.g. `add` → `calculate_sum`); payload text untouched | All 11 seeds with a mapped synonym |
| `move_payload:start` / `move_payload:end` | Relocates the `<IMPORTANT>...</IMPORTANT>` block to the very start or very end of the description | The 6 seeds whose payload is cleanly tag-delimited (IJ-01, TS-01, TS-02, CSR-01, CSR-02, EVP-02) |
| `move_payload:inside_param:<name>` | Moves the payload out of the top-level description and into one input parameter's own `description` field | Same 6 seeds |
| `swap_target` | Substring-replaces the *named target tool* being manipulated (e.g. `send_email` → `wire_transfer`, `transaction_processor` → `payment_gateway`) | The 4 seeds that name a specific target tool (TS-01, TS-02, CSR-01, CSR-02) |
| `rename_tool+swap_target` | Both of the above composed | Same 4 seeds |

Seeds without a tag-delimited payload (IJ-02, IJ-03, EVP-01, EVP-03, EVP-04
— each is one inseparable poisoned sentence in the source) only produce a
`rename_tool` variant; there's no well-defined "payload" substring to
relocate without inventing a split point the source doesn't have.

Every variant keeps its parent seed's `attack_class`, `label: malicious`,
and `source` (it's a reshaping of the same disclosed pattern, not a new
disclosure) and sets `derivation: variant_of:<seed_id>`.

---

## Final counts

```
$ python3 build_corpus.py
Wrote 139 rows to corpus.jsonl

By label:
  benign: 101
  malicious: 38

By attack_class (malicious only):
  cross_server_reference: 9
  exfiltration_via_parameter: 10
  instruction_injection: 6
  tool_shadowing: 13

By derivation:
  original: 112
  variant: 27
```

("original": 101 benign + 11 seeds = 112.)

## Known limitations

- 38 malicious rows from 11 distinct seeds is a small, real corpus, not a
  large one — the task's explicit provenance bar (verbatim-reproducible,
  cited disclosures only) is a harder constraint to hit at scale than
  generating synthetic attacks would be. Where the trade-off came up, this
  corpus chose fewer-but-real over more-but-invented.
- `attack_class` distribution across the 4 requested classes is uneven
  (6/13/9/10) because that's what was actually published and reproducible,
  not a designed balance. A detector eval using this corpus should account
  for that when comparing per-class recall.
- The benign set's `input_schema` reflects whatever each live server
  actually returned — some are minimal (`{}`, no parameters) and some are
  rich; this wasn't normalized, since normalizing it would mean editing
  real servers' real data.
