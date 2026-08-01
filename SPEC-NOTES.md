# SPEC-NOTES: MCP 2026-07-28, read for Portcullis

This is a working technical reading of the `2026-07-28` MCP specification revision, in
terms of what a stateless MCP gateway (Portcullis) has to do about it. It is grounded
in fetched primary sources: the [release-candidate announcement][rc-blog], the
[draft/2026-07-28 specification][spec-2026], its [changelog][changelog], the finalized
[SEP-2575][sep-2575] and [SEP-2567][sep-2567] proposal documents, and the individual
protocol pages linked below.

**Sourcing rule:** every factual claim carries an inline link to the fetched source it
came from. Anything not traceable to a fetched source is marked `[UNSOURCED]` rather
than filled in from memory. As of this writing there are **zero** `[UNSOURCED]`
markers in this document — see the Step 4 report in the session transcript for the
full list of fetched pages.

[rc-blog]: https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
[spec-2026]: https://modelcontextprotocol.io/specification/2026-07-28
[changelog]: https://modelcontextprotocol.io/specification/2026-07-28/changelog
[sep-2575]: https://modelcontextprotocol.io/seps/2575-stateless-mcp
[sep-2567]: https://modelcontextprotocol.io/seps/2567-sessionless-mcp
[sep-2260]: https://modelcontextprotocol.io/seps/2260-Require-Server-requests-to-be-associated-with-Client-requests

---

## 1. Handshake removal (SEP-2575)

The `initialize` / `notifications/initialized` handshake is gone. What it used to
negotiate in one stateful round trip — protocol version, `clientInfo`, and
`capabilities` — is now carried on **every single request**, in the request's
`_meta` object, under the `io.modelcontextprotocol/` prefix
([basic/index §General fields][basic-meta]):

| `_meta` key | Type | Required | Notes |
|---|---|---|---|
| `io.modelcontextprotocol/protocolVersion` | `string` | **Yes** | e.g. `"2026-07-28"` |
| `io.modelcontextprotocol/clientInfo` | `Implementation` | No (but clients SHOULD send it) | name/version, self-reported, not for security decisions |
| `io.modelcontextprotocol/clientCapabilities` | `ClientCapabilities` | **Yes** | empty object = no optional capabilities; servers MUST NOT infer capabilities from prior requests |
| `io.modelcontextprotocol/logLevel` | `LoggingLevel` | No | replaces `logging/setLevel` |

A request missing a required field is malformed: the server MUST reject it with
JSON-RPC `-32602` (Invalid params), HTTP `400 Bad Request`
([basic/index §_meta][basic-meta]). On HTTP transport, `protocolVersion` is *also*
mirrored into the `MCP-Protocol-Version` header, and the header value MUST match the
`_meta` value or the server MUST reject with `HeaderMismatch`
([streamable-http §Protocol Version Header][streamable-http]).

Servers reply with their own identity in `_meta.io.modelcontextprotocol/serverInfo`
on every result ([basic/index §_meta][basic-meta]).

**`server/discover`** is the new, optional-for-clients RPC. Servers MUST implement it;
clients MAY call it before any other request, but don't have to — any RPC can be
invoked cold, with `UnsupportedProtocolVersionError` (`-32022`) as the fallback signal
([server/discover][discover]). Its response bundles `supportedVersions`,
`capabilities`, `_meta.io.modelcontextprotocol/serverInfo`, and optional
`instructions`, and is itself cacheable (`ttlMs`/`cacheScope`) — see §4
([server/discover][discover]). It's useful for two things specifically:
presenting server identity/capabilities in one round trip instead of probing with
separate `tools/list`/`resources/list`/`prompts/list` calls, and as the
**stdio backward-compatibility probe** — stdio has no per-request HTTP status code to
drive fallback detection, so a dual-era client sends `server/discover` first and falls
back to `initialize` on any non-modern error ([server/discover §When to Call][discover];
[versioning §Backward Compatibility][versioning]).

**Gateway implication:** Portcullis must inject `protocolVersion` /
`clientCapabilities` / `clientInfo` into every outbound `_meta` (and the matching HTTP
header) on every proxied call — there's no connection-scoped place to set this once.
Because `server/discover` is optional and cacheable, Portcullis should call it once per
upstream at startup/config-load (not per client request) to learn upstream capabilities
and versions, then cache the result per its own `ttlMs`.

---

## 2. Session removal (SEP-2567)

`Mcp-Session-Id` previously bound five things to a connection's lifetime: negotiated
capabilities/version (now handled by §1), MRTR correlation state (now handled by §6),
application state (shopping-cart-style), mutable list endpoints, and resource
subscriptions ([SEP-2567 §Motivation][sep-2567]). SEP-2567's own motivation section is
blunt about why it was removed: sessions never converged on a consistent scope across
real clients — "ChatGPT creates a fresh session for every individual tool call... most
desktop and IDE clients create one at application launch... almost no clients resume a
prior session" — so server authors couldn't design against session lifetime as a
reliable primitive, and `tools/list` couldn't be cached across an unknowable session
boundary ([SEP-2567 §Problems with session scoping][sep-2567]).

The replacement is **not a protocol feature**: it's a documented tool-design pattern
called **explicit state handles**. A server exposes a `create_*` tool that returns an
opaque ID (e.g. `basket_id`); the model threads that ID through subsequent tool calls
as an ordinary argument. "There is no `handles/*` method, no handle type in the schema,
no wire-level concept of a handle at all" ([SEP-2567 §Specification][sep-2567]).
Consequently, list endpoints (`tools/list`, `resources/list`, `prompts/list`) are now
required to be **session-independent** — they may still vary by authenticated
principal or over time (deploys, plan changes), but not per-connection or as a side
effect of other calls on the same connection ([SEP-2567 §Session-independent list
endpoints][sep-2567]).

This is stated normatively (not just as SEP rationale) in the base protocol's
**Statelessness** section: "Servers MUST NOT rely on prior requests over the same
connection to establish context... State that needs to span multiple requests... MUST
be referenced by an explicit identifier the client passes on each request... an open
connection, such as a STDIO process, is not a conversation or session"
([basic/index §Statelessness][basic-meta]).

On the wire, a modern-only server simply doesn't have `Mcp-Session-Id` semantics: if it
receives one from a legacy client it MUST ignore it and must not mint or echo session
IDs ([streamable-http §Earlier Streamable HTTP Revisions][streamable-http]).

**Gateway implication:** Portcullis itself must hold no per-client-session state to
route or authorize a 2026-07-28↔2026-07-28 call — any instance can handle any request.
This is the property that makes "stateless gateway" true in the easy case. It gets much
harder the moment a *legacy* upstream is in the path — see the Translating section
below.

---

## 3. `Mcp-Method` / `Mcp-Name` routing headers (SEP-2243)

Streamable HTTP mirrors selected JSON-RPC body fields into headers so intermediaries
can route without parsing the body ([streamable-http §Request Metadata][streamable-http]):

| Header | Source field | Required for |
|---|---|---|
| `MCP-Protocol-Version` | `_meta.io.modelcontextprotocol/protocolVersion` | every POST |
| `Mcp-Method` | `method` | every request |
| `Mcp-Name` | `params.name` or `params.uri` | `tools/call`, `resources/read`, `prompts/get` |

These are REQUIRED for compliance. If a value can't be represented as plain ASCII
(non-ASCII, control chars, leading/trailing whitespace, or a literal match on the
sentinel pattern), it MUST be Base64-encoded as `=?base64?{...}?=`
([streamable-http §Value Encoding][streamable-http]).

**What a server MUST do on disagreement:** any server that processes the message body
MUST validate that header values (decoded, if Base64) match the corresponding body
values, and MUST reject on any mismatch — missing required header, value mismatch, or
invalid characters — with HTTP `400 Bad Request` and JSON-RPC error `-32020`
(`HeaderMismatch`) ([streamable-http §Server Validation][streamable-http]). Header
*names* are compared case-insensitively; header *values* are case-sensitive
([streamable-http §Case Sensitivity][streamable-http]). Intermediaries that route or
rate-limit on these mirrored headers SHOULD also check that `MCP-Protocol-Version`
indicates a version that actually requires header–body validation before trusting an
unvalidated header value ([streamable-http §Server Validation][streamable-http]).

There's also a third, optional header family: `Mcp-Param-{Name}`, populated from tool
parameters the server annotates with `x-mcp-header` in `inputSchema`. Servers MAY use
this; clients MUST support it if a tool definition requests it. Constraints are strict
— only primitive, statically-reachable schema properties, no arrays/composition/`$ref`
in the path, case-insensitively unique names ([streamable-http §Schema
Extension][streamable-http]).

**Gateway implication:** this is the header validation Portcullis's own spec explicitly
wants done *correctly*, not skipped like "most implementations." Concretely: derive
`Mcp-Method`/`Mcp-Name` from the parsed body server-side (don't trust client-sent
headers blindly if Portcullis is the enforcement point) or, if trusting the client's
headers for routing before parsing the body (the whole point of mirroring them),
validate them against the body immediately after parsing and reject with `-32020`
`400` on mismatch before forwarding upstream. Namespace-based routing (`{namespace}.{tool}`)
should key off the validated `Mcp-Name`/body value, never the raw header alone.

---

## 4. `ttlMs` / `cacheScope` on list and resource-read results (SEP-2549)

Servers MUST include caching hints on `resultType: "complete"` results from
`server/discover`, `tools/list`, `prompts/list`, `resources/list`,
`resources/templates/list`, and `resources/read`. Interim `input_required` results
carry no caching hints and results produced via an MRTR retry (carrying
`inputResponses`/`requestState`) MUST NOT be cached at all
([caching §Cacheable Results][caching], [caching §Cache Key][caching]).

- **`ttlMs`** (integer, ms): freshness hint, analogous to `Cache-Control: max-age`.
  `0` = immediately stale; positive = fresh for that long; **absent** → client
  SHOULD assume `0` and this "should only occur in older server versions"; **negative**
  → client SHOULD treat as `0`. Servers MUST provide a value `>= 0`
  ([caching §Time-to-Live][caching]).
- **`cacheScope`**: `"public"` (no user-specific data, any client/shared
  gateway/caching proxy MAY store and serve it to any user) or `"private"` (reusable
  only within the same authorization context — different access token ⇒ different
  cache) ([caching §Cache Scope Field][caching]).

TTL and `listChanged` push notifications are complementary, not exclusive — a relevant
notification invalidates a still-fresh cached response immediately
([caching §Interaction with Notifications][caching]). For paginated lists, each page
is independently cacheable with its own `ttlMs`, but `cacheScope` MUST be consistent
across all pages of one list request ([caching §Interaction with Pagination][caching]).

**Gateway implication:** if Portcullis does any response caching of its own (e.g. to
serve `tools/list` cheaply across many downstream clients), it must key strictly by
method+params (never by anything session-like, per §2), respect `cacheScope: "private"`
by partitioning the cache per auth context, and must never cache an MRTR-retry result.
Because `cacheScope: "public"` explicitly means safe-to-share-across-tokens
even from an authenticated endpoint, a gateway-level shared cache is spec-sanctioned
for `"public"` results — this is one of the cleanest places for Portcullis to add
value.

---

## 5. W3C Trace Context in `_meta` (SEP-414)

As an explicit exception to the normal `_meta` key-naming/prefix rule, three
unprefixed keys are reserved for distributed tracing:
**`traceparent`, `tracestate`, `baggage`** — [W3C Trace Context](https://www.w3.org/TR/trace-context/)
and [W3C Baggage](https://www.w3.org/TR/baggage/) formats respectively, "to maintain
compatibility with existing implementations and OpenTelemetry semantic conventions for
MCP" ([basic/index §_meta][basic-meta]). Example, verbatim from the spec:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "get_weather",
    "arguments": { "location": "New York" },
    "_meta": {
      "traceparent": "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
    }
  }
}
```

**Gateway implication:** Portcullis sits exactly where trace propagation matters most —
it's the fan-out point to a fleet of upstreams. It should read `traceparent`/`tracestate`/
`baggage` from inbound `params._meta`, start/continue an OTel span, and forward
(propagate, not regenerate) the same keys downstream, adding its own span as a child.
Since these are `params._meta` fields (request-scoped, not a header), this is body-level
plumbing, not HTTP-header plumbing — don't conflate it with the `Mcp-Method`/`Mcp-Name`
header mirroring in §3.

---

## 6. Multi-round-trip requests (SEP-2322)

MRTR replaces the old pattern of servers sending independent JSON-RPC *requests* to
clients mid-stream. Every result now carries a required `resultType`: `"complete"` for
an ordinary finished result, or `"input_required"` for an MRTR interim result
([basic/index §ResultType][basic-meta]). Servers MUST send `roots/list`,
`sampling/createMessage`, and `elicitation/create` *only* via this mechanism —
standalone server-initiated requests of these types are no longer supported at all
([mrtr §Note][mrtr]).

**Core types** ([mrtr §Core Types][mrtr]):
- **`InputRequests`**: map of server-assigned string key → request object
  (`ElicitRequest` / `CreateMessageRequest` / `ListRootsRequest`).
- **`InputResponses`**: map with the *same keys*, client's result for each
  (`ElicitResult` / `CreateMessageResult` / `ListRootsResult`).
- **`InputRequiredResult`**: `{ resultType: "input_required", inputRequests?, requestState? }`.
  `requestState` is an **opaque string, meaningful only to the server** — clients
  MUST NOT inspect, parse, modify, or assume anything about its contents
  ([mrtr §InputRequiredResult][mrtr]).

**Full round trip** ([mrtr §Basic Workflow][mrtr], diagram reproduced faithfully):

```
Client -> Server : tools/call (id: 1)
Server -> Client : InputRequiredResult (id: 1, inputRequests: {...}, requestState: "...")
                    [initial request now terminated]
Client            : gathers input from user (out of band)
Client -> Server : tools/call (id: 2, ORIGINAL params + inputResponses{...} + requestState echoed verbatim)
Server -> Client : Result (id: 2, final result, resultType: "complete")
```

Rules that make this work statelessly on the server side:
1. Only `prompts/get`, `resources/read`, `tools/call` may return `InputRequiredResult`
   ([mrtr §Supported Requests][mrtr]).
2. `requestState`, if it affects authz/resource access/business logic, MUST be
   integrity-protected (HMAC/AEAD) by the server and rejected on verification failure —
   it's attacker-controlled input once it round-trips through the client
   ([mrtr §Server Requirements][mrtr]). Servers SHOULD bind principal, a short TTL, and
   a digest of the originating request's method+params inside it to bound replay
   ([mrtr §Server Requirements][mrtr]).
3. The retry uses a **new** JSON-RPC `id` — id:1 and id:2 are independent requests
   ([mrtr §Client Requirements][mrtr]).
4. Servers MUST NOT include an `inputRequests` entry type the client hasn't declared
   capability support for ([mrtr §Server Requirements][mrtr]).
5. Servers MUST NOT assume the client ever retries at all ([mrtr §Server
   Requirements][mrtr]).

**Gateway implication:** this is the single biggest architectural fact for Portcullis.
An `InputRequiredResult` is a normal HTTP response body to a normal POST — nothing
about it requires Portcullis to hold the connection open or remember anything between
id:1 and id:2. The retry (id:2) is a brand-new, self-contained POST that can land on
*any* Portcullis instance and route to *any* upstream instance, as long as the upstream
itself minted a self-verifying `requestState`. Portcullis must simply pass
`inputRequests`/`requestState`/`inputResponses` through byte-for-byte without
inspecting or mutating `requestState` (per the client-side MUST NOT above, which a
transparent gateway should also honor) — and must never silently convert a
`"complete"` result to `"input_required"` or vice versa when doing protocol
translation for legacy upstreams (see the Translating section).

---

## 7. Server-initiated request restriction (SEP-2260)

`roots/list`, `sampling/createMessage`, `elicitation/create` MUST be associated with an
originating client-to-server request (nested inside `tools/call`/`resources/read`/
`prompts/get` processing); standalone server-initiated requests outside notifications
"MUST NOT be implemented" ([SEP-2260 §Abstract][sep-2260]). SEP-2260's own text
carves out an exception for `ping`, describing it as excepted from the restriction and
noting Streamable HTTP servers can use it to keep an SSE stream alive
([SEP-2260 §Motivation][sep-2260]) — **but** the finalized changelog for this same
revision states `ping` is removed entirely, in both directions, as part of SEP-2575
("Client-to-server ping is also removed because any normal RPC call already proves
server liveness, and transport-layer mechanisms... handle connection-health checks more
appropriately") ([changelog §Major changes, item 5][changelog]). SEP-2260 is preserved
as a historical record of the design "as accepted" and explicitly defers to "the
current specification and its changelog" for authoritative requirements
([SEP-2260 preservation note][sep-2260]) — so the changelog wins: **there is no `ping`
method in 2026-07-28 at all**, and the SEP-2260 ping exception is moot in the final
spec. (Flagged in the Step 4 report as a resolved cross-document discrepancy, not left
ambiguous here.)

Practically, this restriction is what makes §6's stateless MRTR pattern coherent: since
server-to-client "requests" are now embedded results rather than independent messages,
"restricting" them to be request-associated is close to automatic — the transport-level
enforcement is in `streamable-http.md`: "The server MUST NOT send independent JSON-RPC
requests on this stream. Server-to-client interactions... are embedded as input
requests inside an `InputRequiredResult`... not delivered as separate requests on this
or any other stream" ([streamable-http §Receiving Messages][streamable-http]).

**Gateway implication:** Portcullis should treat any legacy-style unsolicited
server→client JSON-RPC *request* arriving from an upstream (if bridging a legacy
server — see below) as something that must be translated into an `InputRequiredResult`
on a still-open client request, never forwarded as a raw request to a 2026-07-28
client, since modern clients have no code path to receive one at all.

---

## 8. JSON Schema 2020-12 for tools (SEP-2106)

MCP now uses JSON Schema with an explicit dialect model
([basic/index §JSON Schema Usage][basic-meta]):
- No `$schema` field → **defaults to 2020-12**.
- Explicit `$schema` → that dialect is used instead (draft-07 shown as the example).
- Implementations MUST support at least 2020-12.

**What's now allowed:** per the changelog, `inputSchema`/`outputSchema` are "loosened
to allow any JSON Schema 2020-12 keywords," and `structuredContent` now allows any JSON
value ([changelog §Minor changes, item 10][changelog]) — previously these were
constrained to a narrower subset.

**What's newly forbidden / bounded**, both introduced alongside the loosening as
security controls ([basic/index §JSON Schema Usage][basic-meta]):
- **`$ref` resolution:** 2020-12 permits `$ref` to an absolute URI, but implementations
  MUST NOT auto-dereference network URIs. An opt-in fetch mode MAY exist but MUST be
  off by default and, if enabled, SHOULD enforce a host allowlist, reject loopback/
  link-local/private addresses, and apply timeouts/size limits/logging. A schema that
  fails to validate due to an unresolved external `$ref` SHOULD be rejected, not treated
  as permissive.
- **Composition-keyword bounds:** `anyOf`/`oneOf`/`allOf`/`if`-`then`-`else`/`$defs`
  are expensive to validate; implementations SHOULD apply bounds (max depth, max
  subschema count, per-validation time budget) so a malicious schema can't DoS the
  validator.

**Gateway implication:** if Portcullis validates tool-call arguments against
`inputSchema` itself (e.g. for policy enforcement before forwarding), it must use a
2020-12-capable validator, must never auto-fetch remote `$ref`s, and must apply its own
complexity bounds independent of whatever the upstream server intended — a malicious or
compromised upstream tool definition is exactly the kind of "tool-poisoning" surface
Portcullis is meant to detect, and an unbounded schema is itself a poisoning vector
against the gateway's own validator, not just against the end client.

---

## 9. Deprecations: Roots, Sampling, Logging

All three are deprecated by **SEP-2577**, effective `2026-07-28`, under the new
[feature lifecycle policy](https://modelcontextprotocol.io/community/feature-lifecycle)
(itself from SEP-2596): "Deprecated" is a real lifecycle stage, not documentation-only —
features stay fully functional for **at least twelve months** before becoming eligible
for removal ("earliest removal: first revision released on or after 2027-07-28")
([deprecated §Deprecated table][deprecated]). These are explicitly **annotation-only**
deprecations: "the methods, types, and capability flags continue to work in this
release and in every specification version published within a year of it"
([rc-blog][rc-blog]).

| Feature | Migration path | Source |
|---|---|---|
| **Roots** | Pass directories/files via tool parameters, resource URIs, or server configuration | [client/roots §Deprecated warning][roots] |
| **Sampling** | Integrate directly with LLM provider APIs | [client/sampling §Deprecated warning][sampling] |
| **Logging** | `stderr` for stdio transports; [OpenTelemetry](https://opentelemetry.io/) for structured observability | [server/utilities/logging §Deprecated warning][logging] |

Two more items are worth noting even though not asked for explicitly: **Dynamic Client
Registration** (OAuth) is deprecated in favor of Client ID Metadata Documents, and the
**HTTP+SSE transport** (already deprecated since `2025-03-26`) is formally reclassified
"Deprecated" under the lifecycle policy, migrating to Streamable HTTP
([deprecated §Deprecated table][deprecated]).

**Gateway implication:** Portcullis's translation layer (§10) still has to *speak*
Roots/Sampling/Logging fluently on the legacy-upstream side — deprecation doesn't
remove them from `2025-11-25` servers, and the migration guidance ("integrate directly
with LLM provider APIs" for Sampling) is advice for *server authors*, not something a
proxy can retrofit on a legacy server's behalf. Portcullis should treat these as
long-lived translation targets (12+ months minimum), not code to skip writing.

---

## Translating 2026-07-28 clients to 2025-11-25 servers

This is the hard part, and the part Portcullis exists to do. Every point below is a
place the two protocol generations disagree; "Bridgeable" items are mechanical
translation, "Hard" items require the gateway to hold real state (in tension with its
own statelessness), and one item is flagged **effectively impossible** to bridge
without compromising either the client's stateless contract or correctness.

1. **Handshake.** [Bridgeable, requires a connection pool] A `2025-11-25` server
   expects `initialize`/`notifications/initialized` before anything else, scoped to a
   connection ([streamable-http §Earlier Streamable HTTP Revisions][streamable-http] —
   describes the legacy shape being replaced). A `2026-07-28` client never sends this.
   Portcullis must perform `initialize` against each legacy upstream itself — either
   lazily on first use per gateway instance, or via a warm pool of already-initialized
   connections — and never expose that handshake to the client. Because the legacy
   session this creates is tied to *a connection*, not to any individual client
   request, this is naturally a gateway-owned resource pool, not per-client-request
   state, so it doesn't reintroduce client-visible statefulness — but it does mean a
   Portcullis instance now owns live legacy sessions it must keep warm, health-check,
   and re-establish on failure.

2. **`Mcp-Session-Id`.** [Bridgeable, same pool as #1] The legacy server will mint one
   and expect it echoed on every subsequent call within that logical session
   ([streamable-http §Earlier Streamable HTTP Revisions][streamable-http]). Portcullis
   holds this inside the connection-pool entry from #1; it never reaches the modern
   client, which has no concept of it (§2).

3. **`resultType` absence.** [Bridgeable, explicitly spec-sanctioned] Legacy results
   have no `resultType` field at all. The spec directly instructs the modern side how
   to handle this: "For backward compatibility with servers implementing earlier
   protocol versions, which do not include `resultType`, clients MUST treat an absent
   `resultType` as `\"complete\"`" ([basic/index §ResultType][basic-meta]). Portcullis
   can pass a legacy result through unmodified and rely on this rule, or — better, since
   Portcullis is itself something a client trusts — inject `resultType: "complete"`
   explicitly so downstream clients that are stricter than the spec requires don't choke.

4. **Missing `ttlMs`/`cacheScope`.** [Bridgeable, lossy] Legacy list/read results carry
   neither field. Per §4's own fallback rule, an absent `ttlMs` means "assume 0,
   immediately stale" — the safe default. Portcullis can inject `ttlMs: 0,
   cacheScope: "private"` to stay spec-compliant without inventing freshness
   guarantees the legacy server never made. It *can* additionally use the legacy
   server's `notifications/*/list_changed` (which does exist pre-`2026-07-28`) as an
   invalidation signal for the gateway's own cache, but that's an optimization on top
   of the honest default, not a substitute for it.

5. **Legacy error code `-32002`.** [Bridgeable, spec-sanctioned] `2025-11-25` returns
   `-32002` for resource-not-found; `2026-07-28` uses `-32602`. The spec explicitly
   permits the modern side to accept the old code: "Clients SHOULD still accept `-32002`
   ... from servers implementing earlier versions" ([basic/index §Error Codes][basic-meta]).
   Portcullis can pass `-32002` through unchanged and remain compliant, though
   translating it to `-32602` for a stricter downstream client is also legitimate.

6. **`Mcp-Method`/`Mcp-Name`/`MCP-Protocol-Version` headers.** [Bridgeable, one-directional]
   These don't exist in `2025-11-25`. Portcullis validates/consumes them on the
   client-facing leg (§3) but must not send them to a legacy upstream, which has no
   concept of the `HeaderMismatch` error and no obligation to accept or ignore
   unrecognized headers gracefully in the way the modern spec mandates for
   forward-compatible intermediaries.

7. **Roots / Sampling / Logging as live legacy RPCs.** [Hard] `2025-11-25` servers send
   `roots/list`, `sampling/createMessage`, and `logging/setLevel`-configured
   `notifications/message` as genuine, independent, session-scoped JSON-RPC traffic —
   the exact pattern §7 says modern clients can no longer receive at all
   (`streamable-http §Receiving Messages`: "The server MUST NOT send independent
   JSON-RPC requests on this stream" — for `2026-07-28`; the legacy behavior being
   replaced is described in [SEP-2260 §Current Specification][sep-2260]). Portcullis
   must intercept every legacy server-initiated `roots/list`/`sampling/createMessage`
   and repackage it as an `InputRequiredResult.inputRequests` entry on whatever modern
   client request is in flight (§6) — this requires the gateway to *originate* MRTR
   semantics the legacy server knows nothing about, effectively acting as an MRTR
   server on the legacy server's behalf.

8. **`logging/setLevel` vs per-request `logLevel`.** [Hard] Modern clients set log
   level per-request in `_meta.io.modelcontextprotocol/logLevel`; legacy servers only
   understand a stateful `logging/setLevel` RPC scoped to the session
   ([logging §Deprecated warning][logging] describes the modern replacement; the RPC
   itself is what's being replaced). To honor a modern client's per-request log level
   against a legacy upstream, Portcullis must call `logging/setLevel` on the
   pooled legacy session before forwarding — meaning two client requests with
   *different* requested log levels sharing the same pooled legacy connection can
   race or bleed into each other. There's no clean per-request answer here as long as
   the legacy side is genuinely session-scoped for this feature; the practical fallback
   is one legacy connection per distinct (upstream, log-level) pair, shrinking pool
   reuse.

9. **MRTR round trip vs synchronous server-initiated request — the hard case.**
   [**Effectively impossible to bridge statelessly**] This is the one to flag loudest.
   A modern client's retry (id:2) is, by design, a brand-new, self-contained HTTP POST
   that can land on any Portcullis instance and carries no connection to the original
   request (id:1) except the `requestState` blob it echoes back (§6). But the legacy
   server on the other side sent `sampling/createMessage` (say) as a **synchronous
   request over a still-open connection/session**, and it is *blocking on that exact
   connection* waiting for a same-shaped JSON-RPC response before it will produce the
   final tool-call result. For Portcullis to satisfy the legacy server, it must:
   - keep that specific legacy connection open and the pending request alive between
     id:1 and id:2 (a real, unbounded-duration — MRTR explicitly warns human-in-the-loop
     delay can be unbounded, [mrtr §Security Considerations][mrtr] /
     [SEP-2260 §Timeout Considerations][sep-2260] — in-memory wait, tying up a legacy
     session for as long as the human takes to answer);
   - mint its *own* `requestState` (encrypted/HMAC'd per §6 rule 2) that, when echoed
     back on id:2, lets *whichever Portcullis instance receives the retry* find the
     right paused legacy connection and the right pending JSON-RPC id to answer;
   - and — this is the part that breaks statelessness rather than just complicating it —
     if id:2 lands on a *different* Portcullis instance than the one holding the paused
     legacy connection (exactly what a stateless round-robin LB in front of Portcullis
     is free to do, and exactly the deployment model §1/§2 are designed to enable), that
     instance has no way to reach the paused connection unless the pending-request table
     is itself shared across the fleet (e.g. in Redis/etcd, keyed by the `requestState`
     Portcullis minted) — at which point Portcullis has reintroduced exactly the shared
     mutable session state that `2026-07-28` was designed to eliminate, just one layer
     down, scoped to legacy-bridging traffic only. There is no version of this bridge
     that is both (a) stateless per Portcullis instance and (b) correct against a legacy
     server that blocks synchronously on a single connection. The realistic options are:
     sticky-route retries for legacy-bridged requests specifically (reintroducing the
     exact operational pain `2026-07-28` removed, but scoped only to legacy traffic),
     or accept a shared coordination store as a deliberate, scoped exception to
     Portcullis's statelessness claim.

[basic-meta]: https://modelcontextprotocol.io/specification/2026-07-28/basic/index
[streamable-http]: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
[mrtr]: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
[caching]: https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching
[discover]: https://modelcontextprotocol.io/specification/2026-07-28/server/discover
[versioning]: https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning
[deprecated]: https://modelcontextprotocol.io/specification/2026-07-28/deprecated
[roots]: https://modelcontextprotocol.io/specification/2026-07-28/client/roots
[sampling]: https://modelcontextprotocol.io/specification/2026-07-28/client/sampling
[logging]: https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/logging
