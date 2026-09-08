-- Portcullis admission schema: the contract between the Go data plane and
-- the Python control plane.
--
-- The gateway only ever READS tool_verdicts and WRITES scan_queue and
-- decision_log. The worker only ever READS scan_queue and WRITES
-- tool_verdicts. Neither calls the other; this database is the whole
-- interface, which is what keeps a ~3s model call off a request path with a
-- sub-millisecond budget.
--
-- Apply with:
--   psql postgres://portcullis:portcullis@localhost:15432/portcullis \
--        -f control/migrations/001_admission.sql

BEGIN;

-- tool_verdicts: one row per (namespace, tool, exact definition).
--
-- Rows are INSERTed, never UPDATEd in place, so the set of rows sharing a
-- (namespace, tool_name) IS the version history of that tool's definitions.
-- A server that serves a benign description and later swaps in a poisoned
-- one produces a second row under a different content_hash; the first
-- verdict stays true about the text it was actually formed about, and
-- stops applying the moment the text changes. That is the whole rug-pull
-- defence, expressed as a primary key.
CREATE TABLE IF NOT EXISTS tool_verdicts (
    namespace           text        NOT NULL,
    tool_name           text        NOT NULL,
    -- sha256 over the canonical form defined in
    -- gateway/internal/admission/hash.go and control/app/hashing.py, with
    -- shared golden vectors in testdata/tool_hash_vectors.json.
    content_hash        text        NOT NULL,

    upstream_name       text        NOT NULL DEFAULT '',
    -- benign | malicious | uncertain | layer3_failure. Constrained so a
    -- worker bug cannot write a value the gateway would have to guess
    -- about; the gateway treats an unrecognized verdict as unknown rather
    -- than benign, but it should never have to.
    verdict             text        NOT NULL
        CHECK (verdict IN ('benign', 'malicious', 'uncertain', 'layer3_failure')),
    attack_class        text,
    confidence          real,
    -- The literal substring of the description that justified a malicious
    -- verdict, verified by layer3_llm.py as an exact substring. Stored so a
    -- denial is auditable against the text that earned it.
    evidence_span       text,
    produced_by         text,       -- layer1 | layer2 | layer3
    -- Ties this verdict to the eval run that characterized the scanner's
    -- quality (control/evals/results/<fingerprint>/), so "why was this
    -- denied" and "how good is that judgement" are answerable together.
    scanner_fingerprint text        NOT NULL DEFAULT '',
    input_tokens        integer     NOT NULL DEFAULT 0,
    output_tokens       integer     NOT NULL DEFAULT 0,
    latency_ms          integer     NOT NULL DEFAULT 0,
    scanned_at          timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (namespace, tool_name, content_hash)
);

-- The gateway's only read: exact-match on the full primary key, so the
-- primary key index already serves it. This index instead serves the
-- operator question "show me every definition this tool has ever served",
-- which is how a rug-pull is investigated after the fact.
CREATE INDEX IF NOT EXISTS tool_verdicts_history_idx
    ON tool_verdicts (namespace, tool_name, scanned_at DESC);

-- scan_queue: definitions the gateway has seen but has no verdict for.
--
-- The gateway enqueues on every discovery refresh and relies on the primary
-- key for idempotency, so re-offering the same definition is free.
CREATE TABLE IF NOT EXISTS scan_queue (
    namespace     text        NOT NULL,
    tool_name     text        NOT NULL,
    content_hash  text        NOT NULL,

    upstream_name text        NOT NULL DEFAULT '',
    tool_json_name text       NOT NULL,
    description   text        NOT NULL,
    input_schema  jsonb       NOT NULL DEFAULT '{}'::jsonb,
    -- The exact bytes the gateway hashed. The worker re-hashes THESE rather
    -- than re-deriving a canonical form from parsed columns, so the two
    -- implementations cannot drift into disagreeing about the key.
    canonical     text        NOT NULL,

    state         text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'in_progress', 'done', 'failed')),
    attempts      integer     NOT NULL DEFAULT 0,
    last_error    text,
    enqueued_at   timestamptz NOT NULL DEFAULT now(),
    claimed_at    timestamptz,

    PRIMARY KEY (namespace, tool_name, content_hash)
);

-- The worker's claim query: oldest pending first.
CREATE INDEX IF NOT EXISTS scan_queue_pending_idx
    ON scan_queue (state, enqueued_at)
    WHERE state IN ('pending', 'in_progress');

-- decision_log: every admission decision, allow and deny alike.
--
-- Written asynchronously by the gateway so an audit write can never add
-- latency to, or fail, a proxied request. Deliberately records the
-- content_hash and scanner_fingerprint on every row: without them a denial
-- is unfalsifiable after the upstream changes its description again.
CREATE TABLE IF NOT EXISTS decision_log (
    id                  bigserial   PRIMARY KEY,
    ts                  timestamptz NOT NULL DEFAULT now(),
    client_id           text        NOT NULL DEFAULT '',
    -- list | call
    enforcement_point   text        NOT NULL,
    namespace           text        NOT NULL,
    tool_name           text        NOT NULL,
    content_hash        text        NOT NULL DEFAULT '',
    -- allow | deny
    decision            text        NOT NULL CHECK (decision IN ('allow', 'deny')),
    -- Low-cardinality: benign | malicious | uncertain | scan_failed |
    -- unknown_hash | undiscovered | unavailable.
    reason              text        NOT NULL,
    verdict             text,
    attack_class        text,
    produced_by         text,
    scanner_fingerprint text        NOT NULL DEFAULT '',
    -- True when the decision used a cached verdict because the store was
    -- unreachable. Distinguishes "enforced" from "enforced on stale data".
    stale               boolean     NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS decision_log_ts_idx ON decision_log (ts DESC);
-- Supports the two questions an operator actually asks: "what did we block
-- recently" and "what happened to this specific tool".
CREATE INDEX IF NOT EXISTS decision_log_denials_idx
    ON decision_log (ts DESC) WHERE decision = 'deny';
CREATE INDEX IF NOT EXISTS decision_log_tool_idx
    ON decision_log (namespace, tool_name, ts DESC);

COMMIT;
