"""psycopg-backed scan queue and verdict store.

The real implementation of app.queue.ScanQueue. Schema lives in
control/migrations/001_admission.sql.
"""

from __future__ import annotations

import json
import os

import psycopg
from psycopg.rows import dict_row

from app.queue import ScanJob, VerdictRow

DEFAULT_DSN = os.environ.get(
    "PORTCULLIS_ADMISSION_DATABASE_URL",
    "postgres://portcullis:portcullis@localhost:15432/portcullis",
)


def connect(dsn: str | None = None) -> psycopg.Connection:
    return psycopg.connect(dsn or DEFAULT_DSN, row_factory=dict_row, autocommit=False)


# Claims jobs with FOR UPDATE SKIP LOCKED so several workers can drain the
# queue concurrently without ever handing the same definition to two of
# them -- duplicate scans are duplicate API spend, and this is the one
# place that would silently double it.
CLAIM_SQL = """
WITH claimed AS (
    SELECT namespace, tool_name, content_hash
      FROM scan_queue
     WHERE state = 'pending'
     ORDER BY enqueued_at
     LIMIT %s
     FOR UPDATE SKIP LOCKED
)
UPDATE scan_queue q
   SET state = 'in_progress', claimed_at = now(), attempts = q.attempts + 1
  FROM claimed c
 WHERE q.namespace = c.namespace
   AND q.tool_name = c.tool_name
   AND q.content_hash = c.content_hash
RETURNING q.namespace, q.tool_name, q.content_hash, q.upstream_name,
          q.tool_json_name, q.description, q.input_schema, q.canonical, q.attempts
"""

INSERT_VERDICT_SQL = """
INSERT INTO tool_verdicts (namespace, tool_name, content_hash, upstream_name,
                           verdict, attack_class, confidence, evidence_span,
                           produced_by, scanner_fingerprint,
                           input_tokens, output_tokens, latency_ms)
VALUES (%(namespace)s, %(tool_name)s, %(content_hash)s, %(upstream_name)s,
        %(verdict)s, %(attack_class)s, %(confidence)s, %(evidence_span)s,
        %(produced_by)s, %(scanner_fingerprint)s,
        %(input_tokens)s, %(output_tokens)s, %(latency_ms)s)
ON CONFLICT (namespace, tool_name, content_hash) DO UPDATE
   SET verdict = EXCLUDED.verdict,
       attack_class = EXCLUDED.attack_class,
       confidence = EXCLUDED.confidence,
       evidence_span = EXCLUDED.evidence_span,
       produced_by = EXCLUDED.produced_by,
       scanner_fingerprint = EXCLUDED.scanner_fingerprint,
       input_tokens = EXCLUDED.input_tokens,
       output_tokens = EXCLUDED.output_tokens,
       latency_ms = EXCLUDED.latency_ms,
       scanned_at = now()
"""


class PostgresQueue:
    def __init__(self, conn: psycopg.Connection):
        self.conn = conn

    def claim(self, limit: int = 1) -> list[ScanJob]:
        with self.conn.cursor() as cur:
            cur.execute(CLAIM_SQL, (limit,))
            rows = cur.fetchall()
        self.conn.commit()
        return [
            ScanJob(
                namespace=r["namespace"],
                tool_name=r["tool_name"],
                content_hash=r["content_hash"],
                tool_json_name=r["tool_json_name"],
                description=r["description"],
                input_schema=r["input_schema"] if isinstance(r["input_schema"], dict)
                else json.loads(r["input_schema"]),
                canonical=r["canonical"],
                upstream_name=r["upstream_name"],
                # attempts was already incremented by the claim, so this is
                # the number of attempts INCLUDING this one; the worker
                # compares `attempts + 1 >= max_attempts`, so subtract to
                # keep that arithmetic meaning what it says.
                attempts=max(r["attempts"] - 1, 0),
            )
            for r in rows
        ]

    def complete(self, job: ScanJob, row: VerdictRow) -> None:
        # One transaction: a verdict that landed while the queue row stayed
        # pending would be rescanned (wasted spend); a queue row marked done
        # with no verdict would leave the tool permanently unknown.
        with self.conn.cursor() as cur:
            cur.execute(INSERT_VERDICT_SQL, vars(row))
            cur.execute(
                "UPDATE scan_queue SET state = 'done', last_error = NULL "
                " WHERE namespace = %s AND tool_name = %s AND content_hash = %s",
                (job.namespace, job.tool_name, job.content_hash),
            )
        self.conn.commit()

    def fail(self, job: ScanJob, error: str, *, permanent: bool) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                "UPDATE scan_queue SET state = %s, last_error = %s "
                " WHERE namespace = %s AND tool_name = %s AND content_hash = %s",
                ("failed" if permanent else "pending", error[:2000],
                 job.namespace, job.tool_name, job.content_hash),
            )
        self.conn.commit()
