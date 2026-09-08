"""The scan queue and verdict store, as the worker sees them.

Split from the psycopg implementation so the worker's logic -- claim, hash-
verify, classify, record -- is testable without a database. `PostgresQueue`
in db.py is the real implementation; `InMemoryQueue` here backs the tests.

The gateway writes `scan_queue` and reads `tool_verdicts`; this module is
the mirror image. Neither process calls the other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True)
class ScanJob:
    """One tool definition awaiting a verdict."""

    namespace: str
    tool_name: str
    content_hash: str
    # The tool's own `name` field as the upstream advertised it, which is
    # what the classifier is shown -- not the gateway's namespaced form.
    tool_json_name: str
    description: str
    input_schema: dict
    # The exact bytes the gateway hashed. The worker re-hashes THESE rather
    # than re-deriving a canonical form from the parsed columns, so a
    # divergence between the two implementations surfaces as a refusal to
    # scan rather than as a verdict filed under a key nobody reads.
    canonical: str
    upstream_name: str = ""
    attempts: int = 0


@dataclass
class VerdictRow:
    """A verdict ready to be written."""

    namespace: str
    tool_name: str
    content_hash: str
    verdict: str
    upstream_name: str = ""
    attack_class: str | None = None
    confidence: float | None = None
    evidence_span: str | None = None
    produced_by: str | None = None
    scanner_fingerprint: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0


class ScanQueue(Protocol):
    def claim(self, limit: int = 1) -> list[ScanJob]:
        """Atomically claim up to `limit` pending jobs."""
        ...

    def complete(self, job: ScanJob, row: VerdictRow) -> None:
        """Record a verdict and mark the job done, atomically."""
        ...

    def fail(self, job: ScanJob, error: str, *, permanent: bool) -> None:
        """Release a job after a failure.

        `permanent` marks it failed for good; otherwise it returns to
        pending for another attempt.
        """
        ...


class InMemoryQueue:
    """Test double. Mirrors PostgresQueue's semantics, including the
    single-claim guarantee."""

    def __init__(self, jobs: list[ScanJob] | None = None):
        self.pending: list[ScanJob] = list(jobs or [])
        self.in_progress: list[ScanJob] = []
        self.verdicts: dict[tuple[str, str, str], VerdictRow] = {}
        self.failures: list[tuple[ScanJob, str, bool]] = []

    def claim(self, limit: int = 1) -> list[ScanJob]:
        claimed = self.pending[:limit]
        self.pending = self.pending[limit:]
        self.in_progress.extend(claimed)
        return claimed

    def complete(self, job: ScanJob, row: VerdictRow) -> None:
        self.verdicts[(row.namespace, row.tool_name, row.content_hash)] = row
        if job in self.in_progress:
            self.in_progress.remove(job)

    def fail(self, job: ScanJob, error: str, *, permanent: bool) -> None:
        self.failures.append((job, error, permanent))
        if job in self.in_progress:
            self.in_progress.remove(job)
        if not permanent:
            self.pending.append(job)
