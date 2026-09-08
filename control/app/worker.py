"""The scanning worker: drains the scan queue, writes verdicts.

This is the half of the integration that costs money and time. It runs the
existing three-layer cascade (control/scanner/cascade.py) unchanged, out of
band, so a ~3s layer-3 call never lands on a request the gateway is holding
open. The gateway's side of the contract is a single indexed SELECT.

What this worker will not do
----------------------------
Write a verdict it cannot justify. Two refusals, both deliberate:

  * If the canonical bytes it was handed do not hash to the content_hash
    the row is keyed by, the job fails permanently instead of being scanned.
    A verdict filed under the wrong key is worse than no verdict: the
    gateway would never read it, so enforcement would silently do nothing
    while every dashboard showed scanning succeeding.
  * A transport failure is retried, then recorded as `layer3_failure` --
    never as `benign`. An outage is not a clean bill of health, and the
    gateway's default policy denies on that verdict.
"""

from __future__ import annotations

import logging
import time

from app import hashing
from app.queue import ScanJob, ScanQueue, VerdictRow

log = logging.getLogger("portcullis.worker")

# Attempts before a job is parked in `failed`. A parked job has no verdict,
# so the gateway keeps treating its tool as unknown -- withheld from
# listings, and allowed or denied on call per the configured policy. It
# never silently becomes benign.
DEFAULT_MAX_ATTEMPTS = 3


class Worker:
    def __init__(
        self,
        queue: ScanQueue,
        cascade,
        scanner_fingerprint: str = "",
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    ):
        self.queue = queue
        self.cascade = cascade
        self.scanner_fingerprint = scanner_fingerprint
        self.max_attempts = max_attempts

    def run_once(self, batch: int = 1) -> int:
        """Claim and process up to `batch` jobs. Returns how many were
        processed (successfully or not)."""
        jobs = self.queue.claim(limit=batch)
        for job in jobs:
            self.process(job)
        return len(jobs)

    def run_forever(self, poll_interval: float = 2.0, batch: int = 4) -> None:
        while True:
            try:
                if self.run_once(batch=batch) == 0:
                    time.sleep(poll_interval)
            except KeyboardInterrupt:
                return
            except Exception:  # noqa: BLE001 -- a worker must outlive one bad job
                log.exception("worker loop error; backing off")
                time.sleep(poll_interval)

    def process(self, job: ScanJob) -> None:
        if not self._hash_matches(job):
            # See the module docstring: refusing here is what stops the two
            # implementations drifting apart silently.
            recomputed = hashing.hash_canonical(job.canonical.encode())
            log.error(
                "refusing to scan %s.%s: canonical bytes hash to %s but the row is keyed by %s. "
                "The Go and Python hash implementations have diverged -- check "
                "testdata/tool_hash_vectors.json.",
                job.namespace, job.tool_name, recomputed, job.content_hash,
            )
            self.queue.fail(job, f"hash_mismatch:{recomputed}", permanent=True)
            return

        started = time.perf_counter()
        try:
            verdict = self.cascade.classify(job.tool_json_name, job.description, job.input_schema)
        except Exception as exc:  # noqa: BLE001
            permanent = job.attempts + 1 >= self.max_attempts
            log.warning(
                "scan failed for %s.%s (attempt %d/%d): %r",
                job.namespace, job.tool_name, job.attempts + 1, self.max_attempts, exc,
            )
            if permanent:
                # Out of attempts: record the non-answer explicitly rather
                # than leaving the row pending forever. `layer3_failure` is
                # denied by the gateway's default policy.
                self.queue.complete(job, self._row(job, verdict=None, latency_ms=self._ms(started)))
            else:
                self.queue.fail(job, repr(exc), permanent=False)
            return

        self.queue.complete(job, self._row(job, verdict=verdict, latency_ms=self._ms(started)))
        log.info(
            "scanned %s.%s -> %s (by %s, hash %s)",
            job.namespace, job.tool_name, verdict.verdict, verdict.produced_by, job.content_hash[:12],
        )

    def _hash_matches(self, job: ScanJob) -> bool:
        return hashing.hash_canonical(job.canonical.encode()) == job.content_hash

    @staticmethod
    def _ms(started: float) -> int:
        return int((time.perf_counter() - started) * 1000)

    def _row(self, job: ScanJob, verdict, latency_ms: int) -> VerdictRow:
        if verdict is None:
            return VerdictRow(
                namespace=job.namespace,
                tool_name=job.tool_name,
                content_hash=job.content_hash,
                upstream_name=job.upstream_name,
                verdict="layer3_failure",
                scanner_fingerprint=self.scanner_fingerprint,
                latency_ms=latency_ms,
            )

        tokens = verdict.layer3_tokens or {"input": 0, "output": 0}
        evidence = None
        if verdict.layer3_result is not None:
            evidence = verdict.layer3_result.evidence_span
        return VerdictRow(
            namespace=job.namespace,
            tool_name=job.tool_name,
            content_hash=job.content_hash,
            upstream_name=job.upstream_name,
            verdict=verdict.verdict,
            attack_class=verdict.attack_class,
            confidence=verdict.confidence,
            evidence_span=evidence,
            produced_by=verdict.produced_by,
            scanner_fingerprint=self.scanner_fingerprint,
            input_tokens=tokens["input"],
            output_tokens=tokens["output"],
            latency_ms=latency_ms,
        )
