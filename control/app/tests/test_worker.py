"""Worker tests.

The behaviours asserted here are the ones that decide whether enforcement
actually works: a verdict must be written under the key the gateway reads,
and a failure must never be recorded as "benign".
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app import hashing
from app.queue import InMemoryQueue, ScanJob
from app.worker import Worker


@dataclass
class FakeLayer3Result:
    evidence_span: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0


@dataclass
class FakeVerdict:
    """Shaped like scanner.cascade.CascadeVerdict."""

    verdict: str
    attack_class: str | None = None
    confidence: float = 0.9
    produced_by: str = "layer1"
    layer3_result: FakeLayer3Result | None = None

    @property
    def layer3_tokens(self):
        if self.layer3_result is None:
            return None
        return {"input": self.layer3_result.input_tokens, "output": self.layer3_result.output_tokens}


class FakeCascade:
    def __init__(self, verdict=None, raises=None):
        self._verdict = verdict
        self._raises = raises
        self.calls = []

    def classify(self, name, description, input_schema):
        self.calls.append((name, description, input_schema))
        if self._raises is not None:
            raise self._raises
        return self._verdict


def job_for(name="summarize", description="Summarize the user's notes.", namespace="notes", attempts=0):
    schema = {"type": "object"}
    canonical = hashing.canonical_form(name, description, schema).decode()
    return ScanJob(
        namespace=namespace,
        tool_name=name,
        content_hash=hashing.hash_canonical(canonical.encode()),
        tool_json_name=name,
        description=description,
        input_schema=schema,
        canonical=canonical,
        upstream_name="notes-upstream",
        attempts=attempts,
    )


def test_a_scanned_job_writes_a_verdict_under_the_gateways_key():
    job = job_for()
    queue = InMemoryQueue([job])
    cascade = FakeCascade(FakeVerdict(verdict="malicious", attack_class="instruction_injection"))

    Worker(queue, cascade, scanner_fingerprint="6cdd4785936c4da9").run_once()

    key = (job.namespace, job.tool_name, job.content_hash)
    assert key in queue.verdicts, "verdict was not filed under the key the gateway reads"
    row = queue.verdicts[key]
    assert row.verdict == "malicious"
    assert row.attack_class == "instruction_injection"
    assert row.scanner_fingerprint == "6cdd4785936c4da9"
    assert not queue.pending and not queue.in_progress


def test_the_classifier_sees_the_tools_own_name_not_the_namespaced_one():
    job = job_for()
    cascade = FakeCascade(FakeVerdict(verdict="benign"))
    Worker(InMemoryQueue([job]), cascade).run_once()

    name, description, schema = cascade.calls[0]
    assert name == "summarize", "the classifier was shown the gateway's namespaced name"
    assert description == job.description
    assert schema == job.input_schema


def test_a_hash_mismatch_is_refused_permanently_and_never_scanned():
    """The cross-language tripwire. A verdict filed under the wrong key
    would leave enforcement silently doing nothing."""
    good = job_for()
    tampered = ScanJob(**{**good.__dict__, "content_hash": "0" * 64})
    queue = InMemoryQueue([tampered])
    cascade = FakeCascade(FakeVerdict(verdict="benign"))

    Worker(queue, cascade).run_once()

    assert not cascade.calls, "a job whose bytes do not match its key was scanned anyway"
    assert not queue.verdicts, "a verdict was written for a mismatched key"
    assert len(queue.failures) == 1
    _, error, permanent = queue.failures[0]
    assert permanent is True
    assert error.startswith("hash_mismatch:")
    assert not queue.pending, "a permanently-failed job was requeued"


def test_a_transient_failure_is_retried_rather_than_recorded():
    job = job_for(attempts=0)
    queue = InMemoryQueue([job])
    cascade = FakeCascade(raises=RuntimeError("connection reset"))

    Worker(queue, cascade, max_attempts=3).run_once()

    assert not queue.verdicts, "a retryable failure was recorded as a verdict"
    assert len(queue.pending) == 1, "the job was not returned to the queue"
    _, _, permanent = queue.failures[0]
    assert permanent is False


def test_an_exhausted_job_is_recorded_as_a_scan_failure_not_as_benign():
    """The single most important negative case: an outage must not read as
    a clean bill of health. The gateway denies layer3_failure by default."""
    job = job_for(attempts=2)
    queue = InMemoryQueue([job])
    cascade = FakeCascade(raises=RuntimeError("still broken"))

    Worker(queue, cascade, max_attempts=3).run_once()

    key = (job.namespace, job.tool_name, job.content_hash)
    assert key in queue.verdicts
    assert queue.verdicts[key].verdict == "layer3_failure"
    assert queue.verdicts[key].verdict != "benign"
    assert not queue.pending


def test_layer3_tokens_and_evidence_are_carried_onto_the_row():
    job = job_for()
    queue = InMemoryQueue([job])
    verdict = FakeVerdict(
        verdict="malicious",
        attack_class="exfiltration_via_parameter",
        produced_by="layer3",
        layer3_result=FakeLayer3Result(evidence_span="read ~/.ssh/id_rsa", input_tokens=1200, output_tokens=64),
    )

    Worker(queue, FakeCascade(verdict)).run_once()

    row = queue.verdicts[(job.namespace, job.tool_name, job.content_hash)]
    assert row.evidence_span == "read ~/.ssh/id_rsa"
    assert row.input_tokens == 1200
    assert row.output_tokens == 64
    assert row.produced_by == "layer3"
    assert row.latency_ms >= 0


def test_run_once_reports_an_empty_queue():
    assert Worker(InMemoryQueue([]), FakeCascade(FakeVerdict("benign"))).run_once() == 0


def test_a_batch_is_processed_in_one_pass():
    jobs = [job_for(name=f"tool{i}") for i in range(4)]
    queue = InMemoryQueue(jobs)
    worker = Worker(queue, FakeCascade(FakeVerdict(verdict="benign")))

    assert worker.run_once(batch=4) == 4
    assert len(queue.verdicts) == 4


@pytest.mark.parametrize("verdict", ["benign", "malicious", "uncertain", "layer3_failure"])
def test_every_cascade_verdict_value_round_trips(verdict):
    """All four values control/scanner/cascade.py can produce must survive
    to the row -- including layer3_failure, which the gateway has explicit
    behaviour for."""
    job = job_for()
    queue = InMemoryQueue([job])
    Worker(queue, FakeCascade(FakeVerdict(verdict=verdict))).run_once()
    assert queue.verdicts[(job.namespace, job.tool_name, job.content_hash)].verdict == verdict
