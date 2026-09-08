"""Tests for eval run identity.

The point of a fingerprint is that two numbers carrying the same one came
from the same setup, and two carrying different ones did not. Both halves
need to hold: a fingerprint that ignores a knob lets two configurations
collide, and one that folds in wall-clock time makes every run
incomparable with itself.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

import fingerprint


@pytest.fixture()
def corpus_file(tmp_path: Path) -> Path:
    path = tmp_path / "corpus.jsonl"
    path.write_text('{"id": "a"}\n{"id": "b"}\n')
    return path


def _build(corpus_file: Path, **overrides) -> fingerprint.RunConfig:
    kwargs = dict(
        corpus_path=corpus_file,
        corpus_rows=2,
        split_spec="v1:test",
        scored_split="held_out",
        model="claude-opus-5",
        embedder_model="all-MiniLM-L6-v2",
        layer2_threshold=0.85,
        layer1_short_circuit=0.85,
        layer2_short_circuit=0.92,
        limit=None,
        skip_llm=False,
    )
    kwargs.update(overrides)
    return fingerprint.build(**kwargs)


def test_same_configuration_yields_the_same_fingerprint(corpus_file):
    assert _build(corpus_file).fingerprint == _build(corpus_file).fingerprint


@pytest.mark.parametrize(
    "override",
    [
        {"model": "claude-sonnet-5"},
        {"layer2_threshold": 0.9},
        {"layer1_short_circuit": 0.7},
        {"layer2_short_circuit": 0.95},
        {"split_spec": "v2:test"},
        {"scored_split": "train"},
        {"embedder_model": "all-mpnet-base-v2"},
        {"limit": 10},
        {"skip_llm": True},
    ],
)
def test_every_knob_that_moves_a_number_changes_the_fingerprint(corpus_file, override):
    assert _build(corpus_file).fingerprint != _build(corpus_file, **override).fingerprint


def test_changing_the_corpus_changes_the_fingerprint(corpus_file, tmp_path):
    other = tmp_path / "other.jsonl"
    other.write_text('{"id": "a"}\n{"id": "c"}\n')
    assert _build(corpus_file).fingerprint != _build(other, corpus_rows=2).fingerprint


def test_corpus_content_change_is_detected_even_at_the_same_path(corpus_file):
    before = _build(corpus_file).fingerprint
    corpus_file.write_text('{"id": "a"}\n{"id": "MUTATED"}\n')
    assert _build(corpus_file).fingerprint != before


def test_partial_runs_are_flagged(corpus_file):
    assert not _build(corpus_file).is_partial
    assert _build(corpus_file, limit=5).is_partial
    assert _build(corpus_file, skip_llm=True).is_partial


def test_manifest_carries_the_fingerprint_and_partial_flag(corpus_file):
    config = _build(corpus_file, limit=3)
    manifest = config.manifest(started_at="2026-01-01T00:00:00+00:00", wall_elapsed_s=1.25)
    assert manifest["fingerprint"] == config.fingerprint
    assert manifest["partial"] is True
    assert manifest["config"]["model"] == "claude-opus-5"


def test_tracked_package_versions_are_recorded(corpus_file):
    packages = _build(corpus_file).packages
    assert set(fingerprint.TRACKED_PACKAGES) <= set(packages)


def test_written_artifacts_are_strict_json_with_no_nan(corpus_file, tmp_path):
    """NaN is not valid JSON. An undefined metric must serialize as null, or
    every strict parser downstream (Go's encoding/json included) fails."""
    config = _build(corpus_file)
    out = fingerprint.write_results(
        tmp_path / "results",
        config,
        manifest=config.manifest(started_at="t", wall_elapsed_s=0.0),
        metrics={"precision": float("nan"), "f1": float("inf"), "nested": {"recall": float("nan")},
                 "listed": [1.0, float("nan")], "ok": 0.5},
        rows=[{"id": "a", "similarity": float("nan")}],
    )

    metrics_text = (out / "metrics.json").read_text()
    assert "NaN" not in metrics_text and "Infinity" not in metrics_text

    metrics = json.loads(metrics_text)  # would raise on a bare NaN token
    assert metrics["precision"] is None
    assert metrics["f1"] is None
    assert metrics["nested"]["recall"] is None
    assert metrics["listed"] == [1.0, None]
    assert metrics["ok"] == 0.5

    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    assert rows[0]["similarity"] is None


def test_results_are_bucketed_by_fingerprint(corpus_file, tmp_path):
    """Different configurations must not overwrite each other's numbers."""
    results = tmp_path / "results"
    a = _build(corpus_file)
    b = _build(corpus_file, layer2_threshold=0.9)

    for config in (a, b):
        fingerprint.write_results(
            results, config,
            manifest=config.manifest(started_at="t", wall_elapsed_s=0.0),
            metrics={"recall": 1.0}, rows=[],
        )

    buckets = sorted(p.name for p in results.iterdir())
    assert buckets == sorted({a.fingerprint, b.fingerprint})
    assert len(buckets) == 2


def test_json_safe_leaves_ordinary_values_alone():
    payload = {"a": 1, "b": "two", "c": [3, {"d": 4.5}], "e": None, "f": True}
    assert fingerprint._json_safe(payload) == payload


def test_file_sha256_matches_hashlib(tmp_path):
    import hashlib

    path = tmp_path / "f.bin"
    path.write_bytes(b"portcullis" * 10_000)
    assert fingerprint.file_sha256(path) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_git_sha_never_raises():
    assert isinstance(fingerprint._git_sha(), str)


def test_fingerprint_is_stable_across_wall_clock(corpus_file):
    """started_at lives in the manifest, not the fingerprint: the same
    configuration run twice must land in the same bucket."""
    config = _build(corpus_file)
    m1 = config.manifest(started_at="2026-01-01T00:00:00+00:00", wall_elapsed_s=1.0)
    m2 = config.manifest(started_at="2026-06-01T00:00:00+00:00", wall_elapsed_s=999.0)
    assert m1["fingerprint"] == m2["fingerprint"]
    assert m1["started_at"] != m2["started_at"]


def test_undefined_metrics_really_do_produce_nan():
    """Guards the premise of the NaN test above: the harness genuinely emits
    NaN for an undefined metric, so the sanitizer is load-bearing rather
    than defensive. A layer that flags nothing has no defined precision --
    which is exactly what layer 2 does on the held-out split."""
    import run_eval

    rows = [
        {"id": "m1", "label": "malicious"},
        {"id": "b1", "label": "benign"},
    ]
    prf = run_eval.confusion_and_prf(rows, {"m1": False, "b1": False})
    assert prf.tp == 0 and prf.fp == 0
    assert math.isnan(prf.precision), "no positive predictions should leave precision undefined"
    assert math.isnan(prf.f1)
