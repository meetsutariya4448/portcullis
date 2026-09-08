"""Tests for the deterministic train/held-out corpus split.

The properties asserted here are the ones the eval's single-configuration
claim rests on: if a seed family straddles the split, a held-out variant is
scored against an index still holding its near-identical parent, and the
"held-out" number quietly becomes a near-duplicate-retrieval number again.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

import split

CORPUS_PATH = Path(__file__).resolve().parent.parent / "corpus" / "corpus.jsonl"


@pytest.fixture(scope="module")
def corpus() -> list[dict]:
    with CORPUS_PATH.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def test_every_row_is_assigned_exactly_one_side(corpus):
    assignment = split.assign(corpus)
    assert len(assignment) == len(corpus)
    assert set(assignment.values()) <= {split.TRAIN, split.HELD_OUT}


def test_assignment_is_independent_of_row_order(corpus):
    """A split that depended on input ordering would silently change
    whenever build_corpus.py's source files were reordered."""
    assert split.assign(list(reversed(corpus))) == split.assign(corpus)


def test_assignment_is_stable_across_calls(corpus):
    assert split.assign(corpus) == split.assign(corpus)


def test_no_seed_family_straddles_the_split(corpus):
    """The property the whole design exists for: a variant and its parent
    seed must never end up on opposite sides."""
    assignment = split.assign(corpus)
    sides = defaultdict(set)
    for row in corpus:
        if row["label"] == "malicious":
            sides[split.seed_family_id(row)].add(assignment[row["id"]])
    straddling = {family for family, s in sides.items() if len(s) > 1}
    assert not straddling, f"seed families on both sides: {sorted(straddling)}"


def test_no_source_host_straddles_the_split(corpus):
    assignment = split.assign(corpus)
    sides = defaultdict(set)
    for row in corpus:
        if row["label"] == "benign":
            sides[split.source_host(row)].add(assignment[row["id"]])
    straddling = {host for host, s in sides.items() if len(s) > 1}
    assert not straddling, f"source hosts on both sides: {sorted(straddling)}"


def test_every_attack_class_appears_on_both_sides(corpus):
    """Stratification: a class landing entirely on one side would make its
    held-out recall either undefined or unmeasurable."""
    assignment = split.assign(corpus)
    per_class = defaultdict(set)
    for row in corpus:
        if row["label"] == "malicious":
            per_class[row["attack_class"]].add(assignment[row["id"]])
    assert per_class, "no malicious rows found"
    for attack_class, sides in sorted(per_class.items()):
        assert sides == {split.TRAIN, split.HELD_OUT}, (
            f"{attack_class} only appears on {sorted(sides)}"
        )


def test_both_sides_are_non_empty_for_every_stratum(corpus):
    assignment = split.assign(corpus)
    per_stratum = defaultdict(set)
    for row in corpus:
        per_stratum[split.stratum_key(row)].add(assignment[row["id"]])
    for stratum, sides in sorted(per_stratum.items()):
        assert sides == {split.TRAIN, split.HELD_OUT}, (
            f"stratum {stratum} only has {sorted(sides)}"
        )


def test_committed_corpus_matches_the_computed_split(corpus):
    """corpus.jsonl carries a `split` field so the assignment is auditable
    in git; this catches a corpus rebuilt under a different rule, or a
    hand-edited row."""
    assignment = split.assign(corpus)
    mismatched = [r["id"] for r in corpus if r.get("split") != assignment[r["id"]]]
    assert not mismatched, (
        f"{len(mismatched)} rows disagree with split.assign(); "
        f"re-run corpus/build_corpus.py. First few: {mismatched[:5]}"
    )


def test_held_out_side_is_a_meaningful_fraction(corpus):
    """Not an exact-count assertion -- that would just restate the current
    corpus. Guards against a rule change that collapses one side."""
    assignment = split.assign(corpus)
    held_out = sum(1 for v in assignment.values() if v == split.HELD_OUT)
    fraction = held_out / len(corpus)
    assert 0.2 <= fraction <= 0.6, f"held-out fraction {fraction:.2f} is out of range"


def test_split_spec_records_the_target():
    """SPLIT_SPEC is folded into the eval run fingerprint, so it must change
    whenever the assignment rule does."""
    assert str(split.HELD_OUT_TARGET) in split.SPLIT_SPEC


def test_seed_family_id_resolves_variants_to_their_parent():
    assert split.seed_family_id({"id": "TS-01", "derivation": "original"}) == "TS-01"
    assert split.seed_family_id({"id": "TS-01-V03", "derivation": "variant_of:TS-01"}) == "TS-01"


def test_source_host_groups_by_server_not_url_path():
    a = {"id": "x", "source": "https://example.com/api/mcp"}
    b = {"id": "y", "source": "https://example.com/other/endpoint"}
    assert split.source_host(a) == split.source_host(b) == "example.com"
