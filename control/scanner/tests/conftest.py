"""Shared fixtures for scanner tests: real rows loaded from the labeled
corpus (control/evals/corpus/corpus.jsonl) rather than hand-written
examples, so layer tests exercise the same sourced/provenance-tracked data
the eval step will eventually score against.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest

CORPUS_PATH = Path(__file__).resolve().parent.parent.parent / "evals" / "corpus" / "corpus.jsonl"


@pytest.fixture(scope="session")
def corpus_rows() -> list[dict]:
    with CORPUS_PATH.open() as f:
        return [json.loads(line) for line in f if line.strip()]


@pytest.fixture(scope="session")
def benign_rows(corpus_rows: list[dict]) -> list[dict]:
    return [r for r in corpus_rows if r["label"] == "benign"]


@pytest.fixture(scope="session")
def malicious_rows(corpus_rows: list[dict]) -> list[dict]:
    return [r for r in corpus_rows if r["label"] == "malicious"]


@pytest.fixture(scope="session")
def malicious_by_class(malicious_rows: list[dict]) -> dict[str, list[dict]]:
    by_class = defaultdict(list)
    for row in malicious_rows:
        by_class[row["attack_class"]].append(row)
    return dict(by_class)


@pytest.fixture()
def instruction_injection_row(malicious_by_class: dict[str, list[dict]]) -> dict:
    """IJ-01: the canonical Invariant Labs 'add two numbers' poisoned-description
    sample — reads ~/.cursor/mcp.json and ~/.ssh/id_rsa.pub, tells the model not
    to mention it. Good single-row fixture for a description containing
    imperative, sensitive-path, and conceal-behavior signals at once.
    """
    return next(r for r in malicious_by_class["instruction_injection"] if r["id"] == "IJ-01")
