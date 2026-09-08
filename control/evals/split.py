"""Deterministic train / held-out assignment for the labeled corpus.

Why this exists
---------------
Before this module, `run_eval.py` had no held-out set at all, and its
layer-2 numbers mixed two different index configurations inside a single
precision/recall pair: malicious rows were scored against an index with
the row (or its whole seed family) excluded, while benign rows were scored
against the *full* index (`_build_layer2_cache`'s `full_layer2` branch).
Precision and recall therefore came from different setups, so neither the
F1 nor any comparison against another layer meant quite what it looked
like.

The fix is one index and one scored population: layer 2 indexes
**train-split malicious rows only**, and every reported number is computed
over **held-out rows only** -- benign and malicious alike, all of them
outside the index. `split` is a property of the corpus row, written into
`corpus.jsonl` by `build_corpus.py`, so which side a row landed on is
auditable in git rather than recomputed differently by each consumer.

How the split is chosen
-----------------------
Grouped, not row-wise. A row-wise split would scatter the 27 mechanical
variants of the 11 seeds across both sides, leaving a held-out variant's
near-identical parent sitting in the index -- exactly the near-duplicate
retrieval the existing leave-one-seed-family-out diagnostic was written to
expose. So:

  * malicious rows group by **seed family** (`seed_family_id`), stratified
    by `attack_class` so both sides carry all four classes;
  * benign rows group by **source server host**, so the same server's tools
    never straddle the split.

Within a stratum, groups are ordered by `sha256(group_key)` and taken into
the held-out side until it reaches `HELD_OUT_TARGET` of the stratum's rows,
always leaving at least one group on each side.

The ordering key is a hash of the group's own identifier and nothing else.
It does not depend on scores, on this corpus's contents, or on any run --
so the assignment was fixed before any number was computed and cannot be
re-rolled to flatter results. Changing `HELD_OUT_TARGET`, the grouping, or
the hash changes `SPLIT_SPEC`, which is folded into the eval's run
fingerprint; a report generated under a different split is therefore
identifiably a different configuration rather than silently comparable.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from urllib.parse import urlparse

# Fraction of a stratum's rows to place on the held-out side. 0.40 keeps
# enough malicious families in the index for layer 2 to have anything to
# retrieve at all, while leaving a held-out side large enough to report.
HELD_OUT_TARGET = 0.40

TRAIN = "train"
HELD_OUT = "held_out"

# Folded into the eval run fingerprint. Bump the version whenever the
# assignment rule changes, so two reports built under different rules can
# never be mistaken for the same configuration.
SPLIT_SPEC = f"v1:grouped:sha256:target={HELD_OUT_TARGET}"


def seed_family_id(row: dict) -> str:
    """The seed a malicious row belongs to: itself when it IS a seed
    (``derivation == "original"``), otherwise the seed named in
    ``variant_of:<seed_id>``.

    Duplicated deliberately from run_eval.py rather than imported: this
    module must stay importable by `build_corpus.py` and the control-plane
    worker without dragging in the eval harness's anthropic /
    sentence-transformers imports.
    """
    derivation = row.get("derivation", "original")
    if derivation.startswith("variant_of:"):
        return derivation.split(":", 1)[1]
    return row["id"]


def source_host(row: dict) -> str:
    """The server a benign row was harvested from. Benign rows carry the
    live remote URL in `source`; grouping by host keeps one server's tools
    together.
    """
    source = row.get("source") or ""
    netloc = urlparse(source).netloc
    return netloc or source or row["id"]


def group_key(row: dict) -> str:
    """The unit the split moves as a whole."""
    if row["label"] == "malicious":
        return f"family:{seed_family_id(row)}"
    return f"host:{source_host(row)}"


def stratum_key(row: dict) -> str:
    """The bucket within which `HELD_OUT_TARGET` is applied, so every attack
    class appears on both sides instead of a whole class landing on one.
    """
    if row["label"] == "malicious":
        return f"malicious:{row.get('attack_class')}"
    return "benign"


def _order_key(group: str) -> str:
    return hashlib.sha256(group.encode()).hexdigest()


def assign(rows: list[dict]) -> dict[str, str]:
    """Return ``{row_id: TRAIN | HELD_OUT}`` for every row.

    Pure and deterministic: the same corpus always yields the same
    assignment, on any machine, with no seed to record.
    """
    strata: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        strata[stratum_key(row)][group_key(row)].append(row)

    assignment: dict[str, str] = {}
    for _, groups in sorted(strata.items()):
        total_rows = sum(len(g) for g in groups.values())
        ordered = sorted(groups.items(), key=lambda kv: _order_key(kv[0]))

        held_out_rows = 0
        held_out_groups = 0
        for index, (_, group_rows) in enumerate(ordered):
            groups_left = len(ordered) - index
            # Always leave at least one group on the train side, and take at
            # least one group onto the held-out side.
            must_stop = groups_left <= 1 and held_out_groups > 0
            must_take = held_out_groups == 0
            take = must_take or (
                not must_stop and held_out_rows < HELD_OUT_TARGET * total_rows
            )

            side = HELD_OUT if take else TRAIN
            if take:
                held_out_rows += len(group_rows)
                held_out_groups += 1
            for row in group_rows:
                assignment[row["id"]] = side

    return assignment


def summarize(rows: list[dict]) -> str:
    """One-line-per-stratum summary, for build_corpus.py's stdout and the
    eval report's methodology section.
    """
    assignment = assign(rows)
    counts: dict[tuple[str, str], int] = defaultdict(int)
    groups: dict[tuple[str, str], set] = defaultdict(set)
    for row in rows:
        side = assignment[row["id"]]
        key = (stratum_key(row), side)
        counts[key] += 1
        groups[key].add(group_key(row))

    lines = []
    for stratum in sorted({stratum_key(r) for r in rows}):
        train_n = counts[(stratum, TRAIN)]
        held_n = counts[(stratum, HELD_OUT)]
        train_g = len(groups[(stratum, TRAIN)])
        held_g = len(groups[(stratum, HELD_OUT)])
        lines.append(
            f"  {stratum}: train {train_n} rows / {train_g} groups, "
            f"held_out {held_n} rows / {held_g} groups"
        )
    return "\n".join(lines)
