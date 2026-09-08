#!/usr/bin/env python3
"""Assemble corpus.jsonl from the three provenance-tracked sources:

  - harvest_samples.jsonl  (benign  - real tools/list results, see harvest_registry.py)
  - seeds.json             (malicious, derivation=original - see seeds.json's source_note per entry)
  - variants.jsonl         (malicious, derivation=variant_of:<seed_id> - see generate_variants.py)

Writes corpus.jsonl with exactly the fields: id, name, description,
input_schema, label, attack_class, source, derivation, split. Then prints
the final count by label, by attack_class, and by split side.

`split` is assigned by ../split.py -- a deterministic, group-wise
train/held-out assignment computed from row identity alone. It is written
into the corpus (rather than recomputed by each consumer) so that which
side a row landed on is auditable in git, and so the eval harness and the
control-plane worker cannot drift into disagreeing about it.
"""

import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
OUT_PATH = HERE / "corpus.jsonl"

sys.path.insert(0, str(HERE.parent))

import split as split_module  # noqa: E402  (needs the sys.path line above)


def load_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    benign_raw = load_jsonl(HERE / "harvest_samples.jsonl")
    seeds = json.loads((HERE / "seeds.json").read_text())
    variants = load_jsonl(HERE / "variants.jsonl")

    rows = []

    for i, s in enumerate(benign_raw, start=1):
        rows.append(
            {
                "id": f"benign-{i:04d}",
                "name": s["tool_name"],
                "description": s["tool_description"],
                "input_schema": s.get("input_schema", {}),
                "label": "benign",
                "attack_class": None,
                "source": s["remote_url"],
                "derivation": "original",
            }
        )

    for s in seeds:
        rows.append(
            {
                "id": s["id"],
                "name": s["name"],
                "description": s["description"],
                "input_schema": s["input_schema"],
                "label": "malicious",
                "attack_class": s["attack_class"],
                "source": s["source"],
                "derivation": "original",
            }
        )

    for v in variants:
        rows.append(
            {
                "id": v["variant_id"],
                "name": v["name"],
                "description": v["description"],
                "input_schema": v["input_schema"],
                "label": "malicious",
                "attack_class": v["attack_class"],
                "source": v["source"],
                "derivation": f"variant_of:{v['id']}",
            }
        )

    # Assigned after every row exists, since the split is computed over
    # whole groups (seed families / source hosts) rather than row by row.
    assignment = split_module.assign(rows)
    for r in rows:
        r["split"] = assignment[r["id"]]

    with open(OUT_PATH, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")

    label_counts = Counter(r["label"] for r in rows)
    class_counts = Counter(r["attack_class"] for r in rows if r["attack_class"])
    derivation_counts = Counter(
        "original" if r["derivation"] == "original" else "variant" for r in rows
    )

    print(f"Wrote {len(rows)} rows to {OUT_PATH}\n")
    print("By label:")
    for label, count in label_counts.items():
        print(f"  {label}: {count}")
    print("\nBy attack_class (malicious only):")
    for cls, count in sorted(class_counts.items()):
        print(f"  {cls}: {count}")
    print("\nBy derivation:")
    for kind, count in derivation_counts.items():
        print(f"  {kind}: {count}")

    print(f"\nBy split ({split_module.SPLIT_SPEC}):")
    print(split_module.summarize(rows))


if __name__ == "__main__":
    main()
