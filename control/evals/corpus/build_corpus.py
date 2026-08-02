#!/usr/bin/env python3
"""Assemble corpus.jsonl from the three provenance-tracked sources:

  - harvest_samples.jsonl  (benign  - real tools/list results, see harvest_registry.py)
  - seeds.json             (malicious, derivation=original - see seeds.json's source_note per entry)
  - variants.jsonl         (malicious, derivation=variant_of:<seed_id> - see generate_variants.py)

Writes corpus.jsonl with exactly the fields: id, name, description,
input_schema, label, attack_class, source, derivation. Then prints the
final count by label and by attack_class.
"""

import json
from collections import Counter
from pathlib import Path

HERE = Path(__file__).parent
OUT_PATH = HERE / "corpus.jsonl"


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


if __name__ == "__main__":
    main()
