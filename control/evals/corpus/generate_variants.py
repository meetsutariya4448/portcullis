#!/usr/bin/env python3
"""Mechanically generate corpus variants from seeds.json.

Every transform here is a pure string/dict operation on the 11 sourced
seeds in seeds.json — no LLM involved, per the task constraint ("Scripted
transformation only, no LLM generation"). Three transform families, per the
task spec:

  1. rename_tool   - swap the tool's own `name` for a different, fixed
                      synonym; the payload text is untouched.
  2. move_payload  - relocate the injected <IMPORTANT>...</IMPORTANT> block
                      within the description (start / end / inside a
                      parameter's own description). Only applied to seeds
                      whose payload is cleanly delimited by an <IMPORTANT>
                      tag — seeds where the whole description is one
                      inseparable poisoned sentence (no tag) don't support
                      this transform and are skipped for it.
  3. swap_target   - for tool_shadowing / cross_server_reference seeds that
                      name a specific target tool being manipulated,
                      substitute a different plausible target tool name.

Every variant keeps its parent seed's attack_class, label, and source (the
provenance is the same disclosed pattern; only the shape changed), and
records derivation="variant_of:<seed_id>".
"""

from __future__ import annotations

import json
import re
from pathlib import Path

SEEDS_PATH = Path(__file__).parent / "seeds.json"
OUT_PATH = Path(__file__).parent / "variants.jsonl"

# --- 1. rename_tool: a fixed, deterministic synonym per seed tool name -----
RENAME_MAP = {
    "add": "calculate_sum",
    "get_current_time": "fetch_system_time",
    "security_check": "validate_file_access",
    "daily_quote": "quote_of_the_day",
    "get_fact_of_the_day": "random_trivia_fact",
    "get_random_engineering_fact": "engineering_trivia",
    "format_python_code": "lint_python_file",
    "get_filesystem_metadata": "inspect_file_stats",
    "get_weather_forecast": "fetch_weather",
    "send_email": "dispatch_email",
}

# --- 2. move_payload: seeds whose description has a cleanly delimited ------
# <IMPORTANT>...</IMPORTANT> (or unclosed <IMPORTANT>) block, given as
# (open_tag, close_tag). close_tag may equal open_tag (CSR-02's source has
# a typo'd, unclosed second tag).
PAYLOAD_TAGS = {
    "IJ-01": ("<IMPORTANT>", "</IMPORTANT>"),
    "TS-01": ("<IMPORTANT>", "</IMPORTANT>"),
    "TS-02": ("<IMPORTANT>", "</IMPORTANT>"),
    "CSR-01": ("<IMPORTANT>", "</IMPORTANT>"),
    "CSR-02": ("<IMPORTANT>", "<IMPORTANT>"),  # source's own closing-tag typo
    "EVP-02": ("<IMPORTANT>", "</IMPORTANT>"),
}

# --- 3. swap_target: literal substring -> substring replacements, only for -
# seeds that name a specific *other* tool they manipulate.
TARGET_SWAPS = {
    "TS-01": [("send_email", "wire_transfer"), ("mcp_tool_send_email", "mcp_tool_wire_transfer")],
    "TS-02": [("transaction_processor", "payment_gateway")],
    "CSR-01": [("mcp_whatsapp", "mcp_slack"), ("send_message", "post_message")],
    "CSR-02": [("create_issue", "create_ticket")],
}


def split_payload(description: str, open_tag: str, close_tag: str):
    """Split description into (prefix, payload, suffix) around the first
    open_tag...close_tag block. payload includes both tags."""
    start = description.find(open_tag)
    if start == -1:
        return None
    end = description.find(close_tag, start + len(open_tag))
    if end == -1:
        return None
    end += len(close_tag)
    return description[:start], description[start:end], description[end:]


def variant_rename_tool(seed: dict) -> dict | None:
    new_name = RENAME_MAP.get(seed["name"])
    if not new_name:
        return None
    v = dict(seed)
    v["name"] = new_name
    v["variant_kind"] = "rename_tool"
    return v


def variants_move_payload(seed: dict) -> list[dict]:
    tags = PAYLOAD_TAGS.get(seed["id"])
    if not tags:
        return []
    split = split_payload(seed["description"], *tags)
    if split is None:
        return []
    prefix, payload, suffix = split
    prefix_stripped = prefix.strip()
    suffix_stripped = suffix.strip()
    out = []

    # payload at the very start (before the benign prefix text)
    if prefix_stripped:
        start_desc = payload + "\n\n" + prefix_stripped
        v = dict(seed)
        v["description"] = start_desc
        v["variant_kind"] = "move_payload:start"
        out.append(v)

    # payload at the very end (after the benign prefix text) — only a
    # distinct variant if that's not already the original layout
    end_desc = (prefix_stripped + "\n\n" + payload) if prefix_stripped else payload
    if end_desc.strip() != seed["description"].strip():
        v = dict(seed)
        v["description"] = end_desc
        v["variant_kind"] = "move_payload:end"
        out.append(v)

    # payload moved inside a parameter's own description, top-level
    # description reduced to just the benign prefix
    props = seed["input_schema"].get("properties", {})
    if props:
        param_name = next(iter(props))
        v = dict(seed)
        new_schema = json.loads(json.dumps(seed["input_schema"]))  # deep copy
        existing = new_schema["properties"][param_name].get("description", "")
        new_schema["properties"][param_name]["description"] = (existing + " " + payload).strip()
        v["input_schema"] = new_schema
        v["description"] = prefix_stripped or f"{seed['name']} tool."
        v["variant_kind"] = f"move_payload:inside_param:{param_name}"
        out.append(v)

    return out


def variants_swap_target(seed: dict) -> list[dict]:
    swaps = TARGET_SWAPS.get(seed["id"])
    if not swaps:
        return []
    desc = seed["description"]
    for old, new in swaps:
        desc = re.sub(re.escape(old), new, desc)
    if desc == seed["description"]:
        return []
    v = dict(seed)
    v["description"] = desc
    v["variant_kind"] = "swap_target"
    return [v]


def main():
    seeds = json.loads(SEEDS_PATH.read_text())
    variants = []

    for seed in seeds:
        renamed = variant_rename_tool(seed)
        if renamed:
            variants.append(renamed)

        variants.extend(variants_move_payload(seed))
        variants.extend(variants_swap_target(seed))

        # Compose transform: rename_tool + swap_target together, when both
        # apply, for a bit more structural diversity per seed.
        if renamed:
            swapped_and_renamed = variants_swap_target(renamed)
            for v in swapped_and_renamed:
                v["variant_kind"] = "rename_tool+swap_target"
            variants.extend(swapped_and_renamed)

    for i, v in enumerate(variants, start=1):
        v["variant_id"] = f"{v['id']}-V{i:02d}"

    with open(OUT_PATH, "w") as f:
        for v in variants:
            f.write(json.dumps(v) + "\n")

    print(f"Generated {len(variants)} variants from {len(seeds)} seeds -> {OUT_PATH}")
    from collections import Counter

    kind_counts = Counter(v["variant_kind"] for v in variants)
    for kind, count in sorted(kind_counts.items()):
        print(f"  {kind}: {count}")


if __name__ == "__main__":
    main()
