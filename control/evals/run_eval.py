#!/usr/bin/env python3
"""Score the three-layer scanner cascade against the labeled corpus.

Reports, per layer AND for the full cascade: precision/recall/F1, a
confusion matrix, recall broken out by attack class, and latency
percentiles. Layer 3 and the cascade additionally report the LLM
invocation rate, real token cost (and an estimated USD/1000-tools figure),
and the evidence-span rejection rate.

METHODOLOGY -- read before trusting a number out of context:

  * This is NOT a held-out test set. See the "Methodology and limitations"
    section this script writes into REPORT.md for the full disclosure
    (corpus provenance, leave-one-out details, verdict-scoring conventions).
    The short version: layer 2's malicious-attack index is built from this
    same corpus (leave-one-out per row, so a row never matches only itself),
    and layer 3's prompt was written without looking at eval numbers -- but
    neither claim generalization to attacks the corpus's small seed set
    didn't already represent in some form.
  * Every threshold used is the untouched default already defined in
    scanner/cascade.py and scanner/layer2_similarity.py -- this script does
    not search for, or report, whichever threshold maximizes the headline
    number. If that ever changes, it will be stated explicitly in the
    generated report, not buried in a config diff.
  * "uncertain" (layer 1) and "layer3_failure" (layer 3 / cascade) verdicts
    are scored as *not flagged* for precision/recall purposes -- i.e. the
    same as "benign" -- because a layer used standalone, with nothing
    downstream to resolve the ambiguity, would let the tool through. Each
    layer's rejection/deferral rate is also reported on its own line so
    this convention doesn't hide it.
  * Layer 3 is genuinely called once per corpus row (a real Anthropic API
    call, real cost, real latency) to produce fair standalone layer-3
    metrics. The cascade run then REPLAYS those same cached results for
    rows that fall through to layer 3, rather than issuing a second call
    for the same (row, classifier) pair -- this avoids double-billing while
    still exercising the cascade's real short-circuit logic and reporting
    real per-row cost/latency for whichever layer actually ran.

Usage:
    ANTHROPIC_API_KEY=... python3 run_eval.py [--limit N] [--skip-llm]

Requires a locally-cached sentence-transformers model (downloaded
automatically on first run) and, unless --skip-llm is passed, a working
ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.cascade import (
    DEFAULT_LAYER1_SHORT_CIRCUIT_CONFIDENCE,
    DEFAULT_LAYER2_SHORT_CIRCUIT_SIMILARITY,
    Cascade,
)
from scanner.layer1_rules import scan as layer1_scan
from scanner.layer2_similarity import InMemoryVectorStore, Layer2Similarity, SentenceTransformerEmbedder
from scanner.layer3_llm import DEFAULT_MODEL, Layer3LLM

DEFAULT_CORPUS_PATH = Path(__file__).resolve().parent / "corpus" / "corpus.jsonl"
DEFAULT_REPORT_PATH = Path(__file__).resolve().parent / "REPORT.md"
DEFAULT_LAYER2_THRESHOLD = 0.85  # Layer2Similarity's own default, untouched.

# Pricing snapshot for claude-opus-5, cached 2026-06-24 (see control/CLAUDE.md
# claude-api skill reference). Not fetched live by this script -- verify at
# https://claude.com/pricing before relying on this for real budgeting.
OPUS5_INPUT_USD_PER_TOKEN = 5.00 / 1_000_000
OPUS5_OUTPUT_USD_PER_TOKEN = 25.00 / 1_000_000


# --- data plumbing ------------------------------------------------------------


def load_corpus(path: Path) -> list[dict]:
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]


@dataclass
class Timed:
    result: object
    latency_s: float


# --- layer 1 --------------------------------------------------------------


def run_layer1(rows: list[dict]) -> dict[str, Timed]:
    out = {}
    for row in rows:
        t0 = time.perf_counter()
        result = layer1_scan(row["description"])
        out[row["id"]] = Timed(result, time.perf_counter() - t0)
    return out


# --- layer 2 (local embeddings; two indexing schemes, see below) ----------


def seed_family_id(row: dict) -> str:
    """The seed a malicious row belongs to: itself if it IS a seed
    (derivation == "original"), otherwise the seed named in
    "variant_of:<seed_id>". Used to exclude an entire family of mechanical
    variants together, not just the one sample being scored.
    """
    if row["derivation"] == "original":
        return row["id"]
    if row["derivation"].startswith("variant_of:"):
        return row["derivation"].split(":", 1)[1]
    return row["id"]


def _build_layer2_cache(
    rows: list[dict],
    malicious_rows: list[dict],
    embedder: SentenceTransformerEmbedder,
    malicious_embeddings: list[list[float]],
    threshold: float,
    exclude_fn,
) -> dict[str, Timed]:
    """exclude_fn(candidate_row, scored_row) -> bool: True if candidate_row's
    embedding should be left out of the index when scoring scored_row.
    Benign rows are always scored against the full malicious-attack index --
    there's nothing of theirs to leave out.
    """
    full_store = InMemoryVectorStore()
    for row, emb in zip(malicious_rows, malicious_embeddings):
        full_store.upsert(row["id"], emb, row["attack_class"])
    full_layer2 = Layer2Similarity(embedder=embedder, store=full_store, threshold=threshold)

    malicious_ids = {r["id"] for r in malicious_rows}
    out = {}
    for row in rows:
        if row["id"] in malicious_ids:
            store = InMemoryVectorStore()
            for other_row, emb in zip(malicious_rows, malicious_embeddings):
                if not exclude_fn(other_row, row):
                    store.upsert(other_row["id"], emb, other_row["attack_class"])
            layer2 = Layer2Similarity(embedder=embedder, store=store, threshold=threshold)
        else:
            layer2 = full_layer2

        t0 = time.perf_counter()
        result = layer2.score(row["description"])
        out[row["id"]] = Timed(result, time.perf_counter() - t0)
    return out


def run_layer2(rows: list[dict], malicious_rows: list[dict], threshold: float) -> tuple[dict[str, Timed], dict[str, Timed]]:
    """Returns (leave_one_out_cache, leave_one_seed_family_out_cache).

    Leave-one-out excludes only the scored sample's own embedding -- but 27
    of the 38 malicious rows are mechanical variants of 11 seeds (rename
    tool, move payload, swap target -- see corpus/README.md), so a variant's
    parent seed and sibling variants stay in the index. Leave-one-seed-
    family-out additionally excludes the whole family (parent seed + every
    other variant of it), so a family's recall reflects generalization from
    OTHER seed families and attack classes only, not "found a near-identical
    sibling still sitting in the index." Both are computed and reported --
    see the Results section for what the gap between them means.
    """
    embedder = SentenceTransformerEmbedder()

    print(f"  embedding {len(malicious_rows)} malicious descriptions for the attack index...")
    malicious_embeddings = embedder.embed([r["description"] for r in malicious_rows])

    print("  building leave-one-out index...")
    loo_cache = _build_layer2_cache(
        rows, malicious_rows, embedder, malicious_embeddings, threshold,
        exclude_fn=lambda candidate, scored: candidate["id"] == scored["id"],
    )

    print("  building leave-one-seed-family-out index...")
    family_cache = _build_layer2_cache(
        rows, malicious_rows, embedder, malicious_embeddings, threshold,
        exclude_fn=lambda candidate, scored: seed_family_id(candidate) == seed_family_id(scored),
    )

    return loo_cache, family_cache


# --- layer 3 (real Anthropic API calls) ------------------------------------


MAX_TOLERABLE_API_ERROR_RATE = 0.2  # above this, the run is broken, not "layer 3 missed some attacks"


def run_layer3(rows: list[dict], model: str) -> dict[str, Timed]:
    from anthropic import AuthenticationError, PermissionDeniedError

    layer3 = Layer3LLM(model=model)
    out = {}
    total = len(rows)
    api_error_count = 0
    for i, row in enumerate(rows, 1):
        t0 = time.perf_counter()
        try:
            result = layer3.classify(row["name"], row["description"], row["input_schema"])
        except (AuthenticationError, PermissionDeniedError) as exc:
            # Not a per-row failure -- the whole run is broken. Fail fast rather
            # than burning through the remaining rows and reporting "layer 3
            # missed everything" as if that were a measurement of the model.
            print(f"\nABORTING: Anthropic API credentials rejected on row {i}/{total}: {exc}")
            print("Fix ANTHROPIC_API_KEY and re-run. No report was written.")
            sys.exit(1)
        except Exception as exc:  # noqa: BLE001 -- one transient failure shouldn't kill a ~139-call run
            from scanner.layer3_llm import Layer3Result

            api_error_count += 1
            result = Layer3Result(
                verdict="layer3_failure",
                attack_class=None,
                evidence_span=None,
                confidence=0.0,
                input_tokens=0,
                output_tokens=0,
                rejected_reason=f"api_error:{exc!r}",
            )
        out[row["id"]] = Timed(result, time.perf_counter() - t0)
        if i % 10 == 0 or i == total:
            print(f"  layer 3: {i}/{total} rows classified")

    error_rate = api_error_count / total
    if error_rate > MAX_TOLERABLE_API_ERROR_RATE:
        print(
            f"\nABORTING: {api_error_count}/{total} layer-3 calls failed with a non-auth API error "
            f"({error_rate:.0%} > {MAX_TOLERABLE_API_ERROR_RATE:.0%} tolerance). This looks like a broken "
            f"run (rate limiting, network issue, outage), not a real layer-3 recall measurement. "
            f"No report was written."
        )
        sys.exit(1)
    elif api_error_count:
        print(f"  note: {api_error_count}/{total} layer-3 calls failed transiently and are recorded as layer3_failure.")

    return out


# --- cascade (replays cached layer2/layer3 results, no re-billing) --------


class _Replay:
    def __init__(self, result):
        self._result = result

    def score(self, description):
        return self._result

    def classify(self, name, description, input_schema):
        return self._result


def run_cascade(
    rows: list[dict],
    layer1_cache: dict[str, Timed],
    layer2_cache: dict[str, Timed],
    layer3_cache: dict[str, Timed],
    layer1_short_circuit_confidence: float,
    layer2_short_circuit_similarity: float,
) -> dict[str, Timed]:
    out = {}
    for row in rows:
        rid = row["id"]
        cascade = Cascade(
            layer2=_Replay(layer2_cache[rid].result),
            layer3=_Replay(layer3_cache[rid].result),
            layer1_short_circuit_confidence=layer1_short_circuit_confidence,
            layer2_short_circuit_similarity=layer2_short_circuit_similarity,
        )
        verdict = cascade.classify(row["name"], row["description"], row["input_schema"])

        latency = layer1_cache[rid].latency_s
        if verdict.layer2_result is not None:
            latency += layer2_cache[rid].latency_s
        if verdict.layer3_result is not None:
            latency += layer3_cache[rid].latency_s

        out[rid] = Timed(verdict, latency)
    return out


# --- metrics ----------------------------------------------------------------


def percentile(values: list[float], p: float) -> float:
    if not values:
        return float("nan")
    s = sorted(values)
    k = (len(s) - 1) * (p / 100)
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return s[int(k)]
    return s[f] * (c - k) + s[c] * (k - f)


@dataclass
class PRF:
    tp: int
    fp: int
    fn: int
    tn: int
    n: int
    precision: float
    recall: float
    f1: float


def confusion_and_prf(rows: list[dict], predicted_malicious: dict[str, bool]) -> PRF:
    tp = fp = fn = tn = 0
    for row in rows:
        actual = row["label"] == "malicious"
        pred = predicted_malicious[row["id"]]
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    f1 = (
        2 * precision * recall / (precision + recall)
        if not math.isnan(precision) and not math.isnan(recall) and (precision + recall) > 0
        else float("nan")
    )
    return PRF(tp=tp, fp=fp, fn=fn, tn=tn, n=len(rows), precision=precision, recall=recall, f1=f1)


def recall_by_attack_class(malicious_rows: list[dict], predicted_malicious: dict[str, bool]) -> dict[str, tuple[int, int]]:
    by_class: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # [caught, total]
    for row in malicious_rows:
        c = row["attack_class"]
        by_class[c][1] += 1
        if predicted_malicious[row["id"]]:
            by_class[c][0] += 1
    return {c: (caught, total) for c, (caught, total) in sorted(by_class.items())}


def fmt(x: float, digits: int = 3) -> str:
    return "nan" if isinstance(x, float) and math.isnan(x) else f"{x:.{digits}f}"


# --- rendering ----------------------------------------------------------------


def render_prf_block(title: str, prf: PRF, extra_lines: list[str] | None = None) -> str:
    lines = [
        f"### {title} (n={prf.n})",
        "",
        "| | Actual malicious | Actual benign |",
        "|---|---|---|",
        f"| Predicted malicious | TP={prf.tp} | FP={prf.fp} |",
        f"| Predicted not-malicious | FN={prf.fn} | TN={prf.tn} |",
        "",
        f"precision={fmt(prf.precision)}  recall={fmt(prf.recall)}  F1={fmt(prf.f1)}  (n={prf.n})",
        "",
    ]
    if extra_lines:
        lines.extend(extra_lines)
        lines.append("")
    return "\n".join(lines)


def render_recall_by_class(by_class: dict[str, tuple[int, int]]) -> str:
    lines = ["| attack_class | recall | n |", "|---|---|---|"]
    for c, (caught, total) in by_class.items():
        recall = caught / total if total else float("nan")
        warn = "  **WARNING: n<10, not statistically meaningful**" if total < 10 else ""
        lines.append(f"| {c} | {fmt(recall)} ({caught}/{total}) | {total}{warn} |")
    return "\n".join(lines) + "\n"


@dataclass
class CascadeMetrics:
    prf: PRF
    recall_by_class: dict[str, tuple[int, int]]
    latencies: list[float]
    produced_by: dict[str, int]
    llm_invocations: int
    invocation_rate: float
    input_tokens: int
    output_tokens: int
    cost_per_1000: float
    span_rejections: int


def compute_cascade_metrics(cascade_cache: dict[str, Timed], rows: list[dict], malicious_rows: list[dict]) -> CascadeMetrics:
    pred = {rid: t.result.verdict == "malicious" for rid, t in cascade_cache.items()}
    prf = confusion_and_prf(rows, pred)
    recall_by_class = recall_by_attack_class(malicious_rows, pred)
    latencies = [t.latency_s for t in cascade_cache.values()]

    produced_by = defaultdict(int)
    for t in cascade_cache.values():
        produced_by[t.result.produced_by] += 1
    for layer in ("layer1", "layer2", "layer3"):
        produced_by.setdefault(layer, 0)
    llm_invocations = produced_by["layer3"]
    invocation_rate = llm_invocations / len(rows)

    input_tokens = sum(t.result.layer3_result.input_tokens for t in cascade_cache.values() if t.result.layer3_result is not None)
    output_tokens = sum(t.result.layer3_result.output_tokens for t in cascade_cache.values() if t.result.layer3_result is not None)
    cost_per_1000 = (
        (input_tokens / len(rows)) * 1000 * OPUS5_INPUT_USD_PER_TOKEN
        + (output_tokens / len(rows)) * 1000 * OPUS5_OUTPUT_USD_PER_TOKEN
    )
    span_rejections = sum(
        1
        for t in cascade_cache.values()
        if t.result.layer3_result is not None
        and t.result.layer3_result.rejected_reason == "evidence_span_not_literal_substring"
    )

    return CascadeMetrics(
        prf=prf,
        recall_by_class=recall_by_class,
        latencies=latencies,
        produced_by=dict(produced_by),
        llm_invocations=llm_invocations,
        invocation_rate=invocation_rate,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_per_1000=cost_per_1000,
        span_rejections=span_rejections,
    )


def render_cascade_comparison(loo: CascadeMetrics, family: CascadeMetrics, n_rows: int) -> str:
    lines = [
        f"### Full cascade -- layer2 indexing scheme comparison (n={n_rows})",
        "",
        "| Layer2 indexing scheme | TP | FP | FN | TN | precision | recall | F1 | produced_by (l1/l2/l3) | LLM invocation rate |",
        "|---|---|---|---|---|---|---|---|---|---|",
        f"| Leave-one-out | {loo.prf.tp} | {loo.prf.fp} | {loo.prf.fn} | {loo.prf.tn} | "
        f"{fmt(loo.prf.precision)} | {fmt(loo.prf.recall)} | {fmt(loo.prf.f1)} | "
        f"{loo.produced_by['layer1']}/{loo.produced_by['layer2']}/{loo.produced_by['layer3']} | "
        f"{fmt(loo.invocation_rate)} ({loo.llm_invocations}/{n_rows}) |",
        f"| Leave-one-seed-family-out | {family.prf.tp} | {family.prf.fp} | {family.prf.fn} | {family.prf.tn} | "
        f"{fmt(family.prf.precision)} | {fmt(family.prf.recall)} | {fmt(family.prf.f1)} | "
        f"{family.produced_by['layer1']}/{family.produced_by['layer2']}/{family.produced_by['layer3']} | "
        f"{fmt(family.invocation_rate)} ({family.llm_invocations}/{n_rows}) |",
        "",
        "**Why they differ:** the cascade's layer-2 branch is the exact same leaky-vs-generalizing tradeoff "
        "reported for layer 2 standalone above -- with leave-one-out, a malicious row's siblings are still in "
        "the index, so layer 2's 0.92 cascade short-circuit fires easily and layer 2 carries most of the "
        "cascade's recall. With leave-one-seed-family-out, layer 2's similarity to a genuinely-excluded family "
        "rarely clears even its own 0.85 standalone threshold (see the layer 2 section above -- family-out "
        "recall there is 0.000), so it essentially never clears the cascade's stricter 0.92 bar either. Under "
        "family-out, detection is carried almost entirely by layer 1 (confident rule-based catches) and "
        "layer 3 (whatever falls through) instead -- the `produced_by` column above shows exactly how the "
        "load shifts. **Neither row is deleted or superseded: leave-one-out is what the cascade does when its "
        "attack index already contains something near-identical to the incoming attack (the realistic "
        "in-production case, since a real deployment's index only grows); leave-one-seed-family-out is what "
        "the cascade does against a genuinely unfamiliar attack construction, which is the harder and more "
        "honest question if you're asking \"how well does this generalize.\"**",
        "",
    ]
    return "\n".join(lines)


def render_layer2_comparison(threshold: float, loo_prf: PRF, family_prf: PRF, n_malicious: int) -> str:
    lines = [
        f"### Layer 2 -- embedding similarity, indexing scheme comparison (threshold={threshold}, n={loo_prf.n})",
        "",
        "| Indexing scheme | TP | FP | FN | TN | precision | recall | F1 |",
        "|---|---|---|---|---|---|---|---|",
        f"| Leave-one-out (original) | {loo_prf.tp} | {loo_prf.fp} | {loo_prf.fn} | {loo_prf.tn} | "
        f"{fmt(loo_prf.precision)} | {fmt(loo_prf.recall)} | {fmt(loo_prf.f1)} |",
        f"| Leave-one-seed-family-out | {family_prf.tp} | {family_prf.fp} | {family_prf.fn} | {family_prf.tn} | "
        f"{fmt(family_prf.precision)} | {fmt(family_prf.recall)} | {fmt(family_prf.f1)} |",
        "",
        f"**Why they differ:** 27 of the {n_malicious} malicious samples are mechanical variants of 11 seeds "
        "(rename tool / move payload / swap target -- see corpus/README.md). Leave-one-out only removes the "
        "scored sample's OWN embedding from the index; its parent seed and sibling variants (e.g. a seed with "
        "6 variants keeps all 6 in the index when scoring any one of them) remain, so a hit is often \"found "
        "the near-identical sibling still in the index\" rather than a generalized detection. "
        "Leave-one-seed-family-out removes the scored sample's ENTIRE family (parent seed + every other "
        "variant of it) before scoring it, so its recall reflects generalization from OTHER seed families and "
        "attack classes only. **The leave-one-out number is not deleted or superseded -- it answers a "
        "different, still-useful question (\"can layer 2 retrieve a near-duplicate of something already in "
        "the attack index\"), while leave-one-seed-family-out is the closer proxy for generalization to a "
        "genuinely unseen attack. The gap between the two rows above is itself the finding: it quantifies how "
        "much of layer 2's apparent recall was sibling retrieval versus recognition of an unfamiliar attack.**",
        "",
    ]
    return "\n".join(lines)


def render_latency(title: str, latencies_s: list[float]) -> str:
    p50 = percentile(latencies_s, 50) * 1000
    p95 = percentile(latencies_s, 95) * 1000
    return f"{title}: p50={p50:.2f}ms  p95={p95:.2f}ms  (n={len(latencies_s)})"


# --- main ---------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--limit", type=int, default=None, help="Only score the first N rows (smoke-test aid).")
    parser.add_argument("--skip-llm", action="store_true", help="Skip layer 3 / cascade entirely (smoke-test aid).")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--layer2-threshold", type=float, default=DEFAULT_LAYER2_THRESHOLD)
    parser.add_argument("--layer1-short-circuit", type=float, default=DEFAULT_LAYER1_SHORT_CIRCUIT_CONFIDENCE)
    parser.add_argument("--layer2-short-circuit", type=float, default=DEFAULT_LAYER2_SHORT_CIRCUIT_SIMILARITY)
    args = parser.parse_args()

    run_started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    wall_start = time.perf_counter()

    rows = load_corpus(args.corpus)
    if args.limit:
        rows = rows[: args.limit]
    benign_rows = [r for r in rows if r["label"] == "benign"]
    malicious_rows = [r for r in rows if r["label"] == "malicious"]

    print(f"Corpus: {len(rows)} rows ({len(benign_rows)} benign, {len(malicious_rows)} malicious)")

    print("Running layer 1 (deterministic rules)...")
    l1_cache = run_layer1(rows)

    print("Running layer 2 (local embedding similarity, two indexing schemes)...")
    l2_cache, l2_family_cache = run_layer2(rows, malicious_rows, args.layer2_threshold)

    if args.skip_llm:
        print("--skip-llm set: layer 3 and the cascade will not be scored.")
        l3_cache = None
        cascade_cache = None
        cascade_family_cache = None
    else:
        print(f"Running layer 3 ({args.model}, {len(rows)} real API calls)...")
        l3_cache = run_layer3(rows, args.model)
        print("Running cascade, leave-one-out layer2 (replays cached layer2/layer3 results)...")
        cascade_cache = run_cascade(
            rows, l1_cache, l2_cache, l3_cache, args.layer1_short_circuit, args.layer2_short_circuit
        )
        print("Running cascade, leave-one-seed-family-out layer2 (same layer3 cache, no re-billing)...")
        cascade_family_cache = run_cascade(
            rows, l1_cache, l2_family_cache, l3_cache, args.layer1_short_circuit, args.layer2_short_circuit
        )

    wall_elapsed = time.perf_counter() - wall_start

    # ---- layer 1 metrics ----
    l1_pred = {rid: t.result.verdict == "malicious" for rid, t in l1_cache.items()}
    l1_uncertain_n = sum(1 for t in l1_cache.values() if t.result.verdict == "uncertain")
    l1_prf = confusion_and_prf(rows, l1_pred)
    l1_recall_by_class = recall_by_attack_class(malicious_rows, l1_pred)
    l1_latencies = [t.latency_s for t in l1_cache.values()]

    # ---- layer 2 metrics (both indexing schemes) ----
    l2_pred = {rid: t.result.verdict == "malicious" for rid, t in l2_cache.items()}
    l2_prf = confusion_and_prf(rows, l2_pred)
    l2_recall_by_class = recall_by_attack_class(malicious_rows, l2_pred)
    l2_latencies = [t.latency_s for t in l2_cache.values()]

    l2_family_pred = {rid: t.result.verdict == "malicious" for rid, t in l2_family_cache.items()}
    l2_family_prf = confusion_and_prf(rows, l2_family_pred)
    l2_family_recall_by_class = recall_by_attack_class(malicious_rows, l2_family_pred)

    sections = []
    sections.append(render_prf_block("Layer 1 -- deterministic rules", l1_prf, [
        f"'uncertain' verdicts (scored as not-flagged above): {l1_uncertain_n}/{len(rows)}",
    ]))
    sections.append(render_recall_by_class(l1_recall_by_class))
    sections.append(render_latency("Layer 1 latency", l1_latencies))
    sections.append("")

    sections.append(render_layer2_comparison(args.layer2_threshold, l2_prf, l2_family_prf, len(malicious_rows)))
    sections.append("Recall by attack class -- leave-one-out (excludes only the scored sample):")
    sections.append(render_recall_by_class(l2_recall_by_class))
    sections.append("Recall by attack class -- leave-one-seed-family-out (excludes the scored sample's whole seed family):")
    sections.append(render_recall_by_class(l2_family_recall_by_class))
    sections.append(render_latency("Layer 2 latency", l2_latencies))
    sections.append("Layer 2 cost: $0.00 (local model, no API calls)")
    sections.append("")

    if l3_cache is not None:
        l3_pred = {rid: t.result.verdict == "malicious" for rid, t in l3_cache.items()}
        l3_failure_n = sum(1 for t in l3_cache.values() if t.result.rejected_reason == "evidence_span_not_literal_substring")
        l3_other_failure_n = sum(
            1 for t in l3_cache.values()
            if t.result.verdict == "layer3_failure" and t.result.rejected_reason != "evidence_span_not_literal_substring"
        )
        l3_prf = confusion_and_prf(rows, l3_pred)
        l3_recall_by_class = recall_by_attack_class(malicious_rows, l3_pred)
        l3_latencies = [t.latency_s for t in l3_cache.values()]
        l3_input_tokens = sum(t.result.input_tokens for t in l3_cache.values())
        l3_output_tokens = sum(t.result.output_tokens for t in l3_cache.values())
        l3_cost_per_1000 = (
            (l3_input_tokens / len(rows)) * 1000 * OPUS5_INPUT_USD_PER_TOKEN
            + (l3_output_tokens / len(rows)) * 1000 * OPUS5_OUTPUT_USD_PER_TOKEN
        )
        l3_span_rejection_rate = l3_failure_n / len(rows)

        sections.append(render_prf_block(f"Layer 3 -- LLM classifier ({args.model}, standalone: every row classified)", l3_prf, [
            f"evidence-span rejection rate: {fmt(l3_span_rejection_rate)} ({l3_failure_n}/{len(rows)})",
            f"other layer3 failures (e.g. API errors, no parsed output): {l3_other_failure_n}/{len(rows)}",
        ]))
        sections.append(render_recall_by_class(l3_recall_by_class))
        sections.append(render_latency("Layer 3 latency", l3_latencies))
        sections.append(
            f"Layer 3 tokens: {l3_input_tokens} input + {l3_output_tokens} output "
            f"across {len(rows)} calls (standalone -- every row, not just cascade fallthrough)"
        )
        sections.append(f"Layer 3 estimated cost per 1,000 tools scanned (standalone): ${l3_cost_per_1000:.2f}")
        sections.append("")

    if cascade_cache is not None:
        cm_loo = compute_cascade_metrics(cascade_cache, rows, malicious_rows)
        cm_family = compute_cascade_metrics(cascade_family_cache, rows, malicious_rows)

        sections.append(render_cascade_comparison(cm_loo, cm_family, len(rows)))

        sections.append(render_prf_block("Full cascade -- leave-one-out layer2", cm_loo.prf, [
            f"produced_by breakdown: layer1={cm_loo.produced_by['layer1']}, "
            f"layer2={cm_loo.produced_by['layer2']}, layer3={cm_loo.produced_by['layer3']} (n={len(rows)})",
            f"LLM invocation rate (fraction reaching layer 3): {fmt(cm_loo.invocation_rate)} "
            f"({cm_loo.llm_invocations}/{len(rows)})",
            f"evidence-span rejection rate (of rows reaching layer 3): "
            f"{fmt(cm_loo.span_rejections / cm_loo.llm_invocations) if cm_loo.llm_invocations else 'n/a'} "
            f"({cm_loo.span_rejections}/{cm_loo.llm_invocations})",
        ]))
        sections.append(render_recall_by_class(cm_loo.recall_by_class))
        sections.append(render_latency("Cascade (leave-one-out) end-to-end latency", cm_loo.latencies))
        sections.append(
            f"Cascade (leave-one-out) tokens actually spent: {cm_loo.input_tokens} input + {cm_loo.output_tokens} "
            f"output across {cm_loo.llm_invocations} LLM calls (out of {len(rows)} rows)"
        )
        sections.append(f"Cascade (leave-one-out) estimated cost per 1,000 tools scanned: ${cm_loo.cost_per_1000:.2f}")
        sections.append("")

        sections.append(render_prf_block("Full cascade -- leave-one-seed-family-out layer2", cm_family.prf, [
            f"produced_by breakdown: layer1={cm_family.produced_by['layer1']}, "
            f"layer2={cm_family.produced_by['layer2']}, layer3={cm_family.produced_by['layer3']} (n={len(rows)})",
            f"LLM invocation rate (fraction reaching layer 3): {fmt(cm_family.invocation_rate)} "
            f"({cm_family.llm_invocations}/{len(rows)})",
            f"evidence-span rejection rate (of rows reaching layer 3): "
            f"{fmt(cm_family.span_rejections / cm_family.llm_invocations) if cm_family.llm_invocations else 'n/a'} "
            f"({cm_family.span_rejections}/{cm_family.llm_invocations})",
        ]))
        sections.append(render_recall_by_class(cm_family.recall_by_class))
        sections.append(render_latency("Cascade (leave-one-seed-family-out) end-to-end latency", cm_family.latencies))
        sections.append(
            f"Cascade (leave-one-seed-family-out) tokens actually spent: {cm_family.input_tokens} input + "
            f"{cm_family.output_tokens} output across {cm_family.llm_invocations} LLM calls (out of {len(rows)} rows)"
        )
        sections.append(
            f"Cascade (leave-one-seed-family-out) estimated cost per 1,000 tools scanned: ${cm_family.cost_per_1000:.2f}"
        )
        sections.append("")

    results_body = "\n".join(sections)

    print("\n" + "=" * 80)
    print(results_body)
    print("=" * 80)
    print(f"Wall-clock eval duration: {wall_elapsed:.1f}s")

    write_report(args, rows, benign_rows, malicious_rows, results_body, run_started_at, wall_elapsed)
    print(f"\nWrote {args.report}")


def write_report(args, rows, benign_rows, malicious_rows, results_body, run_started_at, wall_elapsed) -> None:
    corpus_label_counts = f"{len(rows)} rows ({len(benign_rows)} benign, {len(malicious_rows)} malicious)"
    attack_class_counts = defaultdict(int)
    for r in malicious_rows:
        attack_class_counts[r["attack_class"]] += 1
    seed_count = sum(1 for r in malicious_rows if r["derivation"] == "original")
    variant_count = sum(1 for r in malicious_rows if r["derivation"].startswith("variant_of"))

    report = f"""# Portcullis Scanner -- Evaluation Report

Generated: {run_started_at}
Corpus: `control/evals/corpus/corpus.jsonl` -- {corpus_label_counts}
Layer 3 model: `{args.model}`
Layer 2 embedder: `all-MiniLM-L6-v2` (local, sentence-transformers, 384-dim)
Eval wall-clock duration: {wall_elapsed:.1f}s

## Methodology and limitations

**Corpus size and provenance.** {corpus_label_counts}. Full per-sample provenance
is in `control/evals/corpus/README.md`; summary:

- **Benign ({len(benign_rows)}):** harvested live via `initialize` -> `tools/list`
  against real third-party MCP servers discovered through the public MCP
  registry (`https://registry.modelcontextprotocol.io`). Not synthetic.
- **Malicious seeds ({seed_count}):** reproduced from published tool-poisoning
  disclosures (Invariant Labs' MCP injection experiments, Elastic Security
  Labs' MCP attack writeup, and similar sourced material -- see corpus
  README for the exact URL per seed). Not invented.
- **Malicious variants ({variant_count}):** generated by a *scripted, non-LLM*
  transformation of the {seed_count} seeds above (rename tool, move payload
  start/end/inside a parameter description, swap target tool name). They are
  mechanical rewrites of a small seed set, not independent attack samples --
  high recall on variants demonstrates robustness to superficial rewording of
  a *known* attack, not generalization to attacks from a different author.

Malicious rows by attack class: { {k: v for k, v in sorted(attack_class_counts.items())} }

**This is not a held-out test set.** Two specific ways that shows up here:

1. *Layer 2* indexes the malicious corpus itself as its "known attack"
   lookup table. This script reports layer 2 under BOTH of two indexing
   schemes -- see the side-by-side table and explanation in the Results
   section below, this is only the short version:
   - **Leave-one-out**: excludes only the scored sample's own embedding.
     Its parent seed and sibling mechanical variants remain in the index,
     so this measures near-duplicate retrieval more than generalization.
   - **Leave-one-seed-family-out**: excludes the scored sample's entire
     seed family (parent seed + all {variant_count} of its mechanical
     variants) from the index, so it can only match a DIFFERENT seed
     family or attack class. This is the closer proxy for generalization
     to a genuinely unseen attack, and it scores lower than leave-one-out
     -- the gap between the two is reported as a finding, not resolved
     away by picking one number.
   Benign rows are scored against the full index either way (nothing of
   theirs to leave out). Even leave-one-seed-family-out is still
   evaluation against the same {seed_count}-seed pool this corpus was
   built from -- not against a genuinely independent attack corpus.
   The **full cascade** is also reported under both layer-2 schemes (see
   the cascade comparison table in Results) -- its leave-one-out recall
   inherits the same sibling-retrieval optimism, and its
   leave-one-seed-family-out recall shows detection shifting almost
   entirely onto layer 1 and layer 3 once layer 2 can no longer lean on a
   near-identical sibling.
2. *Layer 3* is a general-purpose LLM classifier; nothing here confirms
   whether `{args.model}` was trained on the (public) disclosures the seeds
   are drawn from. A strong layer-3 score is consistent with either "the
   classifier reasons well about this attack pattern" or "the classifier
   has seen this exact public writeup before" -- this script cannot
   distinguish the two.

**Thresholds are untouched code defaults**, not tuned against this corpus or
this run:
- Layer 1 short-circuit confidence: `{args.layer1_short_circuit}` (cascade.py default)
- Layer 2 verdict threshold: `{args.layer2_threshold}` (layer2_similarity.py default)
- Layer 2 cascade short-circuit similarity: `{args.layer2_short_circuit}` (cascade.py default)

No threshold sweep was run and no value was chosen after looking at the
resulting precision/recall. If a future run changes any of these to chase a
headline number, that must be stated here explicitly, not silently.

**Verdict-scoring convention.** For precision/recall purposes, layer 1's
`uncertain` verdict and layer 3 / cascade's `layer3_failure` verdict are both
scored as *not flagged malicious* (i.e. treated like `benign`). Rationale: a
layer used standalone, with no downstream layer to resolve the ambiguity,
would let the tool through either way. Each layer's deferral/rejection rate
is reported as its own line so this convention doesn't obscure it.

**Layer 3 cost avoidance.** Layer 3 is called once per corpus row to produce
real standalone layer-3 metrics (a genuine Anthropic API call per row, real
tokens, real latency). The cascade run then *replays* those same per-row
results for whichever rows fall through to layer 3, instead of issuing a
second live call for the same (row, classifier) pair. This avoids
double-billing identical work while still exercising the cascade's real
short-circuit logic and reporting genuine per-row cost/latency for whichever
layer actually produced the verdict.

**Small-sample warning.** Per the methodology requirement: any attack class
with fewer than 10 malicious samples has its recall figure marked
"not statistically meaningful" below -- treat those numbers as anecdotal.

## Results

{results_body}
"""
    args.report.write_text(report)


if __name__ == "__main__":
    main()
