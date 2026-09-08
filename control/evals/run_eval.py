#!/usr/bin/env python3
"""Score the three-layer scanner cascade against the labeled corpus.

Reports, per layer AND for the full cascade: precision/recall/F1, a
confusion matrix, recall broken out by attack class, and latency
percentiles. Layer 3 and the cascade additionally report the LLM
invocation rate, real token cost (and an estimated USD/1000-tools figure),
and the evidence-span rejection rate.

METHODOLOGY -- read before trusting a number out of context:

  * Every headline number is computed over the corpus's HELD-OUT split
    only, against a layer-2 attack index built from the TRAIN split only.
    One index, one scored population, nothing scored that is in the index
    -- so precision and recall describe the same configuration and the F1
    over them means something. (Before this, malicious rows were scored
    against a row- or family-excluded index while benign rows were scored
    against the full one, blending two configurations inside every
    published pair.) See split.py for how the split is assigned.
  * Every run is fingerprinted (see fingerprint.py) over its corpus hash,
    split spec, model, thresholds, embedder and resolved library versions,
    and writes machine-readable artifacts to evals/results/<fingerprint>/.
    Numbers carrying different fingerprints are not comparable. A partial
    run (--limit / --skip-llm) is recorded but refuses to overwrite
    REPORT.md.
  * A held-out family is unseen by the index, but still drawn from the same
    11-seed pool the corpus was built from -- not an independent attack
    corpus. Layer 1's rules were also authored with those seeds visible.
    Both caveats are restated in the generated report.
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
  * An API/transport error on a layer-3 call is reported separately and an
    error-excluded figure is published beside the conventional one. An
    outage is not a missed detection.
  * Layer 3 is genuinely called once per held-out row (a real Anthropic API
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
from dataclasses import asdict, dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import fingerprint  # noqa: E402  (needs the sys.path lines above)
import split  # noqa: E402

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
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / "results"
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

    NOTE: this per-row-index construction is now used ONLY for the
    supplementary leave-one-out / leave-one-seed-family-out **recall**
    diagnostic over malicious rows (see run_layer2_diagnostics). It must
    not be used to produce a precision or F1 figure: each scored row sees a
    different index, so a precision computed by mixing these scores with
    benign scores from a full index blends configurations inside a single
    number. That was the defect this harness's headline numbers carried.
    The headline path is run_layer2_heldout below: one fixed index, one
    scored population.
    """
    malicious_ids = {r["id"] for r in malicious_rows}
    out = {}
    for row in rows:
        if row["id"] not in malicious_ids:
            raise ValueError(
                f"row {row['id']} is not malicious; the leave-one-out diagnostic "
                "is recall-only and must be given malicious rows exclusively"
            )
        store = InMemoryVectorStore()
        for other_row, emb in zip(malicious_rows, malicious_embeddings):
            if not exclude_fn(other_row, row):
                store.upsert(other_row["id"], emb, other_row["attack_class"])
        layer2 = Layer2Similarity(embedder=embedder, store=store, threshold=threshold)

        t0 = time.perf_counter()
        result = layer2.score(row["description"])
        out[row["id"]] = Timed(result, time.perf_counter() - t0)
    return out


def run_layer2_heldout(
    scored_rows: list[dict],
    index_rows: list[dict],
    threshold: float,
) -> tuple[dict[str, Timed], SentenceTransformerEmbedder]:
    """The headline layer-2 configuration: ONE index, built from the
    train-split malicious rows, against which every scored row -- benign and
    malicious alike -- is scored.

    Because no scored row is in the index, there is nothing to leave out and
    no per-row index variation. Precision and recall therefore come from the
    same setup, which is what makes an F1 over them meaningful.
    """
    embedder = SentenceTransformerEmbedder()

    print(f"  embedding {len(index_rows)} train-split malicious descriptions for the attack index...")
    index_embeddings = embedder.embed([r["description"] for r in index_rows]) if index_rows else []

    store = InMemoryVectorStore()
    for row, emb in zip(index_rows, index_embeddings):
        store.upsert(row["id"], emb, row["attack_class"])
    layer2 = Layer2Similarity(embedder=embedder, store=store, threshold=threshold)

    print(f"  scoring {len(scored_rows)} held-out rows against it...")
    out = {}
    for row in scored_rows:
        t0 = time.perf_counter()
        result = layer2.score(row["description"])
        out[row["id"]] = Timed(result, time.perf_counter() - t0)
    return out, embedder


def run_layer2_diagnostics(
    malicious_rows: list[dict],
    embedder: SentenceTransformerEmbedder,
    threshold: float,
) -> tuple[dict[str, Timed], dict[str, Timed]]:
    """Supplementary, **recall-only** diagnostic: (leave_one_out, leave_one_seed_family_out).

    This is not the headline configuration -- run_layer2_heldout is. It is
    kept because the gap between the two schemes is a real and useful
    finding: leave-one-out excludes only the scored sample's own embedding,
    but 27 of the 38 malicious rows are mechanical variants of 11 seeds
    (rename tool, move payload, swap target -- see corpus/README.md), so a
    variant's parent and siblings stay in the index and a "hit" is often
    near-duplicate retrieval. Leave-one-seed-family-out excludes the whole
    family, so recall there reflects generalization from OTHER families
    only. The gap quantifies how much of layer 2's apparent recall was
    sibling retrieval.

    Scored over malicious rows only, and reported only as recall. Adding
    benign rows here would mean scoring them against a different index than
    the malicious rows saw, which is exactly the blend this harness no
    longer publishes.
    """
    print(f"  embedding {len(malicious_rows)} malicious descriptions for the diagnostic index...")
    malicious_embeddings = embedder.embed([r["description"] for r in malicious_rows])

    print("  leave-one-out (recall diagnostic)...")
    loo_cache = _build_layer2_cache(
        malicious_rows, malicious_rows, embedder, malicious_embeddings, threshold,
        exclude_fn=lambda candidate, scored: candidate["id"] == scored["id"],
    )

    print("  leave-one-seed-family-out (recall diagnostic)...")
    family_cache = _build_layer2_cache(
        malicious_rows, malicious_rows, embedder, malicious_embeddings, threshold,
        exclude_fn=lambda candidate, scored: seed_family_id(candidate) == seed_family_id(scored),
    )

    return loo_cache, family_cache


# --- layer 3 (real Anthropic API calls) ------------------------------------


MAX_TOLERABLE_API_ERROR_RATE = 0.2  # above this, the run is broken, not "layer 3 missed some attacks"


def run_layer3(rows: list[dict], model: str) -> tuple[dict[str, Timed], set[str]]:
    """Returns (results_by_row_id, ids_that_failed_with_an_api_error).

    The second element exists because an API error is not a detection
    result. Folding it into the "not flagged malicious" bucket -- which is
    what happens to every `layer3_failure` for scoring purposes -- makes a
    transient outage look like a recall miss. The committed report before
    this change carried 10/139 such rows straight in its recall
    denominator. Reporting the id set lets the caller publish an
    error-excluded figure beside the conventional one instead of choosing
    silently between them.
    """
    from anthropic import AuthenticationError, PermissionDeniedError

    layer3 = Layer3LLM(model=model)
    out = {}
    api_error_ids: set[str] = set()
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
            api_error_ids.add(row["id"])
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

    return out, api_error_ids


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


def render_layer2_diagnostic(
    threshold: float,
    loo_recall: tuple[int, int],
    family_recall: tuple[int, int],
    n_malicious: int,
) -> str:
    """Recall-only, and labelled as supplementary.

    Precision/F1 columns were deliberately removed from this table. Each
    scored row here sees a different index, and the benign rows they would
    have to be weighed against see a different one again -- so any
    precision computed across them describes no single configuration. The
    headline block above is the number to quote; this table answers only
    "how much of layer 2's recall is sibling retrieval?"
    """
    loo_caught, loo_total = loo_recall
    fam_caught, fam_total = family_recall
    lines = [
        f"### Supplementary diagnostic -- layer 2 index leakage (threshold={threshold})",
        "",
        "*Recall only, over all malicious rows. Not the headline configuration, and not comparable "
        "with the held-out numbers above: every row here is scored against an index built for that "
        "row alone.*",
        "",
        "| Indexing scheme | recall | caught / total |",
        "|---|---|---|",
        f"| Leave-one-out | {fmt(loo_caught / loo_total) if loo_total else 'nan'} | {loo_caught}/{loo_total} |",
        f"| Leave-one-seed-family-out | {fmt(fam_caught / fam_total) if fam_total else 'nan'} | {fam_caught}/{fam_total} |",
        "",
        f"**Why they differ:** 27 of the {n_malicious} malicious samples are mechanical variants of 11 seeds "
        "(rename tool / move payload / swap target -- see corpus/README.md). Leave-one-out only removes the "
        "scored sample's OWN embedding from the index; its parent seed and sibling variants (e.g. a seed with "
        "6 variants keeps all 6 in the index when scoring any one of them) remain, so a hit is often \"found "
        "the near-identical sibling still in the index\" rather than a generalized detection. "
        "Leave-one-seed-family-out removes the scored sample's ENTIRE family before scoring it, so its recall "
        "reflects generalization from OTHER seed families and attack classes only. **The gap between these "
        "two rows is the finding: it quantifies how much of layer 2's apparent recall was sibling retrieval "
        "rather than recognition of an unfamiliar attack.** The held-out configuration reported above answers "
        "the same question more directly -- its index contains no scored row's family at all -- so these rows "
        "are retained as corroboration, not as an alternative headline.",
        "",
    ]
    return "\n".join(lines)


def render_latency(title: str, latencies_s: list[float]) -> str:
    p50 = percentile(latencies_s, 50) * 1000
    p95 = percentile(latencies_s, 95) * 1000
    return f"{title}: p50={p50:.2f}ms  p95={p95:.2f}ms  (n={len(latencies_s)})"


# --- main ---------------------------------------------------------------------


def _predictions(cache: dict[str, Timed]) -> dict[str, bool]:
    return {rid: t.result.verdict == "malicious" for rid, t in cache.items()}


def _recall_pair(rows: list[dict], pred: dict[str, bool]) -> tuple[int, int]:
    caught = sum(1 for r in rows if pred.get(r["id"]))
    return caught, len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS_PATH)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT_PATH)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--limit", type=int, default=None, help="Only score the first N rows (smoke-test aid; marks the run partial).")
    parser.add_argument("--skip-llm", action="store_true", help="Skip layer 3 / cascade entirely (smoke-test aid; marks the run partial).")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--layer2-threshold", type=float, default=DEFAULT_LAYER2_THRESHOLD)
    parser.add_argument("--layer1-short-circuit", type=float, default=DEFAULT_LAYER1_SHORT_CIRCUIT_CONFIDENCE)
    parser.add_argument("--layer2-short-circuit", type=float, default=DEFAULT_LAYER2_SHORT_CIRCUIT_SIMILARITY)
    args = parser.parse_args()

    run_started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    wall_start = time.perf_counter()

    all_rows = load_corpus(args.corpus)
    missing_split = [r["id"] for r in all_rows if "split" not in r]
    if missing_split:
        print(
            f"ABORTING: {len(missing_split)} corpus rows have no `split` field "
            f"(first: {missing_split[:3]}). Re-run corpus/build_corpus.py -- the "
            f"held-out configuration cannot be constructed without it."
        )
        sys.exit(1)

    rows = all_rows[: args.limit] if args.limit else all_rows

    # The scored population is the held-out side only. The train side exists
    # solely to build layer 2's attack index -- nothing scored here has ever
    # been in that index, which is what makes precision and recall below
    # products of the same configuration.
    scored_rows = [r for r in rows if r["split"] == split.HELD_OUT]
    index_rows = [r for r in rows if r["split"] == split.TRAIN and r["label"] == "malicious"]
    all_malicious = [r for r in all_rows if r["label"] == "malicious"]

    benign_rows = [r for r in scored_rows if r["label"] == "benign"]
    malicious_rows = [r for r in scored_rows if r["label"] == "malicious"]

    if not scored_rows or not malicious_rows:
        print(
            "ABORTING: the held-out split is empty (or has no malicious rows) for this "
            "corpus slice. --limit takes the first N rows in file order, which is "
            "benign-first; use a larger N or drop --limit."
        )
        sys.exit(1)

    print(f"Corpus: {len(all_rows)} rows total; split spec {split.SPLIT_SPEC}")
    print(split.summarize(all_rows))
    print(
        f"Scoring {len(scored_rows)} held-out rows "
        f"({len(benign_rows)} benign, {len(malicious_rows)} malicious) "
        f"against an index of {len(index_rows)} train-split malicious rows."
    )

    print("Running layer 1 (deterministic rules)...")
    l1_cache = run_layer1(scored_rows)

    print("Running layer 2 (local embedding similarity, held-out index)...")
    l2_cache, embedder = run_layer2_heldout(scored_rows, index_rows, args.layer2_threshold)

    print("Running layer 2 index-leakage diagnostics (local, recall only)...")
    l2_loo_cache, l2_family_cache = run_layer2_diagnostics(all_malicious, embedder, args.layer2_threshold)

    api_error_ids: set[str] = set()
    if args.skip_llm:
        print("--skip-llm set: layer 3 and the cascade will not be scored.")
        l3_cache = None
        cascade_cache = None
    else:
        print(f"Running layer 3 ({args.model}, {len(scored_rows)} real API calls)...")
        l3_cache, api_error_ids = run_layer3(scored_rows, args.model)
        print("Running cascade (replays cached layer2/layer3 results, no re-billing)...")
        cascade_cache = run_cascade(
            scored_rows, l1_cache, l2_cache, l3_cache, args.layer1_short_circuit, args.layer2_short_circuit
        )

    wall_elapsed = time.perf_counter() - wall_start

    config = fingerprint.build(
        corpus_path=args.corpus,
        corpus_rows=len(all_rows),
        split_spec=split.SPLIT_SPEC,
        scored_split=split.HELD_OUT,
        model=args.model,
        embedder_model=getattr(embedder, "model_name", "unknown"),
        layer2_threshold=args.layer2_threshold,
        layer1_short_circuit=args.layer1_short_circuit,
        layer2_short_circuit=args.layer2_short_circuit,
        limit=args.limit,
        skip_llm=args.skip_llm,
    )

    metrics: dict = {"scored_rows": len(scored_rows), "index_rows": len(index_rows)}
    sections = []

    # ---- layer 1 ----
    l1_pred = _predictions(l1_cache)
    l1_uncertain_n = sum(1 for t in l1_cache.values() if t.result.verdict == "uncertain")
    l1_prf = confusion_and_prf(scored_rows, l1_pred)
    l1_latencies = [t.latency_s for t in l1_cache.values()]
    metrics["layer1"] = {**asdict(l1_prf), "uncertain": l1_uncertain_n,
                         "latency_p50_ms": percentile(l1_latencies, 50) * 1000,
                         "latency_p95_ms": percentile(l1_latencies, 95) * 1000}

    sections.append(render_prf_block("Layer 1 -- deterministic rules (held-out)", l1_prf, [
        f"'uncertain' verdicts (scored as not-flagged above): {l1_uncertain_n}/{len(scored_rows)}",
    ]))
    sections.append(render_recall_by_class(recall_by_attack_class(malicious_rows, l1_pred)))
    sections.append(render_latency("Layer 1 latency", l1_latencies))
    sections.append("")

    # ---- layer 2 ----
    l2_pred = _predictions(l2_cache)
    l2_prf = confusion_and_prf(scored_rows, l2_pred)
    l2_latencies = [t.latency_s for t in l2_cache.values()]
    metrics["layer2"] = {**asdict(l2_prf), "threshold": args.layer2_threshold,
                         "index_rows": len(index_rows),
                         "latency_p50_ms": percentile(l2_latencies, 50) * 1000,
                         "latency_p95_ms": percentile(l2_latencies, 95) * 1000}

    sections.append(render_prf_block(
        f"Layer 2 -- embedding similarity (held-out; threshold={args.layer2_threshold}, "
        f"index={len(index_rows)} train-split malicious rows)", l2_prf))
    sections.append(render_recall_by_class(recall_by_attack_class(malicious_rows, l2_pred)))
    sections.append(render_latency("Layer 2 latency", l2_latencies))
    sections.append("Layer 2 cost: $0.00 (local model, no API calls)")
    sections.append("")

    loo_recall = _recall_pair(all_malicious, _predictions(l2_loo_cache))
    family_recall = _recall_pair(all_malicious, _predictions(l2_family_cache))
    metrics["layer2_diagnostic"] = {
        "leave_one_out_recall": loo_recall[0] / loo_recall[1] if loo_recall[1] else None,
        "leave_one_out": list(loo_recall),
        "leave_one_seed_family_out_recall": family_recall[0] / family_recall[1] if family_recall[1] else None,
        "leave_one_seed_family_out": list(family_recall),
    }
    sections.append(render_layer2_diagnostic(args.layer2_threshold, loo_recall, family_recall, len(all_malicious)))

    # ---- layer 3 ----
    if l3_cache is not None:
        l3_pred = _predictions(l3_cache)
        l3_span_rejections = sum(
            1 for t in l3_cache.values() if t.result.rejected_reason == "evidence_span_not_literal_substring"
        )
        l3_other_failures = sum(
            1 for t in l3_cache.values()
            if t.result.verdict == "layer3_failure" and t.result.rejected_reason != "evidence_span_not_literal_substring"
        )
        l3_prf = confusion_and_prf(scored_rows, l3_pred)
        l3_latencies = [t.latency_s for t in l3_cache.values()]
        l3_input_tokens = sum(t.result.input_tokens for t in l3_cache.values())
        l3_output_tokens = sum(t.result.output_tokens for t in l3_cache.values())
        l3_cost_per_1000 = (
            (l3_input_tokens / len(scored_rows)) * 1000 * OPUS5_INPUT_USD_PER_TOKEN
            + (l3_output_tokens / len(scored_rows)) * 1000 * OPUS5_OUTPUT_USD_PER_TOKEN
        )

        # An API error is not a detection outcome. Reported beside the
        # conventional figure so a transient outage can never be read as a
        # recall miss (see run_layer3's docstring).
        healthy_rows = [r for r in scored_rows if r["id"] not in api_error_ids]
        l3_prf_excl = confusion_and_prf(healthy_rows, l3_pred)

        extra = [
            f"evidence-span rejection rate: {fmt(l3_span_rejections / len(scored_rows))} "
            f"({l3_span_rejections}/{len(scored_rows)})",
            f"other layer3 failures (e.g. API errors, no parsed output): {l3_other_failures}/{len(scored_rows)}",
        ]
        if api_error_ids:
            extra.append(
                f"API-error rows excluded: {len(api_error_ids)}/{len(scored_rows)} -- "
                f"excluding them, precision={fmt(l3_prf_excl.precision)} "
                f"recall={fmt(l3_prf_excl.recall)} F1={fmt(l3_prf_excl.f1)} (n={l3_prf_excl.n}). "
                f"An API error is an outage, not a missed detection; both figures are shown "
                f"so neither convention hides the other."
            )
        else:
            extra.append("API-error rows: 0 -- no error-excluded figure is needed for this run.")

        metrics["layer3"] = {
            **asdict(l3_prf), "model": args.model,
            "api_error_rows": len(api_error_ids),
            "prf_excluding_api_errors": asdict(l3_prf_excl),
            "span_rejections": l3_span_rejections,
            "other_failures": l3_other_failures,
            "input_tokens": l3_input_tokens, "output_tokens": l3_output_tokens,
            "cost_per_1000_usd": l3_cost_per_1000,
            "latency_p50_ms": percentile(l3_latencies, 50) * 1000,
            "latency_p95_ms": percentile(l3_latencies, 95) * 1000,
        }

        sections.append(render_prf_block(
            f"Layer 3 -- LLM classifier ({args.model}, standalone: every held-out row classified)",
            l3_prf, extra))
        sections.append(render_recall_by_class(recall_by_attack_class(malicious_rows, l3_pred)))
        sections.append(render_latency("Layer 3 latency", l3_latencies))
        sections.append(
            f"Layer 3 tokens: {l3_input_tokens} input + {l3_output_tokens} output "
            f"across {len(scored_rows)} calls (standalone -- every held-out row, not just cascade fallthrough)"
        )
        sections.append(f"Layer 3 estimated cost per 1,000 tools scanned (standalone): ${l3_cost_per_1000:.2f}")
        sections.append("")

    # ---- cascade ----
    if cascade_cache is not None:
        cm = compute_cascade_metrics(cascade_cache, scored_rows, malicious_rows)
        metrics["cascade"] = {
            **asdict(cm.prf), "produced_by": cm.produced_by,
            "llm_invocations": cm.llm_invocations, "invocation_rate": cm.invocation_rate,
            "input_tokens": cm.input_tokens, "output_tokens": cm.output_tokens,
            "cost_per_1000_usd": cm.cost_per_1000, "span_rejections": cm.span_rejections,
            "latency_p50_ms": percentile(cm.latencies, 50) * 1000,
            "latency_p95_ms": percentile(cm.latencies, 95) * 1000,
        }

        sections.append(render_prf_block("Full cascade (held-out)", cm.prf, [
            f"produced_by breakdown: layer1={cm.produced_by['layer1']}, "
            f"layer2={cm.produced_by['layer2']}, layer3={cm.produced_by['layer3']} (n={len(scored_rows)})",
            f"LLM invocation rate (fraction reaching layer 3): {fmt(cm.invocation_rate)} "
            f"({cm.llm_invocations}/{len(scored_rows)})",
            f"evidence-span rejection rate (of rows reaching layer 3): "
            f"{fmt(cm.span_rejections / cm.llm_invocations) if cm.llm_invocations else 'n/a'} "
            f"({cm.span_rejections}/{cm.llm_invocations})",
        ]))
        sections.append(render_recall_by_class(cm.recall_by_class))
        sections.append(render_latency("Cascade end-to-end latency", cm.latencies))
        sections.append(
            f"Cascade tokens actually spent: {cm.input_tokens} input + {cm.output_tokens} "
            f"output across {cm.llm_invocations} LLM calls (out of {len(scored_rows)} rows)"
        )
        sections.append(f"Cascade estimated cost per 1,000 tools scanned: ${cm.cost_per_1000:.2f}")
        sections.append("")

    results_body = "\n".join(sections)

    print("\n" + "=" * 80)
    print(results_body)
    print("=" * 80)
    print(f"Wall-clock eval duration: {wall_elapsed:.1f}s")

    per_row = []
    for row in scored_rows:
        rid = row["id"]
        entry = {
            "id": rid, "label": row["label"], "attack_class": row["attack_class"],
            "split": row["split"],
            "layer1": l1_cache[rid].result.verdict,
            "layer2_similarity": l2_cache[rid].result.similarity,
            "layer2": l2_cache[rid].result.verdict,
        }
        if l3_cache is not None:
            entry["layer3"] = l3_cache[rid].result.verdict
            entry["layer3_rejected_reason"] = l3_cache[rid].result.rejected_reason
            entry["api_error"] = rid in api_error_ids
        if cascade_cache is not None:
            entry["cascade"] = cascade_cache[rid].result.verdict
            entry["cascade_produced_by"] = cascade_cache[rid].result.produced_by
        per_row.append(entry)

    manifest = config.manifest(started_at=run_started_at, wall_elapsed_s=wall_elapsed)
    out_dir = fingerprint.write_results(
        args.results_dir, config, manifest=manifest, metrics=metrics, rows=per_row
    )
    print(f"\nWrote machine-readable results to {out_dir}")

    if config.is_partial:
        print(
            f"\nPartial run (limit={args.limit}, skip_llm={args.skip_llm}): "
            f"{args.report} was NOT overwritten. A partial measurement must not be "
            f"published as if it were a full one -- see {out_dir}/manifest.json."
        )
        return

    write_report(args, config, all_rows, scored_rows, index_rows, benign_rows, malicious_rows,
                 results_body, run_started_at, wall_elapsed)
    print(f"Wrote {args.report}")


def write_report(args, config, all_rows, scored_rows, index_rows, benign_rows, malicious_rows,
                 results_body, run_started_at, wall_elapsed) -> None:
    all_malicious = [r for r in all_rows if r["label"] == "malicious"]
    corpus_label_counts = (
        f"{len(all_rows)} rows "
        f"({sum(1 for r in all_rows if r['label'] == 'benign')} benign, {len(all_malicious)} malicious)"
    )
    scored_counts = f"{len(scored_rows)} rows ({len(benign_rows)} benign, {len(malicious_rows)} malicious)"
    attack_class_counts = defaultdict(int)
    for r in all_malicious:
        attack_class_counts[r["attack_class"]] += 1
    seed_count = sum(1 for r in all_malicious if r["derivation"] == "original")
    variant_count = sum(1 for r in all_malicious if r["derivation"].startswith("variant_of"))

    report = f"""# Portcullis Scanner -- Evaluation Report

Run fingerprint: `{config.fingerprint}`
Generated: {run_started_at}
Corpus: `control/evals/corpus/corpus.jsonl` -- {corpus_label_counts}, sha256 `{config.corpus_sha256[:16]}`
Scored population: **held-out split only** -- {scored_counts}
Layer 2 attack index: {len(index_rows)} train-split malicious rows
Layer 3 model: `{config.model}`
Layer 2 embedder: `{config.embedder_model}` (local, sentence-transformers, 384-dim)
Harness version: {config.harness_version}   git: `{config.git_sha}`
Package versions: {", ".join(f"{k}=={v}" for k, v in sorted(config.packages.items()))}
Eval wall-clock duration: {wall_elapsed:.1f}s

Machine-readable results for this run: `control/evals/results/{config.fingerprint}/`
(`manifest.json`, `metrics.json`, `rows.jsonl`).

> **Quoting a number from this report:** cite it together with the run
> fingerprint above. Numbers from two different fingerprints came from two
> different configurations and are not comparable -- that is precisely the
> mistake this harness was restructured to make impossible.

## Methodology and limitations

**Corpus size and provenance.** {corpus_label_counts}. Full per-sample provenance
is in `control/evals/corpus/README.md`; summary:

- **Benign ({sum(1 for r in all_rows if r['label'] == 'benign')}):** harvested live via `initialize` -> `tools/list`
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

**There is now a held-out split, and every headline number comes from it.**
Split spec `{config.split_spec}` (see `control/evals/split.py`). The assignment is
grouped, not row-wise: malicious rows move as whole **seed families** and benign
rows as whole **source servers**, stratified so all four attack classes appear on
both sides. Group ordering is a hash of the group's own identifier, so the split
was fixed before any number was computed and cannot be re-rolled to flatter a
result. The `split` field is committed into `corpus.jsonl`, so which side a row
landed on is auditable in git.

Split composition:

```
{split.summarize(all_rows)}
```

**What this fixed.** Layer 2 previously scored malicious rows against an index
with the row (or its seed family) removed, while scoring benign rows against the
*full* index. Precision and recall inside a single published pair therefore came
from two different index configurations, and the F1 over them described neither.
Now there is one index -- built from train-split malicious rows only -- and one
scored population, the held-out side, none of which is in that index. The
leave-one-out / leave-one-seed-family-out comparison is retained below as a
**recall-only supplementary diagnostic** over all malicious rows, clearly marked
as not comparable with the headline block.

**Remaining limitations, unchanged by the split:**

1. Even the held-out families come from the same {seed_count}-seed pool this corpus
   was built from. A held-out family is unseen *by the index*, not drawn from an
   independent attack corpus by a different author.
2. Layer 1's rules were authored with the seed set visible (see
   `layer1_rules.py`'s own docstring: two rule categories were added because they
   "show up heavily in the actual corpus seeds"). Its held-out recall is
   therefore still optimistic relative to genuinely novel attacks, even though no
   held-out row was individually inspected.
3. *Layer 3* is a general-purpose LLM classifier; nothing here confirms whether
   `{config.model}` was trained on the (public) disclosures the seeds are drawn
   from. A strong layer-3 score is consistent with either "the classifier reasons
   well about this attack pattern" or "the classifier has seen this exact public
   writeup before" -- this script cannot distinguish the two.

**Thresholds are untouched code defaults**, not tuned against this corpus or
this run:
- Layer 1 short-circuit confidence: `{config.layer1_short_circuit}` (cascade.py default)
- Layer 2 verdict threshold: `{config.layer2_threshold}` (layer2_similarity.py default)
- Layer 2 cascade short-circuit similarity: `{config.layer2_short_circuit}` (cascade.py default)

No threshold sweep was run and no value was chosen after looking at the
resulting precision/recall. If a future run changes any of these to chase a
headline number, that must be stated here explicitly, not silently -- and the
run fingerprint will change, so the two reports cannot be confused.

**Verdict-scoring convention.** For precision/recall purposes, layer 1's
`uncertain` verdict and layer 3 / cascade's `layer3_failure` verdict are both
scored as *not flagged malicious* (i.e. treated like `benign`). Rationale: a
layer used standalone, with no downstream layer to resolve the ambiguity,
would let the tool through either way. Each layer's deferral/rejection rate
is reported as its own line so this convention doesn't obscure it. Rows whose
layer-3 call raised a transport/API error are additionally reported as an
error-excluded figure, because an outage is not a detection outcome.

**Layer 3 cost avoidance.** Layer 3 is called once per held-out row to produce
real standalone layer-3 metrics (a genuine Anthropic API call per row, real
tokens, real latency). The cascade run then *replays* those same per-row
results for whichever rows fall through to layer 3, instead of issuing a
second live call for the same (row, classifier) pair. This avoids
double-billing identical work while still exercising the cascade's real
short-circuit logic and reporting genuine per-row cost/latency for whichever
layer actually produced the verdict.

**Small-sample warning.** Any attack class with fewer than 10 malicious samples
has its recall figure marked "not statistically meaningful" below -- treat those
numbers as anecdotal. The held-out split makes this more acute, not less: it is
a fraction of an already-small malicious set. `n` is printed beside every figure.

## Results

{results_body}
"""
    args.report.write_text(report)


if __name__ == "__main__":
    main()
