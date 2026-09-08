"""Run identity for the eval harness.

Why this exists
---------------
`run_eval.py` used to call `args.report.write_text(...)` on a fixed path:
every run destructively overwrote REPORT.md, produced no machine-readable
artifact, and recorded no git SHA, corpus hash or library versions. Two
consequences, both of which showed up in the committed docs:

  * A `--limit 5` smoke run wrote a report structurally identical to a full
    run, so a partial measurement was indistinguishable from a real one.
  * Numbers copied into README.md and bench/results.md could not be traced
    back to the run that produced them, which is how figures from
    different configurations ended up quoted side by side as if
    comparable.

A `RunConfig` fingerprints every input that can change a number. Results
are written to `evals/results/<fingerprint>/`, append-only, and REPORT.md
is stamped with the fingerprint it was generated from. Two reports with the
same fingerprint are the same configuration; two with different
fingerprints are not comparable, and now say so.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
from dataclasses import asdict, dataclass, field
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

# Bumped when the harness changes in a way that alters what a number means
# (scored population, index construction, scoring convention) even though
# every other input is identical.
HARNESS_VERSION = "2"

# Packages whose resolved version can change a measured number:
# sentence-transformers (and its transitive torch/transformers) determine
# every layer-2 embedding; anthropic determines layer-3 SDK behaviour.
TRACKED_PACKAGES = ("anthropic", "sentence-transformers", "torch", "transformers", "pydantic")


def _package_versions() -> dict[str, str]:
    out = {}
    for name in TRACKED_PACKAGES:
        try:
            out[name] = version(name)
        except PackageNotFoundError:
            out[name] = "not-installed"
    return out


def _git_sha() -> str:
    """The commit the harness ran at, or a sentinel. Never raises: a report
    from a tarball without git history is still a valid report, it just
    can't claim a commit."""
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=Path(__file__).resolve().parent,
        )
        if sha.returncode != 0:
            return "unknown"
        dirty = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=Path(__file__).resolve().parent,
        )
        suffix = "-dirty" if dirty.returncode == 0 and dirty.stdout.strip() else ""
        return sha.stdout.strip() + suffix
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class RunConfig:
    """Every input that can move a reported number.

    Anything absent from this struct is, by construction, a claim that it
    cannot change the measurement.
    """

    harness_version: str
    corpus_path: str
    corpus_sha256: str
    corpus_rows: int
    split_spec: str
    scored_split: str
    model: str
    embedder_model: str
    layer2_threshold: float
    layer1_short_circuit: float
    layer2_short_circuit: float
    limit: int | None
    skip_llm: bool
    git_sha: str
    packages: dict[str, str] = field(default_factory=_package_versions)

    @property
    def fingerprint(self) -> str:
        """Short, stable digest over the canonical form of this config.

        Deliberately excludes wall-clock time, machine identity and row
        ordering: two runs of the same configuration on different days must
        land in the same bucket, or "same setup" means nothing.
        """
        canonical = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    @property
    def is_partial(self) -> bool:
        """A run that did not score the full corpus. Partial runs are
        written to results/ but must never overwrite REPORT.md."""
        return self.limit is not None or self.skip_llm

    def manifest(self, *, started_at: str, wall_elapsed_s: float, extra: dict | None = None) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "started_at": started_at,
            "wall_elapsed_s": round(wall_elapsed_s, 3),
            "partial": self.is_partial,
            "config": asdict(self),
            **(extra or {}),
        }


def build(
    *,
    corpus_path: Path,
    corpus_rows: int,
    split_spec: str,
    scored_split: str,
    model: str,
    embedder_model: str,
    layer2_threshold: float,
    layer1_short_circuit: float,
    layer2_short_circuit: float,
    limit: int | None,
    skip_llm: bool,
) -> RunConfig:
    return RunConfig(
        harness_version=HARNESS_VERSION,
        corpus_path=str(corpus_path),
        corpus_sha256=file_sha256(corpus_path),
        corpus_rows=corpus_rows,
        split_spec=split_spec,
        scored_split=scored_split,
        model=model,
        embedder_model=embedder_model,
        layer2_threshold=layer2_threshold,
        layer1_short_circuit=layer1_short_circuit,
        layer2_short_circuit=layer2_short_circuit,
        limit=limit,
        skip_llm=skip_llm,
        git_sha=_git_sha(),
    )


def _json_safe(value):
    """Replace NaN/Infinity with null, recursively.

    Python's json module emits bare `NaN` by default, which is not valid
    JSON (RFC 8259) and is rejected by strict parsers -- Go's
    encoding/json among them. These artifacts are meant to be read by other
    tools, so an undefined metric (precision with no positive predictions,
    say) is written as `null` rather than as a token that fails to parse.
    """
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return None
    return value


def write_results(
    results_dir: Path,
    config: RunConfig,
    *,
    manifest: dict,
    metrics: dict,
    rows: list[dict],
) -> Path:
    """Write the machine-readable artifacts for one run.

    Append-only by directory: a re-run of the same configuration replaces
    only its own bucket, and a different configuration can never clobber
    another's numbers.
    """
    out = results_dir / config.fingerprint
    out.mkdir(parents=True, exist_ok=True)
    (out / "manifest.json").write_text(
        json.dumps(_json_safe(manifest), indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    (out / "metrics.json").write_text(
        json.dumps(_json_safe(metrics), indent=2, sort_keys=True, allow_nan=False) + "\n"
    )
    with (out / "rows.jsonl").open("w") as f:
        for row in rows:
            f.write(json.dumps(_json_safe(row), sort_keys=True, allow_nan=False) + "\n")
    return out
