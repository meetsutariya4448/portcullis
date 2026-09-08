"""Entry point for the scanning worker.

    PORTCULLIS_ADMISSION_DATABASE_URL=... python3 -m app.run_worker [--once]

Layer 2's attack index is seeded from the corpus's TRAIN split only, via the
same control/evals/split.py the eval harness uses. That is what makes the
published held-out quality numbers describe the classifier actually running
in production, rather than a differently-indexed one.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "evals"))

import split  # noqa: E402
from app.db import PostgresQueue, connect  # noqa: E402
from app.worker import Worker  # noqa: E402

CORPUS = Path(__file__).resolve().parent.parent / "evals" / "corpus" / "corpus.jsonl"


def build_cascade(scanner_fingerprint: str):
    from scanner.cascade import Cascade
    from scanner.layer2_similarity import (
        InMemoryVectorStore,
        Layer2Similarity,
        SentenceTransformerEmbedder,
    )
    from scanner.layer3_llm import Layer3LLM

    rows = [json.loads(line) for line in CORPUS.open() if line.strip()]
    index_rows = [r for r in rows if r["label"] == "malicious" and r["split"] == split.TRAIN]

    embedder = SentenceTransformerEmbedder()
    store = InMemoryVectorStore()
    layer2 = Layer2Similarity(embedder=embedder, store=store)
    layer2.index_corpus(index_rows)
    logging.getLogger("portcullis.worker").info(
        "layer 2 indexed %d train-split attacks (split %s)", len(index_rows), split.SPLIT_SPEC
    )
    return Cascade(layer2=layer2, layer3=Layer3LLM())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="Drain the queue once and exit.")
    parser.add_argument("--batch", type=int, default=4)
    parser.add_argument("--dsn", default=None)
    parser.add_argument(
        "--scanner-fingerprint",
        default=os.environ.get("PORTCULLIS_SCANNER_FINGERPRINT", ""),
        help="Eval run fingerprint characterizing this scanner configuration "
             "(control/evals/results/<fingerprint>/). Stamped onto every verdict.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    worker = Worker(
        queue=PostgresQueue(connect(args.dsn)),
        cascade=build_cascade(args.scanner_fingerprint),
        scanner_fingerprint=args.scanner_fingerprint,
    )

    if args.once:
        processed = 1
        total = 0
        while processed:
            processed = worker.run_once(batch=args.batch)
            total += processed
        logging.getLogger("portcullis.worker").info("drained %d job(s)", total)
        return
    worker.run_forever(batch=args.batch)


if __name__ == "__main__":
    main()
