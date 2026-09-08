"""Puts `control/evals/` on sys.path for the eval-harness tests.

`evals/` is deliberately not a package (pyproject's
`[tool.hatch.build.targets.wheel] packages = ["scanner"]` ships the scanner
only), and `run_eval.py` bootstraps its own imports the same way at
run_eval.py:59. This mirrors that rather than making `evals/` importable
just to satisfy pytest.
"""

from __future__ import annotations

import sys
from pathlib import Path

EVALS_DIR = Path(__file__).resolve().parent.parent
if str(EVALS_DIR) not in sys.path:
    sys.path.insert(0, str(EVALS_DIR))
