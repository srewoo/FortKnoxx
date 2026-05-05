"""Test configuration shared across the suite.

WHY: pytest discovers tests starting from `backend/tests/`, but the
imports under test (`server`, `llm.model_registry`, …) live in
`backend/`. Adding the parent dir to sys.path here keeps the package
layout simple — no editable install required, no PYTHONPATH magic in
CI.
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
