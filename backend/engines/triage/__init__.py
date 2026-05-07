"""
FortKnoxx triage engine.

Three-stage post-processing pipeline that runs after the unified scanner:

  1. fingerprint  — canonical hash that survives file moves and minor edits
  2. dedup        — collapse findings sharing a fingerprint across scanners
  3. llm_triage   — single LLM call per unique fingerprint, cached forever

Plus:
  4. ignore       — apply .fortknoxx/ignore.yml suppressions

Designed to run *after* the existing utils/false_positive_filter.py so it
can be enabled incrementally without breaking current behaviour.
"""

from .fingerprint import build_fingerprint
from .cwe_map import canonical_cwe_family
from .dedup import deduplicate
from .llm_triage import triage_findings
from .ignore import apply_ignore_rules
from .pipeline import run_triage

__all__ = [
    "build_fingerprint",
    "canonical_cwe_family",
    "deduplicate",
    "triage_findings",
    "apply_ignore_rules",
    "run_triage",
]
