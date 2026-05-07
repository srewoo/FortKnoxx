"""
Triage pipeline orchestrator.

Single entry point used by server.py — runs fingerprint → dedup → ignore →
LLM triage in order, returning the cleaned finding list plus a metadata
dict for the report.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .cwe_map import canonical_cwe_family
from .dedup import deduplicate
from .ignore import apply_ignore_rules
from .llm_triage import triage_findings

logger = logging.getLogger(__name__)


def _annotate_cwe_family(findings: list[dict]) -> None:
    for f in findings:
        cwe = f.get("cwe") or f.get("cwe_id")
        f.setdefault("cwe_family", canonical_cwe_family(str(cwe) if cwe else None))


async def run_triage(
    findings: list[dict],
    *,
    repo_path: str,
    db=None,
    orchestrator=None,
    llm_provider: str = "anthropic",
    llm_model: Optional[str] = None,
    enable_llm: bool = True,
) -> tuple[list[dict], dict[str, Any]]:
    """Apply the full triage pipeline.

    Returns ``(findings, meta)``.  ``meta`` carries:
      original_count, deduped_count, suppressed_count, expired_rules,
      llm_calls, llm_cache_hits.
    """
    original_count = len(findings)

    # 1. fingerprint + cwe_family + dedup
    deduped = deduplicate(findings, repo_path=repo_path)
    _annotate_cwe_family(deduped)

    # 2. .fortknoxx/ignore.yml
    kept, ignore_meta = apply_ignore_rules(deduped, repo_path)

    # 3. LLM triage (cached)
    if enable_llm and orchestrator is not None:
        kept = await triage_findings(
            kept,
            db=db,
            orchestrator=orchestrator,
            provider=llm_provider,
            model=llm_model,
        )

    cache_hits = sum(1 for f in kept if (f.get("triage") or {}).get("cached"))
    llm_calls = sum(
        1 for f in kept if f.get("triage") and not (f.get("triage") or {}).get("cached")
    )

    meta = {
        "original_count": original_count,
        "deduped_count": len(deduped),
        "kept_count": len(kept),
        "suppressed_count": len(ignore_meta["suppressed"]),
        "expired_rules": len(ignore_meta["expired_rules"]),
        "llm_calls": llm_calls,
        "llm_cache_hits": cache_hits,
    }
    logger.info("Triage complete: %s", meta)
    return kept, meta
