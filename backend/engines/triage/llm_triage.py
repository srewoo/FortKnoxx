"""
LLM-powered finding triage with permanent fingerprint cache.

Cost model:
  • One LLM call per *unique* fingerprint, ever.
  • Verdicts are persisted to MongoDB (`triage_cache` collection).
  • Re-scans of the same repo = $0.

Verdict schema returned by the LLM:
  {
    "verdict": "true_positive" | "likely_fp" | "needs_context",
    "confidence": 0.0–1.0,
    "reason": "<= 200 chars"
  }

If no LLM provider is available the function is a no-op — findings pass
through with `triage_verdict = "uncertain"` so the caller can still rank
them by scanner reliability.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CACHE_COLLECTION = "triage_cache"
_VALID_VERDICTS = {"true_positive", "likely_fp", "needs_context"}

_SYSTEM_PROMPT = (
    "You are a senior application security engineer triaging static-analysis "
    "findings. For each finding, decide whether it is a true positive, a "
    "likely false positive, or needs human context. Be conservative — when "
    "unsure, return needs_context. Respond ONLY with a single JSON object: "
    '{"verdict": "true_positive"|"likely_fp"|"needs_context", '
    '"confidence": 0.0-1.0, "reason": "<=200 chars"}.'
)

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _summarise(finding: dict) -> str:
    """Compact, deterministic finding summary for the prompt.

    Determinism matters: the same finding must produce the same prompt so
    LLM-side caching (where available) also kicks in.
    """
    parts = [
        f"file: {finding.get('file_path') or finding.get('file') or 'unknown'}",
        f"line: {finding.get('line_start') or finding.get('line') or '?'}",
        f"cwe: {finding.get('cwe') or finding.get('cwe_id') or 'unknown'}",
        f"severity: {finding.get('severity', 'medium')}",
        f"sources: {','.join(sorted(finding.get('sources') or [finding.get('detected_by', 'unknown')]))}",
        f"title: {(finding.get('title') or finding.get('rule_id') or '')[:140]}",
    ]
    snippet = (finding.get("code") or finding.get("snippet") or "")[:400]
    if snippet:
        parts.append(f"code: {snippet}")
    desc = (finding.get("description") or "")[:300]
    if desc:
        parts.append(f"description: {desc}")
    return "\n".join(parts)


def _parse_verdict(raw: str) -> dict[str, Any]:
    """Best-effort JSON parse. LLMs occasionally wrap output in markdown."""
    if not raw:
        return {"verdict": "needs_context", "confidence": 0.0, "reason": "empty response"}
    match = _JSON_RE.search(raw)
    if not match:
        return {"verdict": "needs_context", "confidence": 0.0, "reason": "no JSON in response"}
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {"verdict": "needs_context", "confidence": 0.0, "reason": "invalid JSON"}
    verdict = str(data.get("verdict", "needs_context")).lower()
    if verdict not in _VALID_VERDICTS:
        verdict = "needs_context"
    try:
        confidence = float(data.get("confidence", 0.5))
    except (TypeError, ValueError):
        confidence = 0.5
    reason = str(data.get("reason", ""))[:200]
    return {"verdict": verdict, "confidence": max(0.0, min(1.0, confidence)), "reason": reason}


async def _cached_verdict(db, fingerprint: str) -> Optional[dict]:
    if db is None:
        return None
    try:
        doc = await db[_CACHE_COLLECTION].find_one({"_id": fingerprint})
    except Exception as exc:
        logger.debug("triage cache read failed: %s", exc)
        return None
    return doc


async def _store_verdict(db, fingerprint: str, payload: dict) -> None:
    if db is None:
        return
    try:
        await db[_CACHE_COLLECTION].update_one(
            {"_id": fingerprint},
            {"$set": payload},
            upsert=True,
        )
    except Exception as exc:
        logger.debug("triage cache write failed: %s", exc)


async def _ask_llm(
    orchestrator,
    finding: dict,
    *,
    provider: str,
    model: Optional[str],
) -> dict[str, Any]:
    """One LLM call. Temperature 0 for cache-friendliness."""
    try:
        raw = await orchestrator.generate_completion(
            provider=provider,
            model=model,
            messages=[{"role": "user", "content": _summarise(finding)}],
            system_message=_SYSTEM_PROMPT,
            temperature=0.0,
            max_tokens=200,
        )
    except Exception as exc:
        logger.warning("LLM triage call failed: %s", exc)
        return {"verdict": "needs_context", "confidence": 0.0, "reason": f"llm error: {exc}"}
    return _parse_verdict(raw)


async def triage_findings(
    findings: list[dict],
    *,
    db=None,
    orchestrator=None,
    provider: str = "anthropic",
    model: Optional[str] = None,
    concurrency: int = 4,
) -> list[dict]:
    """Annotate each finding with a triage verdict (cached by fingerprint).

    Mutates and returns the input list. The mutation is intentional — the
    triage pipeline composes multiple in-place stages.
    """
    if not findings:
        return findings

    # No LLM available → mark uncertain and bail without burning cycles.
    if orchestrator is None or not orchestrator.is_provider_available(provider):
        for f in findings:
            f.setdefault(
                "triage",
                {"verdict": "uncertain", "confidence": 0.0, "reason": "no LLM provider"},
            )
        return findings

    sem = asyncio.Semaphore(concurrency)

    async def _process(f: dict):
        fp = f.get("fingerprint")
        if not fp:
            f["triage"] = {"verdict": "uncertain", "confidence": 0.0, "reason": "no fingerprint"}
            return

        cached = await _cached_verdict(db, fp)
        if cached and "verdict" in cached:
            f["triage"] = {
                "verdict": cached["verdict"],
                "confidence": cached.get("confidence", 0.5),
                "reason": cached.get("reason", ""),
                "cached": True,
            }
            return

        async with sem:
            verdict = await _ask_llm(orchestrator, f, provider=provider, model=model)
        f["triage"] = {**verdict, "cached": False}
        await _store_verdict(db, fp, {**verdict, "fingerprint": fp})

    await asyncio.gather(*(_process(f) for f in findings))
    return findings
