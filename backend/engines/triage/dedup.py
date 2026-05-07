"""
Cross-scanner deduplication.

Findings sharing a fingerprint are merged into one, with:
  • sources       — list of every scanner that detected it
  • severity      — highest severity reported (worst case wins)
  • confidence    — boosted when multiple scanners agree
  • original_ids  — preserved for SARIF export and UI drill-down
"""

from __future__ import annotations

import logging
from typing import Any

from .fingerprint import build_fingerprint

logger = logging.getLogger(__name__)

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}


def _sev_rank(value: Any) -> int:
    if isinstance(value, list):
        value = value[0] if value else "medium"
    return _SEV_RANK.get(str(value or "medium").lower(), 2)


def _scanner_name(finding: dict) -> str:
    return str(
        finding.get("detected_by")
        or finding.get("scanner")
        or finding.get("source")
        or "unknown"
    ).lower()


def _confidence_boost(scanner_count: int) -> float:
    # +0.1 per agreeing scanner, capped at +0.3. Same shape as the legacy
    # filter so existing UI confidence labels stay calibrated.
    return min(0.1 * (scanner_count - 1), 0.3) if scanner_count > 1 else 0.0


def deduplicate(
    findings: list[dict],
    repo_path: str | None = None,
) -> list[dict]:
    """Collapse findings that share a fingerprint. Returns a new list."""
    if not findings:
        return []

    groups: dict[str, list[dict]] = {}
    for f in findings:
        fp = build_fingerprint(f, repo_path=repo_path)
        f.setdefault("fingerprint", fp)
        groups.setdefault(fp, []).append(f)

    merged: list[dict] = []
    for fp, items in groups.items():
        # Pick the most descriptive finding as the base.
        base = max(items, key=lambda i: len(str(i.get("description", ""))))
        scanners = sorted({_scanner_name(i) for i in items})
        worst = max(_sev_rank(i.get("severity")) for i in items)

        out = dict(base)  # shallow copy so we don't mutate the original
        out["fingerprint"] = fp
        out["sources"] = scanners
        out["detection_count"] = len(scanners)
        out["severity"] = _RANK_SEV[worst]

        base_conf = float(out.get("confidence_score") or out.get("confidence") or 0.7)
        out["confidence_score"] = round(min(1.0, base_conf + _confidence_boost(len(scanners))), 3)
        out["original_ids"] = [
            i.get("finding_id") or i.get("id") or i.get("rule_id")
            for i in items
            if i.get("finding_id") or i.get("id") or i.get("rule_id")
        ]
        merged.append(out)

    if len(merged) < len(findings):
        logger.info(
            "Triage dedup: %d findings → %d (%.0f%% reduction)",
            len(findings),
            len(merged),
            100.0 * (1 - len(merged) / len(findings)),
        )
    return merged
