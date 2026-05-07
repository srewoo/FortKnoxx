"""
.fortknoxx/ignore.yml suppression rules.

Format:
  rules:
    - fingerprint: 9f3a1c0e2b8d4f60
      justification: "Reviewed 2026-04-12 — false positive in test fixtures."
      owner: sharaj@mindtickle.com
      expires_at: 2026-07-12        # ISO date; CI fails after this date
    - cwe_family: xss                # broader rule
      path_glob: "**/test/**"
      justification: "XSS in tests is intentional fuzz input."
      expires_at: 2026-12-31

Behaviour:
  • Matched findings are removed from the result list and recorded in
    `triage.suppressed[]` for the report.
  • Expired rules are kept but produce a `triage.expired_rules[]` warning
    so CI can fail loudly rather than silently lose suppression.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:  # PyYAML is already a transitive dependency of FastAPI tooling.
    import yaml
except ImportError:  # pragma: no cover - graceful degradation
    yaml = None


def _load_rules(repo_path: str) -> list[dict[str, Any]]:
    if yaml is None:
        return []
    candidate = Path(repo_path) / ".fortknoxx" / "ignore.yml"
    if not candidate.is_file():
        return []
    try:
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        logger.warning("Invalid .fortknoxx/ignore.yml: %s", exc)
        return []
    rules = data.get("rules") or []
    return [r for r in rules if isinstance(r, dict)]


def _is_expired(rule: dict[str, Any], today: dt.date) -> bool:
    raw = rule.get("expires_at")
    if not raw:
        return False
    try:
        return dt.date.fromisoformat(str(raw)) < today
    except ValueError:
        logger.warning("Bad expires_at in ignore rule: %r", raw)
        return False


def _matches(finding: dict, rule: dict[str, Any]) -> bool:
    if (rfp := rule.get("fingerprint")) and rfp == finding.get("fingerprint"):
        return True
    if (fam := rule.get("cwe_family")) and fam == finding.get("cwe_family"):
        path = finding.get("file_path", "")
        glob = rule.get("path_glob")
        if glob and not fnmatch.fnmatch(path, glob):
            return False
        return True
    return False


def apply_ignore_rules(
    findings: list[dict],
    repo_path: str,
) -> tuple[list[dict], dict[str, Any]]:
    """Filter findings by the repo's ignore.yml.

    Returns ``(kept, meta)`` where ``meta`` contains:
      suppressed:    list of {fingerprint, rule, finding}
      expired_rules: list of expired rules still on disk (for CI warnings)
    """
    rules = _load_rules(repo_path)
    if not rules:
        return findings, {"suppressed": [], "expired_rules": []}

    today = dt.date.today()
    active = [r for r in rules if not _is_expired(r, today)]
    expired = [r for r in rules if _is_expired(r, today)]

    kept: list[dict] = []
    suppressed: list[dict] = []
    for f in findings:
        match = next((r for r in active if _matches(f, r)), None)
        if match:
            suppressed.append({"fingerprint": f.get("fingerprint"), "rule": match})
        else:
            kept.append(f)

    if suppressed:
        logger.info("Ignore rules suppressed %d finding(s)", len(suppressed))
    if expired:
        logger.warning(
            "%d expired ignore rule(s) — review .fortknoxx/ignore.yml", len(expired)
        )

    return kept, {"suppressed": suppressed, "expired_rules": expired}
