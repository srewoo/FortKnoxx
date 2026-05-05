"""Pure scoring functions for security / quality / license compliance.

Extracted from server.py during Phase 1.5. Pure (no I/O, no globals)
so they are trivially testable and callable from any service.

Score conventions (0–100, higher = better):
  - 100 = no findings.
  - Each severity tier subtracts a weighted amount.
  - Volume penalties kick in once findings cross specific thresholds.

Behaviour preserved verbatim from server.py — these numbers feed the
dashboard headline gauge and a regression here would silently shift
every customer's posture.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping


def calculate_security_score(critical: int, high: int, medium: int, low: int) -> int:
    """Overall security score (0–100)."""
    total_vulns = critical + high + medium + low
    if total_vulns == 0:
        return 100

    total_impact = (critical * 15) + (high * 8) + (medium * 3) + (low * 1)
    score = max(0, 100 - total_impact)

    if total_vulns > 20:
        score = max(0, score - 5)
    if total_vulns > 50:
        score = max(0, score - 10)
    if total_vulns > 100:
        score = max(0, score - 15)

    return score


def calculate_quality_score(quality_issues: Iterable[Mapping]) -> int:
    """Code quality score (0–100)."""
    issues = list(quality_issues)
    if not issues:
        return 100

    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issue in issues:
        severity = str(issue.get("severity", "low")).lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    total_impact = (
        severity_counts["critical"] * 10
        + severity_counts["high"] * 5
        + severity_counts["medium"] * 2
        + severity_counts["low"] * 0.5
    )
    score = max(0, 100 - total_impact)

    total_issues = len(issues)
    if total_issues > 50:
        score = max(0, score - 5)
    if total_issues > 100:
        score = max(0, score - 10)
    if total_issues > 200:
        score = max(0, score - 15)

    return int(score)


def calculate_compliance_score(compliance_issues: Iterable[Mapping]) -> int:
    """License compliance score (0–100)."""
    issues = list(compliance_issues)
    if not issues:
        return 100

    risk_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    for issue in issues:
        risk = str(issue.get("license_risk", "unknown")).lower()
        if risk in risk_counts:
            risk_counts[risk] += 1
        else:
            risk_counts["unknown"] += 1

    total_impact = risk_counts["high"] * 15 + risk_counts["medium"] * 5 + risk_counts["unknown"] * 3
    return int(max(0, 100 - total_impact))
