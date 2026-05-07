"""Code↔cloud correlation.

Given a set of code findings + a set of cloud findings (Prowler /
ScoutSuite / CloudSploit), join them via IaC-extracted resource names so
the UI can display:

    "service-x has CVE-2024-XXXX AND its IAM role allows *:*"

Two correlation strategies, run in order — first match wins:

  1. exact resource-name match (cloud finding's resource name matches an
     IaC resource ``name`` field).
  2. service-hint match (cloud finding's resource name *contains* the
     IaC service hint, e.g. resource ``payments-api-task-role`` matches
     service ``payments-api``).

Anything that doesn't correlate stays as a standalone finding — we
never silently drop signal.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .iac_resources import IaCResource

logger = logging.getLogger(__name__)


@dataclass
class CorrelatedFinding:
    """A code or cloud finding annotated with linkage metadata."""

    finding: dict
    correlation: str           # "exact" | "service_hint" | "none"
    linked_resources: list[str]  # IaC resource names that joined


def _service_label(finding: dict) -> str | None:
    """Best-effort service label from a finding."""
    for key in ("service", "service_hint", "module", "package_name"):
        if value := finding.get(key):
            return str(value)
    return None


def _cloud_resource(finding: dict) -> str | None:
    for key in ("resource", "resource_id", "resource_name", "arn"):
        if value := finding.get(key):
            return str(value)
    return None


def correlate_findings(
    code_findings: list[dict],
    cloud_findings: list[dict],
    iac_resources: list[IaCResource],
) -> list[CorrelatedFinding]:
    """Return a unified list with cross-references attached.

    Each cloud finding is annotated with the IaC resources it likely
    matches. Each code finding is annotated with the cloud resources
    deployed for the same service (so a CVE on `payments-api` can show
    "this service runs in IAM role X with finding Y").
    """
    by_name: dict[str, list[IaCResource]] = {}
    by_service: dict[str, list[IaCResource]] = {}
    for res in iac_resources:
        by_name.setdefault(res.name.lower(), []).append(res)
        by_service.setdefault(res.service_hint.lower(), []).append(res)

    correlated: list[CorrelatedFinding] = []

    for cloud in cloud_findings:
        rname = (_cloud_resource(cloud) or "").lower()
        if not rname:
            correlated.append(CorrelatedFinding(cloud, "none", []))
            continue

        # Strategy 1: exact match.
        if rname in by_name:
            correlated.append(CorrelatedFinding(
                cloud, "exact", [r.name for r in by_name[rname]]
            ))
            continue

        # Strategy 2: service-hint substring match.
        hint = next(
            (svc for svc in by_service if svc and svc in rname),
            None,
        )
        if hint:
            correlated.append(CorrelatedFinding(
                cloud, "service_hint", [r.name for r in by_service[hint]]
            ))
            continue

        correlated.append(CorrelatedFinding(cloud, "none", []))

    # For each code finding, attach any cloud resources that match the
    # same service hint. This is what powers "this CVE runs on IAM role
    # X" in the UI.
    for code in code_findings:
        svc = (_service_label(code) or "").lower()
        if not svc:
            correlated.append(CorrelatedFinding(code, "none", []))
            continue
        matches = [r.name for r in by_service.get(svc, [])]
        correlated.append(CorrelatedFinding(
            code,
            "service_hint" if matches else "none",
            matches,
        ))

    if cloud_findings or code_findings:
        linked = sum(1 for c in correlated if c.correlation != "none")
        logger.info(
            "CNAPP correlation: %d/%d findings linked to IaC resources",
            linked, len(correlated),
        )
    return correlated
