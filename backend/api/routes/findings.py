"""Findings list routes — vulnerabilities, quality issues, compliance issues.

Extracted from server.py during Phase 1.5. All read-only and pure
projections from Mongo. Score-summary endpoints delegate to
``services.scoring`` for the math.

Path conventions (preserved from server.py):
  /api/vulnerabilities/{scan_id}        — by scan
  /api/vulnerabilities/repo/{repo_id}   — across all scans of a repo
  /api/quality/{scan_id}                — by scan
  /api/quality/repo/{repo_id}           — across all scans
  /api/quality/summary/{scan_id}        — aggregated metrics
  /api/compliance/{scan_id}             — by scan
  /api/compliance/repo/{repo_id}        — across all scans
  /api/compliance/summary/{scan_id}     — aggregated metrics
  /api/sbom/{repo_id}                   — SBOM derived from latest scan
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api import deps
from api.schemas import Vulnerability
from services.scoring import calculate_compliance_score, calculate_quality_score

router = APIRouter(tags=["findings"])


def _hydrate_created_at(records: list[dict]) -> list[dict]:
    for record in records:
        if isinstance(record.get("created_at"), str):
            record["created_at"] = datetime.fromisoformat(record["created_at"])
    return records


# ---------------------------------------------------------------- #
# Vulnerabilities
# ---------------------------------------------------------------- #


@router.get("/vulnerabilities/{scan_id}", response_model=list[Vulnerability])
async def list_vulnerabilities_for_scan(
    scan_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)
    return _hydrate_created_at(vulns)


@router.get("/vulnerabilities/repo/{repo_id}", response_model=list[Vulnerability])
async def list_vulnerabilities_for_repo(
    repo_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    vulns = await db.vulnerabilities.find({"repo_id": repo_id}, {"_id": 0}).to_list(10000)
    return _hydrate_created_at(vulns)


# ---------------------------------------------------------------- #
# Quality issues
# ---------------------------------------------------------------- #


@router.get("/quality/{scan_id}")
async def list_quality_issues_for_scan(
    scan_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    issues = await db.quality_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)
    return _hydrate_created_at(issues)


@router.get("/quality/repo/{repo_id}")
async def list_quality_issues_for_repo(
    repo_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    issues = await db.quality_issues.find({"repo_id": repo_id}, {"_id": 0}).to_list(10000)
    return _hydrate_created_at(issues)


@router.get("/quality/summary/{scan_id}")
async def quality_summary(
    scan_id: str,
    db=Depends(deps.get_db),
) -> dict[str, Any]:
    issues = await db.quality_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)

    summary: dict[str, Any] = {
        "total_issues": len(issues),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_category": {},
        "by_scanner": {},
        "quality_score": 100,
    }

    for issue in issues:
        severity = str(issue.get("severity", "low")).lower()
        category = issue.get("category", "other")
        scanner = issue.get("detected_by", "unknown")

        if severity in summary["by_severity"]:
            summary["by_severity"][severity] += 1
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        summary["by_scanner"][scanner] = summary["by_scanner"].get(scanner, 0) + 1

    summary["quality_score"] = calculate_quality_score(issues)
    return summary


# ---------------------------------------------------------------- #
# Compliance issues
# ---------------------------------------------------------------- #


@router.get("/compliance/{scan_id}")
async def list_compliance_issues_for_scan(
    scan_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    issues = await db.compliance_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)
    return _hydrate_created_at(issues)


@router.get("/compliance/repo/{repo_id}")
async def list_compliance_issues_for_repo(
    repo_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    issues = await db.compliance_issues.find({"repo_id": repo_id}, {"_id": 0}).to_list(10000)
    return _hydrate_created_at(issues)


@router.get("/compliance/summary/{scan_id}")
async def compliance_summary(
    scan_id: str,
    db=Depends(deps.get_db),
) -> dict[str, Any]:
    issues = await db.compliance_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)

    summary: dict[str, Any] = {
        "total_issues": len(issues),
        "by_risk_level": {"high": 0, "medium": 0, "low": 0, "unknown": 0},
        "by_license": {},
        "compliance_score": 100,
    }

    for issue in issues:
        risk = str(issue.get("license_risk", "unknown")).lower()
        license_name = issue.get("license", "unknown")

        if risk in summary["by_risk_level"]:
            summary["by_risk_level"][risk] += 1
        else:
            summary["by_risk_level"]["unknown"] += 1
        summary["by_license"][license_name] = summary["by_license"].get(license_name, 0) + 1

    summary["compliance_score"] = calculate_compliance_score(issues)
    return summary


# ---------------------------------------------------------------- #
# SBOM derived from compliance issues of latest scan
# ---------------------------------------------------------------- #


@router.get("/sbom/{repo_id}")
async def get_sbom(
    repo_id: str,
    db=Depends(deps.get_db),
) -> dict[str, Any]:
    latest_scan = await db.scans.find_one(
        {"repo_id": repo_id, "status": "completed"},
        {"_id": 0},
        sort=[("started_at", -1)],
    )
    if not latest_scan:
        raise HTTPException(status_code=404, detail="No completed scans found")

    issues = await db.compliance_issues.find(
        {"scan_id": latest_scan["id"]},
        {"_id": 0},
    ).to_list(10000)

    packages = [
        {
            "name": issue.get("package_name", "unknown"),
            "version": issue.get("package_version", ""),
            "type": issue.get("package_type", "unknown"),
            "license": issue.get("license", "unknown"),
            "license_risk": issue.get("license_risk", "unknown"),
        }
        for issue in issues
    ]

    return {
        "repo_id": repo_id,
        "scan_id": latest_scan["id"],
        "generated_at": datetime.now(UTC).isoformat(),
        "total_packages": len(packages),
        "packages": packages,
    }
