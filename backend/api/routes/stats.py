"""Repository stats route.

Extracted from server.py during Phase 1.5. Returns the headline numbers
the dashboard needs in a single round-trip: security score, severity
distribution, OWASP distribution, recent scan history.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api import deps

router = APIRouter(tags=["stats"])
logger = logging.getLogger(__name__)


@router.get("/stats/{repo_id}")
async def get_repository_stats(
    repo_id: str,
    db=Depends(deps.get_db),
) -> dict[str, Any]:
    try:
        latest_scan = await db.scans.find_one(
            {"repo_id": repo_id, "status": "completed"},
            {"_id": 0},
            sort=[("started_at", -1)],
        )
        if not latest_scan:
            return {"message": "No completed scans found"}

        owasp_distribution: dict[str, int] = {}
        vulns = await db.vulnerabilities.find({"scan_id": latest_scan["id"]}, {"_id": 0}).to_list(10000)
        for vuln in vulns:
            category = vuln.get("owasp_category", "unknown")
            owasp_distribution[category] = owasp_distribution.get(category, 0) + 1

        severity_dist = {
            "critical": latest_scan.get("critical_count", 0),
            "high": latest_scan.get("high_count", 0),
            "medium": latest_scan.get("medium_count", 0),
            "low": latest_scan.get("low_count", 0),
        }

        scan_history = (
            await db.scans.find(
                {"repo_id": repo_id, "status": "completed"},
                {
                    "_id": 0,
                    "id": 1,
                    "started_at": 1,
                    "security_score": 1,
                    "vulnerabilities_count": 1,
                },
            )
            .sort("started_at", -1)
            .limit(10)
            .to_list(10)
        )

        return {
            "security_score": latest_scan.get("security_score", 0),
            "total_vulnerabilities": latest_scan.get("vulnerabilities_count", 0),
            "severity_distribution": severity_dist,
            "owasp_distribution": owasp_distribution,
            "scan_history": scan_history,
            "total_files_scanned": latest_scan.get("total_files", 0),
            "tools_used": latest_scan.get("scan_results", {}),
        }

    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 — converted to 500 with stack in logs.
        logger.exception("Error getting stats for repo %s", repo_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
