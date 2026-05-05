"""Read-side scan routes (list, get, delete).

Extracted from server.py during Phase 1.5. The mutating endpoint that
kicks off a new scan (`POST /scans/{repo_id}`) is **not** moved yet —
it depends on the in-progress scan orchestrator, repo cloner, and
background-task plumbing. Phase 1.6 will extract those services and
move the POST handler with them.
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from api import deps
from api.schemas import Scan

router = APIRouter(tags=["scans"])
logger = logging.getLogger(__name__)


def _hydrate_dates(scan: dict) -> dict:
    """Coerce ISO-8601 strings on date columns back to datetime.

    Mongo stores them as strings (we serialise via `.isoformat()` on
    write) but Pydantic's `Scan` model expects datetimes.
    """
    if isinstance(scan.get("started_at"), str):
        scan["started_at"] = datetime.fromisoformat(scan["started_at"])
    if scan.get("completed_at") and isinstance(scan["completed_at"], str):
        scan["completed_at"] = datetime.fromisoformat(scan["completed_at"])
    return scan


@router.get("/scans/{repo_id}", response_model=list[Scan])
async def list_scans_for_repo(
    repo_id: str,
    db=Depends(deps.get_db),
) -> list[dict]:
    scans = await db.scans.find({"repo_id": repo_id}, {"_id": 0}).sort("started_at", -1).to_list(1000)
    return [_hydrate_dates(s) for s in scans]


@router.get("/scans/detail/{scan_id}", response_model=Scan)
async def get_scan(
    scan_id: str,
    db=Depends(deps.get_db),
) -> dict:
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _hydrate_dates(scan)


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: str,
    db=Depends(deps.get_db),
) -> dict:
    result = await db.scans.delete_one({"id": scan_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Cascade — the same triplet that the repository delete cascades.
    await db.vulnerabilities.delete_many({"scan_id": scan_id})
    await db.quality_issues.delete_many({"scan_id": scan_id})
    await db.compliance_issues.delete_many({"scan_id": scan_id})
    return {"message": "Scan deleted successfully"}
