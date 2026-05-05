"""Repository CRUD routes (read + delete).

Extracted from server.py during Phase 1.5. Notes:

- ``GET /repositories`` enriches each repo with the *latest completed*
  scan's headline numbers so the frontend dashboard can render without
  a second round-trip per repo.
- ``DELETE /repositories/{id}`` consolidates two previously-duplicate
  handlers in server.py — one for vanilla repos, one for git-integration
  repos. The merged handler removes from both stores, deletes
  associated scans, vulnerabilities, quality issues, and compliance
  issues. Idempotent: 404 only when neither store knows the id.
- ``POST /repositories`` (the Git integration creation flow) is not
  extracted yet; it has heavy dependencies on the integration service
  and will move in a follow-up.
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException

from api import deps
from api.schemas import Repository
from services.audit_writer import record_audit

router = APIRouter(tags=["repositories"])
logger = logging.getLogger(__name__)


@router.get("/repositories", response_model=list[Repository])
async def list_repositories(db=Depends(deps.get_db)) -> list[dict]:
    repos = await db.repositories.find({}, {"_id": 0}).to_list(1000)
    for repo in repos:
        if isinstance(repo.get("created_at"), str):
            repo["created_at"] = datetime.fromisoformat(repo["created_at"])

        latest_scan = await db.scans.find_one(
            {"repo_id": repo["id"], "status": "completed"},
            {
                "_id": 0,
                "security_score": 1,
                "vulnerabilities_count": 1,
                "critical_count": 1,
                "high_count": 1,
            },
        )
        if latest_scan:
            repo["security_score"] = latest_scan.get("security_score", 0)
            repo["vulnerabilities_count"] = latest_scan.get("vulnerabilities_count", 0)
            repo["critical_count"] = latest_scan.get("critical_count", 0)
            repo["high_count"] = latest_scan.get("high_count", 0)
        else:
            repo["security_score"] = None
            repo["vulnerabilities_count"] = 0
            repo["critical_count"] = 0
            repo["high_count"] = 0
    return repos


@router.get("/repositories/{repo_id}", response_model=Repository)
async def get_repository(
    repo_id: str,
    db=Depends(deps.get_db),
) -> dict:
    repo = await db.repositories.find_one({"id": repo_id}, {"_id": 0})
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    if isinstance(repo.get("created_at"), str):
        repo["created_at"] = datetime.fromisoformat(repo["created_at"])
    return repo


@router.delete("/repositories/{repo_id}")
async def delete_repository(
    repo_id: str,
    db=Depends(deps.get_db),
    git_integration=Depends(deps.get_git_integration),
) -> dict:
    found_in_main = False
    found_in_git = False

    main_result = await db.repositories.delete_one({"id": repo_id})
    if main_result.deleted_count > 0:
        found_in_main = True

    try:
        git_result = await git_integration.remove_repository(repo_id)
        if isinstance(git_result, dict) and git_result.get("success"):
            found_in_git = True
    except Exception as exc:  # noqa: BLE001 — surface as warning, continue cascade.
        logger.warning("Git integration removal failed for %s: %s", repo_id, exc)

    if not (found_in_main or found_in_git):
        raise HTTPException(status_code=404, detail="Repository not found")

    scans = await db.scans.find({"repo_id": repo_id}, {"id": 1}).to_list(1000)
    scan_ids = [scan["id"] for scan in scans]
    if scan_ids:
        await db.vulnerabilities.delete_many({"scan_id": {"$in": scan_ids}})
        await db.quality_issues.delete_many({"scan_id": {"$in": scan_ids}})
        await db.compliance_issues.delete_many({"scan_id": {"$in": scan_ids}})
    await db.scans.delete_many({"repo_id": repo_id})
    await db.vulnerabilities.delete_many({"repo_id": repo_id})

    logger.info("Deleted repository %s and all associated data", repo_id)

    await record_audit(
        action="repository.deleted",
        target_type="repository",
        target_id=repo_id,
        diff={
            "found_in_main": found_in_main,
            "found_in_git": found_in_git,
            "cascaded_scans": len(scan_ids),
        },
    )

    return {"success": True, "message": "Repository deleted successfully"}
