"""Autofix endpoint — generates a unified diff that fixes a finding.

Why a separate route from the existing AI-fix recommendation endpoint:
  • The legacy endpoint returns markdown advice. UIs that already render
    markdown still work.
  • This endpoint returns a structured ``AutofixResult`` with a verified
    unified diff and a ``applies_cleanly`` flag — what the future
    "Apply fix" button needs.

Both endpoints can coexist; this one is additive.
"""

from __future__ import annotations

import logging
import os
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api import deps
from services.autofix import generate_autofix

router = APIRouter(tags=["autofix"])
logger = logging.getLogger(__name__)


class AutofixRequest(BaseModel):
    vulnerability_id: str
    repo_path: str | None = None
    provider: str | None = None
    model: str | None = None


@router.post("/autofix")
async def create_autofix(
    payload: AutofixRequest,
    db=Depends(deps.get_db),
    orchestrator=Depends(deps.get_llm_orchestrator),
):
    """Generate (or fetch from cache) a unified diff for a finding."""
    if orchestrator is None:
        raise HTTPException(status_code=503, detail="LLM orchestrator not configured")

    finding = await db.vulnerabilities.find_one({"id": payload.vulnerability_id}, {"_id": 0})
    if not finding:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    repo_path = payload.repo_path or _infer_repo_path(finding)
    if not repo_path or not os.path.isdir(repo_path):
        raise HTTPException(
            status_code=400,
            detail="repo_path is required and must point to a checked-out repo",
        )

    result = await generate_autofix(
        finding,
        repo_path=repo_path,
        db=db,
        orchestrator=orchestrator,
        provider=payload.provider,
        model=payload.model,
    )
    return asdict(result)


def _infer_repo_path(finding: dict) -> str | None:
    """Best-effort: scans clone repos under /tmp/fortknoxx_repos/{repo_id}.
    If the finding carries a ``repo_id`` and that path exists, use it."""
    repo_id = finding.get("repo_id")
    if not repo_id:
        return None
    candidate = f"/tmp/fortknoxx_repos/{repo_id}"
    return candidate if os.path.isdir(candidate) else None
