"""Git integration routes (GitHub / GitLab connections).

Extracted from server.py during Phase 1.5. The four endpoints listed
here are read-mostly and only depend on `git_integration_service`.

The `POST /repositories` handler that uses the Git integration to add
a remote repository **stays in `server.py` for now** — it cross-writes
to the main Mongo `repositories` collection and that wiring will move
when the repository service is extracted in a follow-up.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api import deps
from settings.models import ConnectGitIntegrationRequest, GitProvider

router = APIRouter(tags=["integrations"])
logger = logging.getLogger(__name__)


@router.get("/integrations/git")
async def list_integrations(
    git_integration=Depends(deps.get_git_integration),
) -> dict[str, list[dict[str, Any]]]:
    try:
        integrations = await git_integration.get_integrations()
        return {"integrations": [i.model_dump() for i in integrations]}
    except Exception as exc:
        logger.exception("Error getting git integrations")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/integrations/git/connect")
async def connect_integration(
    request: ConnectGitIntegrationRequest,
    git_integration=Depends(deps.get_git_integration),
) -> dict[str, Any]:
    try:
        result = await git_integration.connect_integration(
            provider=request.provider,
            name=request.name,
            access_token=request.access_token,
            base_url=request.base_url,
        )
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Connection failed"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error connecting git integration")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/integrations/git/{provider}")
async def disconnect_integration(
    provider: str,
    name: str | None = None,
    git_integration=Depends(deps.get_git_integration),
) -> dict[str, Any]:
    try:
        git_provider = GitProvider(provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}") from exc

    try:
        result = await git_integration.disconnect_integration(git_provider, name or provider)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error", "Disconnection failed"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error disconnecting git integration")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/integrations/git/{provider}/repositories")
async def list_remote_repositories(
    provider: str,
    page: int = 1,
    per_page: int = 30,
    git_integration=Depends(deps.get_git_integration),
) -> dict[str, Any]:
    try:
        git_provider = GitProvider(provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}") from exc

    try:
        result = await git_integration.list_remote_repositories(git_provider, page=page, per_page=per_page)
        if not result.get("success"):
            raise HTTPException(status_code=400, detail=result.get("error"))
        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error listing remote repositories for %s", provider)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
