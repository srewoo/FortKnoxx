"""Health check routes.

Extracted from server.py during Phase 1.5 of the F500 migration. The
behaviour is preserved verbatim — these handlers must remain fast,
side-effect-free, and dependency-tolerant (they are the first thing
load balancers and on-call engineers hit when something looks wrong).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api import deps
from utils.scanner_health import check_all_scanners

router = APIRouter(tags=["health"])
logger = logging.getLogger(__name__)


@router.get("/")
async def root() -> dict[str, str]:
    return {"message": "Security Intelligence Platform API", "version": "1.0.0"}


@router.get("/health")
async def health_check(
    client=Depends(deps.get_client),
) -> dict[str, Any]:
    health: dict[str, Any] = {
        "status": "healthy",
        "database": "unknown",
        "scanners": None,
    }

    try:
        await client.admin.command("ping")
        health["database"] = "connected"
    except Exception as exc:  # noqa: BLE001 — surfaced to caller, not silent.
        health["status"] = "unhealthy"
        health["database"] = f"disconnected: {exc}"

    report = deps.get_scanner_health_report()
    if report is not None:
        health["scanners"] = {
            "total": report.total_scanners,
            "available": report.available_count,
            "unavailable": report.unavailable_count,
            "is_healthy": report.is_healthy(),
        }
        if not report.is_healthy():
            health["status"] = "degraded"

    return health


@router.get("/scanners/health")
async def get_scanner_health(
    settings_manager=Depends(deps.get_settings_manager),
) -> dict[str, Any]:
    report = deps.get_scanner_health_report()
    if report is not None:
        return report.to_dict()

    # Fallback: no cached report at startup — compute one on demand.
    try:
        scanner_settings = await settings_manager.get_scanner_settings()
        fresh = await check_all_scanners(scanner_settings)
        return fresh.to_dict()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Scanner health check failed during request")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to check scanner health: {exc}",
        ) from exc
