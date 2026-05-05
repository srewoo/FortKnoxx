"""Shared application state for FastAPI dependency injection.

WHY: as routes are extracted from server.py into modules under
`api/routes/`, they need access to the singletons (`db`, settings
manager, encryption, scanner health) that previously lived as globals
in server.py. Importing those globals directly from `server` would
create circular imports because `server.py` imports the route modules.

Pattern:
  1. server.py creates the singletons during its own module load and
     during the FastAPI `lifespan` handler.
  2. server.py registers them with `state.bind(...)`.
  3. Route modules call `Depends(get_db)` etc. — they never import
     from server.py.

Tests can substitute the dependencies with `app.dependency_overrides`
without touching module state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase


@dataclass
class _AppState:
    db: AsyncIOMotorDatabase | None = None
    client: AsyncIOMotorClient | None = None
    settings_manager: Any | None = None
    git_integration_service: Any | None = None
    encryption_service: Any | None = None
    scanner_health_report: Any | None = None
    model_manager: Any | None = None
    update_service: Any | None = None
    extras: dict = field(default_factory=dict)


state = _AppState()


def bind(
    *,
    db=None,
    client=None,
    settings_manager=None,
    git_integration_service=None,
    encryption_service=None,
    scanner_health_report=None,
    model_manager=None,
    update_service=None,
    **extras,
) -> None:
    """Populate the shared state. Call once at app startup."""
    if db is not None:
        state.db = db
    if client is not None:
        state.client = client
    if settings_manager is not None:
        state.settings_manager = settings_manager
    if git_integration_service is not None:
        state.git_integration_service = git_integration_service
    if encryption_service is not None:
        state.encryption_service = encryption_service
    if scanner_health_report is not None:
        state.scanner_health_report = scanner_health_report
    if model_manager is not None:
        state.model_manager = model_manager
    if update_service is not None:
        state.update_service = update_service
    if extras:
        state.extras.update(extras)


# ----------------------------------------------------------------------
# FastAPI dependency callables.
#
# Each returns the singleton instance, or raises a clean RuntimeError
# if state was not bound (which means we forgot to call `bind()` in
# the lifespan handler — never expected in normal flow).
# ----------------------------------------------------------------------


def get_db():
    if state.db is None:
        raise RuntimeError("DB not bound; api.deps.bind(db=...) was not called")
    return state.db


def get_client():
    if state.client is None:
        raise RuntimeError("Mongo client not bound")
    return state.client


def get_settings_manager():
    if state.settings_manager is None:
        raise RuntimeError("Settings manager not bound")
    return state.settings_manager


def get_git_integration():
    if state.git_integration_service is None:
        raise RuntimeError("Git integration service not bound")
    return state.git_integration_service


def get_encryption():
    if state.encryption_service is None:
        raise RuntimeError("Encryption service not bound")
    return state.encryption_service


def get_scanner_health_report():
    return state.scanner_health_report


def get_model_manager():
    return state.model_manager
