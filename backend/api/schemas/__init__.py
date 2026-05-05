"""Pydantic schemas used by API routes.

WHY this module exists: extracted from server.py during the Phase 1
decomposition (see docs/adr/ADR-002-migration-plan.md). Keeping
schemas separate makes it possible to:
  - run schema-only validation tests without spinning up the app,
  - share types with future microservices in `apps/`,
  - generate the OpenAPI contract without circular imports.
"""

from .scans import (
    AIFixRequest,
    ReportRequest,
    Repository,
    RepositoryCreate,
    Scan,
    Vulnerability,
)

__all__ = [
    "AIFixRequest",
    "ReportRequest",
    "Repository",
    "RepositoryCreate",
    "Scan",
    "Vulnerability",
]
