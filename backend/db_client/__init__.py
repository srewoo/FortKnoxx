"""Postgres data-access layer (Phase 2).

WHY: Mongo stays for findings (semi-structured, high-volume); Postgres
holds transactional state (tenants, users, audit log, scan envelope,
repository metadata). See ADR-002 (migration plan), ADR-003 (Postgres
choice), and CLAUDE.md §6.

Public surface for application code:

    from db_client import get_session

    async with get_session() as session:
        ...

Routes will adopt this gradually in Phase 2; today nothing in the API
path imports from `db_client` yet — this scaffolding is here so
ALEMBIC migrations can run and so future routes have a stable target.
"""

from .engine import dispose_engine, get_engine, get_session
from .models import Base

__all__ = ["Base", "get_engine", "get_session", "dispose_engine"]
