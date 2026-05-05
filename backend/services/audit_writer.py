"""Append-only audit-log writer (Phase 2).

WHY this is the first real Postgres write path: ADR-008 makes audit_log
Postgres-native (RLS + ACID + per-tenant time-range queries). Routes
should call ``record_audit(...)`` after any state-changing action.

Operating modes:

- **Postgres-disabled** (POSTGRES_DSN unset): the call is a no-op
  except for a structured log line. Today's deployments still run
  Mongo-only; we don't want audit calls to break them.
- **Postgres-enabled but transient failure**: we log the error and
  swallow it. An audit write must never fail a user-visible request.
  Production Phase 6 replaces this best-effort path with the Kafka
  outbox (CLAUDE.md §7) so durability is guaranteed.

The function never raises; it returns ``True`` if a row was written,
``False`` otherwise. Tests assert on the row contents via the session
factory override.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Mapping

logger = logging.getLogger(__name__)

# Single-tenant deployments today: routes don't carry a tenant or
# actor identity yet. Phase 6 (auth + RBAC) wires real values; until
# then we tag rows with a stable system identity so the data is
# usable post-migration without a backfill.
_SYSTEM_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_SYSTEM_ACTOR_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")


def _postgres_enabled() -> bool:
    return bool(os.environ.get("POSTGRES_DSN"))


async def record_audit(
    *,
    action: str,
    target_type: str,
    target_id: str,
    diff: Mapping[str, Any] | None = None,
    actor_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    trace_id: str | None = None,
    session_factory: Any | None = None,
) -> bool:
    """Best-effort audit-log write.

    ``session_factory`` overrides the default ``db_client.get_session``
    context manager — used by tests to inject an in-memory session.
    """
    if not _postgres_enabled() and session_factory is None:
        logger.debug(
            "audit skipped (Postgres disabled): action=%s target=%s/%s",
            action, target_type, target_id,
        )
        return False

    try:
        from db_client.models import AuditLog
    except Exception as exc:  # noqa: BLE001
        logger.warning("audit skipped (db_client import failed): %s", exc)
        return False

    if session_factory is None:
        from db_client import get_session as _default_factory
        session_factory = _default_factory

    row = AuditLog(
        tenant_id=tenant_id or _SYSTEM_TENANT_ID,
        actor_id=actor_id or _SYSTEM_ACTOR_ID,
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        diff=dict(diff or {}),
        trace_id=trace_id,
    )

    try:
        async with session_factory() as session:
            session.add(row)
        return True
    except Exception as exc:  # noqa: BLE001 — must not fail the request.
        logger.error(
            "audit write failed: action=%s target=%s/%s err=%s",
            action, target_type, target_id, exc,
        )
        return False
