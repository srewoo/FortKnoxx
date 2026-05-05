"""Append-only audit log.

WHY: every state-changing API call must produce one row here. The
audit-service consumer is the only writer in production
(api-gateway publishes ``event.audit.action`` to Kafka per ADR-004,
audit-service consumes and writes here). Routes never write directly.

Partitioned by month in production; the migration creates the parent
table only — partitions are added via maintenance jobs.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantOwnedMixin


class AuditLog(TenantOwnedMixin, Base):
    __tablename__ = "audit_log"

    # No `id` — the (tenant_id, occurred_at, sequence) tuple is the
    # natural key. We still need a column for the PK; use a UUID with
    # default uuid4 to keep inserts fast and deterministic across
    # partitions.
    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    diff: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    trace_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    __table_args__ = (Index("ix_audit_log_tenant_occurred", "tenant_id", "occurred_at"),)
