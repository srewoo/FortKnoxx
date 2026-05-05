"""Repository metadata in Postgres.

Mirrors a subset of the existing Mongo `repositories` collection —
enough to enforce tenancy, ownership, and audit. Findings stay in
Mongo through Phase 3 (see ADR-002 / ADR-008).

The class is named `RepositoryRow` to avoid collision with the
existing ``api.schemas.Repository`` Pydantic model. The mapping
between the two lives in a future repository service (Phase 2 wiring).
"""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantOwnedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class RepositoryRow(UUIDPrimaryKeyMixin, TenantOwnedMixin, TimestampMixin, Base):
    __tablename__ = "repositories"

    # The customer-facing slug (== Mongo `id` today).
    external_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    full_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
