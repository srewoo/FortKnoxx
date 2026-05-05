"""Tenant table — root of the multi-tenancy model."""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Tenant(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), nullable=False, unique=True, index=True)
    # active=False soft-deletes a tenant without removing rows; needed
    # for incident response and licence revocation.
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
