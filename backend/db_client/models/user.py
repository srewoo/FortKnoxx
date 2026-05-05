"""User table.

Authn is provided by the VPN at the perimeter (per ADR-002, no SSO),
so this table holds *application-level* identity and role mapping
only — no password hashes, no MFA secrets. A future ADR may revisit
if the VPN model changes.
"""

from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import CITEXT
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TenantOwnedMixin, TimestampMixin, UUIDPrimaryKeyMixin


class User(UUIDPrimaryKeyMixin, TenantOwnedMixin, TimestampMixin, Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(CITEXT(), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    # Roles enforced at the API layer; persistence here is just a
    # pointer ("admin" / "security-engineer" / "developer" / "viewer" /
    # "service-account"). Validation happens in the route layer
    # against a whitelist defined alongside the RBAC policy.
    role: Mapped[str] = mapped_column(String(64), nullable=False, default="viewer")
    active: Mapped[bool] = mapped_column(default=True, nullable=False)
