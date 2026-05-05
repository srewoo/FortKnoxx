"""SQLAlchemy declarative models for FortKnoxx Postgres schema.

Every model imports `Base` from this package so Alembic autogenerate
sees them. Add new model modules by importing them at the bottom of
this file.

Schema design principles (per ADR-003):

- **`tenant_id` on every business table** so row-level security is
  expressible. Even single-tenant deployments must populate it
  (default tenant id can be a constant UUID).
- **UUID primary keys** for portability and scale-out safety.
- **Audit columns** (`created_at`, `updated_at`) on every mutable
  table; `created_at` is server-default `now()`.
- **No raw FKs across schemas** — use logical references for now.
- **`citext` for case-insensitive lookup** (emails, repo URLs).
"""

from .audit_log import AuditLog
from .base import Base
from .repository import RepositoryRow
from .tenant import Tenant
from .user import User

__all__ = ["Base", "AuditLog", "RepositoryRow", "Tenant", "User"]
