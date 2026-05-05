"""Alembic environment.

Drives forward-only migrations against Postgres. We do not support
``alembic downgrade`` in production — schema changes flow through the
three-step pattern (add nullable → backfill → constrain). See
CLAUDE.md §6.
"""

from __future__ import annotations

import os

# Make the backend/ tree importable so we can pick up models.
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from db_client.models import Base  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Resolve the connection string from POSTGRES_DSN — Alembic itself uses
# psycopg2/sync, not asyncpg, so swap the driver if a callers passed an
# asyncpg URL.
dsn = os.environ.get("POSTGRES_DSN")
if not dsn:
    raise RuntimeError(
        "POSTGRES_DSN must be set to run migrations. Example: "
        "postgresql://fortknoxx:secret@localhost:5432/fortknoxx"
    )
if dsn.startswith("postgresql+asyncpg://"):
    dsn = dsn.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)

config.set_main_option("sqlalchemy.url", dsn)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=dsn,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
