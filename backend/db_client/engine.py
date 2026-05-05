"""Async SQLAlchemy engine + session factory.

WHY a single module: every other module imports `get_session()` from
here so we have one place to enforce pool sizing, statement timeouts,
and the per-request connection lifecycle.

Configuration is read from env at first use:
  POSTGRES_DSN          required, e.g. postgresql+asyncpg://user:pass@host/db
  POSTGRES_POOL_SIZE    default 10
  POSTGRES_MAX_OVERFLOW default 20
  POSTGRES_ECHO         default false (set true to log all SQL)
"""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logger = logging.getLogger(__name__)

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _build_engine() -> AsyncEngine:
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        raise RuntimeError(
            "POSTGRES_DSN is not set. Phase 2 requires Postgres; configure "
            "in backend/.env or skip importing db_client until Phase 2 wiring."
        )
    pool_size = int(os.environ.get("POSTGRES_POOL_SIZE", "10"))
    max_overflow = int(os.environ.get("POSTGRES_MAX_OVERFLOW", "20"))
    echo = os.environ.get("POSTGRES_ECHO", "false").lower() == "true"

    return create_async_engine(
        dsn,
        echo=echo,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,  # cheap liveness check on checkout
        pool_recycle=1800,  # recycle every 30 min to avoid stale TCP sessions
    )


def get_engine() -> AsyncEngine:
    global _engine, _session_factory
    if _engine is None:
        _engine = _build_engine()
        _session_factory = async_sessionmaker(
            _engine,
            expire_on_commit=False,
            autoflush=False,
        )
        logger.info("Postgres engine initialised")
    return _engine


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """Async context manager that yields a session and commits on success.

    On exception, rolls back. Always closes the session.
    Use:
        async with get_session() as s:
            s.add(...)
    """
    if _session_factory is None:
        get_engine()  # populates _session_factory as a side-effect
    assert _session_factory is not None

    session = _session_factory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def dispose_engine() -> None:
    """Close the connection pool. Call from FastAPI lifespan shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None
        logger.info("Postgres engine disposed")
