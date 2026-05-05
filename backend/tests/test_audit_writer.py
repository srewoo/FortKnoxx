"""Tests for services.audit_writer.

These tests don't talk to a real Postgres. They inject a fake session
factory so we can assert on what would have been persisted. The live
Postgres path is covered by Phase 9 testcontainers integration tests.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest

from services.audit_writer import record_audit


class _FakeSession:
    def __init__(self):
        self.added: list = []
        self.committed = False

    def add(self, row):
        self.added.append(row)


def _make_factory():
    captured = {"sessions": []}

    @asynccontextmanager
    async def factory():
        s = _FakeSession()
        captured["sessions"].append(s)
        try:
            yield s
            s.committed = True
        except Exception:
            raise

    return factory, captured


@pytest.mark.asyncio
async def test_writes_row_when_factory_provided():
    factory, captured = _make_factory()

    ok = await record_audit(
        action="repository.deleted",
        target_type="repository",
        target_id="repo-123",
        diff={"reason": "user-request"},
        session_factory=factory,
    )

    assert ok is True
    assert len(captured["sessions"]) == 1
    session = captured["sessions"][0]
    assert session.committed is True
    assert len(session.added) == 1
    row = session.added[0]
    assert row.action == "repository.deleted"
    assert row.target_type == "repository"
    assert row.target_id == "repo-123"
    assert row.diff == {"reason": "user-request"}


@pytest.mark.asyncio
async def test_uses_system_identity_when_actor_not_provided():
    factory, captured = _make_factory()
    await record_audit(
        action="x", target_type="y", target_id="z", session_factory=factory,
    )
    row = captured["sessions"][0].added[0]
    assert isinstance(row.tenant_id, uuid.UUID)
    assert isinstance(row.actor_id, uuid.UUID)


@pytest.mark.asyncio
async def test_respects_explicit_actor_and_tenant():
    factory, captured = _make_factory()
    actor = uuid.uuid4()
    tenant = uuid.uuid4()
    await record_audit(
        action="x", target_type="y", target_id="z",
        actor_id=actor, tenant_id=tenant, trace_id="trace-abc",
        session_factory=factory,
    )
    row = captured["sessions"][0].added[0]
    assert row.actor_id == actor
    assert row.tenant_id == tenant
    assert row.trace_id == "trace-abc"


@pytest.mark.asyncio
async def test_no_op_when_postgres_disabled_and_no_factory():
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("POSTGRES_DSN", None)
        ok = await record_audit(
            action="x", target_type="y", target_id="z",
        )
        assert ok is False


@pytest.mark.asyncio
async def test_swallows_session_error_does_not_raise():
    @asynccontextmanager
    async def broken_factory():
        raise RuntimeError("connection refused")
        yield  # pragma: no cover

    ok = await record_audit(
        action="x", target_type="y", target_id="z",
        session_factory=broken_factory,
    )
    assert ok is False


@pytest.mark.asyncio
async def test_diff_defaults_to_empty_dict():
    factory, captured = _make_factory()
    await record_audit(
        action="x", target_type="y", target_id="z", session_factory=factory,
    )
    row = captured["sessions"][0].added[0]
    assert row.diff == {}


@pytest.mark.asyncio
async def test_target_id_coerced_to_string():
    factory, captured = _make_factory()
    await record_audit(
        action="x", target_type="y", target_id=42, session_factory=factory,
    )
    row = captured["sessions"][0].added[0]
    assert row.target_id == "42"
