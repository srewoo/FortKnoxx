"""Schema-level smoke tests for db_client models.

These don't talk to a real Postgres — they verify that the SQLAlchemy
metadata is well-formed, naming conventions hold, every business table
carries `tenant_id`, and the migration file can be loaded.
A live-Postgres test (Alembic upgrade head + insert + query) belongs
in the integration suite (Phase 9, testcontainers).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from db_client.models import AuditLog, Base, RepositoryRow, Tenant, User


@pytest.fixture(scope="module")
def metadata():
    return Base.metadata


def test_expected_tables_present(metadata):
    names = {t.name for t in metadata.sorted_tables}
    assert {"tenants", "users", "audit_log", "repositories"}.issubset(names)


def test_business_tables_have_tenant_id(metadata):
    # Every business table except tenants itself must carry tenant_id.
    business_tables = {"users", "repositories", "audit_log"}
    for name in business_tables:
        table = metadata.tables[name]
        assert "tenant_id" in table.columns, f"{name} is missing tenant_id"


def test_naming_convention_on_pk(metadata):
    for table in metadata.sorted_tables:
        pks = [c for c in table.constraints if c.__class__.__name__ == "PrimaryKeyConstraint"]
        assert pks, f"{table.name} has no PK"
        # Naming convention: pk_<table>
        for pk in pks:
            assert (
                pk.name == f"pk_{table.name}"
            ), f"PK constraint on {table.name} should be 'pk_{table.name}', got '{pk.name}'"


def test_email_is_citext():
    # citext is essential for case-insensitive lookup; regression
    # would silently allow duplicate users with different casing.
    email_col = User.__table__.columns["email"]
    assert email_col.type.__class__.__name__ == "CITEXT"


def test_audit_log_has_compound_index():
    indexes = {idx.name for idx in AuditLog.__table__.indexes}
    assert "ix_audit_log_tenant_occurred" in indexes


def test_repositories_unique_external_id():
    # SQLAlchemy renders `unique=True` on a Column as either a
    # UniqueConstraint or a unique Index, depending on dialect. Either
    # is fine — the migration explicitly creates a UniqueConstraint.
    col = RepositoryRow.__table__.columns["external_id"]
    assert col.unique is True


def test_tenant_has_unique_slug():
    col = Tenant.__table__.columns["slug"]
    assert col.unique is True


def test_initial_migration_loads():
    """The Alembic revision file must be importable and define upgrade()."""
    backend_root = Path(__file__).resolve().parents[2]
    mig_path = (
        backend_root
        / "db_client"
        / "alembic"
        / "versions"
        / "2026_05_05_0001-tenants_users_audit_log_repositories.py"
    )
    assert mig_path.exists(), f"Migration not found at {mig_path}"

    spec = importlib.util.spec_from_file_location("initial_mig", mig_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0001_init"
    assert module.down_revision is None
    assert callable(module.upgrade)
