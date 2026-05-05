"""Tests for api.schemas — Pydantic models extracted from server.py.

These cover the field validators that coerce list-shaped scanner output
to scalars. Stored Mongo documents already rely on this behaviour, so
regressions here would silently corrupt persisted data.
"""

from __future__ import annotations

import pytest

from api.schemas import (
    AIFixRequest,
    Repository,
    RepositoryCreate,
    Scan,
    Vulnerability,
)


class TestRepository:
    def test_minimal_construction(self):
        r = Repository(name="x", url="https://example.com")
        assert r.name == "x"
        assert r.scan_status == "pending"
        assert len(r.id) == 36  # uuid4
        assert r.vulnerabilities_count == 0

    def test_extra_fields_ignored(self):
        r = Repository.model_validate(
            {
                "name": "x",
                "url": "https://example.com",
                "unknown_field": "ignored",
            }
        )
        assert not hasattr(r, "unknown_field")


class TestRepositoryCreate:
    def test_requires_access_token(self):
        with pytest.raises(Exception):
            RepositoryCreate(name="x", url="y")  # missing access_token


class TestVulnerabilityNormalisers:
    def _build(self, **overrides):
        defaults = dict(
            repo_id="r",
            scan_id="s",
            file_path="a.py",
            line_start=1,
            line_end=2,
            severity="high",
            category="c",
            owasp_category="A01",
            title="t",
            description="d",
            detected_by="unit",
        )
        defaults.update(overrides)
        return Vulnerability(**defaults)

    def test_severity_list_is_coerced(self):
        v = self._build(severity=["high"])
        assert v.severity == "high"

    def test_severity_empty_list_defaults_to_medium(self):
        v = self._build(severity=[])
        assert v.severity == "medium"

    def test_file_path_list_is_coerced(self):
        v = self._build(file_path=["src/a.py"])
        assert v.file_path == "src/a.py"

    def test_file_path_empty_list_becomes_empty_string(self):
        v = self._build(file_path=[])
        assert v.file_path == ""

    def test_cwe_list_is_coerced(self):
        v = self._build(cwe=["CWE-89"])
        assert v.cwe == "CWE-89"

    def test_cwe_empty_list_becomes_none(self):
        v = self._build(cwe=[])
        assert v.cwe is None

    def test_scalar_severity_unchanged(self):
        v = self._build(severity="critical")
        assert v.severity == "critical"


class TestScan:
    def test_defaults(self):
        s = Scan(repo_id="r")
        assert s.status == "pending"
        assert s.security_score == 0
        assert s.scan_results == {}


class TestAIFixRequest:
    def test_provider_defaults_to_anthropic_and_model_to_none(self):
        req = AIFixRequest(vulnerability_id="v")
        assert req.provider == "anthropic"
        assert req.model is None
