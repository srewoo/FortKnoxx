"""Tests for api.routes.findings — vulnerabilities, quality, compliance, SBOM."""

from __future__ import annotations


def _seed_vuln(db, **overrides):
    base = {
        "id": "v-1",
        "repo_id": "repo-1",
        "scan_id": "scan-1",
        "file_path": "a.py",
        "line_start": 1,
        "line_end": 2,
        "severity": "high",
        "category": "injection",
        "owasp_category": "A03",
        "title": "t",
        "description": "d",
        "detected_by": "Semgrep",
        "created_at": "2026-05-04T00:00:00+00:00",
    }
    base.update(overrides)
    db.vulnerabilities.insert(base)
    return base


# ---------------------------------------------------------------- #
# Vulnerabilities
# ---------------------------------------------------------------- #


def test_list_vulns_for_scan_empty(client):
    assert client.get("/api/vulnerabilities/scan-1").json() == []


def test_list_vulns_for_scan_returns_records(client, fake_db):
    _seed_vuln(fake_db)
    resp = client.get("/api/vulnerabilities/scan-1")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_list_vulns_for_repo(client, fake_db):
    _seed_vuln(fake_db, id="v-a")
    _seed_vuln(fake_db, id="v-b", scan_id="scan-2")
    resp = client.get("/api/vulnerabilities/repo/repo-1")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


# ---------------------------------------------------------------- #
# Quality
# ---------------------------------------------------------------- #


def test_quality_summary_empty(client):
    resp = client.get("/api/quality/summary/scan-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_issues"] == 0
    assert body["quality_score"] == 100


def test_quality_summary_aggregates(client, fake_db):
    fake_db.quality_issues.insert(
        {
            "id": "q1",
            "scan_id": "scan-1",
            "severity": "high",
            "category": "complexity",
            "detected_by": "Pylint",
        },
        {"id": "q2", "scan_id": "scan-1", "severity": "low", "category": "style", "detected_by": "Flake8"},
        {
            "id": "q3",
            "scan_id": "scan-1",
            "severity": "medium",
            "category": "complexity",
            "detected_by": "Pylint",
        },
    )
    resp = client.get("/api/quality/summary/scan-1")
    body = resp.json()
    assert body["total_issues"] == 3
    assert body["by_severity"]["high"] == 1
    assert body["by_severity"]["medium"] == 1
    assert body["by_severity"]["low"] == 1
    assert body["by_category"]["complexity"] == 2
    assert body["by_scanner"]["Pylint"] == 2
    assert 0 <= body["quality_score"] <= 100


# ---------------------------------------------------------------- #
# Compliance
# ---------------------------------------------------------------- #


def test_compliance_summary_empty(client):
    resp = client.get("/api/compliance/summary/scan-1")
    body = resp.json()
    assert body["total_issues"] == 0
    assert body["compliance_score"] == 100


def test_compliance_summary_aggregates(client, fake_db):
    fake_db.compliance_issues.insert(
        {"id": "c1", "scan_id": "scan-1", "license_risk": "high", "license": "GPL-3.0"},
        {"id": "c2", "scan_id": "scan-1", "license_risk": "low", "license": "MIT"},
        {"id": "c3", "scan_id": "scan-1", "license_risk": "weird", "license": "Custom"},
    )
    resp = client.get("/api/compliance/summary/scan-1")
    body = resp.json()
    assert body["total_issues"] == 3
    assert body["by_risk_level"]["high"] == 1
    assert body["by_risk_level"]["low"] == 1
    assert body["by_risk_level"]["unknown"] == 1  # bucket for unrecognised risk
    assert body["by_license"]["GPL-3.0"] == 1


# ---------------------------------------------------------------- #
# SBOM
# ---------------------------------------------------------------- #


def test_sbom_404_when_no_completed_scans(client):
    resp = client.get("/api/sbom/repo-1")
    assert resp.status_code == 404


def test_sbom_returns_packages(client, fake_db):
    fake_db.scans.insert(
        {
            "id": "scan-1",
            "repo_id": "repo-1",
            "status": "completed",
            "started_at": "2026-05-04T00:00:00+00:00",
        }
    )
    fake_db.compliance_issues.insert(
        {
            "scan_id": "scan-1",
            "package_name": "requests",
            "package_version": "2.31.0",
            "package_type": "pypi",
            "license": "Apache-2.0",
            "license_risk": "low",
        },
        {
            "scan_id": "scan-1",
            "package_name": "lodash",
            "package_version": "4.17.21",
            "package_type": "npm",
            "license": "MIT",
            "license_risk": "low",
        },
    )

    resp = client.get("/api/sbom/repo-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["repo_id"] == "repo-1"
    assert body["total_packages"] == 2
    names = {pkg["name"] for pkg in body["packages"]}
    assert names == {"requests", "lodash"}
