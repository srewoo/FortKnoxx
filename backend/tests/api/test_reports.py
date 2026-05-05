"""Tests for api.routes.reports."""

from __future__ import annotations


def _seed_minimal_scan(db):
    db.scans.insert(
        {
            "id": "scan-1",
            "repo_id": "repo-1",
            "status": "completed",
            "started_at": "2026-05-04T00:00:00+00:00",
        }
    )
    db.repositories.insert({"id": "repo-1", "name": "Sample"})
    db.vulnerabilities.insert(
        {
            "id": "v1",
            "scan_id": "scan-1",
            "repo_id": "repo-1",
            "severity": "high",
            "owasp_category": "A03",
            "file_path": "a.py",
            "line_start": 1,
            "line_end": 2,
            "title": "SQLi",
            "description": "vulnerable query",
            "detected_by": "Semgrep",
        }
    )


def test_generate_404_when_scan_missing(client):
    resp = client.post(
        "/api/reports/generate",
        json={"repo_id": "repo-1", "scan_id": "missing", "format": "json"},
    )
    assert resp.status_code == 404


def test_generate_json_returns_full_report(client, fake_db):
    _seed_minimal_scan(fake_db)

    resp = client.post(
        "/api/reports/generate",
        json={"repo_id": "repo-1", "scan_id": "scan-1", "format": "json"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan"]["id"] == "scan-1"
    assert body["repository"]["id"] == "repo-1"
    assert len(body["vulnerabilities"]) == 1
    # OWASP mapping comes from services.owasp.OWASP_CATEGORIES.
    assert body["owasp_mapping"]["A03"] == "Injection"


def test_generate_csv_returns_flattened_rows(client, fake_db):
    _seed_minimal_scan(fake_db)
    resp = client.post(
        "/api/reports/generate",
        json={"repo_id": "repo-1", "scan_id": "scan-1", "format": "csv"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["format"] == "csv"
    assert body["data"][0]["severity"] == "high"
    assert body["data"][0]["owasp"] == "A03"
    assert body["data"][0]["tool"] == "Semgrep"


def test_generate_unknown_format_returns_message(client, fake_db):
    _seed_minimal_scan(fake_db)
    resp = client.post(
        "/api/reports/generate",
        json={"repo_id": "repo-1", "scan_id": "scan-1", "format": "xml"},
    )
    assert resp.status_code == 200
    assert "Unsupported format" in resp.json()["message"]
