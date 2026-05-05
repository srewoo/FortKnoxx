"""Tests for api.routes.stats."""

from __future__ import annotations


def test_returns_message_when_no_completed_scan(client):
    resp = client.get("/api/stats/repo-1")
    assert resp.status_code == 200
    assert resp.json() == {"message": "No completed scans found"}


def test_returns_distribution_for_latest_scan(client, fake_db):
    fake_db.scans.insert(
        {
            "id": "scan-1",
            "repo_id": "repo-1",
            "status": "completed",
            "started_at": "2026-05-04T00:00:00Z",
            "security_score": 75,
            "vulnerabilities_count": 4,
            "critical_count": 1,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 1,
            "total_files": 42,
            "scan_results": {"semgrep": 2, "trivy": 1},
        }
    )
    fake_db.vulnerabilities.insert(
        {"id": "v1", "scan_id": "scan-1", "owasp_category": "A01"},
        {"id": "v2", "scan_id": "scan-1", "owasp_category": "A03"},
        {"id": "v3", "scan_id": "scan-1", "owasp_category": "A03"},
    )

    resp = client.get("/api/stats/repo-1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["security_score"] == 75
    assert body["total_vulnerabilities"] == 4
    assert body["severity_distribution"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
    }
    assert body["owasp_distribution"] == {"A01": 1, "A03": 2}
    assert body["total_files_scanned"] == 42
    assert body["tools_used"] == {"semgrep": 2, "trivy": 1}


def test_handles_vuln_without_owasp_category(client, fake_db):
    fake_db.scans.insert(
        {
            "id": "scan-1",
            "repo_id": "repo-1",
            "status": "completed",
            "started_at": "2026-05-04T00:00:00Z",
        }
    )
    fake_db.vulnerabilities.insert({"id": "v1", "scan_id": "scan-1"})  # no owasp_category

    resp = client.get("/api/stats/repo-1")
    assert resp.status_code == 200
    assert resp.json()["owasp_distribution"] == {"unknown": 1}
