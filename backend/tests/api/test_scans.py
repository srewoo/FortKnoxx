"""Tests for api.routes.scans."""

from __future__ import annotations


def _seed_scan(db, **overrides):
    scan = {
        "id": "scan-1",
        "repo_id": "repo-1",
        "status": "completed",
        "started_at": "2026-05-04T00:00:00+00:00",
        "completed_at": "2026-05-04T00:05:00+00:00",
        "total_files": 10,
        "vulnerabilities_count": 3,
        "quality_issues_count": 0,
        "compliance_issues_count": 0,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 1,
        "low_count": 0,
        "security_score": 70,
        "quality_score": 100,
        "compliance_score": 100,
        "scan_results": {},
    }
    scan.update(overrides)
    db.scans.insert(scan)
    return scan


def test_list_scans_empty_when_no_repo_data(client):
    resp = client.get("/api/scans/repo-1")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_scans_returns_scans_for_repo(client, fake_db):
    _seed_scan(fake_db, id="scan-a", started_at="2026-05-04T00:00:00+00:00")
    _seed_scan(fake_db, id="scan-b", started_at="2026-05-05T00:00:00+00:00")

    resp = client.get("/api/scans/repo-1")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    # Most recent first per the route's sort.
    assert body[0]["id"] == "scan-b"


def test_get_scan_detail_404_when_missing(client):
    resp = client.get("/api/scans/detail/missing")
    assert resp.status_code == 404


def test_get_scan_detail_returns_scan(client, fake_db):
    _seed_scan(fake_db)
    resp = client.get("/api/scans/detail/scan-1")
    assert resp.status_code == 200
    assert resp.json()["id"] == "scan-1"


def test_delete_scan_404_when_missing(client):
    resp = client.delete("/api/scans/missing")
    assert resp.status_code == 404


def test_delete_scan_cascades_findings(client, fake_db):
    _seed_scan(fake_db)
    fake_db.vulnerabilities.insert(
        {"id": "v1", "scan_id": "scan-1", "repo_id": "repo-1"},
        {"id": "v2", "scan_id": "scan-1", "repo_id": "repo-1"},
    )
    fake_db.quality_issues.insert({"id": "q1", "scan_id": "scan-1"})
    fake_db.compliance_issues.insert({"id": "c1", "scan_id": "scan-1"})

    resp = client.delete("/api/scans/scan-1")
    assert resp.status_code == 200

    # Scan record + all linked findings deleted.
    assert client.get("/api/scans/detail/scan-1").status_code == 404
    assert client.get("/api/vulnerabilities/scan-1").json() == []
    assert client.get("/api/quality/scan-1").json() == []
    assert client.get("/api/compliance/scan-1").json() == []
