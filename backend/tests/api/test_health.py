"""Tests for api.routes.health."""

from __future__ import annotations


def test_root_returns_version(client):
    resp = client.get("/api/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["message"] == "Security Intelligence Platform API"
    assert body["version"] == "1.0.0"


def test_health_when_db_pings(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["database"] == "connected"
    # No scanner report bound in tests — should remain None.
    assert body["scanners"] is None


def test_scanner_health_returns_fresh_report_when_unbound(client, monkeypatch):
    # When no cached report exists, the route runs check_all_scanners.
    # The fake settings manager returns an empty config; we stub the
    # scanner check to avoid touching real binaries.
    from api.routes import health as health_module

    class _FakeReport:
        def to_dict(self):
            return {"available": [], "unavailable": [], "stub": True}

    async def _fake_check(_settings):
        return _FakeReport()

    monkeypatch.setattr(health_module, "check_all_scanners", _fake_check)

    resp = client.get("/api/scanners/health")
    assert resp.status_code == 200
    assert resp.json() == {"available": [], "unavailable": [], "stub": True}
