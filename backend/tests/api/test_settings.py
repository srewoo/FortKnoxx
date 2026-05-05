"""Tests for api.routes.settings — keys, scanner toggles, AI toggles."""

from __future__ import annotations


def test_get_settings_returns_response_shape(client):
    resp = client.get("/api/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert "llm_api_keys" in body


def test_post_api_keys_persists_and_returns_summary(client):
    resp = client.post(
        "/api/settings/api-keys",
        json={
            "openai_api_key": "sk-test-openai",
            "anthropic_api_key": "sk-test-anthropic",
        },
    )
    assert resp.status_code == 200
    assert "updated" in resp.json()


def test_get_api_keys_returns_masked(client):
    client.post("/api/settings/api-keys", json={"openai_api_key": "sk-secret-1234567890"})
    resp = client.get("/api/settings/api-keys")
    assert resp.status_code == 200
    keys = resp.json()["keys"]
    # Mask is the first 8 chars + ellipsis (one-char "…").
    assert keys["openai_api_key"].startswith("sk-secre")
    assert "secret-1234567890" not in keys["openai_api_key"]


def test_get_api_keys_returns_none_for_unset(client):
    resp = client.get("/api/settings/api-keys")
    assert resp.json()["keys"] == {}


def test_get_installed_scanners_lists_known_scanners(client):
    resp = client.get("/api/settings/scanners")
    body = resp.json()
    # The dict must contain at least these well-known scanners.
    assert {"semgrep", "gitleaks", "trivy", "checkov", "bandit"}.issubset(body.keys())
    # Each entry has the documented shape.
    for entry in body.values():
        assert "name" in entry and "type" in entry and "installed" in entry
        assert isinstance(entry["installed"], bool)


def test_get_scanners_config_returns_persisted_state(client):
    resp = client.get("/api/settings/scanners/config")
    assert resp.status_code == 200
    # ScannerSettings has "enable_*" fields; sanity-check one.
    body = resp.json()
    assert "enable_semgrep" in body


def test_put_scanners_config_acks(client):
    resp = client.put(
        "/api/settings/scanners",
        json={"enable_semgrep": False},
    )
    assert resp.status_code == 200
    assert resp.json()["message"].lower().startswith("scanner settings updated")


def test_get_ai_scanners_returns_settings(client):
    resp = client.get("/api/settings/ai-scanners")
    body = resp.json()
    assert "enable_zero_day_detector" in body
    assert isinstance(body["enable_zero_day_detector"], bool)


def test_post_ai_scanners_only_updates_provided_fields(client, fake_db):
    # Initial state has zero-day enabled. Toggle a different field.
    resp = client.post(
        "/api/settings/ai-scanners",
        json={"enable_auth_scanner": True},
    )
    body = resp.json()
    assert body["message"].lower().startswith("ai scanner settings updated")
    # The unchanged keys should still be present in the returned snapshot.
    assert "enable_zero_day_detector" in body["updated"]
