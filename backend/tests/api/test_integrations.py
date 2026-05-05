"""Tests for api.routes.integrations."""

from __future__ import annotations


def test_list_integrations_returns_empty_by_default(client):
    resp = client.get("/api/integrations/git")
    assert resp.status_code == 200
    assert resp.json() == {"integrations": []}


def test_connect_integration_happy_path(client, fake_client_factory, fake_db):
    # Use a fresh client so we can mutate the FakeGitIntegration
    # behaviour for this test in isolation.
    c = fake_client_factory(fake_db)

    resp = c.post(
        "/api/integrations/git/connect",
        json={
            "provider": "github",
            "name": "default",
            "access_token": "ghp_fake",
            "base_url": None,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True


def test_disconnect_with_invalid_provider_returns_400(client):
    resp = client.delete("/api/integrations/git/not-a-real-provider")
    assert resp.status_code == 400


def test_list_remote_repos_for_invalid_provider_returns_400(client):
    resp = client.get("/api/integrations/git/not-a-provider/repositories")
    assert resp.status_code == 400


def test_list_remote_repos_uses_pagination_params(client):
    # The fake returns success regardless; smoke check that pagination
    # query params don't break the route.
    resp = client.get("/api/integrations/git/github/repositories?page=2&per_page=50")
    assert resp.status_code == 200
    assert resp.json()["success"] is True
