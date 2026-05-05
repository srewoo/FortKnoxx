"""Unit tests for the MCP server's HTTP client.

These exercise the tool-layer plumbing (URL shape, header handling,
PAT enforcement) without standing up a real MCP transport. The
end-to-end MCP test belongs in Phase 11's integration suite once a
test PAT issuance flow exists in the API.
"""

from __future__ import annotations

import pytest
import httpx

from fortknoxx_mcp.api_client import ApiClient
from fortknoxx_mcp.config import Settings


def _settings(pat: str = "test-pat") -> Settings:
    return Settings(api_base="http://api.test", pat=pat, request_timeout_s=5.0, log_level="INFO")


@pytest.fixture
def mock_transport():
    return httpx.MockTransport(_handler)


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/api/scans/repo-1" and request.method == "POST":
        return httpx.Response(200, json={"scan_id": "s-1", "status": "started", "message": "ok"})
    if request.url.path == "/api/scans/repo-1" and request.method == "GET":
        return httpx.Response(200, json=[{"id": "s-1"}])
    if request.url.path == "/api/vulnerabilities/s-1":
        return httpx.Response(200, json=[{"id": "v-1", "severity": "high"}])
    if request.url.path == "/api/stats/repo-1":
        return httpx.Response(200, json={"security_score": 80})
    return httpx.Response(404, json={"detail": "not found"})


def _patch_client(client: ApiClient, transport: httpx.MockTransport) -> None:
    """Inject the mock transport into the lazily-created httpx client."""
    headers = {"User-Agent": "fortknoxx-mcp/0.1.0", "Authorization": "Bearer test-pat"}
    client._client = httpx.AsyncClient(  # noqa: SLF001 — test override is intentional
        base_url=client._settings.api_base,  # noqa: SLF001
        timeout=5.0,
        headers=headers,
        transport=transport,
    )


@pytest.mark.asyncio
async def test_trigger_scan_calls_correct_endpoint(mock_transport):
    api = ApiClient(_settings())
    _patch_client(api, mock_transport)
    result = await api.trigger_scan("repo-1")
    assert result["scan_id"] == "s-1"
    assert result["status"] == "started"
    await api.aclose()


@pytest.mark.asyncio
async def test_list_findings(mock_transport):
    api = ApiClient(_settings())
    _patch_client(api, mock_transport)
    result = await api.list_findings("s-1")
    assert result == [{"id": "v-1", "severity": "high"}]
    await api.aclose()


@pytest.mark.asyncio
async def test_repo_stats(mock_transport):
    api = ApiClient(_settings())
    _patch_client(api, mock_transport)
    result = await api.get_repository_stats("repo-1")
    assert result["security_score"] == 80
    await api.aclose()


@pytest.mark.asyncio
async def test_missing_pat_raises_clear_error():
    api = ApiClient(_settings(pat=""))
    with pytest.raises(RuntimeError, match="FORTKNOXX_PAT"):
        await api.trigger_scan("repo-1")


@pytest.mark.asyncio
async def test_missing_pat_on_get_also_raises():
    api = ApiClient(_settings(pat=""))
    with pytest.raises(RuntimeError, match="FORTKNOXX_PAT"):
        await api.list_findings("s-1")
