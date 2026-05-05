"""Thin HTTP client for the FortKnoxx REST API.

WHY a dedicated module: keeps the MCP server's tool definitions
declarative — each tool just maps args → an `ApiClient` method call.
Auth, retry, and timeout policies live in one place. Phase 4 swaps
HTTP for in-process scanner-worker calls; only this module changes.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .config import Settings

logger = logging.getLogger(__name__)


class ApiClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # AsyncClient is lazily created on first request so the server
        # can start without a live API.
        self._client: httpx.AsyncClient | None = None

    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {"User-Agent": "fortknoxx-mcp/0.1.0"}
            if self._settings.pat:
                headers["Authorization"] = f"Bearer {self._settings.pat}"
            self._client = httpx.AsyncClient(
                base_url=self._settings.api_base,
                timeout=self._settings.request_timeout_s,
                headers=headers,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get(self, path: str, **params: Any) -> Any:
        if not self._settings.pat:
            raise RuntimeError(
                "FORTKNOXX_PAT is not set. Configure your Personal Access Token "
                "in the IDE secret store before invoking FortKnoxx tools."
            )
        client = self._ensure_client()
        resp = await client.get(path, params=params or None)
        resp.raise_for_status()
        return resp.json()

    async def _post(self, path: str, json: dict[str, Any] | None = None) -> Any:
        if not self._settings.pat:
            raise RuntimeError(
                "FORTKNOXX_PAT is not set. Configure your Personal Access Token "
                "in the IDE secret store before invoking FortKnoxx tools."
            )
        client = self._ensure_client()
        resp = await client.post(path, json=json or {})
        resp.raise_for_status()
        return resp.json()

    # ---- Public surface used by the tool layer ---------------------- #

    async def trigger_scan(self, repo_id: str) -> dict[str, Any]:
        return await self._post(f"/api/scans/{repo_id}")

    async def list_scans(self, repo_id: str) -> list[dict[str, Any]]:
        return await self._get(f"/api/scans/{repo_id}")

    async def get_scan(self, scan_id: str) -> dict[str, Any]:
        return await self._get(f"/api/scans/detail/{scan_id}")

    async def list_findings(self, scan_id: str) -> list[dict[str, Any]]:
        return await self._get(f"/api/vulnerabilities/{scan_id}")

    async def get_finding(self, vulnerability_id: str) -> dict[str, Any]:
        # No dedicated single-finding endpoint yet; filter the list
        # response. Phase 1.6 should add `GET /vulnerabilities/by-id/{id}`.
        # TODO: replace with a direct fetch once that lands.
        raise NotImplementedError(
            "Direct finding fetch not yet supported by the API; "
            "list findings for the scan and filter by id client-side."
        )

    async def request_ai_fix(
        self,
        vulnerability_id: str,
        provider: str = "anthropic",
        model: str | None = None,
    ) -> dict[str, Any]:
        return await self._post(
            "/api/ai/fix-recommendation",
            json={
                "vulnerability_id": vulnerability_id,
                "provider": provider,
                "model": model,
            },
        )

    async def get_repository_stats(self, repo_id: str) -> dict[str, Any]:
        return await self._get(f"/api/stats/{repo_id}")
