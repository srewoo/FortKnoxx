"""Auto-detect OpenAPI/Swagger specs on a running target.

We probe a small list of well-known paths in parallel and return the
first one that responds with a 200 + a JSON/YAML body that looks like a
spec (has ``openapi`` or ``swagger`` at the top level).

This eliminates the need for the user to hand-supply ``api_spec_path``
in the common case.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin

import httpx

logger = logging.getLogger(__name__)

CANDIDATE_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/openapi.yaml",
    "/swagger.yaml",
)


def _looks_like_spec(content_type: str, body: str) -> bool:
    """Cheap heuristic — avoid full YAML/JSON parsing in the hot path."""
    if not body:
        return False
    head = body[:512].lower()
    if "openapi" in head or "swagger" in head:
        return True
    # Some specs only declare the version inside `info:`; fall back to
    # MIME type when the head sniff misses it.
    return "yaml" in content_type or "json" in content_type and "paths" in head


async def _probe(client: httpx.AsyncClient, base_url: str, path: str) -> str | None:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    try:
        resp = await client.get(url, timeout=4.0, follow_redirects=True)
    except (httpx.HTTPError, httpx.InvalidURL):
        return None
    if resp.status_code != 200:
        return None
    if _looks_like_spec(resp.headers.get("content-type", ""), resp.text):
        return str(resp.url)
    return None


async def discover_openapi_spec_url(target_url: str, *, timeout: float = 8.0) -> str | None:
    """Probe ``CANDIDATE_PATHS`` in parallel and return the first hit."""
    if not target_url:
        return None

    async with httpx.AsyncClient(timeout=timeout) as client:
        tasks = [
            asyncio.create_task(_probe(client, target_url, p))
            for p in CANDIDATE_PATHS
        ]
        try:
            for completed in asyncio.as_completed(tasks, timeout=timeout):
                if (found := await completed):
                    for t in tasks:
                        if not t.done():
                            t.cancel()
                    logger.info("OpenAPI spec discovered at %s", found)
                    return found
        except asyncio.TimeoutError:
            logger.info("OpenAPI auto-discovery timed out for %s", target_url)
    return None
