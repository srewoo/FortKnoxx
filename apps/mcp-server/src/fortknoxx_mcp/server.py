"""MCP server wiring — tools and resources.

Pattern: tools are thin shells around `ApiClient` calls. Result
formatting is the only logic that lives here, because the IDE renders
tool output as text and we want it readable.

The MCP SDK's `Server` class handles JSON-RPC framing and the stdio /
SSE transports. We only define what to expose.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    ListResourcesResult,
    ListToolsResult,
    Resource,
    TextContent,
    Tool,
)

from .api_client import ApiClient
from .config import Settings, load_settings

logger = logging.getLogger(__name__)


# ----- Tool schemas (JSON Schema) ----------------------------------- #
# These are surfaced to the IDE so the agent can fill arguments
# correctly. Keep them tight — a noisy schema slows the agent down.

_SCAN_REPO_SCHEMA = {
    "type": "object",
    "properties": {
        "repo_id": {
            "type": "string",
            "description": "FortKnoxx repository id (UUID or external slug).",
        },
    },
    "required": ["repo_id"],
}

_GET_FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "scan_id": {"type": "string"},
        "min_severity": {
            "type": "string",
            "enum": ["critical", "high", "medium", "low"],
            "description": "Drop findings below this severity.",
        },
    },
    "required": ["scan_id"],
}

_SUGGEST_FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerability_id": {"type": "string"},
        "provider": {
            "type": "string",
            "enum": ["openai", "anthropic", "gemini"],
            "default": "anthropic",
        },
        "model": {
            "type": "string",
            "description": (
                "Optional. Resolved against llm.model_registry — "
                "leave empty for the provider's current default."
            ),
        },
    },
    "required": ["vulnerability_id"],
}

_REPO_STATS_SCHEMA = {
    "type": "object",
    "properties": {"repo_id": {"type": "string"}},
    "required": ["repo_id"],
}


def build_server(settings: Settings | None = None) -> tuple[Server, ApiClient]:
    """Construct the MCP server and the API client backing its tools.

    Returned together so the caller (the CLI entry point) can close the
    client cleanly on shutdown.
    """
    settings = settings or load_settings()
    api = ApiClient(settings)
    server: Server = Server("fortknoxx-mcp")

    @server.list_tools()
    async def _list_tools() -> ListToolsResult:
        return ListToolsResult(
            tools=[
                Tool(
                    name="fortknoxx.scan_repo",
                    description="Trigger a full security scan against a FortKnoxx-registered repo.",
                    inputSchema=_SCAN_REPO_SCHEMA,
                ),
                Tool(
                    name="fortknoxx.get_findings",
                    description="List vulnerabilities for a scan (optionally filtered by severity).",
                    inputSchema=_GET_FINDINGS_SCHEMA,
                ),
                Tool(
                    name="fortknoxx.suggest_fix",
                    description="LLM-backed fix suggestion for a single vulnerability.",
                    inputSchema=_SUGGEST_FIX_SCHEMA,
                ),
                Tool(
                    name="fortknoxx.repo_stats",
                    description="Headline metrics for a repository: score, severity & OWASP distributions.",
                    inputSchema=_REPO_STATS_SCHEMA,
                ),
            ]
        )

    @server.list_resources()
    async def _list_resources() -> ListResourcesResult:
        # We expose a single discovery resource here. Per-repo and
        # per-scan resources are dynamically resolved via the URI
        # template `fortknoxx://repos/{id}/latest-scan`.
        return ListResourcesResult(
            resources=[
                Resource(
                    uri="fortknoxx://policies/active",
                    name="Active security policies",
                    description="Currently-enforced FortKnoxx security gates for this tenant.",
                    mimeType="application/json",
                ),
            ]
        )

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
        logger.info("tool: %s args=%s", name, arguments)

        try:
            if name == "fortknoxx.scan_repo":
                result = await api.trigger_scan(arguments["repo_id"])
                return _as_text(_format_scan_started(result))
            if name == "fortknoxx.get_findings":
                findings = await api.list_findings(arguments["scan_id"])
                min_sev = arguments.get("min_severity")
                if min_sev:
                    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                    threshold = rank.get(min_sev, 0)
                    findings = [
                        f for f in findings if rank.get(str(f.get("severity")).lower(), 0) >= threshold
                    ]
                return _as_text(_format_findings(findings))
            if name == "fortknoxx.suggest_fix":
                result = await api.request_ai_fix(
                    vulnerability_id=arguments["vulnerability_id"],
                    provider=arguments.get("provider", "anthropic"),
                    model=arguments.get("model"),
                )
                return _as_text(result.get("recommendation") or json.dumps(result, indent=2))
            if name == "fortknoxx.repo_stats":
                stats = await api.get_repository_stats(arguments["repo_id"])
                return _as_text(_format_stats(stats))
        except Exception as exc:  # noqa: BLE001 — surfaced to IDE.
            logger.exception("Tool %s failed", name)
            return _as_text(f"❌ {name} failed: {exc}")

        return _as_text(f"Unknown tool: {name}")

    return server, api


# ---- Formatting helpers -------------------------------------------- #


def _as_text(value: str) -> list[TextContent]:
    return [TextContent(type="text", text=value)]


def _format_scan_started(result: dict[str, Any]) -> str:
    return (
        f"Scan started.\n"
        f"  scan_id: {result.get('scan_id')}\n"
        f"  status:  {result.get('status')}\n"
        f"  message: {result.get('message')}"
    )


def _format_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "No findings."
    lines = [f"{len(findings)} finding(s):", ""]
    for f in findings[:50]:
        lines.append(
            f"- [{str(f.get('severity', '?')).upper()}] "
            f"{f.get('title', 'untitled')} "
            f"({f.get('owasp_category', 'A?')}) "
            f"@ {f.get('file_path', '?')}:{f.get('line_start', '?')}"
        )
    if len(findings) > 50:
        lines.append(f"... and {len(findings) - 50} more (truncated for readability)")
    return "\n".join(lines)


def _format_stats(stats: dict[str, Any]) -> str:
    if "message" in stats:
        return stats["message"]
    sev = stats.get("severity_distribution", {})
    return (
        f"Security score: {stats.get('security_score')}\n"
        f"Total vulnerabilities: {stats.get('total_vulnerabilities')}\n"
        f"  critical: {sev.get('critical', 0)}\n"
        f"  high:     {sev.get('high', 0)}\n"
        f"  medium:   {sev.get('medium', 0)}\n"
        f"  low:      {sev.get('low', 0)}\n"
        f"Files scanned: {stats.get('total_files_scanned')}"
    )


async def run_stdio() -> None:
    """Entry point for the stdio transport (the most common mode)."""
    server, api = build_server()
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        await api.aclose()
