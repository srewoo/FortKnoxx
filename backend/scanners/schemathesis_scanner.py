"""
Schemathesis — property-based API fuzzing driven by an OpenAPI spec.

Catches injection / auth / serialisation flaws that static analysis and
the existing pattern-based api_fuzzer miss, by sending generated traffic
to a running service. Pure DAST — requires a base_url; no-ops without it.

Install:
    pip install schemathesis
"""

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SchemathesisScanner:
    """Wrapper for the `schemathesis` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("schemathesis") or shutil.which("st")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(
        self,
        repo_path: str,
        base_url: Optional[str] = None,
        spec_path: Optional[str] = None,
    ) -> List[Dict]:
        if not await self.is_available():
            logger.warning("schemathesis not installed; skipping. Install: pip install schemathesis")
            return []

        spec = spec_path or _autodetect_spec(repo_path)
        if not spec:
            logger.info("schemathesis: no OpenAPI spec found in %s", repo_path)
            return []
        if not base_url:
            logger.info("schemathesis: base_url not provided; skipping runtime fuzz")
            return []

        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as report:
            cmd = [
                self.binary, "run",
                spec,
                "--base-url", base_url,
                "--checks", "all",
                "--hypothesis-max-examples", "50",
                "--report", report.name,
                "--show-errors-tracebacks",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await proc.communicate()
                report_path = Path(report.name)
                payload = json.loads(report_path.read_text() or "{}") if report_path.exists() else {}
            except Exception as exc:
                logger.error("schemathesis failed: %s", exc)
                return []

        findings = []
        for failure in payload.get("results", []):
            for check in failure.get("checks", []):
                if check.get("value") == "failure":
                    findings.append({
                        "id": f"SCHEMATHESIS-{check.get('name', 'unknown')}",
                        "title": f"API contract violation: {check.get('name')}",
                        "description": check.get("message", ""),
                        "severity": "high" if check.get("name") in {"status_code_conformance", "response_schema_conformance"} else "medium",
                        "url": failure.get("path"),
                        "method": failure.get("method"),
                        "scanner": "schemathesis",
                    })
        return findings


def _autodetect_spec(repo_path: str) -> Optional[str]:
    """Find a likely OpenAPI / Swagger document in the repo root."""
    repo = Path(repo_path)
    for name in ("openapi.yaml", "openapi.yml", "openapi.json", "swagger.yaml", "swagger.json"):
        path = repo / name
        if path.exists():
            return str(path)
    # Fallback: search one level deep.
    for path in list(repo.glob("*/openapi.*")) + list(repo.glob("*/swagger.*")):
        return str(path)
    return None
