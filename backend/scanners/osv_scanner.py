"""
osv-scanner — multi-ecosystem dependency vulnerability scanner.

Powered by Google's OSV.dev database. Single binary covers PyPI, npm,
Go, Maven, Cargo, RubyGems, NuGet, Packagist, and OS packages — broader
ecosystem coverage than pip-audit alone.

Install:
    brew install osv-scanner
    # or: go install github.com/google/osv-scanner/cmd/osv-scanner@v1
"""

import asyncio
import json
import logging
import shutil
from typing import List, Dict

logger = logging.getLogger(__name__)


class OSVScanner:
    """Wrapper for the `osv-scanner` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("osv-scanner")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        if not await self.is_available():
            logger.warning("osv-scanner not installed; skipping. Install: brew install osv-scanner")
            return []

        cmd = [self.binary, "--format", "json", "--recursive", repo_path]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if not stdout:
                return []
            payload = json.loads(stdout.decode())
        except json.JSONDecodeError:
            logger.warning("osv-scanner returned non-JSON output")
            return []
        except Exception as exc:
            logger.error("osv-scanner failed: %s", exc)
            return []

        findings: List[Dict] = []
        for result in payload.get("results", []):
            source_path = result.get("source", {}).get("path", "")
            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
                    severity = _max_severity(vuln.get("severity", []))
                    findings.append({
                        "id": vuln.get("id", "OSV-UNKNOWN"),
                        "title": vuln.get("summary", vuln.get("id", "OSV vulnerability")),
                        "description": vuln.get("details", ""),
                        "severity": severity,
                        "package": pkg_info.get("name"),
                        "ecosystem": pkg_info.get("ecosystem"),
                        "installed_version": pkg_info.get("version"),
                        "fixed_versions": _collect_fixed_versions(vuln),
                        "references": [r.get("url") for r in vuln.get("references", []) if r.get("url")],
                        "file_path": source_path,
                        "aliases": vuln.get("aliases", []),
                        "scanner": "osv-scanner",
                    })
        return findings


def _max_severity(severity_list: List[Dict]) -> str:
    """Pull the highest CVSS score out of OSV's severity array; map to label."""
    score = 0.0
    for entry in severity_list:
        raw = entry.get("score", "")
        # CVSS vector starts with "CVSS:". Numeric scores come through OSV API.
        try:
            score = max(score, float(raw))
        except (TypeError, ValueError):
            continue
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "medium"


def _collect_fixed_versions(vuln: Dict) -> List[str]:
    fixed: List[str] = []
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return fixed
