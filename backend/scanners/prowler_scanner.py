"""
Prowler — multi-cloud security & compliance auditor (AWS, GCP, Azure, K8s).

Complements the IaC scanner by auditing *deployed* cloud configuration —
the IaC scanner only sees pre-deploy templates, prowler sees what's
actually running.

Requires cloud credentials in the standard SDK locations
(AWS_PROFILE, GOOGLE_APPLICATION_CREDENTIALS, az login, etc.).

Install:
    pip install prowler
"""

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


class ProwlerScanner:
    """Wrapper for the `prowler` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("prowler")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(self, provider: str = "aws") -> List[Dict]:
        if not await self.is_available():
            logger.warning("prowler not installed; skipping. Install: pip install prowler")
            return []

        with tempfile.TemporaryDirectory() as tmp:
            cmd = [
                self.binary, provider,
                "--output-formats", "json-ocsf",
                "--output-directory", tmp,
                "--output-filename", "prowler",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await proc.communicate()
            except Exception as exc:
                logger.error("prowler failed: %s", exc)
                return []

            report = Path(tmp) / "prowler.ocsf.json"
            if not report.exists():
                logger.warning("prowler produced no report: %s", stderr.decode()[:300])
                return []

            try:
                events = json.loads(report.read_text())
            except json.JSONDecodeError:
                return []

        findings = []
        for event in events:
            if event.get("status_code", "").upper() == "PASS":
                continue
            finding = event.get("finding", {})
            severity = SEVERITY_MAP.get((event.get("severity") or "").lower(), "medium")
            findings.append({
                "id": finding.get("uid") or event.get("uid", "PROWLER-UNKNOWN"),
                "title": finding.get("title", "Cloud misconfiguration"),
                "description": finding.get("desc", ""),
                "severity": severity,
                "scanner": f"prowler-{provider}",
                "metadata": {
                    "resource": event.get("resources", [{}])[0].get("uid"),
                    "region": event.get("cloud", {}).get("region"),
                    "compliance": [c.get("standards") for c in event.get("compliance", {}).get("requirements", [])],
                },
            })
        return findings
