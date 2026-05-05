"""
kube-hunter — runtime probe of a Kubernetes cluster from an attacker
perspective. Looks for exposed dashboards, anonymous-auth API servers,
kubelet read-only ports, etc.

Install:
    pip install kube-hunter
"""

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class KubeHunterScanner:
    """Wrapper for the `kube-hunter` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("kube-hunter")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(self, remote: Optional[str] = None) -> List[Dict]:
        if not await self.is_available():
            logger.warning("kube-hunter not installed; skipping. Install: pip install kube-hunter")
            return []

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "kube-hunter.json"
            cmd = [self.binary, "--report", "json", "--log", "WARN"]
            if remote:
                cmd += ["--remote", remote]
            else:
                cmd += ["--cidr", "127.0.0.1/32"]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()
                report_path.write_bytes(stdout)
                payload = json.loads(stdout.decode() or "{}")
            except Exception as exc:
                logger.error("kube-hunter failed: %s", exc)
                return []

        severity_map = {"high": "high", "medium": "medium", "low": "low"}
        findings = []
        for vuln in payload.get("vulnerabilities", []):
            findings.append({
                "id": f"KUBEHUNTER-{vuln.get('vid', 'unknown')}",
                "title": vuln.get("vulnerability", "K8s cluster exposure"),
                "description": vuln.get("description", ""),
                "severity": severity_map.get((vuln.get("severity") or "").lower(), "medium"),
                "scanner": "kube-hunter",
                "metadata": {
                    "category": vuln.get("category"),
                    "location": vuln.get("location"),
                    "evidence": vuln.get("evidence"),
                },
            })
        return findings
