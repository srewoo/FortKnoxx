"""
kube-bench — CIS Kubernetes Benchmark check.

Audits the kubelet / API-server / etcd / controller-manager config of
the cluster the host is part of (or a static config file path).

Install:
    brew install kube-bench
    # or:  https://github.com/aquasecurity/kube-bench/releases
"""

import asyncio
import json
import logging
import shutil
from typing import Dict, List

logger = logging.getLogger(__name__)


class KubeBenchScanner:
    """Wrapper for the `kube-bench` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("kube-bench")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(self, targets: str = "node") -> List[Dict]:
        if not await self.is_available():
            logger.warning("kube-bench not installed; skipping. https://github.com/aquasecurity/kube-bench")
            return []

        cmd = [self.binary, "run", "--targets", targets, "--json"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            payload = json.loads(stdout.decode() or "{}")
        except Exception as exc:
            logger.error("kube-bench failed: %s", exc)
            return []

        findings: List[Dict] = []
        for control in payload.get("Controls", []):
            for test in control.get("tests", []):
                for result in test.get("results", []):
                    state = (result.get("status") or "").upper()
                    if state in {"PASS", "INFO"}:
                        continue
                    severity = "high" if state == "FAIL" else "medium"
                    findings.append({
                        "id": f"CIS-{result.get('test_number', 'unknown')}",
                        "title": result.get("test_desc", "CIS K8s benchmark failure"),
                        "description": result.get("remediation", ""),
                        "severity": severity,
                        "scanner": "kube-bench",
                        "metadata": {
                            "section": control.get("text"),
                            "scored": result.get("scored"),
                            "actual_value": result.get("actual_value"),
                        },
                    })
        return findings
