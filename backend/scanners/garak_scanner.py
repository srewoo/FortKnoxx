"""
NVIDIA garak — LLM red-teaming framework.

Probes generative-AI endpoints for prompt injection, jailbreaks, data
leakage, encoding attacks, and toxicity. Complements FortKnoxx's existing
LLM_security engine (which focuses on static surface discovery) by
running active adversarial probes against a live model.

Install:
    pip install garak
"""

import asyncio
import json
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class GarakScanner:
    """Wrapper for the `garak` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("garak")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(
        self,
        model_type: str = "openai",
        model_name: str = "gpt-3.5-turbo",
        probes: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Run a garak probe sweep against the configured model.

        ``model_type`` / ``model_name`` follow garak's naming
        (e.g. openai/gpt-4, huggingface/gpt2, replicate/llama2).
        """
        if not await self.is_available():
            logger.warning("garak not installed; skipping. Install: pip install garak")
            return []

        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "garak.report.jsonl"
            cmd = [
                self.binary,
                "--model_type", model_type,
                "--model_name", model_name,
                "--probes", ",".join(probes or ["promptinject", "dan", "leakreplay"]),
                "--report_prefix", str(report_path.with_suffix("")),
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
            except Exception as exc:
                logger.error("garak failed: %s", exc)
                return []

            return _parse_report(report_path)


def _parse_report(report_path: Path) -> List[Dict]:
    if not report_path.exists():
        return []
    findings: List[Dict] = []
    for line in report_path.read_text().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("entry_type") != "eval":
            continue
        passed = int(entry.get("passed", 0))
        total = int(entry.get("total", 0)) or 1
        if passed >= total:
            continue  # All probes survived — no finding.
        fail_rate = 1 - (passed / total)
        findings.append({
            "id": f"GARAK-{entry.get('probe', 'unknown')}-{entry.get('detector', 'unknown')}",
            "title": f"LLM red-team failure: {entry.get('probe')}",
            "description": (
                f"Probe '{entry.get('probe')}' detector '{entry.get('detector')}' "
                f"failed {total - passed}/{total} attempts ({fail_rate:.0%})."
            ),
            "severity": _severity(fail_rate),
            "scanner": "garak",
            "metadata": {
                "probe": entry.get("probe"),
                "detector": entry.get("detector"),
                "passed": passed,
                "total": total,
            },
        })
    return findings


def _severity(fail_rate: float) -> str:
    if fail_rate >= 0.5:
        return "critical"
    if fail_rate >= 0.25:
        return "high"
    if fail_rate >= 0.1:
        return "medium"
    return "low"
