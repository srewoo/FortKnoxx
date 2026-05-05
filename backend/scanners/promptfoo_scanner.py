"""
promptfoo — eval harness for LLM prompts.

Used here as a regression suite: detect prompt-injection / jailbreak /
PII-leak failures against the project's prompt files. Activates only
when a `promptfooconfig.yaml` is present in the repo (project opt-in).

Install:
    npm i -g promptfoo
"""

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class PromptfooScanner:
    """Wrapper for the `promptfoo` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("promptfoo")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        if not await self.is_available():
            logger.warning("promptfoo not installed; skipping. Install: npm i -g promptfoo")
            return []

        config = _find_config(repo_path)
        if not config:
            logger.info("promptfoo: no promptfooconfig.{yaml,yml,json} in %s", repo_path)
            return []

        cmd = [self.binary, "eval", "-c", str(config), "--output", "-", "--no-progress-bar"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path,
            )
            stdout, _ = await proc.communicate()
            if not stdout:
                return []
            payload = json.loads(stdout.decode())
        except Exception as exc:
            logger.error("promptfoo failed: %s", exc)
            return []

        findings: List[Dict] = []
        for row in payload.get("results", {}).get("results", []):
            if row.get("success"):
                continue
            findings.append({
                "id": f"PROMPTFOO-{row.get('id', 'unknown')}",
                "title": f"Prompt eval failed: {row.get('description', row.get('id', 'case'))}",
                "description": row.get("response", {}).get("error", "") or row.get("gradingResult", {}).get("reason", ""),
                "severity": "high",
                "scanner": "promptfoo",
                "metadata": {
                    "prompt": row.get("prompt"),
                    "vars": row.get("vars"),
                },
            })
        return findings


def _find_config(repo_path: str):
    repo = Path(repo_path)
    for name in ("promptfooconfig.yaml", "promptfooconfig.yml", "promptfooconfig.json"):
        cfg = repo / name
        if cfg.exists():
            return cfg
    return None
