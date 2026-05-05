"""
CycloneDX SBOM generator.

Produces a CycloneDX-1.5 SBOM (JSON) for a Python project. Complements
the existing Syft integration, which generates SPDX/Syft-native SBOMs.

CycloneDX is increasingly required for compliance (US EO 14028, EU CRA).

Install:
    pip install cyclonedx-bom
"""

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class CycloneDXScanner:
    """Wrapper for the `cyclonedx-py` CLI."""

    def __init__(self) -> None:
        self.binary = shutil.which("cyclonedx-py")

    async def is_available(self) -> bool:
        return self.binary is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        if not await self.is_available():
            logger.warning("cyclonedx-py not installed; skipping. Install: pip install cyclonedx-bom")
            return []

        # Pick the most likely manifest for the project.
        repo = Path(repo_path)
        manifest = next(
            (p for p in [repo / "requirements.txt", repo / "pyproject.toml", repo / "Pipfile.lock"] if p.exists()),
            None,
        )
        if manifest is None:
            logger.info("No supported Python manifest in %s; skipping CycloneDX", repo_path)
            return []

        # cyclonedx-py 4.x: subcommand depends on the manifest type.
        sub = "requirements" if manifest.name == "requirements.txt" else "pip"
        cmd = [self.binary, sub, "--format", "json", str(manifest)]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0 or not stdout:
                logger.warning("cyclonedx-py exited %s: %s", proc.returncode, stderr.decode()[:300])
                return []
            sbom = json.loads(stdout.decode())
        except Exception as exc:
            logger.error("cyclonedx-py failed: %s", exc)
            return []

        components = sbom.get("components", [])
        return [{
            "id": "cyclonedx-sbom",
            "title": f"CycloneDX SBOM generated ({len(components)} components)",
            "description": "Software Bill of Materials in CycloneDX 1.5 format",
            "severity": "info",
            "scanner": "cyclonedx",
            "components": [
                {
                    "name": c.get("name"),
                    "version": c.get("version"),
                    "purl": c.get("purl"),
                    "licenses": [l.get("license", {}).get("id") for l in c.get("licenses", [])],
                }
                for c in components
            ],
            "sbom_format": "CycloneDX-1.5",
        }]
