"""
License compliance scanner.

Flags dependencies with copyleft / network-copyleft licenses (GPL, AGPL,
LGPL, SSPL) that may contaminate the project. Uses `pip-licenses` for
Python and `license-checker` (npm) for JS/TS, both invoked only when the
respective package manager is present.

Install:
    pip install pip-licenses
    npm i -g license-checker
"""

import asyncio
import json
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)

# Licenses we treat as policy-blocking by default. Project policy may
# override later via settings; keeping this list narrow avoids false
# positives on permissive ecosystems.
COPYLEFT: Set[str] = {
    "GPL-2.0", "GPL-3.0", "GPL-2.0-only", "GPL-3.0-only",
    "GPL-2.0-or-later", "GPL-3.0-or-later",
    "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    "LGPL-2.1", "LGPL-3.0", "LGPL-2.1-or-later", "LGPL-3.0-or-later",
    "SSPL-1.0", "BUSL-1.1",
}


class LicenseScanner:
    """Combined Python + JS license compliance checker."""

    def __init__(self) -> None:
        self.pip_licenses = shutil.which("pip-licenses")
        self.license_checker = shutil.which("license-checker")

    async def is_available(self) -> bool:
        return bool(self.pip_licenses or self.license_checker)

    async def scan(self, repo_path: str) -> List[Dict]:
        repo = Path(repo_path)
        findings: List[Dict] = []

        if self.pip_licenses and (repo / "requirements.txt").exists():
            findings.extend(await self._scan_python())
        if self.license_checker and (repo / "package.json").exists():
            findings.extend(await self._scan_npm(repo_path))

        if not findings:
            logger.info("license scanner: no copyleft dependencies found (or no manifests)")
        return findings

    async def _scan_python(self) -> List[Dict]:
        cmd = [self.pip_licenses, "--format=json", "--with-urls"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            packages = json.loads(stdout.decode() or "[]")
        except Exception as exc:
            logger.error("pip-licenses failed: %s", exc)
            return []

        return [
            self._mk_finding(p.get("Name"), p.get("Version"), p.get("License"), "pypi", p.get("URL"))
            for p in packages
            if _is_copyleft(p.get("License", ""))
        ]

    async def _scan_npm(self, repo_path: str) -> List[Dict]:
        cmd = [self.license_checker, "--json", "--production"]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path,
            )
            stdout, _ = await proc.communicate()
            packages = json.loads(stdout.decode() or "{}")
        except Exception as exc:
            logger.error("license-checker failed: %s", exc)
            return []

        findings = []
        for spec, info in packages.items():
            license_str = info.get("licenses", "")
            if _is_copyleft(license_str if isinstance(license_str, str) else " ".join(license_str)):
                name, _, version = spec.rpartition("@")
                findings.append(self._mk_finding(name, version, license_str, "npm", info.get("repository")))
        return findings

    @staticmethod
    def _mk_finding(name, version, license_str, ecosystem, url) -> Dict:
        return {
            "id": f"LICENSE-{ecosystem.upper()}-{name}",
            "title": f"Copyleft license: {name} ({license_str})",
            "description": (
                f"Dependency '{name}@{version}' uses a copyleft/network-copyleft license "
                f"({license_str}). Review legal/compliance implications before distribution."
            ),
            "severity": "high" if "AGPL" in (license_str or "").upper() or "SSPL" in (license_str or "").upper() else "medium",
            "package": name,
            "installed_version": version,
            "ecosystem": ecosystem,
            "license": license_str,
            "references": [url] if url else [],
            "scanner": "license-scanner",
        }


def _is_copyleft(license_str: str) -> bool:
    if not license_str:
        return False
    upper = license_str.upper()
    return any(spdx.upper() in upper for spdx in COPYLEFT)
