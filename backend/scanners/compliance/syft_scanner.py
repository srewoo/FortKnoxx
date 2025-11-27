"""
Syft Scanner - Software Bill of Materials (SBOM) Generation
License: Apache-2.0 (Free, Open Source)
Installation: brew install syft (macOS) or curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh

Features:
- Generate SBOM in multiple formats (SPDX, CycloneDX, JSON)
- Support for containers, filesystems, archives
- Package detection for 15+ package managers
- License detection
- Multi-language support
"""

import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SyftScanner:
    """
    Syft scanner for SBOM generation.

    Supported ecosystems:
    - Python (pip, poetry, pipenv)
    - JavaScript (npm, yarn)
    - Go (modules)
    - Java (Maven, Gradle)
    - Ruby (Bundler)
    - Rust (Cargo)
    - .NET (NuGet)
    - PHP (Composer)
    - And more...
    """

    # License risk classification
    LICENSE_RISK = {
        # High risk - viral/copyleft licenses
        "high": [
            "GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0",
            "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
            "GPL-2.0-or-later", "GPL-3.0-or-later", "AGPL-3.0-or-later"
        ],
        # Medium risk - weak copyleft
        "medium": [
            "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
            "LGPL-2.0", "OSL-3.0", "CPL-1.0"
        ],
        # Low risk - permissive licenses
        "low": [
            "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause",
            "ISC", "Unlicense", "CC0-1.0", "0BSD", "Zlib",
            "BSL-1.0", "Artistic-2.0", "PostgreSQL"
        ]
    }

    def __init__(self):
        self.tool_path = shutil.which("syft")

    async def is_available(self) -> bool:
        """Check if syft is installed"""
        return self.tool_path is not None

    async def generate_sbom(self, repo_path: str, output_format: str = "json") -> Dict:
        """
        Generate SBOM for the repository.

        Args:
            repo_path: Path to the repository
            output_format: Output format (json, spdx-json, cyclonedx-json)

        Returns:
            SBOM data dictionary
        """
        if not await self.is_available():
            logger.warning("Syft not available, skipping SBOM generation")
            return {}

        try:
            format_map = {
                "json": "json",
                "spdx": "spdx-json",
                "cyclonedx": "cyclonedx-json"
            }

            output_fmt = format_map.get(output_format, "json")

            cmd = [
                self.tool_path,
                f"dir:{repo_path}",
                "-o", output_fmt,
                "--quiet"
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=600
            )

            if result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    logger.error("Failed to parse Syft JSON output")
                    return {}

            return {}

        except subprocess.TimeoutExpired:
            logger.error("Syft SBOM generation timed out")
            return {}
        except Exception as e:
            logger.error(f"Syft scan error: {str(e)}")
            return {}

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Scan repository and return license compliance issues.

        Args:
            repo_path: Path to the repository

        Returns:
            List of license compliance issues found
        """
        sbom = await self.generate_sbom(repo_path)
        if not sbom:
            return []

        return self._analyze_licenses(sbom, repo_path)

    def _analyze_licenses(self, sbom: Dict, repo_path: str) -> List[Dict]:
        """Analyze SBOM for license compliance issues"""
        results = []

        artifacts = sbom.get("artifacts", [])
        for artifact in artifacts:
            name = artifact.get("name", "unknown")
            version = artifact.get("version", "")
            licenses = artifact.get("licenses", [])
            pkg_type = artifact.get("type", "unknown")

            # Check each license
            for license_info in licenses:
                license_id = ""
                if isinstance(license_info, str):
                    license_id = license_info
                elif isinstance(license_info, dict):
                    license_id = license_info.get("value", "") or license_info.get("expression", "")

                if not license_id:
                    # Unknown/missing license
                    results.append({
                        "file_path": f"{pkg_type}/{name}",
                        "line_start": 0,
                        "line_end": 0,
                        "severity": "medium",
                        "category": "license-compliance",
                        "owasp_category": "A06",
                        "title": f"Unknown License: {name}@{version}",
                        "description": f"Package {name}@{version} has no detectable license. This may pose legal risks.",
                        "code_snippet": f"{name}=={version}",
                        "detected_by": "Syft",
                        "package_name": name,
                        "package_version": version,
                        "package_type": pkg_type,
                        "license": "UNKNOWN",
                        "license_risk": "unknown",
                    })
                    continue

                # Classify license risk
                risk_level = self._classify_license_risk(license_id)

                if risk_level in ["high", "medium"]:
                    results.append({
                        "file_path": f"{pkg_type}/{name}",
                        "line_start": 0,
                        "line_end": 0,
                        "severity": "medium" if risk_level == "high" else "low",
                        "category": "license-compliance",
                        "owasp_category": "A06",
                        "title": f"Copyleft License: {name}@{version}",
                        "description": f"Package {name}@{version} uses {license_id} license. This is a {'strong' if risk_level == 'high' else 'weak'} copyleft license that may require your code to be open-sourced.",
                        "code_snippet": f"{name}=={version}",
                        "detected_by": "Syft",
                        "package_name": name,
                        "package_version": version,
                        "package_type": pkg_type,
                        "license": license_id,
                        "license_risk": risk_level,
                    })

            # No licenses found
            if not licenses:
                results.append({
                    "file_path": f"{pkg_type}/{name}",
                    "line_start": 0,
                    "line_end": 0,
                    "severity": "low",
                    "category": "license-compliance",
                    "owasp_category": "A06",
                    "title": f"No License Detected: {name}@{version}",
                    "description": f"Package {name}@{version} has no license information. Consider verifying the license manually.",
                    "code_snippet": f"{name}=={version}",
                    "detected_by": "Syft",
                    "package_name": name,
                    "package_version": version,
                    "package_type": pkg_type,
                    "license": "NONE",
                    "license_risk": "unknown",
                })

        return results

    def _classify_license_risk(self, license_id: str) -> str:
        """Classify license risk level"""
        license_upper = license_id.upper()

        for risk, licenses in self.LICENSE_RISK.items():
            for lic in licenses:
                if lic.upper() in license_upper or license_upper in lic.upper():
                    return risk

        return "unknown"

    def get_sbom_summary(self, sbom: Dict) -> Dict:
        """Generate summary from SBOM data"""
        artifacts = sbom.get("artifacts", [])

        summary = {
            "total_packages": len(artifacts),
            "by_type": {},
            "by_license": {},
            "license_compliance": {
                "permissive": 0,
                "copyleft": 0,
                "unknown": 0
            },
            "languages_detected": set()
        }

        for artifact in artifacts:
            pkg_type = artifact.get("type", "unknown")
            licenses = artifact.get("licenses", [])

            # Count by type
            summary["by_type"][pkg_type] = summary["by_type"].get(pkg_type, 0) + 1

            # Track language
            lang = artifact.get("language", "")
            if lang:
                summary["languages_detected"].add(lang)

            # Count licenses
            for license_info in licenses:
                license_id = ""
                if isinstance(license_info, str):
                    license_id = license_info
                elif isinstance(license_info, dict):
                    license_id = license_info.get("value", "") or license_info.get("expression", "")

                if license_id:
                    summary["by_license"][license_id] = summary["by_license"].get(license_id, 0) + 1

                    risk = self._classify_license_risk(license_id)
                    if risk == "low":
                        summary["license_compliance"]["permissive"] += 1
                    elif risk in ["high", "medium"]:
                        summary["license_compliance"]["copyleft"] += 1
                    else:
                        summary["license_compliance"]["unknown"] += 1
                else:
                    summary["license_compliance"]["unknown"] += 1

            if not licenses:
                summary["license_compliance"]["unknown"] += 1

        summary["languages_detected"] = list(summary["languages_detected"])

        return summary

    def get_compliance_score(self, findings: List[Dict]) -> int:
        """Calculate license compliance score"""
        if not findings:
            return 100

        deductions = 0
        for finding in findings:
            risk = finding.get("license_risk", "unknown")
            if risk == "high":
                deductions += 10
            elif risk == "medium":
                deductions += 5
            elif risk == "unknown":
                deductions += 2

        return max(0, 100 - deductions)
