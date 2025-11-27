"""
pip-audit Scanner - Python Package Vulnerability Auditing
License: Apache-2.0 (Free, Open Source)
Installation: pip install pip-audit

Features:
- Audits Python packages for known vulnerabilities
- Uses PyPI Advisory Database
- OSV database integration
- Provides fix suggestions
- Multiple output formats
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class PipAuditScanner:
    """
    pip-audit scanner for Python package vulnerability detection.

    Checks installed packages and requirements files against:
    - PyPI Advisory Database
    - OSV (Open Source Vulnerabilities) database
    - GitHub Advisory Database
    """

    def __init__(self):
        self.tool_path = shutil.which("pip-audit")

    async def is_available(self) -> bool:
        """Check if pip-audit is installed"""
        return self.tool_path is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Run pip-audit on Python projects in the repository.

        Args:
            repo_path: Path to the repository

        Returns:
            List of vulnerabilities found
        """
        if not await self.is_available():
            logger.warning("pip-audit not available, skipping scan")
            return []

        results = []

        try:
            repo = Path(repo_path)

            # Find requirements files
            requirements_files = list(repo.rglob("requirements*.txt"))
            requirements_files.extend(repo.rglob("requirements/*.txt"))

            # Find pyproject.toml files
            pyproject_files = list(repo.rglob("pyproject.toml"))

            # Find Pipfile.lock files
            pipfile_locks = list(repo.rglob("Pipfile.lock"))

            # Scan requirements.txt files
            for req_file in requirements_files[:10]:  # Limit to 10 files
                file_results = await self._scan_requirements(req_file, repo_path)
                results.extend(file_results)

            # Scan pyproject.toml files
            for pyproject in pyproject_files[:5]:
                file_results = await self._scan_pyproject(pyproject, repo_path)
                results.extend(file_results)

            return results

        except Exception as e:
            logger.error(f"pip-audit scan error: {str(e)}")
            return []

    async def _scan_requirements(self, req_file: Path, repo_path: str) -> List[Dict]:
        """Scan a requirements.txt file"""
        try:
            cmd = [
                self.tool_path,
                "--requirement", str(req_file),
                "--format", "json",
                "--strict",  # Fail on any vulnerability
                "--progress-spinner", "off"
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # pip-audit outputs to stdout even with vulnerabilities found
            output = result.stdout or result.stderr
            if output:
                try:
                    data = json.loads(output)
                    return self._parse_results(data, req_file, repo_path)
                except json.JSONDecodeError:
                    # Try to parse line-by-line for error messages
                    return self._parse_error_output(output, req_file, repo_path)

            return []

        except subprocess.TimeoutExpired:
            logger.warning(f"pip-audit timed out for {req_file}")
            return []
        except Exception as e:
            logger.debug(f"pip-audit error for {req_file}: {str(e)}")
            return []

    async def _scan_pyproject(self, pyproject_file: Path, repo_path: str) -> List[Dict]:
        """Scan a pyproject.toml file"""
        try:
            # Check if it's a Poetry or standard pyproject.toml
            cmd = [
                self.tool_path,
                "--format", "json",
                "--progress-spinner", "off"
            ]

            # Run in the directory containing pyproject.toml
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(pyproject_file.parent)
            )

            output = result.stdout or result.stderr
            if output:
                try:
                    data = json.loads(output)
                    return self._parse_results(data, pyproject_file, repo_path)
                except json.JSONDecodeError:
                    return []

            return []

        except Exception as e:
            logger.debug(f"pip-audit error for {pyproject_file}: {str(e)}")
            return []

    def _parse_results(self, data: Dict, source_file: Path, repo_path: str) -> List[Dict]:
        """Parse pip-audit JSON output"""
        results = []

        # Get relative path
        file_path = str(source_file)
        if file_path.startswith(repo_path):
            file_path = file_path[len(repo_path):].lstrip("/")

        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            vulns = dep.get("vulns", [])
            for vuln in vulns:
                # Determine severity from CVSS or aliases
                severity = self._determine_severity(vuln)

                result = {
                    "file_path": file_path,
                    "line_start": 0,
                    "line_end": 0,
                    "severity": severity,
                    "category": "vulnerable-dependency",
                    "owasp_category": "A06",  # Vulnerable and Outdated Components
                    "title": f"Vulnerable Package: {dep.get('name', 'unknown')} {dep.get('version', '')}",
                    "description": f"{vuln.get('id', 'Unknown')}: {vuln.get('description', 'No description available')}",
                    "code_snippet": f"{dep.get('name', '')}=={dep.get('version', '')}",
                    "detected_by": "pip-audit",
                    "cve": vuln.get("id", ""),
                    "cwe": "",
                    "cvss_score": None,
                    "package_name": dep.get("name", ""),
                    "package_version": dep.get("version", ""),
                    "fixed_versions": vuln.get("fix_versions", []),
                    "aliases": vuln.get("aliases", []),
                }

                results.append(result)

        return results

    def _parse_error_output(self, output: str, source_file: Path, repo_path: str) -> List[Dict]:
        """Parse non-JSON error output"""
        results = []

        file_path = str(source_file)
        if file_path.startswith(repo_path):
            file_path = file_path[len(repo_path):].lstrip("/")

        # Look for vulnerability lines
        for line in output.split("\n"):
            if "GHSA-" in line or "CVE-" in line or "PYSEC-" in line:
                results.append({
                    "file_path": file_path,
                    "line_start": 0,
                    "line_end": 0,
                    "severity": "high",
                    "category": "vulnerable-dependency",
                    "owasp_category": "A06",
                    "title": "Vulnerable Package Detected",
                    "description": line.strip(),
                    "code_snippet": "",
                    "detected_by": "pip-audit",
                })

        return results

    def _determine_severity(self, vuln: Dict) -> str:
        """Determine severity from vulnerability data"""
        vuln_id = vuln.get("id", "").upper()

        # Check aliases for CVSS info
        aliases = vuln.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CVE-"):
                # Could look up CVSS here if needed
                pass

        # Default severity based on vulnerability ID prefix
        if "CRITICAL" in vuln.get("description", "").upper():
            return "critical"
        elif vuln_id.startswith("PYSEC-"):
            return "high"  # PYSEC vulnerabilities are usually significant
        elif vuln_id.startswith("GHSA-"):
            return "high"
        elif vuln_id.startswith("CVE-"):
            return "high"

        return "medium"

    def get_audit_summary(self, findings: List[Dict]) -> Dict:
        """Generate a summary of the audit"""
        summary = {
            "total_vulnerabilities": len(findings),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "affected_packages": set(),
            "fixable_vulnerabilities": 0,
            "audit_score": 100
        }

        for finding in findings:
            severity = finding.get("severity", "medium")
            package = finding.get("package_name", "")
            fixed_versions = finding.get("fixed_versions", [])

            summary["by_severity"][severity] += 1
            summary["affected_packages"].add(package)
            if fixed_versions:
                summary["fixable_vulnerabilities"] += 1

        # Convert set to count
        summary["affected_packages"] = len(summary["affected_packages"])

        # Calculate audit score
        deductions = (
            summary["by_severity"]["critical"] * 25 +
            summary["by_severity"]["high"] * 15 +
            summary["by_severity"]["medium"] * 5 +
            summary["by_severity"]["low"] * 1
        )

        summary["audit_score"] = max(0, 100 - deductions)

        return summary
