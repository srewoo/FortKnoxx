"""
npm audit Scanner - Node.js Package Vulnerability Auditing
License: Built-in with npm (Free, Open Source)
Installation: Comes with Node.js

Features:
- Audits npm packages for known vulnerabilities
- Uses npm Advisory Database
- Provides fix suggestions
- Supports package-lock.json and yarn.lock
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


class NpmAuditScanner:
    """
    npm audit scanner for Node.js package vulnerability detection.

    Also supports yarn audit for yarn-based projects.
    """

    def __init__(self):
        self.npm_path = shutil.which("npm")
        self.yarn_path = shutil.which("yarn")

    async def is_available(self) -> bool:
        """Check if npm is installed"""
        return self.npm_path is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Run npm/yarn audit on Node.js projects in the repository.

        Args:
            repo_path: Path to the repository

        Returns:
            List of vulnerabilities found
        """
        if not await self.is_available():
            logger.warning("npm not available, skipping scan")
            return []

        results = []

        try:
            repo = Path(repo_path)

            # Find all package.json files (and their associated lock files)
            package_jsons = list(repo.rglob("package.json"))

            # Exclude node_modules
            package_jsons = [
                p for p in package_jsons
                if "node_modules" not in str(p)
            ]

            for package_json in package_jsons[:10]:  # Limit to 10 projects
                project_dir = package_json.parent

                # Check for lock files
                has_package_lock = (project_dir / "package-lock.json").exists()
                has_yarn_lock = (project_dir / "yarn.lock").exists()

                if has_yarn_lock and self.yarn_path:
                    file_results = await self._run_yarn_audit(project_dir, repo_path)
                elif has_package_lock:
                    file_results = await self._run_npm_audit(project_dir, repo_path)
                else:
                    # No lock file, skip
                    continue

                results.extend(file_results)

            return results

        except Exception as e:
            logger.error(f"npm audit scan error: {str(e)}")
            return []

    async def _run_npm_audit(self, project_dir: Path, repo_path: str) -> List[Dict]:
        """Run npm audit on a project"""
        try:
            cmd = [
                self.npm_path,
                "audit",
                "--json",
                "--audit-level=low"
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(project_dir)
            )

            # npm audit returns non-zero on vulnerabilities found
            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return self._parse_npm_results(data, project_dir, repo_path)
                except json.JSONDecodeError:
                    logger.debug(f"Failed to parse npm audit output for {project_dir}")
                    return []

            return []

        except subprocess.TimeoutExpired:
            logger.warning(f"npm audit timed out for {project_dir}")
            return []
        except Exception as e:
            logger.debug(f"npm audit error for {project_dir}: {str(e)}")
            return []

    async def _run_yarn_audit(self, project_dir: Path, repo_path: str) -> List[Dict]:
        """Run yarn audit on a project"""
        try:
            cmd = [
                self.yarn_path,
                "audit",
                "--json"
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(project_dir)
            )

            if result.stdout:
                # Yarn outputs multiple JSON objects, one per line
                results = []
                for line in result.stdout.strip().split("\n"):
                    if line:
                        try:
                            data = json.loads(line)
                            if data.get("type") == "auditAdvisory":
                                parsed = self._parse_yarn_advisory(data, project_dir, repo_path)
                                if parsed:
                                    results.append(parsed)
                        except json.JSONDecodeError:
                            continue
                return results

            return []

        except subprocess.TimeoutExpired:
            logger.warning(f"yarn audit timed out for {project_dir}")
            return []
        except Exception as e:
            logger.debug(f"yarn audit error for {project_dir}: {str(e)}")
            return []

    def _parse_npm_results(self, data: Dict, project_dir: Path, repo_path: str) -> List[Dict]:
        """Parse npm audit JSON output (npm v7+ format)"""
        results = []

        # Get relative path
        file_path = str(project_dir / "package-lock.json")
        if file_path.startswith(repo_path):
            file_path = file_path[len(repo_path):].lstrip("/")

        # Handle npm v7+ format
        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln_info in vulnerabilities.items():
            severity = vuln_info.get("severity", "moderate")
            via = vuln_info.get("via", [])

            # Get advisory details
            advisory_details = []
            for v in via:
                if isinstance(v, dict):
                    advisory_details.append(v)
                elif isinstance(v, str):
                    # Just a package name reference
                    pass

            for advisory in advisory_details:
                result = {
                    "file_path": file_path,
                    "line_start": 0,
                    "line_end": 0,
                    "severity": self._map_severity(severity),
                    "category": "vulnerable-dependency",
                    "owasp_category": "A06",  # Vulnerable and Outdated Components
                    "title": f"Vulnerable Package: {pkg_name}",
                    "description": advisory.get("title", "No title available"),
                    "code_snippet": f"{pkg_name}@{vuln_info.get('range', 'unknown')}",
                    "detected_by": "npm-audit",
                    "cve": advisory.get("cve", ""),
                    "cwe": self._format_cwe(advisory.get("cwe", [])),
                    "cvss_score": advisory.get("cvss", {}).get("score"),
                    "package_name": pkg_name,
                    "package_version": vuln_info.get("range", ""),
                    "fixed_in": vuln_info.get("fixAvailable", {}).get("version", ""),
                    "url": advisory.get("url", ""),
                    "advisory_id": str(advisory.get("source", "")),
                }

                results.append(result)

            # If no advisory details, create a generic entry
            if not advisory_details:
                result = {
                    "file_path": file_path,
                    "line_start": 0,
                    "line_end": 0,
                    "severity": self._map_severity(severity),
                    "category": "vulnerable-dependency",
                    "owasp_category": "A06",
                    "title": f"Vulnerable Package: {pkg_name}",
                    "description": f"Vulnerable to issues via: {', '.join(str(v) for v in via)}",
                    "code_snippet": f"{pkg_name}@{vuln_info.get('range', 'unknown')}",
                    "detected_by": "npm-audit",
                    "package_name": pkg_name,
                    "package_version": vuln_info.get("range", ""),
                    "fixed_in": vuln_info.get("fixAvailable", {}).get("version", "") if isinstance(vuln_info.get("fixAvailable"), dict) else "",
                }
                results.append(result)

        return results

    def _parse_yarn_advisory(self, data: Dict, project_dir: Path, repo_path: str) -> Optional[Dict]:
        """Parse a single yarn audit advisory"""
        advisory = data.get("data", {}).get("advisory", {})
        if not advisory:
            return None

        # Get relative path
        file_path = str(project_dir / "yarn.lock")
        if file_path.startswith(repo_path):
            file_path = file_path[len(repo_path):].lstrip("/")

        return {
            "file_path": file_path,
            "line_start": 0,
            "line_end": 0,
            "severity": self._map_severity(advisory.get("severity", "moderate")),
            "category": "vulnerable-dependency",
            "owasp_category": "A06",
            "title": f"Vulnerable Package: {advisory.get('module_name', 'unknown')}",
            "description": advisory.get("title", "No title available"),
            "code_snippet": f"{advisory.get('module_name', '')}@{advisory.get('vulnerable_versions', '')}",
            "detected_by": "yarn-audit",
            "cve": advisory.get("cves", [""])[0] if advisory.get("cves") else "",
            "cwe": advisory.get("cwe", ""),
            "cvss_score": advisory.get("cvss", {}).get("score"),
            "package_name": advisory.get("module_name", ""),
            "package_version": advisory.get("vulnerable_versions", ""),
            "fixed_in": advisory.get("patched_versions", ""),
            "url": advisory.get("url", ""),
            "advisory_id": str(advisory.get("id", "")),
        }

    def _map_severity(self, npm_severity: str) -> str:
        """Map npm severity to standard severity"""
        mapping = {
            "critical": "critical",
            "high": "high",
            "moderate": "medium",
            "low": "low",
            "info": "low"
        }
        return mapping.get(npm_severity.lower(), "medium")

    def _format_cwe(self, cwe_list: List) -> str:
        """Format CWE list to string"""
        if not cwe_list:
            return ""
        if isinstance(cwe_list, list):
            return ", ".join(str(c) for c in cwe_list)
        return str(cwe_list)

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
            fixed_in = finding.get("fixed_in", "")

            summary["by_severity"][severity] += 1
            summary["affected_packages"].add(package)
            if fixed_in:
                summary["fixable_vulnerabilities"] += 1

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
