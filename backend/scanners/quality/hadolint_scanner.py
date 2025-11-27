"""
Hadolint Scanner - Dockerfile Best Practices Linter
License: GPL-3.0 (Free, Open Source)
Installation: brew install hadolint (macOS) or docker pull hadolint/hadolint

Features:
- Dockerfile best practices enforcement
- Security issue detection
- Efficiency recommendations
- ShellCheck integration for RUN commands
- CIS Docker Benchmark checks
"""

import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class HadolintScanner:
    """
    Hadolint scanner for Dockerfile analysis.

    Rule categories:
    - DL: Dockerfile Lint rules
    - SC: ShellCheck rules (for RUN commands)

    Common rules:
    - DL3000-DL3999: Dockerfile specific rules
    - DL4000-DL4999: Style rules
    """

    # Severity mapping
    SEVERITY_MAP = {
        "error": "high",
        "warning": "medium",
        "info": "low",
        "style": "low"
    }

    # Common Hadolint rules and their security implications
    RULE_INFO = {
        "DL3000": {"severity": "high", "owasp": "A05", "desc": "Use absolute WORKDIR"},
        "DL3001": {"severity": "medium", "owasp": "A05", "desc": "Use cd in RUN is often a mistake"},
        "DL3002": {"severity": "high", "owasp": "A01", "desc": "Do not switch to root USER"},
        "DL3003": {"severity": "medium", "owasp": "A05", "desc": "Use WORKDIR instead of cd"},
        "DL3004": {"severity": "high", "owasp": "A01", "desc": "Do not use sudo"},
        "DL3005": {"severity": "medium", "owasp": "A06", "desc": "Do not use apt-get upgrade"},
        "DL3006": {"severity": "medium", "owasp": "A06", "desc": "Always tag the version of base image"},
        "DL3007": {"severity": "high", "owasp": "A06", "desc": "Using latest is prone to errors"},
        "DL3008": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in apt-get install"},
        "DL3009": {"severity": "low", "owasp": "A05", "desc": "Delete apt-get lists after install"},
        "DL3010": {"severity": "low", "owasp": "A05", "desc": "Use ADD for extracting archives"},
        "DL3011": {"severity": "medium", "owasp": "A05", "desc": "Valid UNIX ports range from 0 to 65535"},
        "DL3012": {"severity": "medium", "owasp": "A05", "desc": "Multiple ENTRYPOINT instructions"},
        "DL3013": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in pip install"},
        "DL3014": {"severity": "low", "owasp": "A05", "desc": "Use -y with apt-get install"},
        "DL3015": {"severity": "low", "owasp": "A05", "desc": "Avoid additional packages with apt-get"},
        "DL3016": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in npm"},
        "DL3018": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in apk add"},
        "DL3019": {"severity": "low", "owasp": "A05", "desc": "Use --no-cache with apk add"},
        "DL3020": {"severity": "medium", "owasp": "A05", "desc": "Use COPY instead of ADD for files"},
        "DL3021": {"severity": "medium", "owasp": "A05", "desc": "COPY with more than 2 arguments requires destination ending with /"},
        "DL3022": {"severity": "medium", "owasp": "A05", "desc": "COPY --from should reference a previously defined FROM alias"},
        "DL3023": {"severity": "high", "owasp": "A05", "desc": "COPY --from cannot reference its own FROM alias"},
        "DL3024": {"severity": "medium", "owasp": "A05", "desc": "FROM aliases must be unique"},
        "DL3025": {"severity": "medium", "owasp": "A05", "desc": "Use arguments JSON notation for CMD and ENTRYPOINT"},
        "DL3026": {"severity": "medium", "owasp": "A05", "desc": "Use only an allowed registry in FROM"},
        "DL3027": {"severity": "low", "owasp": "A05", "desc": "Do not use apt in RUN"},
        "DL3028": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in gem install"},
        "DL3029": {"severity": "low", "owasp": "A05", "desc": "Do not use --platform with FROM"},
        "DL3030": {"severity": "medium", "owasp": "A06", "desc": "Use --no-install-recommends with yum install"},
        "DL3032": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in yum install"},
        "DL3033": {"severity": "high", "owasp": "A01", "desc": "Specify version with yum"},
        "DL3034": {"severity": "medium", "owasp": "A06", "desc": "Non-interactive mode for zypper"},
        "DL3035": {"severity": "medium", "owasp": "A06", "desc": "Do not use zypper dist-upgrade"},
        "DL3036": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in zypper"},
        "DL3037": {"severity": "low", "owasp": "A05", "desc": "Specify version with zypper install"},
        "DL3038": {"severity": "low", "owasp": "A05", "desc": "Use the -y switch with dnf install"},
        "DL3040": {"severity": "medium", "owasp": "A06", "desc": "dnf clean all missing after dnf command"},
        "DL3041": {"severity": "medium", "owasp": "A06", "desc": "Specify version with dnf install"},
        "DL3042": {"severity": "low", "owasp": "A05", "desc": "Avoid cache directory with pip install"},
        "DL3043": {"severity": "high", "owasp": "A05", "desc": "ONBUILD not allowed with FROM"},
        "DL3044": {"severity": "medium", "owasp": "A05", "desc": "Do not refer to an environment variable in ADD"},
        "DL3045": {"severity": "medium", "owasp": "A05", "desc": "COPY to relative destination without WORKDIR"},
        "DL3046": {"severity": "medium", "owasp": "A05", "desc": "useradd without flag -l and target size"},
        "DL3047": {"severity": "medium", "owasp": "A05", "desc": "Avoid wget and curl in RUN"},
        "DL3048": {"severity": "low", "owasp": "A05", "desc": "Invalid label key"},
        "DL3049": {"severity": "low", "owasp": "A05", "desc": "Missing label"},
        "DL3050": {"severity": "medium", "owasp": "A05", "desc": "Missing essential label"},
        "DL3051": {"severity": "low", "owasp": "A05", "desc": "Missing label key"},
        "DL3052": {"severity": "low", "owasp": "A05", "desc": "Missing label value"},
        "DL3053": {"severity": "low", "owasp": "A05", "desc": "Empty label value"},
        "DL3054": {"severity": "low", "owasp": "A05", "desc": "Label deprecated"},
        "DL3055": {"severity": "low", "owasp": "A05", "desc": "Label namespace deprecated"},
        "DL3056": {"severity": "low", "owasp": "A05", "desc": "Using label in FROM is discouraged"},
        "DL3057": {"severity": "low", "owasp": "A05", "desc": "HEALTHCHECK missing"},
        "DL3058": {"severity": "low", "owasp": "A05", "desc": "Label key is reserved"},
        "DL3059": {"severity": "low", "owasp": "A05", "desc": "Multiple consecutive RUN"},
        "DL3060": {"severity": "medium", "owasp": "A06", "desc": "Pin versions in yarn add"},
        "DL4000": {"severity": "low", "owasp": "A05", "desc": "MAINTAINER is deprecated"},
        "DL4001": {"severity": "low", "owasp": "A05", "desc": "Use shell or exec form for CMD"},
        "DL4003": {"severity": "medium", "owasp": "A05", "desc": "Multiple CMD instructions"},
        "DL4004": {"severity": "medium", "owasp": "A05", "desc": "Multiple ENTRYPOINT instructions"},
        "DL4005": {"severity": "medium", "owasp": "A05", "desc": "Use SHELL to change the default shell"},
        "DL4006": {"severity": "medium", "owasp": "A05", "desc": "Set the SHELL option -o pipefail"},
    }

    def __init__(self):
        self.tool_path = shutil.which("hadolint")

    async def is_available(self) -> bool:
        """Check if hadolint is installed"""
        return self.tool_path is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Run Hadolint on all Dockerfiles in the repository.

        Args:
            repo_path: Path to the repository

        Returns:
            List of Dockerfile issues found
        """
        if not await self.is_available():
            logger.warning("Hadolint not available, skipping scan")
            return []

        try:
            # Find all Dockerfiles
            repo = Path(repo_path)
            dockerfiles = list(repo.rglob("Dockerfile*"))
            dockerfiles.extend(repo.rglob("*.dockerfile"))

            # Exclude common directories
            dockerfiles = [
                f for f in dockerfiles
                if not any(
                    excluded in str(f)
                    for excluded in ["node_modules", "venv", ".venv", ".git"]
                )
            ]

            if not dockerfiles:
                logger.info("No Dockerfiles found in repository")
                return []

            results = []
            for dockerfile in dockerfiles:
                file_results = await self._scan_file(dockerfile, repo_path)
                results.extend(file_results)

            return results

        except Exception as e:
            logger.error(f"Hadolint scan error: {str(e)}")
            return []

    async def _scan_file(self, file_path: Path, repo_path: str) -> List[Dict]:
        """Scan a single Dockerfile"""
        try:
            cmd = [
                self.tool_path,
                "--format", "json",
                "--no-fail",  # Don't exit with error code on warnings
                str(file_path)
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return self._parse_results(data, repo_path)
                except json.JSONDecodeError:
                    logger.debug(f"Failed to parse Hadolint output for {file_path}")
                    return []

            return []

        except subprocess.TimeoutExpired:
            logger.warning(f"Hadolint timed out for {file_path}")
            return []
        except Exception as e:
            logger.debug(f"Hadolint error for {file_path}: {str(e)}")
            return []

    def _parse_results(self, findings: List[Dict], repo_path: str) -> List[Dict]:
        """Parse Hadolint JSON output"""
        results = []

        for finding in findings:
            code = finding.get("code", "DL0000")
            level = finding.get("level", "warning")

            # Get file path
            file_path = finding.get("file", "unknown")
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/")

            # Get rule info
            rule_info = self.RULE_INFO.get(code, {
                "severity": self.SEVERITY_MAP.get(level, "medium"),
                "owasp": "A05",
                "desc": ""
            })

            # Override severity if rule-specific info exists
            severity = rule_info.get("severity", self.SEVERITY_MAP.get(level, "medium"))

            result = {
                "file_path": file_path,
                "line_start": finding.get("line", 0),
                "line_end": finding.get("line", 0),
                "column": finding.get("column", 0),
                "severity": severity,
                "category": "dockerfile",
                "owasp_category": rule_info.get("owasp", "A05"),
                "title": f"[{code}] Dockerfile Issue",
                "description": finding.get("message", ""),
                "code_snippet": "",
                "detected_by": "Hadolint",
                "rule_id": code,
                "wiki_url": f"https://github.com/hadolint/hadolint/wiki/{code}",
            }

            results.append(result)

        return results

    def get_dockerfile_summary(self, findings: List[Dict]) -> Dict:
        """Generate a summary of Dockerfile issues"""
        summary = {
            "total_issues": len(findings),
            "by_severity": {
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "common_issues": {},
            "dockerfile_score": 100,
            "security_issues": 0,
            "best_practice_issues": 0
        }

        security_rules = ["DL3002", "DL3004", "DL3007", "DL3023", "DL3033", "DL3043"]

        for finding in findings:
            severity = finding.get("severity", "low")
            rule_id = finding.get("rule_id", "unknown")

            summary["by_severity"][severity] += 1
            summary["common_issues"][rule_id] = summary["common_issues"].get(rule_id, 0) + 1

            if rule_id in security_rules:
                summary["security_issues"] += 1
            else:
                summary["best_practice_issues"] += 1

        # Calculate Dockerfile score
        deductions = (
            summary["by_severity"]["high"] * 15 +
            summary["by_severity"]["medium"] * 5 +
            summary["by_severity"]["low"] * 1
        )

        summary["dockerfile_score"] = max(0, 100 - deductions)

        # Sort common issues by frequency
        summary["common_issues"] = dict(
            sorted(summary["common_issues"].items(), key=lambda x: x[1], reverse=True)[:10]
        )

        return summary
