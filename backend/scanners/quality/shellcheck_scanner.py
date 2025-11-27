"""
ShellCheck Scanner - Shell Script Analysis
License: GPL-3.0 (Free, Open Source)
Installation: brew install shellcheck (macOS) or apt install shellcheck (Linux)

Features:
- Syntax errors detection
- Semantic issues identification
- Best practice violations
- POSIX compliance checking
- Bash/sh/dash/ksh support
"""

import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)


class ShellCheckScanner:
    """
    ShellCheck scanner for shell script analysis.

    Checks for:
    - Quoting issues
    - Command substitution problems
    - Test operator issues
    - Deprecated syntax
    - Portability issues
    - Common mistakes
    """

    # Severity mapping (ShellCheck uses: error, warning, info, style)
    SEVERITY_MAP = {
        "error": "high",
        "warning": "medium",
        "info": "low",
        "style": "low"
    }

    # Common issue categories mapped to OWASP
    OWASP_MAP = {
        # Command injection related
        "SC2086": "A03",  # Injection - Double quote to prevent globbing
        "SC2046": "A03",  # Injection - Quote command substitution
        "SC2091": "A03",  # Injection - Remove surrounding $()
        "SC2116": "A03",  # Injection - Useless echo
        # Security misconfiguration
        "SC2034": "A05",  # Unused variable
        "SC2154": "A05",  # Variable referenced but not assigned
        # Insecure design
        "SC2006": "A04",  # Use $() instead of ``
        "SC2012": "A04",  # Use find instead of ls
    }

    def __init__(self):
        self.tool_path = shutil.which("shellcheck")

    async def is_available(self) -> bool:
        """Check if shellcheck is installed"""
        return self.tool_path is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Run ShellCheck on all shell scripts in the repository.

        Args:
            repo_path: Path to the repository

        Returns:
            List of issues found
        """
        if not await self.is_available():
            logger.warning("ShellCheck not available, skipping scan")
            return []

        try:
            # Find all shell scripts
            shell_files = []
            repo = Path(repo_path)

            # Common shell script extensions
            extensions = [".sh", ".bash", ".ksh", ".zsh"]
            for ext in extensions:
                shell_files.extend(repo.rglob(f"*{ext}"))

            # Also check files without extension that have shebang
            for file_path in repo.rglob("*"):
                if file_path.is_file() and file_path.suffix == "":
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            first_line = f.readline()
                            if first_line.startswith("#!") and any(
                                shell in first_line for shell in ["bash", "sh", "zsh", "ksh"]
                            ):
                                shell_files.append(file_path)
                    except Exception:
                        continue

            if not shell_files:
                logger.info("No shell scripts found in repository")
                return []

            # Exclude common directories
            shell_files = [
                f for f in shell_files
                if not any(
                    excluded in str(f)
                    for excluded in ["node_modules", "venv", ".venv", ".git", "__pycache__"]
                )
            ]

            results = []
            for shell_file in shell_files[:50]:  # Limit to 50 files
                file_results = await self._scan_file(shell_file, repo_path)
                results.extend(file_results)

            return results

        except Exception as e:
            logger.error(f"ShellCheck scan error: {str(e)}")
            return []

    async def _scan_file(self, file_path: Path, repo_path: str) -> List[Dict]:
        """Scan a single shell script file"""
        try:
            cmd = [
                self.tool_path,
                "--format=json1",
                "--severity=warning",  # Include warning and above
                "--external-sources",  # Allow sourcing external files
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
                    logger.debug(f"Failed to parse ShellCheck output for {file_path}")
                    return []

            return []

        except subprocess.TimeoutExpired:
            logger.warning(f"ShellCheck timed out for {file_path}")
            return []
        except Exception as e:
            logger.debug(f"ShellCheck error for {file_path}: {str(e)}")
            return []

    def _parse_results(self, data: Dict, repo_path: str) -> List[Dict]:
        """Parse ShellCheck JSON output"""
        results = []

        comments = data.get("comments", [])
        for comment in comments:
            code = f"SC{comment.get('code', '0000')}"
            level = comment.get("level", "warning")

            # Get file path
            file_path = comment.get("file", "unknown")
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/")

            # Determine OWASP category
            owasp = self.OWASP_MAP.get(code, "A05")

            result = {
                "file_path": file_path,
                "line_start": comment.get("line", 0),
                "line_end": comment.get("endLine", comment.get("line", 0)),
                "column": comment.get("column", 0),
                "severity": self.SEVERITY_MAP.get(level, "low"),
                "category": "shell-script",
                "owasp_category": owasp,
                "title": f"[{code}] Shell Script Issue",
                "description": comment.get("message", ""),
                "code_snippet": "",
                "detected_by": "ShellCheck",
                "rule_id": code,
                "fix": comment.get("fix", {}).get("replacements", []),
                "wiki_url": f"https://www.shellcheck.net/wiki/{code}",
            }

            results.append(result)

        return results

    def get_shell_summary(self, findings: List[Dict]) -> Dict:
        """Generate a summary of shell script issues"""
        summary = {
            "total_issues": len(findings),
            "by_severity": {
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "common_issues": {},
            "shell_score": 100
        }

        for finding in findings:
            severity = finding.get("severity", "low")
            rule_id = finding.get("rule_id", "unknown")

            summary["by_severity"][severity] += 1
            summary["common_issues"][rule_id] = summary["common_issues"].get(rule_id, 0) + 1

        # Calculate shell script score
        deductions = (
            summary["by_severity"]["high"] * 10 +
            summary["by_severity"]["medium"] * 3 +
            summary["by_severity"]["low"] * 1
        )

        summary["shell_score"] = max(0, 100 - deductions)

        # Sort common issues by frequency
        summary["common_issues"] = dict(
            sorted(summary["common_issues"].items(), key=lambda x: x[1], reverse=True)[:10]
        )

        return summary
