"""
Flake8 Scanner - Python PEP 8 Style Enforcement
License: MIT (Free, Open Source)
Installation: pip install flake8 flake8-bugbear flake8-comprehensions flake8-security

Features:
- PEP 8 style guide enforcement
- PyFlakes error detection
- McCabe complexity checking
- Plugin ecosystem support
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


class Flake8Scanner:
    """
    Flake8 scanner for Python PEP 8 compliance.

    Error code prefixes:
    - E: pycodestyle errors
    - W: pycodestyle warnings
    - F: PyFlakes errors
    - C: McCabe complexity
    - B: flake8-bugbear (if installed)
    - S: flake8-bandit security (if installed)
    """

    def __init__(self):
        self.tool_path = shutil.which("flake8")

        # Error code to severity mapping
        self.severity_map = {
            "E9": "high",     # Runtime errors
            "F": "high",      # PyFlakes (undefined names, etc.)
            "E": "medium",    # PEP 8 errors
            "W": "low",       # PEP 8 warnings
            "C9": "medium",   # Complexity
            "B": "medium",    # Bugbear
            "S": "high",      # Security
        }

        # Code categories
        self.category_map = {
            "E1": "indentation",
            "E2": "whitespace",
            "E3": "blank-line",
            "E4": "import",
            "E5": "line-length",
            "E7": "statement",
            "E9": "runtime-error",
            "W1": "indentation-warning",
            "W2": "whitespace-warning",
            "W3": "blank-line-warning",
            "W5": "line-break-warning",
            "W6": "deprecation",
            "F": "pyflakes",
            "C9": "complexity",
            "B": "bugbear",
            "S": "security",
        }

    async def is_available(self) -> bool:
        """Check if flake8 is installed"""
        return self.tool_path is not None

    async def scan(
        self,
        repo_path: str,
        max_line_length: int = 120,
        max_complexity: int = 10,
        config_file: Optional[str] = None
    ) -> List[Dict]:
        """
        Run Flake8 scan on Python files.

        Args:
            repo_path: Path to the repository
            max_line_length: Maximum allowed line length
            max_complexity: Maximum cyclomatic complexity
            config_file: Optional path to .flake8 config file

        Returns:
            List of style violations found
        """
        if not await self.is_available():
            logger.warning("Flake8 not available, skipping scan")
            return []

        try:
            # Build flake8 command
            cmd = [
                self.tool_path,
                f"--max-line-length={max_line_length}",
                f"--max-complexity={max_complexity}",
                "--format=json",  # Requires flake8-json plugin, fallback below
                "--exclude=.git,__pycache__,*.egg-info,build,dist,venv,.venv,node_modules",
                "--ignore=E501,W503",  # Ignore line too long and line break before binary operator
                repo_path
            ]

            if config_file and os.path.exists(config_file):
                cmd.insert(1, f"--config={config_file}")

            # Try JSON format first
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # Check if JSON output worked
            if result.stdout:
                try:
                    findings = json.loads(result.stdout)
                    return self._parse_json_results(findings, repo_path)
                except json.JSONDecodeError:
                    # Fall back to default format parsing
                    return self._parse_default_results(result.stdout, repo_path)

            # If no stdout, try default format
            cmd_default = [
                self.tool_path,
                f"--max-line-length={max_line_length}",
                f"--max-complexity={max_complexity}",
                "--format=default",
                "--exclude=.git,__pycache__,*.egg-info,build,dist,venv,.venv,node_modules",
                "--ignore=E501,W503",
                repo_path
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd_default,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                return self._parse_default_results(result.stdout, repo_path)

            return []

        except subprocess.TimeoutExpired:
            logger.error("Flake8 scan timed out")
            return []
        except Exception as e:
            logger.error(f"Flake8 scan error: {str(e)}")
            return []

    def _parse_json_results(self, findings: Dict, repo_path: str) -> List[Dict]:
        """Parse Flake8 JSON output"""
        results = []

        for file_path, violations in findings.items():
            # Get relative path
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/")

            for violation in violations:
                code = violation.get("code", "E000")
                results.append(self._create_result(
                    file_path=file_path,
                    line=violation.get("line_number", 0),
                    column=violation.get("column_number", 0),
                    code=code,
                    message=violation.get("text", "")
                ))

        return results

    def _parse_default_results(self, output: str, repo_path: str) -> List[Dict]:
        """Parse Flake8 default format output (file:line:col: code message)"""
        results = []

        for line in output.strip().split("\n"):
            if not line:
                continue

            try:
                # Format: file:line:col: code message
                parts = line.split(":", 3)
                if len(parts) >= 4:
                    file_path = parts[0]
                    line_num = int(parts[1])
                    col_num = int(parts[2])
                    code_message = parts[3].strip()

                    # Extract code and message
                    code_parts = code_message.split(" ", 1)
                    code = code_parts[0]
                    message = code_parts[1] if len(code_parts) > 1 else ""

                    # Get relative path
                    if file_path.startswith(repo_path):
                        file_path = file_path[len(repo_path):].lstrip("/")

                    results.append(self._create_result(
                        file_path=file_path,
                        line=line_num,
                        column=col_num,
                        code=code,
                        message=message
                    ))
            except (ValueError, IndexError) as e:
                logger.debug(f"Could not parse flake8 line: {line} - {e}")
                continue

        return results

    def _create_result(self, file_path: str, line: int, column: int, code: str, message: str) -> Dict:
        """Create a standardized result dictionary"""
        # Determine severity based on code prefix
        severity = "low"
        for prefix, sev in self.severity_map.items():
            if code.startswith(prefix):
                severity = sev
                break

        # Determine category
        category = "style"
        for prefix, cat in self.category_map.items():
            if code.startswith(prefix):
                category = cat
                break

        # OWASP mapping
        owasp = "A05"  # Security Misconfiguration for most style issues
        if code.startswith("S"):
            owasp = "A03"  # Injection for security issues
        elif code.startswith("F"):
            owasp = "A04"  # Insecure Design for logic errors

        return {
            "file_path": file_path,
            "line_start": line,
            "line_end": line,
            "column": column,
            "severity": severity,
            "category": f"code-style-{category}",
            "owasp_category": owasp,
            "title": f"[{code}] {category.replace('-', ' ').title()}",
            "description": message,
            "code_snippet": "",
            "detected_by": "Flake8",
            "rule_id": code,
            "style_category": category,
        }

    def get_style_summary(self, findings: List[Dict]) -> Dict:
        """Generate a summary of style violations"""
        summary = {
            "total_violations": len(findings),
            "by_category": {},
            "by_severity": {
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "pep8_score": 100
        }

        for finding in findings:
            category = finding.get("style_category", "other")
            severity = finding.get("severity", "low")

            summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
            summary["by_severity"][severity] += 1

        # Calculate PEP 8 compliance score
        deductions = (
            summary["by_severity"]["high"] * 5 +
            summary["by_severity"]["medium"] * 2 +
            summary["by_severity"]["low"] * 0.5
        )

        summary["pep8_score"] = max(0, 100 - deductions)

        return summary
