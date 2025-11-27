"""
Pylint Scanner - Python Code Quality Analysis
License: GPL-2.0 (Free, Open Source)
Installation: pip install pylint

Features:
- PEP 8 style checking
- Error detection
- Refactoring suggestions
- Code complexity metrics
- Duplicate code detection
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


class PylintScanner:
    """
    Pylint scanner for Python code quality analysis.

    Provides comprehensive code analysis including:
    - Convention violations (C)
    - Refactoring suggestions (R)
    - Warnings (W)
    - Errors (E)
    - Fatal errors (F)
    """

    def __init__(self):
        self.tool_path = shutil.which("pylint")

        # Pylint message categories mapped to severity
        self.severity_map = {
            "F": "critical",   # Fatal
            "E": "high",       # Error
            "W": "medium",     # Warning
            "R": "low",        # Refactor
            "C": "low",        # Convention
            "I": "low"         # Informational
        }

        # OWASP mapping for quality issues
        self.owasp_map = {
            "E": "A04",  # Insecure Design (errors indicate design issues)
            "W": "A05",  # Security Misconfiguration
            "R": "A04",  # Insecure Design
            "C": "A05",  # Misconfiguration (style issues)
            "F": "A04",  # Fatal = design issue
        }

    async def is_available(self) -> bool:
        """Check if pylint is installed"""
        return self.tool_path is not None

    async def scan(self, repo_path: str, config_file: Optional[str] = None) -> List[Dict]:
        """
        Run Pylint scan on Python files in the repository.

        Args:
            repo_path: Path to the repository
            config_file: Optional path to pylintrc config file

        Returns:
            List of quality issues found
        """
        if not await self.is_available():
            logger.warning("Pylint not available, skipping scan")
            return []

        try:
            # Find all Python files
            python_files = list(Path(repo_path).rglob("*.py"))

            if not python_files:
                logger.info("No Python files found in repository")
                return []

            # Build pylint command
            cmd = [
                self.tool_path,
                "--output-format=json",
                "--disable=C0114,C0115,C0116",  # Disable missing docstring warnings
                "--max-line-length=120",
                "--ignore-patterns=test_*,*_test.py,conftest.py",
            ]

            if config_file and os.path.exists(config_file):
                cmd.append(f"--rcfile={config_file}")

            # Add files (limit to avoid command line too long)
            files_to_scan = [str(f) for f in python_files[:100]]
            cmd.extend(files_to_scan)

            # Run pylint
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=repo_path
            )

            # Pylint returns non-zero even for warnings, so check for valid JSON
            if result.stdout:
                try:
                    findings = json.loads(result.stdout)
                    return self._parse_results(findings, repo_path)
                except json.JSONDecodeError:
                    logger.error(f"Failed to parse Pylint JSON output: {result.stdout[:500]}")
                    return []

            return []

        except subprocess.TimeoutExpired:
            logger.error("Pylint scan timed out")
            return []
        except Exception as e:
            logger.error(f"Pylint scan error: {str(e)}")
            return []

    def _parse_results(self, findings: List[Dict], repo_path: str) -> List[Dict]:
        """Parse Pylint JSON output into standard format"""
        results = []

        for finding in findings:
            message_type = finding.get("type", "C")[0].upper()

            # Get relative path
            file_path = finding.get("path", "unknown")
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/")

            result = {
                "file_path": file_path,
                "line_start": finding.get("line", 0),
                "line_end": finding.get("endLine", finding.get("line", 0)),
                "column": finding.get("column", 0),
                "severity": self.severity_map.get(message_type, "low"),
                "category": "code-quality",
                "owasp_category": self.owasp_map.get(message_type, "A05"),
                "title": f"[{finding.get('message-id', 'unknown')}] {finding.get('symbol', 'unknown')}",
                "description": finding.get("message", ""),
                "code_snippet": "",
                "detected_by": "Pylint",
                "rule_id": finding.get("message-id", ""),
                "symbol": finding.get("symbol", ""),
                "module": finding.get("module", ""),
                "obj": finding.get("obj", ""),
                "quality_type": message_type,  # F, E, W, R, C
            }

            results.append(result)

        return results

    def get_quality_summary(self, findings: List[Dict]) -> Dict:
        """Generate a summary of code quality metrics"""
        summary = {
            "total_issues": len(findings),
            "by_type": {
                "fatal": 0,
                "error": 0,
                "warning": 0,
                "refactor": 0,
                "convention": 0
            },
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            },
            "quality_score": 100
        }

        type_map = {
            "F": "fatal",
            "E": "error",
            "W": "warning",
            "R": "refactor",
            "C": "convention"
        }

        for finding in findings:
            quality_type = finding.get("quality_type", "C")
            severity = finding.get("severity", "low")

            if quality_type in type_map:
                summary["by_type"][type_map[quality_type]] += 1
            summary["by_severity"][severity] += 1

        # Calculate quality score (deductions based on issue types)
        deductions = (
            summary["by_type"]["fatal"] * 20 +
            summary["by_type"]["error"] * 10 +
            summary["by_type"]["warning"] * 3 +
            summary["by_type"]["refactor"] * 1 +
            summary["by_type"]["convention"] * 0.5
        )

        summary["quality_score"] = max(0, 100 - deductions)

        return summary
