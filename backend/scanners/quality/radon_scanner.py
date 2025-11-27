"""
Radon Scanner - Python Code Complexity Metrics
License: MIT (Free, Open Source)
Installation: pip install radon

Features:
- Cyclomatic Complexity (CC)
- Maintainability Index (MI)
- Raw metrics (LOC, LLOC, SLOC, comments, blanks)
- Halstead complexity metrics
"""

import asyncio
import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class RadonScanner:
    """
    Radon scanner for Python code complexity analysis.

    Metrics provided:
    - Cyclomatic Complexity (CC): Measures code complexity
    - Maintainability Index (MI): Measures maintainability (0-100)
    - Raw Metrics: LOC, LLOC, SLOC, comments, multi-line strings, blanks
    - Halstead Metrics: Volume, difficulty, effort, time, bugs
    """

    # Cyclomatic Complexity grades and their meanings
    CC_GRADES = {
        "A": {"threshold": 5, "risk": "low", "description": "Simple, low risk"},
        "B": {"threshold": 10, "risk": "low", "description": "Well-structured, moderate complexity"},
        "C": {"threshold": 20, "risk": "medium", "description": "Slightly complex, moderate risk"},
        "D": {"threshold": 30, "risk": "medium", "description": "More complex, elevated risk"},
        "E": {"threshold": 40, "risk": "high", "description": "Complex, high risk"},
        "F": {"threshold": float("inf"), "risk": "critical", "description": "Very complex, very high risk"}
    }

    # Maintainability Index grades
    MI_GRADES = {
        "A": {"min": 20, "max": 100, "description": "Highly maintainable"},
        "B": {"min": 10, "max": 20, "description": "Moderately maintainable"},
        "C": {"min": 0, "max": 10, "description": "Difficult to maintain"}
    }

    def __init__(self):
        self.tool_path = shutil.which("radon")

    async def is_available(self) -> bool:
        """Check if radon is installed"""
        return self.tool_path is not None

    async def scan(self, repo_path: str) -> List[Dict]:
        """
        Run comprehensive Radon analysis.

        Args:
            repo_path: Path to the repository

        Returns:
            List of complexity issues found
        """
        if not await self.is_available():
            logger.warning("Radon not available, skipping scan")
            return []

        results = []

        try:
            # Run Cyclomatic Complexity analysis
            cc_results = await self._run_cc_analysis(repo_path)
            results.extend(cc_results)

            # Run Maintainability Index analysis
            mi_results = await self._run_mi_analysis(repo_path)
            results.extend(mi_results)

            return results

        except Exception as e:
            logger.error(f"Radon scan error: {str(e)}")
            return []

    async def _run_cc_analysis(self, repo_path: str) -> List[Dict]:
        """Run Cyclomatic Complexity analysis"""
        try:
            cmd = [
                self.tool_path,
                "cc",
                "--json",
                "--show-complexity",
                "--min", "C",  # Only report C grade or worse (CC > 10)
                "--exclude", "test_*,*_test.py,tests/,venv/,.venv/,node_modules/",
                repo_path
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return self._parse_cc_results(data, repo_path)
                except json.JSONDecodeError:
                    logger.error("Failed to parse Radon CC JSON output")
                    return []

            return []

        except subprocess.TimeoutExpired:
            logger.error("Radon CC analysis timed out")
            return []
        except Exception as e:
            logger.error(f"Radon CC analysis error: {str(e)}")
            return []

    async def _run_mi_analysis(self, repo_path: str) -> List[Dict]:
        """Run Maintainability Index analysis"""
        try:
            cmd = [
                self.tool_path,
                "mi",
                "--json",
                "--show",
                "--min", "C",  # Only report C grade (MI < 10)
                "--exclude", "test_*,*_test.py,tests/,venv/,.venv/,node_modules/",
                repo_path
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    return self._parse_mi_results(data, repo_path)
                except json.JSONDecodeError:
                    logger.error("Failed to parse Radon MI JSON output")
                    return []

            return []

        except subprocess.TimeoutExpired:
            logger.error("Radon MI analysis timed out")
            return []
        except Exception as e:
            logger.error(f"Radon MI analysis error: {str(e)}")
            return []

    async def get_raw_metrics(self, repo_path: str) -> Dict:
        """Get raw code metrics for the repository"""
        try:
            cmd = [
                self.tool_path,
                "raw",
                "--json",
                "--summary",
                "--exclude", "test_*,*_test.py,tests/,venv/,.venv/,node_modules/",
                repo_path
            ]

            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    return {}

            return {}

        except Exception as e:
            logger.error(f"Radon raw metrics error: {str(e)}")
            return {}

    def _parse_cc_results(self, data: Dict, repo_path: str) -> List[Dict]:
        """Parse Cyclomatic Complexity results"""
        results = []

        for file_path, functions in data.items():
            # Get relative path
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/")

            for func in functions:
                complexity = func.get("complexity", 0)
                rank = func.get("rank", "A")

                # Skip low complexity (A and B grades)
                if rank in ["A", "B"]:
                    continue

                # Determine severity based on grade
                severity = "low"
                if rank == "F":
                    severity = "critical"
                elif rank == "E":
                    severity = "high"
                elif rank in ["C", "D"]:
                    severity = "medium"

                grade_info = self.CC_GRADES.get(rank, self.CC_GRADES["F"])

                result = {
                    "file_path": file_path,
                    "line_start": func.get("lineno", 0),
                    "line_end": func.get("endline", func.get("lineno", 0)),
                    "severity": severity,
                    "category": "code-complexity",
                    "owasp_category": "A04",  # Insecure Design
                    "title": f"High Cyclomatic Complexity ({rank}): {func.get('name', 'unknown')}",
                    "description": f"Function '{func.get('name', 'unknown')}' has cyclomatic complexity of {complexity} (Grade {rank}). {grade_info['description']}. Consider refactoring to reduce complexity.",
                    "code_snippet": "",
                    "detected_by": "Radon",
                    "rule_id": f"CC-{rank}",
                    "complexity_grade": rank,
                    "complexity_value": complexity,
                    "function_name": func.get("name", ""),
                    "function_type": func.get("type", "function"),
                }

                results.append(result)

        return results

    def _parse_mi_results(self, data: Dict, repo_path: str) -> List[Dict]:
        """Parse Maintainability Index results"""
        results = []

        for file_path, mi_data in data.items():
            # Get relative path
            if file_path.startswith(repo_path):
                file_path = file_path[len(repo_path):].lstrip("/")

            mi_score = mi_data.get("mi", 100)
            rank = mi_data.get("rank", "A")

            # Skip well-maintained files
            if rank in ["A", "B"]:
                continue

            # Determine severity
            severity = "medium" if rank == "B" else "high"

            result = {
                "file_path": file_path,
                "line_start": 1,
                "line_end": 1,
                "severity": severity,
                "category": "maintainability",
                "owasp_category": "A04",  # Insecure Design
                "title": f"Low Maintainability Index ({rank}): {file_path}",
                "description": f"File has a Maintainability Index of {mi_score:.2f} (Grade {rank}). Files with MI < 10 are considered difficult to maintain. Consider refactoring to improve maintainability.",
                "code_snippet": "",
                "detected_by": "Radon",
                "rule_id": f"MI-{rank}",
                "maintainability_grade": rank,
                "maintainability_score": mi_score,
            }

            results.append(result)

        return results

    def get_complexity_summary(self, findings: List[Dict]) -> Dict:
        """Generate a summary of complexity metrics"""
        cc_findings = [f for f in findings if f.get("category") == "code-complexity"]
        mi_findings = [f for f in findings if f.get("category") == "maintainability"]

        summary = {
            "total_complexity_issues": len(cc_findings),
            "total_maintainability_issues": len(mi_findings),
            "by_cc_grade": {
                "C": 0, "D": 0, "E": 0, "F": 0
            },
            "by_mi_grade": {
                "B": 0, "C": 0
            },
            "complexity_score": 100
        }

        for finding in cc_findings:
            grade = finding.get("complexity_grade", "C")
            if grade in summary["by_cc_grade"]:
                summary["by_cc_grade"][grade] += 1

        for finding in mi_findings:
            grade = finding.get("maintainability_grade", "B")
            if grade in summary["by_mi_grade"]:
                summary["by_mi_grade"][grade] += 1

        # Calculate complexity score
        deductions = (
            summary["by_cc_grade"]["F"] * 20 +
            summary["by_cc_grade"]["E"] * 10 +
            summary["by_cc_grade"]["D"] * 5 +
            summary["by_cc_grade"]["C"] * 2 +
            summary["by_mi_grade"]["C"] * 15 +
            summary["by_mi_grade"]["B"] * 5
        )

        summary["complexity_score"] = max(0, 100 - deductions)

        return summary
