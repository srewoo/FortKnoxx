"""
SQLFluff Scanner - SQL code quality and security analysis
Detects SQL injection patterns, unsafe queries, and code quality issues
"""

import logging
import subprocess
import json
import os
from typing import List, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


def find_sql_files(repo_path: str) -> List[str]:
    """Find SQL files in repository"""
    sql_files = []
    sql_extensions = ['.sql', '.SQL']

    for root, _, files in os.walk(repo_path):
        for file in files:
            if any(file.endswith(ext) for ext in sql_extensions):
                sql_files.append(os.path.join(root, file))

    return sql_files


async def scan(repo_path: str) -> List[Dict]:
    """
    Run SQLFluff scanner for SQL security and quality issues

    Detects:
    - SQL injection vulnerabilities
    - Unsafe SQL practices
    - Code quality issues
    - Style violations
    """
    try:
        sql_files = find_sql_files(repo_path)

        if not sql_files:
            logger.info("No SQL files found in repository")
            return []

        logger.info(f"Found {len(sql_files)} SQL files to scan")

        # Run SQLFluff lint
        cmd = [
            "sqlfluff",
            "lint",
            "--format", "json",
            "--dialect", "ansi",  # Use ANSI SQL as default, can be configured
        ]
        cmd.extend(sql_files)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if not result.stdout:
            return []

        findings = json.loads(result.stdout)
        issues = []

        for file_result in findings:
            file_path = file_result.get("filepath", "")
            violations = file_result.get("violations", [])

            for violation in violations:
                # Map to vulnerability format
                severity = map_severity(violation.get("rule_code", ""))

                issue = {
                    "title": f"SQL Issue: {violation.get('description', 'SQL quality issue')}",
                    "description": violation.get("description", ""),
                    "severity": severity,
                    "file_path": file_path,
                    "line_start": violation.get("line_no", 0),
                    "line_end": violation.get("line_no", 0),
                    "code_snippet": violation.get("line_pos", ""),
                    "rule_code": violation.get("rule_code", ""),
                    "detected_by": "sqlfluff",
                    "category": "SQL Security",
                    "owasp_category": "A03",  # Injection
                    "cwe": "CWE-89",  # SQL Injection
                }
                issues.append(issue)

        logger.info(f"SQLFluff found {len(issues)} SQL issues")
        return issues

    except subprocess.TimeoutExpired:
        logger.error("SQLFluff scan timed out")
        return []
    except json.JSONDecodeError:
        logger.error("Failed to parse SQLFluff output")
        return []
    except Exception as e:
        logger.error(f"SQLFluff scan failed: {str(e)}")
        return []


def map_severity(rule_code: str) -> str:
    """Map SQLFluff rule codes to severity levels"""
    # Security-critical rules
    if rule_code.startswith("L0"):  # Layout issues
        return "low"
    elif rule_code.startswith("L1"):  # Structure issues
        return "medium"
    elif rule_code.startswith("L2"):  # Capitalization
        return "low"
    elif rule_code.startswith("L3"):  # Ambiguous issues (potential security)
        return "high"
    elif rule_code.startswith("L4"):  # Column references
        return "medium"
    elif rule_code.startswith("L5"):  # Aliasing
        return "low"
    else:
        return "medium"
