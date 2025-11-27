"""
Gosec Scanner - Go Security Checker
Inspects Go source code for security problems
"""

import logging
import subprocess
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)


async def scan(repo_path: str) -> List[Dict]:
    """
    Run Gosec scanner for Go security vulnerabilities

    Gosec detects:
    - Hardcoded credentials
    - SQL injection
    - Command injection
    - Path traversal
    - Weak cryptography
    - Insecure TLS configurations
    - Integer overflow
    - Memory safety issues
    """
    try:
        # Check if gosec is installed
        if not _is_gosec_installed():
            logger.warning("Gosec not found, skipping scan. Install: go install github.com/securego/gosec/v2/cmd/gosec@latest")
            return []

        # Check if there are Go files
        if not _has_go_files(repo_path):
            logger.info("No Go files found in repository")
            return []

        cmd = [
            "gosec",
            "-fmt=json",
            "-quiet",
            "-exclude-generated",
            "./..."
        ]

        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Gosec returns non-zero exit code when issues found
        if not result.stdout:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Gosec output")
            return []

        issues = []
        for finding in data.get("Issues", []):
            severity = _map_gosec_severity(finding.get("severity", "MEDIUM"))

            # Extract code snippet
            code = finding.get("code", "")

            issue = {
                "title": f"Go Security: {finding.get('details', 'Security issue')}",
                "description": _build_description(finding),
                "severity": severity,
                "file_path": finding.get("file", ""),
                "line_start": int(finding.get("line", "0").split("-")[0]) if finding.get("line") else 0,
                "line_end": int(finding.get("line", "0").split("-")[-1]) if finding.get("line") else 0,
                "code_snippet": code,
                "detected_by": "gosec",
                "category": "Go Security",
                "rule_id": finding.get("rule_id", ""),
                "cwe": finding.get("cwe", {}).get("id", "") if isinstance(finding.get("cwe"), dict) else "",
                "owasp_category": _get_owasp_category(finding.get("rule_id", "")),
            }
            issues.append(issue)

        logger.info(f"Gosec found {len(issues)} Go security issues")
        return issues

    except subprocess.TimeoutExpired:
        logger.warning("Gosec scan timed out")
        return []
    except Exception as e:
        logger.error(f"Gosec scan failed: {str(e)}")
        return []


def _is_gosec_installed() -> bool:
    """Check if gosec is installed"""
    try:
        result = subprocess.run(
            ["gosec", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _has_go_files(repo_path: str) -> bool:
    """Check if repository contains Go files"""
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".go"):
                return True
    return False


def _map_gosec_severity(severity: str) -> str:
    """Map Gosec severity to standard levels"""
    mapping = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low"
    }
    return mapping.get(severity.upper(), "medium")


def _build_description(finding: Dict) -> str:
    """Build detailed description from Gosec finding"""
    description = finding.get("details", "")

    # Add CWE info if available
    cwe = finding.get("cwe", {})
    if isinstance(cwe, dict) and cwe.get("id"):
        description += f"\n\nCWE: {cwe.get('id')} - {cwe.get('name', '')}"
        if cwe.get("url"):
            description += f"\nReference: {cwe['url']}"

    return description


def _get_owasp_category(rule_id: str) -> str:
    """Map Gosec rule to OWASP category"""
    # Gosec rule ID mappings
    injection_rules = ["G201", "G202", "G203"]  # SQL, Template, Subprocess
    crypto_rules = ["G401", "G402", "G403", "G404", "G501", "G502", "G503", "G504", "G505"]
    secrets_rules = ["G101", "G102"]
    file_rules = ["G301", "G302", "G303", "G304", "G305", "G306", "G307"]
    network_rules = ["G102", "G110", "G111", "G112"]

    if rule_id in injection_rules:
        return "A03"  # Injection
    elif rule_id in crypto_rules:
        return "A02"  # Cryptographic Failures
    elif rule_id in secrets_rules:
        return "A07"  # Authentication Failures
    elif rule_id in file_rules:
        return "A01"  # Broken Access Control
    elif rule_id in network_rules:
        return "A05"  # Security Misconfiguration
    else:
        return "A03"  # Default to Injection
