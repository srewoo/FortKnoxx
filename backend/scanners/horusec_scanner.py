"""
Horusec Scanner - Multi-Language Security Analysis
Open-source tool that performs static code analysis to identify security flaws
Supports: Python, JavaScript, Go, Java, C#, Ruby, PHP, Kotlin, Dart, and more
"""

import logging
import subprocess
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)


async def scan(repo_path: str) -> List[Dict]:
    """
    Run Horusec multi-language security scanner

    Horusec detects:
    - Hardcoded secrets and credentials
    - SQL injection
    - XSS vulnerabilities
    - Command injection
    - Path traversal
    - Insecure cryptography
    - Security misconfigurations
    - Vulnerable dependencies
    - And many more across 18+ languages
    """
    try:
        # Check if horusec is installed
        if not _is_horusec_installed():
            logger.warning("Horusec not found, skipping scan. Install: curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash")
            return []

        cmd = [
            "horusec", "start",
            "-p", repo_path,
            "-o", "json",
            "-O", "/dev/stdout",
            "--disable-docker",  # Run without Docker for speed
            "-i", ".git,node_modules,vendor,venv,.venv,__pycache__",  # Ignore paths
            "--enable-git-history=false"  # Skip git history for speed
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )

        output = result.stdout

        if not output:
            return []

        # Find JSON in output (Horusec may include other text)
        json_start = output.find('{')
        json_end = output.rfind('}') + 1

        if json_start == -1 or json_end == 0:
            return []

        json_str = output[json_start:json_end]

        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            logger.warning("Failed to parse Horusec output")
            return []

        issues = []

        # Parse analysis results
        analysis_vulns = data.get("analysisVulnerabilities", [])

        for vuln_wrapper in analysis_vulns:
            vuln = vuln_wrapper.get("vulnerabilities", {})

            if not vuln:
                continue

            severity = _map_severity(vuln.get("severity", "MEDIUM"))

            # Build description
            description = vuln.get("details", "")
            if vuln.get("code"):
                description += f"\n\nCode:\n```\n{vuln['code']}\n```"

            issue = {
                "title": f"{vuln.get('language', 'Code')}: {vuln.get('securityTool', 'Horusec')} - {_get_short_title(vuln)}",
                "description": description,
                "severity": severity,
                "file_path": vuln.get("file", ""),
                "line_start": int(vuln.get("line", "0")) if vuln.get("line") else 0,
                "line_end": int(vuln.get("line", "0")) if vuln.get("line") else 0,
                "column": int(vuln.get("column", "0")) if vuln.get("column") else 0,
                "code_snippet": vuln.get("code", "")[:500],
                "detected_by": "horusec",
                "category": f"{vuln.get('language', 'Code')} Security",
                "rule_id": vuln.get("rule_id", ""),
                "security_tool": vuln.get("securityTool", ""),
                "confidence": vuln.get("confidence", ""),
                "owasp_category": _get_owasp_category(vuln),
                "cwe": _extract_cwe(vuln),
                "vulnerability_type": vuln.get("type", ""),
            }
            issues.append(issue)

        logger.info(f"Horusec found {len(issues)} security issues")
        return issues

    except subprocess.TimeoutExpired:
        logger.warning("Horusec scan timed out")
        return []
    except Exception as e:
        logger.error(f"Horusec scan failed: {str(e)}")
        return []


def _is_horusec_installed() -> bool:
    """Check if Horusec is installed"""
    try:
        result = subprocess.run(
            ["horusec", "version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _map_severity(severity: str) -> str:
    """Map Horusec severity to standard levels"""
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "low",
        "UNKNOWN": "medium"
    }
    return mapping.get(severity.upper(), "medium")


def _get_short_title(vuln: Dict) -> str:
    """Get a short title from vulnerability details"""
    details = vuln.get("details", "")

    # Take first sentence or first 100 chars
    if ". " in details:
        return details.split(". ")[0]
    elif len(details) > 100:
        return details[:100] + "..."
    elif details:
        return details
    else:
        return vuln.get("type", "Security Issue")


def _get_owasp_category(vuln: Dict) -> str:
    """Map Horusec finding to OWASP category"""
    details_lower = vuln.get("details", "").lower()
    vuln_type = vuln.get("type", "").lower()

    if any(kw in details_lower or kw in vuln_type for kw in ["sql", "injection", "xss", "command"]):
        return "A03"  # Injection
    elif any(kw in details_lower or kw in vuln_type for kw in ["crypto", "cipher", "random", "hash"]):
        return "A02"  # Cryptographic Failures
    elif any(kw in details_lower or kw in vuln_type for kw in ["auth", "password", "credential", "secret"]):
        return "A07"  # Authentication Failures
    elif any(kw in details_lower or kw in vuln_type for kw in ["access", "permission", "path", "traversal"]):
        return "A01"  # Broken Access Control
    elif any(kw in details_lower or kw in vuln_type for kw in ["config", "header", "cors"]):
        return "A05"  # Security Misconfiguration
    elif any(kw in details_lower or kw in vuln_type for kw in ["dependency", "vulnerable", "outdated"]):
        return "A06"  # Vulnerable Components
    else:
        return "A03"  # Default


def _extract_cwe(vuln: Dict) -> str:
    """Extract CWE from vulnerability info"""
    details = vuln.get("details", "")

    # Look for CWE pattern in details
    import re
    cwe_match = re.search(r'CWE-(\d+)', details, re.IGNORECASE)
    if cwe_match:
        return f"CWE-{cwe_match.group(1)}"

    # Map common vulnerability types to CWEs
    vuln_type = vuln.get("type", "").lower()
    details_lower = details.lower()

    cwe_mapping = {
        "sql": "CWE-89",
        "xss": "CWE-79",
        "command": "CWE-78",
        "path": "CWE-22",
        "hardcoded": "CWE-798",
        "password": "CWE-259",
        "credential": "CWE-798",
        "random": "CWE-330",
        "crypto": "CWE-327",
        "deserial": "CWE-502",
        "xxe": "CWE-611",
        "ssrf": "CWE-918",
        "csrf": "CWE-352",
        "open redirect": "CWE-601",
    }

    for pattern, cwe in cwe_mapping.items():
        if pattern in vuln_type or pattern in details_lower:
            return cwe

    return ""
