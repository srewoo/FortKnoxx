"""
Snyk CLI Scanner - Modern dependency and code scanning
Provides superior vulnerability database coverage
Free tier available with 200 tests/month
"""

import logging
import subprocess
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)

# Store token for use across functions
_snyk_token = None


async def scan(repo_path: str, snyk_token: str = None) -> List[Dict]:
    """
    Run Snyk CLI scanner for dependency vulnerabilities

    Snyk provides:
    - Excellent vulnerability database (better than NVD alone)
    - Fix recommendations with upgrade paths
    - License compliance checking
    - Container scanning

    Args:
        repo_path: Path to repository
        snyk_token: Snyk API token for authentication
    """
    global _snyk_token
    try:
        # Check if snyk is installed
        if not _is_snyk_installed():
            logger.warning("Snyk CLI not found, skipping scan. Install: npm install -g snyk")
            return []

        # Store token for use in scan functions
        _snyk_token = snyk_token

        # Authenticate if token provided
        if snyk_token:
            authenticated = _authenticate_snyk(snyk_token)
            if authenticated:
                logger.info("Snyk authenticated successfully")
            else:
                logger.warning("Snyk authentication failed, scanning may be limited")
        else:
            logger.warning("No Snyk token provided, scanning may be limited")

        issues = []

        # Scan for dependency vulnerabilities
        dep_issues = await _scan_dependencies(repo_path)
        issues.extend(dep_issues)

        # Scan code for security issues (if authenticated)
        if snyk_token:
            code_issues = await _scan_code(repo_path)
            issues.extend(code_issues)

        logger.info(f"Snyk found {len(issues)} vulnerabilities")
        return issues

    except Exception as e:
        logger.error(f"Snyk scan failed: {str(e)}")
        return []


def _is_snyk_installed() -> bool:
    """Check if Snyk CLI is installed"""
    try:
        result = subprocess.run(
            ["snyk", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _authenticate_snyk(token: str) -> bool:
    """
    Authenticate Snyk CLI with token

    Args:
        token: Snyk API token

    Returns:
        True if authentication successful
    """
    try:
        # Set environment variable for Snyk authentication
        env = os.environ.copy()
        env['SNYK_TOKEN'] = token

        # Authenticate using snyk auth command
        result = subprocess.run(
            ["snyk", "auth", token],
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )

        if result.returncode == 0:
            logger.info("Snyk authentication successful")
            return True
        else:
            logger.error(f"Snyk authentication failed: {result.stderr}")
            return False

    except Exception as e:
        logger.error(f"Snyk authentication error: {str(e)}")
        return False


async def _scan_dependencies(repo_path: str) -> List[Dict]:
    """Scan dependencies for known vulnerabilities"""
    issues = []

    try:
        cmd = [
            "snyk", "test",
            "--json",
            "--all-projects",
            "--detection-depth=4"
        ]

        # Prepare environment with token if available
        env = os.environ.copy()
        if _snyk_token:
            env['SNYK_TOKEN'] = _snyk_token

        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300,
            env=env
        )

        if not result.stdout:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Snyk may return non-JSON on errors
            return []

        # Handle both single project and multi-project results
        if isinstance(data, list):
            for project_data in data:
                issues.extend(_parse_snyk_result(project_data, repo_path))
        else:
            issues.extend(_parse_snyk_result(data, repo_path))

    except subprocess.TimeoutExpired:
        logger.warning("Snyk dependency scan timed out")
    except Exception as e:
        logger.error(f"Snyk dependency scan error: {str(e)}")

    return issues


async def _scan_code(repo_path: str) -> List[Dict]:
    """Scan code for security issues using Snyk Code"""
    issues = []

    try:
        cmd = [
            "snyk", "code", "test",
            "--json"
        ]

        # Prepare environment with token if available
        env = os.environ.copy()
        if _snyk_token:
            env['SNYK_TOKEN'] = _snyk_token

        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300,
            env=env
        )

        if not result.stdout:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []

        # Parse Snyk Code results
        runs = data.get("runs", [])
        for run in runs:
            results = run.get("results", [])
            for finding in results:
                rule_id = finding.get("ruleId", "")
                message = finding.get("message", {}).get("text", "")

                locations = finding.get("locations", [])
                for location in locations:
                    physical = location.get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {})
                    region = physical.get("region", {})

                    file_path = artifact.get("uri", "")
                    line_start = region.get("startLine", 0)

                    # Map Snyk severity to our severity levels
                    level = finding.get("level", "warning")
                    severity = _map_snyk_level(level)

                    issue = {
                        "title": f"Snyk Code: {rule_id}",
                        "description": message,
                        "severity": severity,
                        "file_path": os.path.join(repo_path, file_path) if file_path else "",
                        "line_start": line_start,
                        "line_end": region.get("endLine", line_start),
                        "detected_by": "snyk-code",
                        "category": "Security",
                        "rule_id": rule_id,
                        "owasp_category": _get_owasp_category(rule_id),
                        "cwe": _extract_cwe(finding),
                    }
                    issues.append(issue)

    except subprocess.TimeoutExpired:
        logger.warning("Snyk code scan timed out")
    except Exception as e:
        logger.debug(f"Snyk code scan not available: {str(e)}")

    return issues


def _parse_snyk_result(data: Dict, repo_path: str) -> List[Dict]:
    """Parse Snyk test result into standardized format"""
    issues = []

    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "medium").lower()

        # Build description with fix info
        description = vuln.get("description", vuln.get("title", ""))

        # Add fix information if available
        if vuln.get("fixedIn"):
            description += f"\n\nFixed in: {', '.join(vuln['fixedIn'])}"
        if vuln.get("upgradePath"):
            upgrade = vuln['upgradePath']
            if isinstance(upgrade, list) and len(upgrade) > 1:
                description += f"\nUpgrade path: {' -> '.join(str(u) for u in upgrade if u)}"

        # Safely extract CVE and CWE identifiers
        identifiers = vuln.get("identifiers", {})
        cve_list = identifiers.get("CVE", [])
        cwe_list = identifiers.get("CWE", [])
        cve = cve_list[0] if isinstance(cve_list, list) and len(cve_list) > 0 else ""
        cwe = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else ""

        # Safely extract file path from 'from' field
        from_list = vuln.get("from", [])
        file_path = os.path.join(repo_path, from_list[0]) if isinstance(from_list, list) and len(from_list) > 0 else ""

        issue = {
            "title": f"Vulnerable dependency: {vuln.get('packageName', 'Unknown')}@{vuln.get('version', '')}",
            "description": description,
            "severity": severity,
            "file_path": file_path,
            "line_start": 0,
            "line_end": 0,
            "detected_by": "snyk",
            "category": "Dependency",
            "cve": cve,
            "cwe": cwe,
            "owasp_category": "A06",  # Vulnerable and Outdated Components
            "package_name": vuln.get("packageName", ""),
            "package_version": vuln.get("version", ""),
            "cvss_score": vuln.get("cvssScore", 0),
            "exploit_maturity": vuln.get("exploit", ""),
        }
        issues.append(issue)

    return issues


def _map_snyk_level(level: str) -> str:
    """Map Snyk severity levels to our standard levels"""
    mapping = {
        "error": "critical",
        "warning": "medium",
        "note": "low",
        "high": "high",
        "critical": "critical",
        "medium": "medium",
        "low": "low"
    }
    return mapping.get(level.lower(), "medium")


def _get_owasp_category(rule_id: str) -> str:
    """Map Snyk rule to OWASP category"""
    rule_lower = rule_id.lower()

    if "inject" in rule_lower or "sqli" in rule_lower:
        return "A03"  # Injection
    elif "xss" in rule_lower or "script" in rule_lower:
        return "A03"  # Injection
    elif "auth" in rule_lower or "password" in rule_lower:
        return "A07"  # Authentication Failures
    elif "crypto" in rule_lower or "cipher" in rule_lower:
        return "A02"  # Cryptographic Failures
    elif "access" in rule_lower or "permission" in rule_lower:
        return "A01"  # Broken Access Control
    elif "config" in rule_lower:
        return "A05"  # Security Misconfiguration
    else:
        return "A03"  # Default to Injection


def _extract_cwe(finding: Dict) -> str:
    """Extract CWE from Snyk finding"""
    properties = finding.get("properties", {})
    cwe = properties.get("cwe", [])
    if cwe and isinstance(cwe, list):
        return cwe[0]
    return ""
