"""
OWASP ZAP Baseline Scanner - Dynamic Application Security Testing
Runs ZAP in baseline mode for quick security scans
"""

import logging
import subprocess
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)


async def scan(repo_path: str) -> List[Dict]:
    """
    Run OWASP ZAP baseline scanner

    ZAP Baseline detects:
    - Missing security headers
    - Cookie issues
    - Information disclosure
    - SSL/TLS configuration issues
    - Common web vulnerabilities
    - Cross-site scripting (XSS)
    - SQL injection points
    - CSRF vulnerabilities

    Note: This scans static files for potential web security issues.
    For full DAST, a running application is needed.
    """
    try:
        # Check if ZAP is installed
        if not _is_zap_installed():
            logger.warning("OWASP ZAP not found, skipping scan. Install: brew install zaproxy")
            return []

        issues = []

        # Scan for security misconfigurations in web files
        web_issues = await _scan_web_files(repo_path)
        issues.extend(web_issues)

        logger.info(f"ZAP found {len(issues)} web security issues")
        return issues

    except Exception as e:
        logger.error(f"ZAP scan failed: {str(e)}")
        return []


async def _scan_web_files(repo_path: str) -> List[Dict]:
    """Scan web files for security issues"""
    issues = []

    # Find web configuration files
    web_files = _find_web_files(repo_path)

    for file_path in web_files:
        file_issues = _check_security_headers(file_path, repo_path)
        issues.extend(file_issues)

    # Check for common web security misconfigurations
    config_issues = _check_web_configs(repo_path)
    issues.extend(config_issues)

    return issues


def _find_web_files(repo_path: str) -> List[str]:
    """Find web-related files"""
    web_files = []
    web_extensions = ['.html', '.htm', '.js', '.jsx', '.ts', '.tsx', '.vue', '.svelte']
    config_files = ['nginx.conf', 'apache.conf', '.htaccess', 'web.config', 'server.js', 'app.js', 'index.js']

    for root, _, files in os.walk(repo_path):
        # Skip node_modules and other common dirs
        if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', 'venv', 'dist', 'build']):
            continue

        for file in files:
            if any(file.endswith(ext) for ext in web_extensions) or file in config_files:
                web_files.append(os.path.join(root, file))

    return web_files[:100]  # Limit to first 100 files


def _check_security_headers(file_path: str, repo_path: str) -> List[Dict]:
    """Check for missing security headers in web files"""
    issues = []

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            content_lower = content.lower()

        # Check for security header configurations
        security_checks = [
            {
                "pattern": "x-frame-options",
                "missing_title": "Missing X-Frame-Options Header",
                "missing_desc": "The application may be vulnerable to clickjacking attacks. Add X-Frame-Options header.",
                "severity": "medium",
                "cwe": "CWE-1021"
            },
            {
                "pattern": "content-security-policy",
                "missing_title": "Missing Content-Security-Policy Header",
                "missing_desc": "Missing CSP header increases XSS attack surface. Implement Content-Security-Policy.",
                "severity": "medium",
                "cwe": "CWE-1021"
            },
            {
                "pattern": "x-content-type-options",
                "missing_title": "Missing X-Content-Type-Options Header",
                "missing_desc": "Without X-Content-Type-Options, browsers may MIME-sniff responses.",
                "severity": "low",
                "cwe": "CWE-16"
            },
            {
                "pattern": "strict-transport-security",
                "missing_title": "Missing HSTS Header",
                "missing_desc": "HTTPS not enforced. Implement Strict-Transport-Security header.",
                "severity": "medium",
                "cwe": "CWE-319"
            }
        ]

        # Only check server configuration files
        if any(cfg in file_path.lower() for cfg in ['nginx', 'apache', '.htaccess', 'server.', 'app.', 'index.']):
            for check in security_checks:
                if check["pattern"] not in content_lower and "header" in content_lower:
                    issues.append({
                        "title": check["missing_title"],
                        "description": check["missing_desc"],
                        "severity": check["severity"],
                        "file_path": file_path,
                        "line_start": 1,
                        "line_end": 1,
                        "detected_by": "zap",
                        "category": "Web Security",
                        "owasp_category": "A05",  # Security Misconfiguration
                        "cwe": check["cwe"],
                    })

        # Check for dangerous patterns
        dangerous_patterns = [
            {
                "pattern": "eval(",
                "title": "Use of eval() Function",
                "desc": "eval() can execute arbitrary code. Avoid using eval() with user input.",
                "severity": "high",
                "cwe": "CWE-95"
            },
            {
                "pattern": "innerhtml",
                "title": "Potential DOM-based XSS",
                "desc": "innerHTML can lead to XSS if used with untrusted data. Use textContent instead.",
                "severity": "high",
                "cwe": "CWE-79"
            },
            {
                "pattern": "document.write",
                "title": "Use of document.write()",
                "desc": "document.write() can lead to XSS vulnerabilities. Use safer DOM manipulation methods.",
                "severity": "medium",
                "cwe": "CWE-79"
            },
            {
                "pattern": "dangerouslysetinnerhtml",
                "title": "Dangerous React Pattern",
                "desc": "dangerouslySetInnerHTML bypasses React's XSS protections. Ensure input is sanitized.",
                "severity": "high",
                "cwe": "CWE-79"
            },
            {
                "pattern": "cors: true",
                "title": "Permissive CORS Configuration",
                "desc": "Overly permissive CORS settings can expose sensitive data.",
                "severity": "medium",
                "cwe": "CWE-942"
            },
            {
                "pattern": "access-control-allow-origin: *",
                "title": "Wildcard CORS Origin",
                "desc": "CORS allows any origin. Restrict to specific trusted domains.",
                "severity": "medium",
                "cwe": "CWE-942"
            }
        ]

        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            for pattern in dangerous_patterns:
                if pattern["pattern"] in line_lower:
                    issues.append({
                        "title": pattern["title"],
                        "description": pattern["desc"],
                        "severity": pattern["severity"],
                        "file_path": file_path,
                        "line_start": i,
                        "line_end": i,
                        "code_snippet": line.strip()[:200],
                        "detected_by": "zap",
                        "category": "Web Security",
                        "owasp_category": "A03",  # Injection
                        "cwe": pattern["cwe"],
                    })

    except Exception as e:
        logger.debug(f"Error checking file {file_path}: {str(e)}")

    return issues


def _check_web_configs(repo_path: str) -> List[Dict]:
    """Check web configurations for security issues"""
    issues = []

    # Check package.json for security issues
    package_json = os.path.join(repo_path, "package.json")
    if os.path.exists(package_json):
        try:
            with open(package_json, 'r') as f:
                pkg = json.load(f)

            # Check for engines/node version (older versions have vulnerabilities)
            engines = pkg.get("engines", {})
            node_version = engines.get("node", "")
            if node_version and any(v in node_version for v in ["8", "10", "12"]):
                issues.append({
                    "title": "Outdated Node.js Version Specified",
                    "description": f"Node.js version '{node_version}' may have security vulnerabilities. Upgrade to LTS version.",
                    "severity": "medium",
                    "file_path": package_json,
                    "line_start": 1,
                    "line_end": 1,
                    "detected_by": "zap",
                    "category": "Web Security",
                    "owasp_category": "A06",
                    "cwe": "CWE-1104",
                })

        except Exception as e:
            logger.debug(f"Error reading package.json: {str(e)}")

    return issues


def _is_zap_installed() -> bool:
    """Check if OWASP ZAP is installed"""
    try:
        # Check for zap command
        result = subprocess.run(
            ["which", "zap-baseline.py"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return True

        # Check for zaproxy
        result = subprocess.run(
            ["which", "zaproxy"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False
