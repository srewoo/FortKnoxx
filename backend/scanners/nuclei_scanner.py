"""
Nuclei Scanner - Template-based vulnerability scanning
Fast and customizable vulnerability scanner using community templates

Detects:
- Known CVEs and vulnerabilities
- Misconfigurations
- Exposed panels and services
- Security headers
- Technology-specific vulnerabilities
"""

import logging
import subprocess
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)


async def scan(repo_path: str) -> List[Dict]:
    """
    Run Nuclei scanner for template-based vulnerability detection

    Note: Nuclei primarily scans running applications/URLs
    For static code scanning, we'll scan for configuration files
    and known vulnerability patterns
    """
    try:
        # Check if nuclei is installed
        if not os.path.exists("/usr/local/bin/nuclei") and not os.path.exists("/opt/homebrew/bin/nuclei"):
            logger.warning("Nuclei not found, skipping scan. Install with: brew install nuclei or go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            return []

        # Scan for configuration and infrastructure files
        config_patterns = [
            "docker-compose.yml",
            "Dockerfile",
            "kubernetes/*.yaml",
            "k8s/*.yaml",
            ".github/workflows/*.yml",
            "*.conf",
            "nginx.conf",
            "apache2.conf",
        ]

        cmd = [
            "nuclei",
            "-target", repo_path,
            "-tags", "config,exposure,misconfiguration",
            "-severity", "critical,high,medium",
            "-json",
            "-silent",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if not result.stdout:
            logger.info("Nuclei scan completed with no findings")
            return []

        issues = []
        for line in result.stdout.strip().split('\n'):
            if not line:
                continue

            try:
                finding = json.loads(line)

                issue = {
                    "title": finding.get("info", {}).get("name", "Nuclei finding"),
                    "description": finding.get("info", {}).get("description", ""),
                    "severity": finding.get("info", {}).get("severity", "medium"),
                    "file_path": finding.get("matched-at", repo_path),
                    "line_start": 1,
                    "line_end": 1,
                    "code_snippet": finding.get("extracted-results", [""])[0] if finding.get("extracted-results") else "",
                    "detected_by": "nuclei",
                    "category": "Configuration",
                    "template_id": finding.get("template-id", ""),
                    "matcher_name": finding.get("matcher-name", ""),
                    "cve": finding.get("info", {}).get("classification", {}).get("cve-id", [""])[0] if finding.get("info", {}).get("classification", {}).get("cve-id") else None,
                    "owasp_category": "A05",  # Security Misconfiguration
                    "cwe": "CWE-16",  # Configuration
                }
                issues.append(issue)

            except json.JSONDecodeError:
                logger.warning(f"Failed to parse Nuclei output line: {line[:100]}")
                continue

        logger.info(f"Nuclei found {len(issues)} configuration issues")
        return issues

    except subprocess.TimeoutExpired:
        logger.error("Nuclei scan timed out")
        return []
    except FileNotFoundError:
        logger.warning("Nuclei binary not found")
        return []
    except Exception as e:
        logger.error(f"Nuclei scan failed: {str(e)}")
        return []
