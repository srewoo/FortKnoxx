"""
Cargo Audit Scanner - Rust Security Advisory Database
Audits Cargo.lock files for crates with security vulnerabilities
"""

import logging
import subprocess
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)


async def scan(repo_path: str) -> List[Dict]:
    """
    Run cargo-audit scanner for Rust dependency vulnerabilities

    Cargo-audit checks:
    - RustSec Advisory Database vulnerabilities
    - Unmaintained crates
    - Yanked crates
    - Security advisories
    """
    try:
        # Check if cargo-audit is installed
        if not _is_cargo_audit_installed():
            logger.warning("cargo-audit not found, skipping scan. Install: cargo install cargo-audit")
            return []

        # Check if there's a Cargo.lock file
        cargo_lock = os.path.join(repo_path, "Cargo.lock")
        if not os.path.exists(cargo_lock):
            # Try to find Cargo.lock in subdirectories
            cargo_lock = _find_cargo_lock(repo_path)
            if not cargo_lock:
                logger.info("No Cargo.lock found in repository")
                return []

        cmd = [
            "cargo", "audit",
            "--json",
            "--file", cargo_lock
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        # cargo-audit returns non-zero when vulnerabilities found
        if not result.stdout:
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.warning("Failed to parse cargo-audit output")
            return []

        issues = []

        # Parse vulnerabilities
        vulnerabilities = data.get("vulnerabilities", {})

        for vuln in vulnerabilities.get("list", []):
            advisory = vuln.get("advisory", {})
            package = vuln.get("package", {})

            severity = _map_severity(advisory.get("severity", "medium"))

            # Build description
            description = advisory.get("description", "")
            if advisory.get("url"):
                description += f"\n\nReference: {advisory['url']}"
            if advisory.get("patched_versions"):
                description += f"\nPatched versions: {', '.join(advisory['patched_versions'])}"

            issue = {
                "title": f"Rust Vulnerability: {advisory.get('id', 'Unknown')} in {package.get('name', 'Unknown')}",
                "description": description,
                "severity": severity,
                "file_path": cargo_lock,
                "line_start": 0,
                "line_end": 0,
                "detected_by": "cargo-audit",
                "category": "Rust Security",
                "advisory_id": advisory.get("id", ""),
                "cve": advisory.get("aliases", [""])[0] if advisory.get("aliases") else "",
                "owasp_category": "A06",  # Vulnerable and Outdated Components
                "package_name": package.get("name", ""),
                "package_version": package.get("version", ""),
                "patched_versions": advisory.get("patched_versions", []),
            }
            issues.append(issue)

        # Parse warnings (unmaintained, yanked crates)
        warnings = data.get("warnings", {})

        for warning in warnings.get("unmaintained", []):
            advisory = warning.get("advisory", {})
            package = warning.get("package", {})

            issue = {
                "title": f"Unmaintained Crate: {package.get('name', 'Unknown')}",
                "description": f"{advisory.get('description', 'This crate is unmaintained.')}\n\nConsider finding an alternative.",
                "severity": "low",
                "file_path": cargo_lock,
                "line_start": 0,
                "line_end": 0,
                "detected_by": "cargo-audit",
                "category": "Rust Security",
                "owasp_category": "A06",
                "package_name": package.get("name", ""),
                "package_version": package.get("version", ""),
            }
            issues.append(issue)

        for warning in warnings.get("yanked", []):
            package = warning.get("package", {})

            issue = {
                "title": f"Yanked Crate: {package.get('name', 'Unknown')}@{package.get('version', '')}",
                "description": "This crate version has been yanked from crates.io. Update to a newer version.",
                "severity": "medium",
                "file_path": cargo_lock,
                "line_start": 0,
                "line_end": 0,
                "detected_by": "cargo-audit",
                "category": "Rust Security",
                "owasp_category": "A06",
                "package_name": package.get("name", ""),
                "package_version": package.get("version", ""),
            }
            issues.append(issue)

        logger.info(f"cargo-audit found {len(issues)} Rust security issues")
        return issues

    except subprocess.TimeoutExpired:
        logger.warning("cargo-audit scan timed out")
        return []
    except Exception as e:
        logger.error(f"cargo-audit scan failed: {str(e)}")
        return []


def _is_cargo_audit_installed() -> bool:
    """Check if cargo-audit is installed"""
    try:
        result = subprocess.run(
            ["cargo", "audit", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _find_cargo_lock(repo_path: str) -> str:
    """Find Cargo.lock in repository"""
    for root, _, files in os.walk(repo_path):
        if "Cargo.lock" in files:
            return os.path.join(root, "Cargo.lock")
    return ""


def _map_severity(severity: str) -> str:
    """Map RustSec severity to standard levels"""
    severity_lower = severity.lower() if severity else "medium"
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "low"
    }
    return mapping.get(severity_lower, "medium")
