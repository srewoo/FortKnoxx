"""
Pyre Scanner - Python Type Checker by Meta
Catches type-related security vulnerabilities in Python code
"""

import logging
import subprocess
import json
import os
from typing import List, Dict

logger = logging.getLogger(__name__)


async def scan(repo_path: str) -> List[Dict]:
    """
    Run Pyre type checker for Python type safety issues

    Pyre detects:
    - Type errors that could lead to runtime crashes
    - Taint analysis (data flow security)
    - Type confusion vulnerabilities
    - Incorrect API usage
    - Missing type annotations on security-critical code
    """
    try:
        # Check if pyre is installed
        if not _is_pyre_installed():
            logger.warning("Pyre not found, skipping scan. Install: pip install pyre-check")
            return []

        # Check if there are Python files
        if not _has_python_files(repo_path):
            logger.info("No Python files found in repository")
            return []

        issues = []

        # Run Pyre check
        check_issues = await _run_pyre_check(repo_path)
        issues.extend(check_issues)

        logger.info(f"Pyre found {len(issues)} Python type issues")
        return issues

    except Exception as e:
        logger.error(f"Pyre scan failed: {str(e)}")
        return []


async def _run_pyre_check(repo_path: str) -> List[Dict]:
    """Run Pyre type checking"""
    issues = []

    try:
        # Initialize Pyre if needed (creates .pyre_configuration)
        pyre_config = os.path.join(repo_path, ".pyre_configuration")
        if not os.path.exists(pyre_config):
            # Create minimal config
            _create_pyre_config(repo_path)

        cmd = [
            "pyre",
            "--noninteractive",
            "--output=json",
            "check"
        ]

        result = subprocess.run(
            cmd,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse JSON output (may be in stderr or stdout depending on version)
        output = result.stdout or result.stderr

        if not output:
            return []

        # Pyre outputs one JSON object per line
        for line in output.strip().split('\n'):
            if not line.strip():
                continue

            try:
                errors = json.loads(line)

                # Handle both array and single object formats
                if isinstance(errors, list):
                    for error in errors:
                        issue = _parse_pyre_error(error, repo_path)
                        if issue:
                            issues.append(issue)
                elif isinstance(errors, dict):
                    issue = _parse_pyre_error(errors, repo_path)
                    if issue:
                        issues.append(issue)

            except json.JSONDecodeError:
                continue

    except subprocess.TimeoutExpired:
        logger.warning("Pyre check timed out")
    except Exception as e:
        logger.debug(f"Pyre check error: {str(e)}")

    return issues


def _parse_pyre_error(error: Dict, repo_path: str) -> Dict:
    """Parse a Pyre error into standardized format"""
    if not isinstance(error, dict):
        return None

    # Get location info
    path = error.get("path", "")
    line = error.get("line", 0)
    column = error.get("column", 0)

    # Get error details
    description = error.get("description", "")
    code = error.get("code", 0)
    name = error.get("name", "Type Error")

    # Determine severity based on error type
    severity = _get_severity_from_error(code, name, description)

    # Build full file path
    file_path = os.path.join(repo_path, path) if path and not path.startswith('/') else path

    return {
        "title": f"Python Type: {name}",
        "description": description,
        "severity": severity,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "column": column,
        "detected_by": "pyre",
        "category": "Python Type Safety",
        "error_code": code,
        "owasp_category": _get_owasp_category(name, description),
        "cwe": _get_cwe(name, description),
    }


def _is_pyre_installed() -> bool:
    """Check if Pyre is installed"""
    try:
        result = subprocess.run(
            ["pyre", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _has_python_files(repo_path: str) -> bool:
    """Check if repository contains Python files"""
    for root, _, files in os.walk(repo_path):
        # Skip hidden directories and common non-source dirs
        if any(skip in root for skip in ['.git', 'node_modules', '__pycache__', '.pyre', 'venv', '.venv']):
            continue
        for file in files:
            if file.endswith(".py"):
                return True
    return False


def _create_pyre_config(repo_path: str):
    """Create minimal Pyre configuration"""
    config = {
        "source_directories": ["."],
        "search_path": []
    }

    config_path = os.path.join(repo_path, ".pyre_configuration")
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        logger.debug(f"Could not create Pyre config: {str(e)}")


def _get_severity_from_error(code: int, name: str, description: str) -> str:
    """Determine severity based on error characteristics"""
    name_lower = name.lower()
    desc_lower = description.lower()

    # Critical: potential security issues
    if any(kw in desc_lower for kw in ['taint', 'unsafe', 'injection', 'remote', 'arbitrary']):
        return "critical"

    # High: serious type errors that could cause runtime issues
    if any(kw in desc_lower for kw in ['none', 'null', 'attribute', 'incompatible']):
        return "high"

    # Medium: type mismatches
    if any(kw in name_lower for kw in ['mismatch', 'expected', 'invalid']):
        return "medium"

    # Low: warnings and style issues
    return "low"


def _get_owasp_category(name: str, description: str) -> str:
    """Map Pyre error to OWASP category"""
    desc_lower = description.lower()

    if "taint" in desc_lower:
        return "A03"  # Injection
    elif "auth" in desc_lower or "password" in desc_lower:
        return "A07"  # Authentication Failures
    elif "crypto" in desc_lower:
        return "A02"  # Cryptographic Failures
    elif "file" in desc_lower or "path" in desc_lower:
        return "A01"  # Broken Access Control
    else:
        return "A04"  # Insecure Design


def _get_cwe(name: str, description: str) -> str:
    """Get CWE for Pyre errors"""
    desc_lower = description.lower()

    if "none" in desc_lower or "null" in desc_lower:
        return "CWE-476"  # NULL Pointer Dereference
    elif "type" in desc_lower and "mismatch" in desc_lower:
        return "CWE-843"  # Type Confusion
    elif "attribute" in desc_lower:
        return "CWE-824"  # Access of Uninitialized Pointer
    else:
        return ""
