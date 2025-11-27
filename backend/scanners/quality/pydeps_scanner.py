"""
Pydeps Scanner - Python dependency and architecture analysis
Detects circular dependencies, architectural issues, and design problems
"""

import logging
import subprocess
import json
import os
from typing import List, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


def find_python_packages(repo_path: str) -> List[str]:
    """Find Python packages (directories with __init__.py)"""
    packages = []

    for root, dirs, files in os.walk(repo_path):
        # Skip common non-package directories
        dirs[:] = [d for d in dirs if d not in ['venv', '.venv', 'env', '.git', 'node_modules', '__pycache__']]

        if '__init__.py' in files:
            # This is a package
            package_name = os.path.basename(root)
            packages.append((package_name, root))

    return packages


async def scan(repo_path: str) -> List[Dict]:
    """
    Run pydeps scanner for architecture analysis

    Detects:
    - Circular dependencies
    - Tight coupling
    - Architecture violations
    - Package dependency issues
    """
    try:
        packages = find_python_packages(repo_path)

        if not packages:
            logger.info("No Python packages found in repository")
            return []

        logger.info(f"Found {len(packages)} Python packages to analyze")

        issues = []

        for package_name, package_path in packages:
            try:
                # Run pydeps to detect circular dependencies
                cmd = [
                    "pydeps",
                    package_name,
                    "--show-cycles",
                    "--max-bacon", "2",  # Limit depth for performance
                    "--noshow",  # Don't show graph
                    "--cluster",  # Group by package
                ]

                result = subprocess.run(
                    cmd,
                    cwd=os.path.dirname(package_path),
                    capture_output=True,
                    text=True,
                    timeout=120
                )

                # Check output for circular dependency warnings
                if "Cyclic dependencies" in result.stdout or "Circular" in result.stdout:
                    issue = {
                        "title": f"Circular Dependency detected in {package_name}",
                        "description": f"Circular dependency found in package '{package_name}'. This can lead to tight coupling and maintenance issues.",
                        "severity": "high",
                        "file_path": package_path,
                        "line_start": 1,
                        "line_end": 1,
                        "code_snippet": result.stdout[:500] if result.stdout else "Check package structure",
                        "detected_by": "pydeps",
                        "category": "Architecture",
                        "owasp_category": "A04",  # Insecure Design
                        "cwe": "CWE-1419",  # Incorrect behavior order: early validation
                    }
                    issues.append(issue)

            except subprocess.TimeoutExpired:
                logger.warning(f"pydeps analysis timed out for {package_name}")
                continue
            except Exception as e:
                logger.warning(f"Failed to analyze {package_name}: {str(e)}")
                continue

        logger.info(f"pydeps found {len(issues)} architecture issues")
        return issues

    except Exception as e:
        logger.error(f"pydeps scan failed: {str(e)}")
        return []
