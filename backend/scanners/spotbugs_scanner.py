"""
SpotBugs Scanner - Java Bytecode Static Analysis
Finds bugs in Java programs through bytecode analysis
"""

import logging
import subprocess
import os
import xml.etree.ElementTree as ET
from typing import List, Dict
import tempfile

logger = logging.getLogger(__name__)


async def scan(repo_path: str) -> List[Dict]:
    """
    Run SpotBugs scanner for Java security issues

    SpotBugs detects:
    - Security vulnerabilities (Find Security Bugs plugin)
    - Bad practices
    - Correctness issues
    - Performance issues
    - Malicious code vulnerabilities
    """
    try:
        # Check if spotbugs is installed
        if not _is_spotbugs_installed():
            logger.warning("SpotBugs not found, skipping scan. Install via brew or download from https://spotbugs.github.io/")
            return []

        # Find compiled Java files
        class_dirs = _find_class_directories(repo_path)
        if not class_dirs:
            logger.info("No compiled Java classes found. Build the project first or ensure .class files exist.")
            return []

        issues = []

        for class_dir in class_dirs:
            dir_issues = await _scan_directory(class_dir, repo_path)
            issues.extend(dir_issues)

        logger.info(f"SpotBugs found {len(issues)} Java issues")
        return issues

    except Exception as e:
        logger.error(f"SpotBugs scan failed: {str(e)}")
        return []


async def _scan_directory(class_dir: str, repo_path: str) -> List[Dict]:
    """Scan a directory of compiled Java classes"""
    issues = []

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            output_file = f.name

        cmd = [
            "spotbugs",
            "-textui",
            "-xml:withMessages",
            "-output", output_file,
            "-effort:max",
            "-low",  # Report all bugs including low priority
            class_dir
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse XML output
        if os.path.exists(output_file):
            issues = _parse_spotbugs_xml(output_file, repo_path)
            os.unlink(output_file)

    except subprocess.TimeoutExpired:
        logger.warning("SpotBugs scan timed out")
    except Exception as e:
        logger.error(f"SpotBugs directory scan error: {str(e)}")

    return issues


def _parse_spotbugs_xml(xml_file: str, repo_path: str) -> List[Dict]:
    """Parse SpotBugs XML output"""
    issues = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        for bug in root.findall(".//BugInstance"):
            bug_type = bug.get("type", "")
            priority = int(bug.get("priority", "2"))
            category = bug.get("category", "")

            # Get source location
            source_line = bug.find("SourceLine")
            file_path = ""
            line_start = 0
            line_end = 0

            if source_line is not None:
                source_path = source_line.get("sourcepath", "")
                if source_path:
                    file_path = _find_source_file(repo_path, source_path)
                line_start = int(source_line.get("start", "0"))
                line_end = int(source_line.get("end", line_start))

            # Get long description
            long_message = bug.find("LongMessage")
            description = long_message.text if long_message is not None else ""

            # Get short message
            short_message = bug.find("ShortMessage")
            title = short_message.text if short_message is not None else bug_type

            severity = _map_priority_to_severity(priority, category)

            issue = {
                "title": f"Java: {title}",
                "description": description,
                "severity": severity,
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "detected_by": "spotbugs",
                "category": f"Java {category}",
                "bug_type": bug_type,
                "owasp_category": _get_owasp_category(category, bug_type),
                "cwe": _get_cwe(bug_type),
            }
            issues.append(issue)

    except ET.ParseError as e:
        logger.error(f"Failed to parse SpotBugs XML: {str(e)}")
    except Exception as e:
        logger.error(f"Error processing SpotBugs output: {str(e)}")

    return issues


def _is_spotbugs_installed() -> bool:
    """Check if SpotBugs is installed"""
    try:
        result = subprocess.run(
            ["spotbugs", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _find_class_directories(repo_path: str) -> List[str]:
    """Find directories containing compiled Java classes"""
    class_dirs = set()

    # Common build output directories
    common_dirs = [
        "target/classes",
        "build/classes",
        "out/production",
        "bin"
    ]

    for common_dir in common_dirs:
        full_path = os.path.join(repo_path, common_dir)
        if os.path.exists(full_path):
            class_dirs.add(full_path)

    # Search for .class files
    for root, dirs, files in os.walk(repo_path):
        # Skip common non-source directories
        if any(skip in root for skip in ['.git', 'node_modules', '.idea', '.vscode']):
            continue

        for file in files:
            if file.endswith(".class"):
                class_dirs.add(root)
                break

    return list(class_dirs)


def _find_source_file(repo_path: str, source_path: str) -> str:
    """Find the actual source file path"""
    # Common source directories
    source_dirs = ["src/main/java", "src", "java"]

    for source_dir in source_dirs:
        full_path = os.path.join(repo_path, source_dir, source_path)
        if os.path.exists(full_path):
            return full_path

    # Search in repo
    for root, _, files in os.walk(repo_path):
        if source_path.split("/")[-1] in files:
            return os.path.join(root, source_path.split("/")[-1])

    return source_path


def _map_priority_to_severity(priority: int, category: str) -> str:
    """Map SpotBugs priority to severity"""
    # Security issues are always more severe
    if category == "SECURITY":
        if priority == 1:
            return "critical"
        elif priority == 2:
            return "high"
        else:
            return "medium"

    if priority == 1:
        return "high"
    elif priority == 2:
        return "medium"
    else:
        return "low"


def _get_owasp_category(category: str, bug_type: str) -> str:
    """Map SpotBugs category/bug type to OWASP category"""
    bug_type_lower = bug_type.lower()

    if "sql" in bug_type_lower or "injection" in bug_type_lower:
        return "A03"  # Injection
    elif "xss" in bug_type_lower or "script" in bug_type_lower:
        return "A03"  # Injection
    elif "crypto" in bug_type_lower or "cipher" in bug_type_lower or "random" in bug_type_lower:
        return "A02"  # Cryptographic Failures
    elif "auth" in bug_type_lower or "password" in bug_type_lower:
        return "A07"  # Authentication Failures
    elif "path" in bug_type_lower or "file" in bug_type_lower:
        return "A01"  # Broken Access Control
    elif category == "SECURITY":
        return "A03"  # Default security to Injection
    else:
        return "A04"  # Insecure Design


def _get_cwe(bug_type: str) -> str:
    """Get CWE ID for common SpotBugs bug types"""
    cwe_mapping = {
        "SQL_INJECTION": "CWE-89",
        "XSS": "CWE-79",
        "PATH_TRAVERSAL": "CWE-22",
        "COMMAND_INJECTION": "CWE-78",
        "WEAK_RANDOM": "CWE-330",
        "HARD_CODE_PASSWORD": "CWE-259",
        "INSECURE_COOKIE": "CWE-614",
        "XXE": "CWE-611",
        "LDAP_INJECTION": "CWE-90",
        "XPATH_INJECTION": "CWE-643",
    }

    for pattern, cwe in cwe_mapping.items():
        if pattern.lower() in bug_type.lower():
            return cwe

    return ""
