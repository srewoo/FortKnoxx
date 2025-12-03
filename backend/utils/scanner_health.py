"""
Scanner Health Check Utility
Validates scanner availability at startup and provides health status reporting
"""

import shutil
import subprocess
import logging
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ScannerStatus(Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class ScannerHealthResult:
    """Result of a scanner health check"""
    name: str
    status: ScannerStatus
    version: Optional[str] = None
    error_message: Optional[str] = None
    is_external_tool: bool = False  # True for binary tools like grype, trivy


@dataclass
class ScannerHealthReport:
    """Aggregated health report for all scanners"""
    total_scanners: int = 0
    available_count: int = 0
    unavailable_count: int = 0
    disabled_count: int = 0
    error_count: int = 0
    scanners: List[ScannerHealthResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_scanner(self, result: ScannerHealthResult):
        self.scanners.append(result)
        self.total_scanners += 1
        if result.status == ScannerStatus.AVAILABLE:
            self.available_count += 1
        elif result.status == ScannerStatus.UNAVAILABLE:
            self.unavailable_count += 1
            if result.is_external_tool:
                self.warnings.append(
                    f"⚠️  {result.name}: External tool not installed. "
                    f"Install with: {get_install_instructions(result.name)}"
                )
        elif result.status == ScannerStatus.DISABLED:
            self.disabled_count += 1
        elif result.status == ScannerStatus.ERROR:
            self.error_count += 1

    def is_healthy(self) -> bool:
        """Returns True if at least some scanners are available"""
        return self.available_count > 0

    def get_summary(self) -> str:
        return (
            f"Scanner Health: {self.available_count}/{self.total_scanners} available, "
            f"{self.unavailable_count} unavailable, {self.disabled_count} disabled, "
            f"{self.error_count} errors"
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_scanners": self.total_scanners,
            "available_count": self.available_count,
            "unavailable_count": self.unavailable_count,
            "disabled_count": self.disabled_count,
            "error_count": self.error_count,
            "is_healthy": self.is_healthy(),
            "scanners": [
                {
                    "name": s.name,
                    "status": s.status.value,
                    "version": s.version,
                    "error_message": s.error_message,
                    "is_external_tool": s.is_external_tool
                }
                for s in self.scanners
            ],
            "warnings": self.warnings
        }


def get_install_instructions(scanner_name: str) -> str:
    """Get installation instructions for external tools"""
    instructions = {
        "grype": "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
        "trivy": "brew install trivy (macOS) or apt-get install trivy (Linux)",
        "codeql": "Download from https://github.com/github/codeql-cli-binaries/releases",
        "nuclei": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "snyk": "npm install -g snyk && snyk auth",
        "hadolint": "brew install hadolint (macOS) or apt-get install hadolint (Linux)",
        "shellcheck": "brew install shellcheck (macOS) or apt-get install shellcheck (Linux)",
        "gosec": "go install github.com/securego/gosec/v2/cmd/gosec@latest",
        "trufflehog": "pip install trufflehog or brew install trufflehog",
        "gitleaks": "brew install gitleaks (macOS) or go install github.com/gitleaks/gitleaks/v8@latest",
        "semgrep": "pip install semgrep",
        "checkov": "pip install checkov",
        "bandit": "pip install bandit",
        "eslint": "npm install -g eslint",
        "pylint": "pip install pylint",
        "flake8": "pip install flake8",
        "radon": "pip install radon",
        "syft": "curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin",
        "spotbugs": "Download from https://spotbugs.github.io/",
        "pyre": "pip install pyre-check",
        "horusec": "curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash",
    }
    return instructions.get(scanner_name, f"See {scanner_name} documentation for installation")


def check_binary_tool(name: str, version_flag: str = "--version") -> ScannerHealthResult:
    """Check if a binary tool is installed and get its version"""
    path = shutil.which(name)
    if not path:
        return ScannerHealthResult(
            name=name,
            status=ScannerStatus.UNAVAILABLE,
            error_message=f"{name} not found in PATH",
            is_external_tool=True
        )

    try:
        result = subprocess.run(
            [path, version_flag],
            capture_output=True,
            text=True,
            timeout=10
        )
        version = result.stdout.strip() or result.stderr.strip()
        # Extract just the first line for cleaner output
        version = version.split('\n')[0][:100] if version else "unknown"

        return ScannerHealthResult(
            name=name,
            status=ScannerStatus.AVAILABLE,
            version=version,
            is_external_tool=True
        )
    except subprocess.TimeoutExpired:
        return ScannerHealthResult(
            name=name,
            status=ScannerStatus.ERROR,
            error_message="Version check timed out",
            is_external_tool=True
        )
    except Exception as e:
        return ScannerHealthResult(
            name=name,
            status=ScannerStatus.ERROR,
            error_message=str(e),
            is_external_tool=True
        )


def check_python_module(name: str, import_name: str = None) -> ScannerHealthResult:
    """Check if a Python module is installed"""
    import_name = import_name or name
    try:
        module = __import__(import_name)
        version = getattr(module, '__version__', 'unknown')
        return ScannerHealthResult(
            name=name,
            status=ScannerStatus.AVAILABLE,
            version=version,
            is_external_tool=False
        )
    except ImportError as e:
        return ScannerHealthResult(
            name=name,
            status=ScannerStatus.UNAVAILABLE,
            error_message=str(e),
            is_external_tool=False
        )


async def check_all_scanners(scanner_settings=None) -> ScannerHealthReport:
    """
    Check availability of all scanners

    Args:
        scanner_settings: Optional settings object with enable_* flags

    Returns:
        ScannerHealthReport with status of all scanners
    """
    report = ScannerHealthReport()

    # External binary tools
    external_tools = [
        ("semgrep", "--version"),
        ("gitleaks", "version"),
        ("trivy", "--version"),
        ("checkov", "--version"),
        ("bandit", "--version"),
        ("trufflehog", "--version"),
        ("grype", "version"),
        ("eslint", "--version"),
        ("pylint", "--version"),
        ("flake8", "--version"),
        ("radon", "--version"),
        ("shellcheck", "--version"),
        ("hadolint", "--version"),
        ("nuclei", "-version"),
        ("snyk", "--version"),
        ("gosec", "--version"),
        ("syft", "version"),
        ("horusec", "version"),
    ]

    for tool_name, version_flag in external_tools:
        # Check if disabled in settings
        if scanner_settings:
            setting_name = f"enable_{tool_name}"
            if hasattr(scanner_settings, setting_name) and not getattr(scanner_settings, setting_name):
                report.add_scanner(ScannerHealthResult(
                    name=tool_name,
                    status=ScannerStatus.DISABLED,
                    is_external_tool=True
                ))
                continue

        result = check_binary_tool(tool_name, version_flag)
        report.add_scanner(result)

    # Python modules that provide scanners
    python_scanners = [
        ("pip-audit", "pip_audit"),
        ("sqlfluff", "sqlfluff"),
        ("pydeps", "pydeps"),
    ]

    for name, import_name in python_scanners:
        result = check_python_module(name, import_name)
        report.add_scanner(result)

    return report


def log_scanner_health_report(report: ScannerHealthReport):
    """Log the scanner health report with appropriate levels"""
    logger.info("=" * 60)
    logger.info("SCANNER HEALTH CHECK REPORT")
    logger.info("=" * 60)
    logger.info(report.get_summary())

    if report.unavailable_count > 0:
        logger.warning(f"⚠️  {report.unavailable_count} scanners are unavailable:")
        for scanner in report.scanners:
            if scanner.status == ScannerStatus.UNAVAILABLE:
                logger.warning(f"   - {scanner.name}: {scanner.error_message}")

    if report.warnings:
        logger.warning("Installation suggestions:")
        for warning in report.warnings:
            logger.warning(f"   {warning}")

    if report.error_count > 0:
        logger.error(f"❌ {report.error_count} scanners have errors:")
        for scanner in report.scanners:
            if scanner.status == ScannerStatus.ERROR:
                logger.error(f"   - {scanner.name}: {scanner.error_message}")

    available_scanners = [s.name for s in report.scanners if s.status == ScannerStatus.AVAILABLE]
    if available_scanners:
        logger.info(f"✅ Available scanners: {', '.join(available_scanners)}")

    logger.info("=" * 60)


@dataclass
class ScanExecutionReport:
    """Report tracking scanner execution during a scan"""
    scan_id: str
    scanners_attempted: int = 0
    scanners_succeeded: int = 0
    scanners_failed: int = 0
    scanners_skipped: int = 0
    scanner_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    total_findings: int = 0
    has_critical_failures: bool = False

    def record_scanner_result(
        self,
        scanner_name: str,
        success: bool,
        findings_count: int = 0,
        error_message: str = None,
        skipped: bool = False,
        skip_reason: str = None
    ):
        """Record the result of a scanner execution"""
        self.scanners_attempted += 1

        if skipped:
            self.scanners_skipped += 1
            status = "skipped"
        elif success:
            self.scanners_succeeded += 1
            self.total_findings += findings_count
            status = "success"
        else:
            self.scanners_failed += 1
            status = "failed"

        self.scanner_details[scanner_name] = {
            "status": status,
            "findings_count": findings_count,
            "error_message": error_message,
            "skip_reason": skip_reason
        }

    def get_failure_rate(self) -> float:
        """Get the percentage of scanners that failed"""
        if self.scanners_attempted == 0:
            return 0.0
        return (self.scanners_failed / self.scanners_attempted) * 100

    def should_warn_about_failures(self, threshold: float = 50.0) -> bool:
        """Check if failure rate exceeds threshold"""
        return self.get_failure_rate() > threshold

    def get_failed_scanners(self) -> List[str]:
        """Get list of failed scanner names"""
        return [
            name for name, details in self.scanner_details.items()
            if details["status"] == "failed"
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scanners_attempted": self.scanners_attempted,
            "scanners_succeeded": self.scanners_succeeded,
            "scanners_failed": self.scanners_failed,
            "scanners_skipped": self.scanners_skipped,
            "failure_rate_percent": round(self.get_failure_rate(), 1),
            "total_findings": self.total_findings,
            "has_critical_failures": self.has_critical_failures,
            "scanner_details": self.scanner_details,
            "failed_scanners": self.get_failed_scanners()
        }

    def get_summary_message(self) -> str:
        """Get a summary message for logging/display"""
        if self.scanners_failed == 0:
            return f"✅ All {self.scanners_succeeded} scanners completed successfully with {self.total_findings} findings"
        elif self.should_warn_about_failures():
            return (
                f"⚠️  WARNING: High scanner failure rate ({self.get_failure_rate():.0f}%)! "
                f"{self.scanners_succeeded}/{self.scanners_attempted} succeeded, "
                f"{self.scanners_failed} failed. Results may be incomplete. "
                f"Failed: {', '.join(self.get_failed_scanners())}"
            )
        else:
            return (
                f"⚠️  {self.scanners_succeeded}/{self.scanners_attempted} scanners completed, "
                f"{self.scanners_failed} failed. Failed: {', '.join(self.get_failed_scanners())}"
            )
