"""
Scan Limits Configuration
Handles large repository scanning with configurable limits for timeouts, file counts, and LLM tokens
"""

import os
import logging
import asyncio
from typing import List, Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from pathlib import Path
from functools import wraps
import time

logger = logging.getLogger(__name__)


@dataclass
class ScanLimits:
    """Configuration for scan limits to handle large repositories"""

    # File limits
    max_files_for_ai_scan: int = 500  # Maximum files to analyze with AI scanners
    max_file_size_kb: int = 500  # Skip files larger than this (likely minified/generated)
    max_total_repo_size_mb: int = 500  # Warn if repo exceeds this size

    # Timeout limits (in seconds)
    scanner_timeout: int = 300  # 5 minutes per scanner
    ai_scanner_timeout: int = 600  # 10 minutes for AI-powered scanners
    clone_timeout: int = 600  # 10 minutes for git clone
    total_scan_timeout: int = 3600  # 1 hour total

    # LLM limits
    max_vulnerabilities_for_ai_analysis: int = 100  # Max vulns to send to LLM
    llm_batch_size: int = 10  # Process vulns in batches
    llm_request_timeout: int = 60  # Timeout per LLM request
    max_code_snippet_chars: int = 500  # Truncate code snippets
    max_description_chars: int = 1000  # Truncate descriptions

    # Priority settings
    prioritize_security_files: bool = True  # Prioritize auth, config, API files
    skip_test_files_for_ai: bool = True  # Skip test files for AI analysis
    skip_vendor_dirs: bool = True  # Skip node_modules, vendor, etc.

    @classmethod
    def from_env(cls) -> "ScanLimits":
        """Load limits from environment variables with defaults"""
        return cls(
            max_files_for_ai_scan=int(os.getenv("SCAN_MAX_FILES_AI", "500")),
            max_file_size_kb=int(os.getenv("SCAN_MAX_FILE_SIZE_KB", "500")),
            max_total_repo_size_mb=int(os.getenv("SCAN_MAX_REPO_SIZE_MB", "500")),
            scanner_timeout=int(os.getenv("SCAN_SCANNER_TIMEOUT", "300")),
            ai_scanner_timeout=int(os.getenv("SCAN_AI_SCANNER_TIMEOUT", "600")),
            clone_timeout=int(os.getenv("SCAN_CLONE_TIMEOUT", "600")),
            total_scan_timeout=int(os.getenv("SCAN_TOTAL_TIMEOUT", "3600")),
            max_vulnerabilities_for_ai_analysis=int(os.getenv("SCAN_MAX_VULNS_AI", "100")),
            llm_batch_size=int(os.getenv("SCAN_LLM_BATCH_SIZE", "10")),
            llm_request_timeout=int(os.getenv("SCAN_LLM_REQUEST_TIMEOUT", "60")),
            max_code_snippet_chars=int(os.getenv("SCAN_MAX_SNIPPET_CHARS", "500")),
            max_description_chars=int(os.getenv("SCAN_MAX_DESC_CHARS", "1000")),
        )


@dataclass
class RepoStats:
    """Statistics about a repository for planning scan strategy"""
    total_files: int = 0
    total_size_mb: float = 0.0
    source_files: int = 0
    test_files: int = 0
    config_files: int = 0
    security_relevant_files: int = 0
    largest_file_kb: float = 0.0
    languages_detected: List[str] = field(default_factory=list)
    is_large_repo: bool = False
    estimated_scan_time_minutes: int = 0
    warnings: List[str] = field(default_factory=list)


class RepoAnalyzer:
    """Analyzes repository to determine optimal scan strategy"""

    # File extensions by category
    SOURCE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.c', '.cpp', '.h', '.hpp', '.cs', '.swift', '.kt', '.rs', '.scala'
    }

    TEST_PATTERNS = {'test', 'spec', '__test__', '__tests__', 'tests', '_test'}

    CONFIG_EXTENSIONS = {
        '.json', '.yaml', '.yml', '.toml', '.ini', '.env', '.conf', '.config'
    }

    SECURITY_PATTERNS = {
        'auth', 'login', 'password', 'secret', 'token', 'api', 'key', 'crypt',
        'session', 'oauth', 'jwt', 'permission', 'role', 'access', 'security'
    }

    SKIP_DIRS = {
        'node_modules', 'vendor', 'venv', '.venv', '__pycache__', '.git',
        'dist', 'build', 'out', '.next', 'coverage', '.cache', 'target'
    }

    def __init__(self, limits: ScanLimits):
        self.limits = limits

    def analyze_repo(self, repo_path: str) -> RepoStats:
        """Analyze repository and return statistics"""
        stats = RepoStats()
        path = Path(repo_path)

        if not path.exists():
            stats.warnings.append(f"Repository path does not exist: {repo_path}")
            return stats

        languages = set()

        for file_path in path.rglob('*'):
            if file_path.is_dir():
                continue

            # Skip vendor directories
            if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRS):
                continue

            try:
                file_size_kb = file_path.stat().st_size / 1024
                stats.total_files += 1
                stats.total_size_mb += file_size_kb / 1024

                if file_size_kb > stats.largest_file_kb:
                    stats.largest_file_kb = file_size_kb

                suffix = file_path.suffix.lower()
                name_lower = file_path.name.lower()
                path_lower = str(file_path).lower()

                # Categorize file
                if suffix in self.SOURCE_EXTENSIONS:
                    stats.source_files += 1

                    # Detect language
                    lang_map = {
                        '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
                        '.java': 'java', '.go': 'go', '.rb': 'ruby', '.php': 'php',
                        '.rs': 'rust', '.cs': 'csharp', '.swift': 'swift', '.kt': 'kotlin'
                    }
                    if suffix in lang_map:
                        languages.add(lang_map[suffix])

                if suffix in self.CONFIG_EXTENSIONS:
                    stats.config_files += 1

                # Check if test file
                if any(pattern in name_lower or pattern in path_lower for pattern in self.TEST_PATTERNS):
                    stats.test_files += 1

                # Check if security-relevant
                if any(pattern in name_lower or pattern in path_lower for pattern in self.SECURITY_PATTERNS):
                    stats.security_relevant_files += 1

            except (OSError, PermissionError) as e:
                logger.debug(f"Could not analyze file {file_path}: {e}")
                continue

        stats.languages_detected = list(languages)

        # Determine if large repo
        stats.is_large_repo = (
            stats.total_files > 1000 or
            stats.total_size_mb > self.limits.max_total_repo_size_mb or
            stats.source_files > self.limits.max_files_for_ai_scan
        )

        # Estimate scan time (rough heuristic)
        base_time = 2  # 2 minutes base
        file_time = stats.source_files * 0.01  # 0.01 minutes per file
        ai_time = min(stats.source_files, self.limits.max_files_for_ai_scan) * 0.02  # AI analysis
        stats.estimated_scan_time_minutes = int(base_time + file_time + ai_time)

        # Generate warnings
        if stats.is_large_repo:
            stats.warnings.append(
                f"Large repository detected: {stats.total_files} files, {stats.total_size_mb:.1f}MB. "
                f"AI analysis will be limited to {self.limits.max_files_for_ai_scan} priority files."
            )

        if stats.largest_file_kb > self.limits.max_file_size_kb:
            stats.warnings.append(
                f"Some files exceed {self.limits.max_file_size_kb}KB and will be skipped for AI analysis."
            )

        return stats

    def get_priority_files(self, repo_path: str, max_files: int = None) -> List[str]:
        """
        Get list of priority files for AI analysis
        Prioritizes security-relevant files, then configs, then other source files
        """
        if max_files is None:
            max_files = self.limits.max_files_for_ai_scan

        path = Path(repo_path)
        priority_files = []
        security_files = []
        config_files = []
        source_files = []

        for file_path in path.rglob('*'):
            if file_path.is_dir():
                continue

            # Skip vendor directories
            if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRS):
                continue

            try:
                file_size_kb = file_path.stat().st_size / 1024

                # Skip large files
                if file_size_kb > self.limits.max_file_size_kb:
                    continue

                suffix = file_path.suffix.lower()
                name_lower = file_path.name.lower()
                path_lower = str(file_path).lower()

                # Skip test files if configured
                if self.limits.skip_test_files_for_ai:
                    if any(pattern in name_lower or pattern in path_lower for pattern in self.TEST_PATTERNS):
                        continue

                str_path = str(file_path)

                # Categorize by priority
                if any(pattern in name_lower or pattern in path_lower for pattern in self.SECURITY_PATTERNS):
                    security_files.append(str_path)
                elif suffix in self.CONFIG_EXTENSIONS:
                    config_files.append(str_path)
                elif suffix in self.SOURCE_EXTENSIONS:
                    source_files.append(str_path)

            except (OSError, PermissionError):
                continue

        # Build priority list: security first, then config, then source
        priority_files.extend(security_files[:max_files])
        remaining = max_files - len(priority_files)

        if remaining > 0:
            priority_files.extend(config_files[:remaining])
            remaining = max_files - len(priority_files)

        if remaining > 0:
            priority_files.extend(source_files[:remaining])

        logger.info(
            f"Selected {len(priority_files)} priority files for AI analysis "
            f"({len(security_files)} security, {len(config_files)} config, {len(source_files)} source)"
        )

        return priority_files[:max_files]


def with_timeout(timeout_seconds: int):
    """Decorator to add timeout to async functions"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                func_name = func.__name__
                logger.warning(f"{func_name} timed out after {timeout_seconds}s")
                return None
        return wrapper
    return decorator


async def run_with_timeout(
    coro,
    timeout_seconds: int,
    name: str = "operation",
    default_return=None
):
    """Run a coroutine with timeout and return default on timeout"""
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(f"{name} timed out after {timeout_seconds}s")
        return default_return
    except Exception as e:
        logger.error(f"{name} failed: {str(e)}")
        return default_return


class LLMBatcher:
    """Handles batched LLM processing for large numbers of vulnerabilities"""

    def __init__(self, limits: ScanLimits):
        self.limits = limits

    def prioritize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Prioritize vulnerabilities for LLM analysis
        Returns top N most critical vulnerabilities
        """
        if len(vulnerabilities) <= self.limits.max_vulnerabilities_for_ai_analysis:
            return vulnerabilities

        # Sort by severity priority
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

        def get_priority(vuln):
            severity = vuln.get('severity', 'medium')
            if isinstance(severity, list):
                severity = severity[0] if severity else 'medium'
            return severity_order.get(severity.lower(), 2)

        sorted_vulns = sorted(vulnerabilities, key=get_priority)

        selected = sorted_vulns[:self.limits.max_vulnerabilities_for_ai_analysis]

        logger.info(
            f"Prioritized {len(selected)}/{len(vulnerabilities)} vulnerabilities for AI analysis "
            f"(skipped {len(vulnerabilities) - len(selected)} lower priority)"
        )

        return selected

    def create_batches(self, vulnerabilities: List[Dict]) -> List[List[Dict]]:
        """Split vulnerabilities into batches for LLM processing"""
        batches = []
        for i in range(0, len(vulnerabilities), self.limits.llm_batch_size):
            batch = vulnerabilities[i:i + self.limits.llm_batch_size]
            batches.append(batch)
        return batches

    def truncate_for_llm(self, vulnerability: Dict) -> Dict:
        """Truncate vulnerability data to fit within LLM token limits"""
        truncated = vulnerability.copy()

        # Truncate code snippet
        if 'code_snippet' in truncated and truncated['code_snippet']:
            snippet = str(truncated['code_snippet'])
            if len(snippet) > self.limits.max_code_snippet_chars:
                truncated['code_snippet'] = snippet[:self.limits.max_code_snippet_chars] + '...[truncated]'

        # Truncate description
        if 'description' in truncated and truncated['description']:
            desc = str(truncated['description'])
            if len(desc) > self.limits.max_description_chars:
                truncated['description'] = desc[:self.limits.max_description_chars] + '...[truncated]'

        return truncated

    async def process_batch(
        self,
        batch: List[Dict],
        processor: Callable[[Dict], Any],
        timeout_per_item: int = None
    ) -> List[Any]:
        """Process a batch of vulnerabilities with individual timeouts"""
        if timeout_per_item is None:
            timeout_per_item = self.limits.llm_request_timeout

        results = []
        for vuln in batch:
            truncated = self.truncate_for_llm(vuln)
            try:
                result = await asyncio.wait_for(
                    processor(truncated),
                    timeout=timeout_per_item
                )
                results.append(result)
            except asyncio.TimeoutError:
                logger.warning(f"LLM processing timed out for vulnerability: {vuln.get('title', 'unknown')}")
                results.append(None)
            except Exception as e:
                logger.error(f"LLM processing failed: {str(e)}")
                results.append(None)

        return results


class ScanProgress:
    """Track and report scan progress"""

    def __init__(self, total_scanners: int = 0):
        self.total_scanners = total_scanners
        self.completed_scanners = 0
        self.current_scanner = ""
        self.start_time = time.time()
        self.scanner_times: Dict[str, float] = {}
        self.scanner_results: Dict[str, int] = {}
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def start_scanner(self, scanner_name: str):
        """Mark a scanner as started"""
        self.current_scanner = scanner_name
        self.scanner_times[scanner_name] = time.time()
        logger.info(f"Starting scanner: {scanner_name} ({self.completed_scanners + 1}/{self.total_scanners})")

    def complete_scanner(self, scanner_name: str, result_count: int = 0, error: str = None):
        """Mark a scanner as completed"""
        elapsed = time.time() - self.scanner_times.get(scanner_name, time.time())
        self.scanner_times[scanner_name] = elapsed
        self.scanner_results[scanner_name] = result_count
        self.completed_scanners += 1

        if error:
            self.errors.append(f"{scanner_name}: {error}")
            logger.error(f"Scanner {scanner_name} failed: {error}")
        else:
            logger.info(f"Scanner {scanner_name} completed: {result_count} findings in {elapsed:.1f}s")

    def add_warning(self, warning: str):
        """Add a warning message"""
        self.warnings.append(warning)
        logger.warning(warning)

    def get_progress(self) -> Dict:
        """Get current progress as a dictionary"""
        elapsed = time.time() - self.start_time
        return {
            "completed_scanners": self.completed_scanners,
            "total_scanners": self.total_scanners,
            "current_scanner": self.current_scanner,
            "elapsed_seconds": elapsed,
            "progress_percent": (self.completed_scanners / self.total_scanners * 100) if self.total_scanners > 0 else 0,
            "scanner_results": self.scanner_results,
            "warnings": self.warnings,
            "errors": self.errors
        }

    def get_summary(self) -> str:
        """Get a summary string"""
        elapsed = time.time() - self.start_time
        total_findings = sum(self.scanner_results.values())
        return (
            f"Scan completed in {elapsed:.1f}s: "
            f"{self.completed_scanners}/{self.total_scanners} scanners, "
            f"{total_findings} total findings, "
            f"{len(self.errors)} errors, {len(self.warnings)} warnings"
        )


# Global default limits instance
DEFAULT_LIMITS = ScanLimits.from_env()


def get_scan_limits() -> ScanLimits:
    """Get the default scan limits (can be overridden by env vars)"""
    return DEFAULT_LIMITS
