# Load environment variables FIRST before any other imports
from pathlib import Path
from dotenv import load_dotenv
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone
import asyncio
import json
import subprocess
import shutil
from contextlib import asynccontextmanager

# Import security scanners
from scanners.bandit_scanner import BanditScanner
from scanners.trufflehog_scanner import TruffleHogScanner
from scanners.grype_scanner import GrypeScanner
from scanners.eslint_scanner import ESLintSecurityScanner
from scanners import nuclei_scanner

# Import enhanced scanners (High Value Additions)
from scanners import snyk_scanner
from scanners import gosec_scanner
# DISABLED: Rust-specific, not needed for most projects
# from scanners import cargo_audit_scanner
from scanners import spotbugs_scanner
from scanners import pyre_scanner
from scanners import zap_scanner  # Static web security scanner
from scanners import zap_dast_scanner  # Dynamic DAST scanner (Docker-based)
from scanners import api_fuzzer_scanner  # Dedicated API security fuzzer
from scanners import horusec_scanner

# Import quality scanners
from scanners.quality.pylint_scanner import PylintScanner
from scanners.quality.flake8_scanner import Flake8Scanner
from scanners.quality.radon_scanner import RadonScanner
from scanners.quality.shellcheck_scanner import ShellCheckScanner
from scanners.quality.hadolint_scanner import HadolintScanner
from scanners.quality import sqlfluff_scanner
from scanners.quality import pydeps_scanner

# Import compliance scanners
from scanners.compliance.pip_audit_scanner import PipAuditScanner
from scanners.compliance.npm_audit_scanner import NpmAuditScanner
from scanners.compliance.syft_scanner import SyftScanner

# Import context analyzer
from analysis.context_analyzer import ContextAnalyzer

# Import false positive filter
from utils.false_positive_filter import filter_false_positives, get_filter_stats

# Import scan limits for large repository handling
from utils.scan_limits import (
    ScanLimits, RepoAnalyzer, RepoStats, LLMBatcher, ScanProgress,
    get_scan_limits, run_with_timeout
)

# Import LLM orchestrator
from llm.orchestrator import LLMOrchestrator

# Import AI-powered security engines (with graceful fallback for ML components)
ML_DETECTOR_AVAILABLE = False
FLOW_ANALYZER_AVAILABLE = False
ML_COMPONENTS_AVAILABLE = False

try:
    from engines.zero_day.ml_detector import MLAnomalyDetector
    ML_DETECTOR_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Zero-Day ML Detector not available: {e}")
    MLAnomalyDetector = None

try:
    from engines.logic.flow_analyzer import FlowAnalyzer
    from engines.logic.rule_engine import LogicRuleEngine
    FLOW_ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  Business Logic Analyzer not available: {e}")
    FlowAnalyzer = None
    LogicRuleEngine = None

# These don't require numpy/ML dependencies
from engines.llm_security.surface_discovery import LLMSurfaceDiscovery
from engines.llm_security.payload_generator import AdversarialPayloadGenerator
from engines.llm_security.adversarial_tester import AdversarialTester
from engines.auth_scanner.static_analyzer import AuthStaticAnalyzer

ML_COMPONENTS_AVAILABLE = ML_DETECTOR_AVAILABLE or FLOW_ANALYZER_AVAILABLE
if not ML_COMPONENTS_AVAILABLE:
    print("⚠️  ML/AI components unavailable. Core security scanners will still function normally.")

# Import settings manager
from settings.manager import settings_manager
from settings.git_integration import git_integration_service
from settings.models import (
    UpdateAPIKeysRequest, SettingsResponse, GitProvider,
    ConnectGitIntegrationRequest, AddRepositoryRequest, GitIntegrationStatus,
    UpdateAIScannerSettingsRequest, AIScannerSettings,
    ScannerSettings, UpdateScannerSettingsRequest
)
from secrets_vault.encryption import encryption_service

# NOTE: ROOT_DIR and load_dotenv already called at top of file (lines 1-5)

# Import scanner health utilities
from utils.scanner_health import (
    check_all_scanners, log_scanner_health_report, ScanExecutionReport,
    ScannerHealthReport
)

# MongoDB connection with validation
def get_required_env(key: str, description: str) -> str:
    """Get required environment variable with helpful error message"""
    value = os.environ.get(key)
    if not value:
        raise EnvironmentError(
            f"Required environment variable '{key}' ({description}) is not set. "
            f"Please check your .env file or environment configuration."
        )
    return value

try:
    mongo_url = get_required_env('MONGO_URL', 'MongoDB connection string')
    db_name = get_required_env('DB_NAME', 'MongoDB database name')
    client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=5000)
    db = client[db_name]
except EnvironmentError as e:
    print(f"❌ Configuration Error: {e}")
    raise SystemExit(1)
except Exception as e:
    print(f"❌ Failed to initialize MongoDB client: {e}")
    raise SystemExit(1)

# Global scanner health report (populated at startup)
_scanner_health_report: Optional[ScannerHealthReport] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _scanner_health_report

    # Validate MongoDB connection before proceeding
    logger.info("Validating MongoDB connection...")
    try:
        await client.admin.command('ping')
        logger.info("✅ MongoDB connection validated successfully")
    except Exception as e:
        logger.error(f"❌ MongoDB connection failed: {e}")
        logger.error("Please check your MONGO_URL environment variable and ensure MongoDB is running")
        raise SystemExit(1)

    # Startup: Initialize settings manager
    settings_manager.set_db(db)
    settings_manager.set_encryption(encryption_service)
    logger.info("Settings manager initialized")

    # Initialize Git integration service
    git_integration_service.set_db(db)
    git_integration_service.set_encryption(encryption_service)
    logger.info("Git integration service initialized")

    # Run scanner health check at startup
    logger.info("Running scanner health check...")
    try:
        scanner_settings = await settings_manager.get_scanner_settings()
        _scanner_health_report = await check_all_scanners(scanner_settings)
        log_scanner_health_report(_scanner_health_report)

        if _scanner_health_report.unavailable_count > 0:
            logger.warning(
                f"⚠️  {_scanner_health_report.unavailable_count} scanners are unavailable. "
                "Scans will still run but may have incomplete coverage."
            )
    except Exception as e:
        logger.warning(f"Scanner health check failed: {e}")

    # Initialize GNN Model Manager (loads pre-trained model, does NOT train on startup)
    model_manager = None
    update_service = None
    try:
        from engines.zero_day.model_manager import get_model_manager, ModelManagerConfig
        model_config = ModelManagerConfig(
            enable_background_finetune=False,  # Disabled by default - opt-in only
            finetune_at_startup=False,  # Never train on startup
            collect_feedback=True,  # Collect feedback for future improvements
        )
        model_manager = await get_model_manager(model_config)
        await model_manager.initialize()
        logger.info(f"GNN Model Manager initialized: {model_manager.get_status()}")

        # Initialize Model Update Service (checks for new model versions periodically)
        from engines.zero_day.model_updater import get_update_service, UpdateConfig, UpdateSource
        update_config = UpdateConfig(
            enabled=os.environ.get('MODEL_UPDATE_ENABLED', 'false').lower() == 'true',
            source=UpdateSource.HTTP,
            source_url=os.environ.get('MODEL_UPDATE_URL', ''),
            check_interval_hours=int(os.environ.get('MODEL_UPDATE_INTERVAL_HOURS', '24')),
            notify_on_update=True,
            webhook_url=os.environ.get('MODEL_UPDATE_WEBHOOK', None),
        )
        update_service = await get_update_service(update_config)

        # Register callback to reload model after update
        async def on_model_updated(version):
            logger.info(f"Model updated to version {version.version}, reloading...")
            await model_manager.initialize()

        update_service.on_update(on_model_updated)

        # Start background update scheduler
        await update_service.start()
        logger.info(f"Model Update Service initialized: {update_service.get_status()}")

    except Exception as e:
        logger.warning(f"GNN Model Manager initialization skipped: {e}")

    yield

    # Shutdown: Stop update service and close MongoDB connection
    if update_service:
        await update_service.stop()
    client.close()

# Create the main app without a prefix
app = FastAPI(lifespan=lifespan)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# OWASP Top 10 Mapping
OWASP_CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery"
}

# Define Models
class Repository(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    url: str
    access_token: Optional[str] = None  # Optional - Git Integration repos use integration token
    branch: str = "main"
    last_scan: Optional[str] = None
    scan_status: str = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Security metrics from latest scan
    security_score: Optional[int] = None
    vulnerabilities_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    # Git Integration fields
    provider: Optional[str] = None
    full_name: Optional[str] = None

class RepositoryCreate(BaseModel):
    name: str
    url: str
    access_token: str
    branch: str = "main"

class Vulnerability(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_id: str
    scan_id: str
    file_path: str
    line_start: int
    line_end: int
    severity: str
    category: str
    owasp_category: str
    title: str
    description: str
    code_snippet: Optional[str] = ""
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    fix_recommendation: Optional[str] = None
    detected_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator('cwe', mode='before')
    @classmethod
    def normalize_cwe(cls, v):
        """Convert CWE list to string if needed"""
        if isinstance(v, list):
            return v[0] if v else None
        return v

    @field_validator('severity', mode='before')
    @classmethod
    def normalize_severity(cls, v):
        """Convert severity list to string if needed"""
        if isinstance(v, list):
            return v[0] if v else "medium"
        return v

    @field_validator('file_path', mode='before')
    @classmethod
    def normalize_file_path(cls, v):
        """Convert file_path list to string if needed"""
        if isinstance(v, list):
            return v[0] if v else ""
        return v

class Scan(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    repo_id: str
    status: str = "pending"
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    total_files: int = 0
    vulnerabilities_count: int = 0
    quality_issues_count: int = 0
    compliance_issues_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    security_score: int = 0
    quality_score: int = 100
    compliance_score: int = 100
    scan_results: Dict[str, Any] = Field(default_factory=dict)

class AIFixRequest(BaseModel):
    vulnerability_id: str
    provider: str = "anthropic"
    model: str = "claude-3-7-sonnet-20250219"  # Default to Claude Sonnet 3.7

class ReportRequest(BaseModel):
    repo_id: str
    scan_id: str
    format: str = "json"

# NOTE: APIKeysUpdate removed - duplicate of UpdateAPIKeysRequest from settings.models

# Utility Functions
def get_secure_clone_dir(repo_id: str) -> Optional[str]:
    """
    Get a secure clone directory path with restricted permissions.
    Returns None if repo_id is invalid.
    """
    # Validate repo_id to prevent path traversal
    if not repo_id or '/' in repo_id or '\\' in repo_id or '..' in repo_id:
        return None

    # Use a more secure base directory with restricted permissions
    base_dir = os.environ.get('FORTKNOXX_CLONE_DIR', '/tmp/fortknoxx_repos')

    # Create base directory with restricted permissions if it doesn't exist
    if not os.path.exists(base_dir):
        os.makedirs(base_dir, mode=0o700, exist_ok=True)

    return os.path.join(base_dir, repo_id)


async def clone_repository(repo_url: str, token: str, branch: str, repo_id: str) -> Optional[str]:
    """Clone repository to local directory with automatic branch detection"""
    try:
        # Get secure clone directory
        clone_dir = get_secure_clone_dir(repo_id)
        if not clone_dir:
            logger.error(f"Invalid repo_id: {repo_id}")
            return None

        if os.path.exists(clone_dir):
            shutil.rmtree(clone_dir)

        os.makedirs(clone_dir, exist_ok=True)

        # Parse URL and inject token
        if "github.com" in repo_url:
            auth_url = repo_url.replace("https://", f"https://{token}@")
        elif "gitlab.com" in repo_url:
            auth_url = repo_url.replace("https://", f"https://oauth2:{token}@")
        else:
            auth_url = repo_url

        # Try to detect available branches
        branches_to_try = [branch, "main", "master", "develop", "dev"]
        # Remove duplicates while preserving order
        seen = set()
        branches_to_try = [b for b in branches_to_try if not (b in seen or seen.add(b))]

        last_error = None
        for branch_name in branches_to_try:
            cmd = ["git", "clone", "--depth", "1", "-b", branch_name, auth_url, clone_dir]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                if branch_name != branch:
                    logger.warning(f"Branch '{branch}' not found, used '{branch_name}' instead")
                logger.info(f"Successfully cloned repository to {clone_dir} (branch: {branch_name})")
                return clone_dir
            else:
                last_error = result.stderr
                # Clean up failed attempt before next try
                if os.path.exists(clone_dir):
                    shutil.rmtree(clone_dir)
                os.makedirs(clone_dir, exist_ok=True)

        # If all branches failed, log the last error
        logger.error(f"Failed to clone repository with any branch. Last error: {last_error}")
        return None
    except Exception as e:
        logger.error(f"Error cloning repository: {str(e)}")
        return None

async def run_semgrep_scan(repo_path: str) -> List[Dict]:
    """Run Semgrep SAST scan with comprehensive rulesets"""
    if not shutil.which("semgrep"):
        logger.warning("Semgrep not found, skipping scan")
        return []

    try:
        # Enhanced rulesets for maximum vulnerability coverage
        rulesets = [
            "p/security-audit",      # Comprehensive security audit
            "p/owasp-top-ten",       # OWASP Top 10 vulnerabilities
            "p/sql-injection",       # SQL injection patterns
            "p/command-injection",   # Command injection
            "p/xss",                 # Cross-site scripting
            "p/jwt",                 # JWT security issues
            "p/insecure-transport",  # SSL/TLS issues
            "p/secrets",             # Hardcoded secrets
            "p/nodejs",              # Node.js security
            "p/python",              # Python security
            "p/django",              # Django security
            "p/flask",               # Flask security
            "p/express",             # Express.js security
            "p/react",               # React security
            "p/kubernetes",          # Kubernetes security
            "p/docker",              # Docker security
            "p/ci",                  # CI/CD security
        ]

        # Run with all rulesets
        cmd = ["semgrep", "--json", "--quiet"]
        for ruleset in rulesets:
            cmd.extend(["--config", ruleset])
        cmd.append(repo_path)

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        if result.returncode == 0 or result.returncode == 1:  # 1 means findings found
            data = json.loads(result.stdout)
            return data.get("results", [])
        return []
    except Exception as e:
        logger.error(f"Semgrep scan error: {str(e)}")
        return []

async def run_gitleaks_scan(repo_path: str) -> List[Dict]:
    """Run Gitleaks secret detection"""
    if not shutil.which("gitleaks"):
        logger.warning("Gitleaks not found, skipping scan")
        return []

    try:
        output_file = f"{repo_path}/gitleaks-report.json"
        cmd = [
            "gitleaks",
            "detect",
            "--source", repo_path,
            "--report-path", output_file,
            "--report-format", "json",
            "--no-git"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        return []
    except Exception as e:
        logger.error(f"Gitleaks scan error: {str(e)}")
        return []

async def run_trivy_scan(repo_path: str) -> List[Dict]:
    """Run Trivy dependency scan"""
    if not shutil.which("trivy"):
        logger.warning("Trivy not found, skipping scan")
        return []

    try:
        cmd = [
            "trivy",
            "fs",
            "--format", "json",
            "--quiet",
            repo_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            vulnerabilities = []
            for result_item in data.get("Results", []):
                vulnerabilities.extend(result_item.get("Vulnerabilities", []))
            return vulnerabilities
        return []
    except Exception as e:
        logger.error(f"Trivy scan error: {str(e)}")
        return []

async def run_checkov_scan(repo_path: str) -> List[Dict]:
    """Run Checkov IaC scan"""
    if not shutil.which("checkov"):
        logger.warning("Checkov not found, skipping scan")
        return []

    try:
        cmd = [
            "checkov",
            "-d", repo_path,
            "-o", "json",
            "--quiet"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.stdout:
            data = json.loads(result.stdout)
            return data.get("results", {}).get("failed_checks", [])
        return []
    except Exception as e:
        logger.error(f"Checkov scan error: {str(e)}")
        return []

def map_to_owasp(category: str, title: str, description: str) -> str:
    """Map vulnerability to OWASP Top 10 category"""
    category_lower = category.lower()
    title_lower = title.lower()
    desc_lower = description.lower()
    
    # Mapping logic
    if any(word in category_lower or word in title_lower for word in ["access", "authorization", "permission", "privilege"]):
        return "A01"
    elif any(word in category_lower or word in title_lower for word in ["crypto", "encryption", "hash", "password", "secret"]):
        return "A02"
    elif any(word in category_lower or word in title_lower for word in ["injection", "sql", "xss", "command", "ldap", "xpath"]):
        return "A03"
    elif any(word in category_lower or word in title_lower for word in ["design", "logic", "business"]):
        return "A04"
    elif any(word in category_lower or word in title_lower for word in ["config", "default", "debug", "error"]):
        return "A05"
    elif any(word in category_lower or word in title_lower for word in ["dependency", "component", "library", "cve", "outdated"]):
        return "A06"
    elif any(word in category_lower or word in title_lower for word in ["auth", "session", "token", "credential"]):
        return "A07"
    elif any(word in category_lower or word in title_lower for word in ["integrity", "deserialization", "update"]):
        return "A08"
    elif any(word in category_lower or word in title_lower for word in ["log", "monitor", "audit"]):
        return "A09"
    elif any(word in category_lower or word in title_lower for word in ["ssrf", "request forgery"]):
        return "A10"
    else:
        return "A05"  # Default to misconfiguration

def calculate_security_score(critical: int, high: int, medium: int, low: int) -> int:
    """Calculate overall security score (0-100)"""
    # If no vulnerabilities, perfect score
    total_vulns = critical + high + medium + low
    if total_vulns == 0:
        return 100

    # Weighted scoring with diminishing returns
    # Critical: -15 points each
    # High: -8 points each
    # Medium: -3 points each
    # Low: -1 point each
    total_impact = (critical * 15) + (high * 8) + (medium * 3) + (low * 1)

    # Calculate score (capped at 0 minimum)
    score = max(0, 100 - total_impact)

    # Apply additional penalty for having many vulnerabilities
    if total_vulns > 20:
        score = max(0, score - 5)
    if total_vulns > 50:
        score = max(0, score - 10)
    if total_vulns > 100:
        score = max(0, score - 15)

    return score


def calculate_quality_score(quality_issues: List[Dict]) -> int:
    """Calculate code quality score (0-100)"""
    if not quality_issues:
        return 100

    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for issue in quality_issues:
        severity = issue.get("severity", "low").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Weighted deductions (less severe than security issues)
    # Critical: -10 points each
    # High: -5 points each
    # Medium: -2 points each
    # Low: -0.5 point each
    total_impact = (
        severity_counts["critical"] * 10 +
        severity_counts["high"] * 5 +
        severity_counts["medium"] * 2 +
        severity_counts["low"] * 0.5
    )

    score = max(0, 100 - total_impact)

    # Additional penalty for many issues
    total_issues = len(quality_issues)
    if total_issues > 50:
        score = max(0, score - 5)
    if total_issues > 100:
        score = max(0, score - 10)
    if total_issues > 200:
        score = max(0, score - 15)

    return int(score)


def calculate_compliance_score(compliance_issues: List[Dict]) -> int:
    """Calculate license compliance score (0-100)"""
    if not compliance_issues:
        return 100

    # Count license risk levels
    risk_counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    for issue in compliance_issues:
        risk = issue.get("license_risk", "unknown").lower()
        if risk in risk_counts:
            risk_counts[risk] += 1
        else:
            risk_counts["unknown"] += 1

    # Weighted deductions
    # High risk (GPL, AGPL): -15 points each
    # Medium risk (MPL, EPL): -5 points each
    # Low risk (MIT, Apache): 0 points
    # Unknown: -3 points each
    total_impact = (
        risk_counts["high"] * 15 +
        risk_counts["medium"] * 5 +
        risk_counts["unknown"] * 3
    )

    score = max(0, 100 - total_impact)

    return int(score)

async def process_scan_with_timeout(repo_id: str, scan_id: str, repo_path: str):
    """
    Wrapper function that enforces total scan timeout.
    This prevents scans from running indefinitely.
    """
    scan_limits = get_scan_limits()
    total_timeout = scan_limits.total_scan_timeout  # Default: 3600 seconds (1 hour)

    try:
        await asyncio.wait_for(
            process_scan_results(repo_id, scan_id, repo_path),
            timeout=total_timeout
        )
    except asyncio.TimeoutError:
        logger.error(f"Scan {scan_id} exceeded total timeout of {total_timeout}s")
        # Update scan status to timeout
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "timeout",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": f"Scan exceeded maximum allowed time ({total_timeout}s)"
            }}
        )
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {"scan_status": "timeout"}}
        )
        # Cleanup
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
    except Exception as e:
        logger.error(f"Unexpected error in scan wrapper: {str(e)}")
        # The inner process_scan_results should handle its own errors,
        # but this catches any unexpected issues
        raise


async def run_scanner_with_tracking(
    scanner_name: str,
    scanner_func,
    execution_report: ScanExecutionReport,
    enabled: bool = True,
    available: bool = True,
    timeout_seconds: int = 300
) -> list:
    """
    Run a scanner with tracking and error handling.
    Returns results list (empty if failed/skipped).
    """
    if not enabled:
        execution_report.record_scanner_result(
            scanner_name, success=True, skipped=True, skip_reason="Disabled in settings"
        )
        logger.info(f"{scanner_name}: Disabled in settings")
        return []

    if not available:
        execution_report.record_scanner_result(
            scanner_name, success=False, error_message="Scanner not available/installed"
        )
        logger.warning(f"{scanner_name}: Scanner not available")
        return []

    try:
        results = await asyncio.wait_for(scanner_func(), timeout=timeout_seconds)
        results = results if results is not None else []

        # Validate results is a list
        if not isinstance(results, list):
            logger.warning(f"{scanner_name}: Expected list, got {type(results)}. Converting.")
            results = [results] if results else []

        execution_report.record_scanner_result(
            scanner_name, success=True, findings_count=len(results)
        )
        logger.info(f"{scanner_name} completed: {len(results)} findings")
        return results

    except asyncio.TimeoutError:
        execution_report.record_scanner_result(
            scanner_name, success=False, error_message=f"Timed out after {timeout_seconds}s"
        )
        logger.error(f"{scanner_name}: Timed out after {timeout_seconds}s")
        return []

    except Exception as e:
        execution_report.record_scanner_result(
            scanner_name, success=False, error_message=str(e)
        )
        logger.error(f"{scanner_name} failed: {str(e)}")
        return []


async def process_scan_results(repo_id: str, scan_id: str, repo_path: str):
    """Process all scan results and store vulnerabilities"""

    def normalize_severity(severity_value, default="medium"):
        """Normalize severity value (handle string, list, or other types)"""
        if isinstance(severity_value, list):
            return severity_value[0].lower() if severity_value else default
        elif isinstance(severity_value, str):
            return severity_value.lower()
        else:
            return default

    # Initialize execution report for tracking scanner success/failure
    execution_report = ScanExecutionReport(scan_id=scan_id)
    scan_start_time = asyncio.get_event_loop().time()

    try:
        # Update scan status
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "scanning"}}
        )

        # Initialize scan limits and progress tracking
        scan_limits = get_scan_limits()
        repo_analyzer = RepoAnalyzer(scan_limits)
        llm_batcher = LLMBatcher(scan_limits)

        # Analyze repository for optimal scan strategy
        logger.info("Analyzing repository size and structure...")
        repo_stats = repo_analyzer.analyze_repo(repo_path)
        logger.info(f"Repository analysis: {repo_stats.total_files} files, {repo_stats.total_size_mb:.1f}MB, "
                   f"{repo_stats.source_files} source files, languages: {repo_stats.languages_detected}")

        # Log warnings for large repos
        for warning in repo_stats.warnings:
            logger.warning(warning)

        # Store repo stats in scan metadata
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "repo_stats": {
                    "total_files": repo_stats.total_files,
                    "total_size_mb": round(repo_stats.total_size_mb, 2),
                    "source_files": repo_stats.source_files,
                    "test_files": repo_stats.test_files,
                    "security_relevant_files": repo_stats.security_relevant_files,
                    "languages": repo_stats.languages_detected,
                    "is_large_repo": repo_stats.is_large_repo,
                    "estimated_scan_time_minutes": repo_stats.estimated_scan_time_minutes
                }
            }}
        )

        # Get priority files for AI analysis (limited for large repos)
        priority_files = []
        if repo_stats.is_large_repo:
            priority_files = repo_analyzer.get_priority_files(repo_path)
            logger.info(f"Large repo: AI analysis limited to {len(priority_files)} priority files")

        # Load scanner settings
        logger.info("Loading scanner settings...")
        scanner_settings = await settings_manager.get_scanner_settings()
        logger.info(f"Scanner settings loaded: {scanner_settings.model_dump()}")

        # Run all scanners (conditionally based on settings)
        semgrep_results = []
        if scanner_settings.enable_semgrep:
            semgrep_results = await run_semgrep_scan(repo_path)
            logger.info(f"Semgrep scan completed: {len(semgrep_results)} issues found")
        else:
            logger.info("Semgrep: Disabled in settings")

        gitleaks_results = []
        if scanner_settings.enable_gitleaks:
            gitleaks_results = await run_gitleaks_scan(repo_path)
            logger.info(f"Gitleaks scan completed: {len(gitleaks_results)} secrets found")
        else:
            logger.info("Gitleaks: Disabled in settings")

        trivy_results = []
        if scanner_settings.enable_trivy:
            trivy_results = await run_trivy_scan(repo_path)
            logger.info(f"Trivy scan completed: {len(trivy_results)} vulnerabilities found")
        else:
            logger.info("Trivy: Disabled in settings")

        checkov_results = []
        if scanner_settings.enable_checkov:
            checkov_results = await run_checkov_scan(repo_path)
            logger.info(f"Checkov scan completed: {len(checkov_results)} IaC issues found")
        else:
            logger.info("Checkov: Disabled in settings")

        # Run new free security scanners
        bandit_scanner = BanditScanner()
        trufflehog_scanner = TruffleHogScanner()
        grype_scanner = GrypeScanner()
        eslint_scanner = ESLintSecurityScanner()

        bandit_results = []
        trufflehog_results = []
        grype_results = []
        eslint_results = []

        # Run Bandit if enabled and available (Python security)
        if scanner_settings.enable_bandit and await bandit_scanner.is_available():
            bandit_results = await bandit_scanner.scan(repo_path)
            logger.info(f"Bandit scan completed: {len(bandit_results)} issues found")
        elif not scanner_settings.enable_bandit:
            logger.info("Bandit: Disabled in settings")

        # Run TruffleHog if enabled and available (secret detection)
        if scanner_settings.enable_trufflehog and await trufflehog_scanner.is_available():
            trufflehog_results = await trufflehog_scanner.scan(repo_path, scan_history=True)
            logger.info(f"TruffleHog scan completed: {len(trufflehog_results)} secrets found")
        elif not scanner_settings.enable_trufflehog:
            logger.info("TruffleHog: Disabled in settings")

        # Run Grype if enabled and available (dependency vulnerabilities)
        if scanner_settings.enable_grype and await grype_scanner.is_available():
            grype_results = await grype_scanner.scan(repo_path)
            logger.info(f"Grype scan completed: {len(grype_results)} vulnerabilities found")
        elif not scanner_settings.enable_grype:
            logger.info("Grype: Disabled in settings")

        # Run ESLint if enabled and available (JavaScript/TypeScript security)
        if scanner_settings.enable_eslint and await eslint_scanner.is_available():
            eslint_results = await eslint_scanner.scan(repo_path)
            logger.info(f"ESLint scan completed: {len(eslint_results)} issues found")
        elif not scanner_settings.enable_eslint:
            logger.info("ESLint: Disabled in settings")

        # Initialize quality scanners
        pylint_scanner = PylintScanner()
        flake8_scanner = Flake8Scanner()
        radon_scanner = RadonScanner()
        shellcheck_scanner = ShellCheckScanner()
        hadolint_scanner = HadolintScanner()

        # Initialize compliance scanners
        pip_audit_scanner = PipAuditScanner()
        npm_audit_scanner = NpmAuditScanner()
        syft_scanner = SyftScanner()

        # Quality scan results
        pylint_results = []
        flake8_results = []
        radon_results = []
        shellcheck_results = []
        hadolint_results = []

        # Compliance scan results
        pip_audit_results = []
        npm_audit_results = []
        syft_results = []

        # Run quality scanners (if enabled)
        if scanner_settings.enable_pylint and await pylint_scanner.is_available():
            pylint_results = await pylint_scanner.scan(repo_path)
            logger.info(f"Pylint scan completed: {len(pylint_results)} issues found")
        elif not scanner_settings.enable_pylint:
            logger.info("Pylint: Disabled in settings")

        if scanner_settings.enable_flake8 and await flake8_scanner.is_available():
            flake8_results = await flake8_scanner.scan(repo_path)
            logger.info(f"Flake8 scan completed: {len(flake8_results)} issues found")
        elif not scanner_settings.enable_flake8:
            logger.info("Flake8: Disabled in settings")

        if scanner_settings.enable_radon and await radon_scanner.is_available():
            radon_results = await radon_scanner.scan(repo_path)
            logger.info(f"Radon scan completed: {len(radon_results)} complexity issues found")
        elif not scanner_settings.enable_radon:
            logger.info("Radon: Disabled in settings")

        if scanner_settings.enable_shellcheck and await shellcheck_scanner.is_available():
            shellcheck_results = await shellcheck_scanner.scan(repo_path)
            logger.info(f"ShellCheck scan completed: {len(shellcheck_results)} issues found")
        elif not scanner_settings.enable_shellcheck:
            logger.info("ShellCheck: Disabled in settings")

        if scanner_settings.enable_hadolint and await hadolint_scanner.is_available():
            hadolint_results = await hadolint_scanner.scan(repo_path)
            logger.info(f"Hadolint scan completed: {len(hadolint_results)} Dockerfile issues found")
        elif not scanner_settings.enable_hadolint:
            logger.info("Hadolint: Disabled in settings")

        # Run enhanced quality scanners
        sqlfluff_results = []
        if scanner_settings.enable_sqlfluff:
            sqlfluff_results = await sqlfluff_scanner.scan(repo_path)
            logger.info(f"SQLFluff scan completed: {len(sqlfluff_results)} SQL issues found")
        else:
            logger.info("SQLFluff: Disabled in settings")

        pydeps_results = []
        if scanner_settings.enable_pydeps:
            pydeps_results = await pydeps_scanner.scan(repo_path)
            logger.info(f"pydeps scan completed: {len(pydeps_results)} architecture issues found")
        else:
            logger.info("pydeps: Disabled in settings")

        # Run Nuclei for configuration and template-based scanning
        nuclei_results = []
        if scanner_settings.enable_nuclei:
            nuclei_results = await nuclei_scanner.scan(repo_path)
            logger.info(f"Nuclei scan completed: {len(nuclei_results)} configuration issues found")
        else:
            logger.info("Nuclei: Disabled in settings")

        # Run enhanced security scanners (High Value Additions)
        # Get Snyk token from settings
        api_keys = await settings_manager.get_api_keys()
        snyk_token = api_keys.get("snyk_token")

        snyk_results = []
        if scanner_settings.enable_snyk:
            snyk_results = await snyk_scanner.scan(repo_path, snyk_token=snyk_token)
            logger.info(f"Snyk scan completed: {len(snyk_results)} dependency/code issues found")
        else:
            logger.info("Snyk: Disabled in settings")

        gosec_results = []
        if scanner_settings.enable_gosec:
            gosec_results = await gosec_scanner.scan(repo_path)
            logger.info(f"Gosec scan completed: {len(gosec_results)} Go security issues found")
        else:
            logger.info("Gosec: Disabled in settings")

        # DISABLED: cargo-audit (Rust-specific, not installed)
        cargo_audit_results = []
        # cargo_audit_results = await cargo_audit_scanner.scan(repo_path)
        # logger.info(f"cargo-audit scan completed: {len(cargo_audit_results)} Rust issues found")

        spotbugs_results = []
        if scanner_settings.enable_spotbugs:
            spotbugs_results = await spotbugs_scanner.scan(repo_path)
            logger.info(f"SpotBugs scan completed: {len(spotbugs_results)} Java issues found")
        else:
            logger.info("SpotBugs: Disabled in settings")

        pyre_results = []
        if scanner_settings.enable_pyre:
            pyre_results = await pyre_scanner.scan(repo_path)
            logger.info(f"Pyre scan completed: {len(pyre_results)} Python type issues found")
        else:
            logger.info("Pyre: Disabled in settings")

        # ZAP Static Scanner (web security patterns)
        zap_results = []
        if scanner_settings.enable_zap:
            zap_results = await zap_scanner.scan(repo_path)
            logger.info(f"ZAP static scan completed: {len(zap_results)} web security issues found")
        else:
            logger.info("ZAP: Disabled in settings")

        # API Fuzzer Scanner (dedicated API security testing)
        api_fuzzer_results = []
        if scanner_settings.enable_api_fuzzer:
            api_fuzzer_results = await api_fuzzer_scanner.scan(repo_path)
            logger.info(f"API Fuzzer scan completed: {len(api_fuzzer_results)} API issues found")
        else:
            logger.info("API Fuzzer: Disabled in settings")

        horusec_results = []
        if scanner_settings.enable_horusec:
            horusec_results = await horusec_scanner.scan(repo_path)
            logger.info(f"Horusec scan completed: {len(horusec_results)} multi-language issues found")
        else:
            logger.info("Horusec: Disabled in settings")

        # Run compliance scanners (if enabled)
        if scanner_settings.enable_pip_audit and await pip_audit_scanner.is_available():
            pip_audit_results = await pip_audit_scanner.scan(repo_path)
            logger.info(f"pip-audit scan completed: {len(pip_audit_results)} vulnerabilities found")
        elif not scanner_settings.enable_pip_audit:
            logger.info("pip-audit: Disabled in settings")

        if scanner_settings.enable_npm_audit and await npm_audit_scanner.is_available():
            npm_audit_results = await npm_audit_scanner.scan(repo_path)
            logger.info(f"npm-audit scan completed: {len(npm_audit_results)} vulnerabilities found")
        elif not scanner_settings.enable_npm_audit:
            logger.info("npm-audit: Disabled in settings")

        if scanner_settings.enable_syft and await syft_scanner.is_available():
            syft_results = await syft_scanner.scan(repo_path)
            logger.info(f"Syft scan completed: {len(syft_results)} license issues found")
        elif not scanner_settings.enable_syft:
            logger.info("Syft: Disabled in settings")

        # ===== AI-POWERED SECURITY ENGINES =====
        logger.info("Starting AI-powered security analysis...")
        if repo_stats.is_large_repo:
            logger.info(f"Large repo mode: AI scanners will use {scan_limits.ai_scanner_timeout}s timeout")

        # 1. Zero-Day Detection (ML Anomaly Detector)
        zero_day_results = []
        if scanner_settings.enable_zero_day_detector:
            if ML_DETECTOR_AVAILABLE and MLAnomalyDetector is not None:
                try:
                    ml_detector = MLAnomalyDetector()
                    # Use timeout for AI scanner
                    zero_day_anomalies = await run_with_timeout(
                        ml_detector.analyze_repository(repo_path),
                        timeout_seconds=scan_limits.ai_scanner_timeout,
                        name="Zero-Day Detector",
                        default_return=[]
                    )
                    zero_day_results = zero_day_anomalies or []
                    logger.info(f"Zero-Day Detector completed: {len(zero_day_results)} anomalies found")
                except Exception as e:
                    logger.error(f"Zero-Day Detector failed: {str(e)}")
            else:
                logger.warning("Zero-Day Detector: ML components not available (PyTorch/NumPy issue). Scanner skipped.")
        else:
            logger.info("Zero-Day Detector: Disabled in settings")

        # 2. Business Logic Scanner
        business_logic_results = []
        if scanner_settings.enable_business_logic_scanner:
            if FLOW_ANALYZER_AVAILABLE and FlowAnalyzer is not None:
                try:
                    flow_analyzer = FlowAnalyzer()
                    # Use timeout for flow analysis
                    flow_graph = await run_with_timeout(
                        flow_analyzer.analyze_repository(repo_path),
                        timeout_seconds=scan_limits.ai_scanner_timeout,
                        name="Flow Analyzer",
                        default_return=None
                    )

                    if flow_graph:
                        logic_engine = LogicRuleEngine()
                        logic_violations = await run_with_timeout(
                            logic_engine.analyze_flow_graph(flow_graph, repo_path),
                            timeout_seconds=scan_limits.ai_scanner_timeout,
                            name="Logic Rule Engine",
                            default_return=[]
                        )
                        business_logic_results = logic_violations or []
                    logger.info(f"Business Logic Scanner completed: {len(business_logic_results)} violations found")
                except Exception as e:
                    logger.error(f"Business Logic Scanner failed: {str(e)}")
            else:
                logger.warning("Business Logic Scanner: ML components not available (NumPy issue). Scanner skipped.")
        else:
            logger.info("Business Logic Scanner: Disabled in settings")

        # 3. LLM Security Scanner
        llm_security_results = []
        if scanner_settings.enable_llm_security_scanner:
            try:
                # Get LLM API keys from settings for testing
                llm_api_keys = await settings_manager.get_api_keys()

                # Only run LLM security scanner if API keys are configured
                if llm_api_keys.get("openai_api_key") or llm_api_keys.get("anthropic_api_key") or llm_api_keys.get("gemini_api_key"):
                    llm_discovery = LLMSurfaceDiscovery()
                    llm_endpoints = await run_with_timeout(
                        llm_discovery.discover_llm_usage(repo_path),
                        timeout_seconds=scan_limits.ai_scanner_timeout,
                        name="LLM Discovery",
                        default_return=[]
                    )

                    if llm_endpoints:
                        payload_gen = AdversarialPayloadGenerator()
                        payloads = await payload_gen.generate_all_payloads()

                        # Convert API keys to format expected by tester
                        api_keys_dict = {}
                        if llm_api_keys.get("openai_api_key"):
                            api_keys_dict["openai"] = llm_api_keys["openai_api_key"]
                        if llm_api_keys.get("anthropic_api_key"):
                            api_keys_dict["anthropic"] = llm_api_keys["anthropic_api_key"]
                        if llm_api_keys.get("gemini_api_key"):
                            api_keys_dict["gemini"] = llm_api_keys["gemini_api_key"]

                        tester = AdversarialTester(api_keys=api_keys_dict)
                        # Limit sample size for large repos
                        sample_size = 5 if repo_stats.is_large_repo else 10
                        llm_vulns = await run_with_timeout(
                            tester.test_endpoints(llm_endpoints, payloads, sample_size=sample_size),
                            timeout_seconds=scan_limits.ai_scanner_timeout,
                            name="LLM Adversarial Testing",
                            default_return=[]
                        )
                        llm_security_results = llm_vulns or []
                        logger.info(f"LLM Security Scanner completed: {len(llm_security_results)} vulnerabilities found")
                    else:
                        logger.info("LLM Security Scanner: No LLM endpoints detected")
                else:
                    logger.info("LLM Security Scanner: Skipped (no API keys configured)")
            except Exception as e:
                logger.error(f"LLM Security Scanner failed: {str(e)}")
        else:
            logger.info("LLM Security Scanner: Disabled in settings")

        # 4. Authentication & Authorization Scanner
        auth_scanner_results = []
        if scanner_settings.enable_auth_scanner:
            try:
                auth_analyzer = AuthStaticAnalyzer()
                auth_vulns = await run_with_timeout(
                    auth_analyzer.analyze_repository(repo_path),
                    timeout_seconds=scan_limits.ai_scanner_timeout,
                    name="Auth Scanner",
                    default_return=[]
                )
                auth_scanner_results = auth_vulns or []
                logger.info(f"Auth Scanner completed: {len(auth_scanner_results)} vulnerabilities found")
            except Exception as e:
                logger.error(f"Auth Scanner failed: {str(e)}")
        else:
            logger.info("Auth Scanner: Disabled in settings")

        vulnerabilities = []
        quality_issues = []
        compliance_issues = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Process Semgrep results
        for finding in semgrep_results:
            severity = normalize_severity(finding.get("extra", {}).get("severity", "medium"))
            category = finding.get("check_id", "unknown")
            
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=finding.get("path", "unknown"),
                line_start=finding.get("start", {}).get("line", 0),
                line_end=finding.get("end", {}).get("line", 0),
                severity=severity,
                category=category,
                owasp_category=map_to_owasp(category, finding.get("extra", {}).get("message", ""), ""),
                title=finding.get("extra", {}).get("message", "Security Issue"),
                description=finding.get("extra", {}).get("message", ""),
                code_snippet=finding.get("extra", {}).get("lines", ""),
                detected_by="Semgrep"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Process Gitleaks results
        for secret in gitleaks_results:
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=secret.get("File", "unknown"),
                line_start=secret.get("StartLine", 0),
                line_end=secret.get("EndLine", 0),
                severity="critical",
                category="secret-exposure",
                owasp_category="A02",
                title=f"Secret Detected: {secret.get('Description', 'Unknown')}",
                description=f"Secret found: {secret.get('Secret', '')[:20]}...",
                code_snippet=secret.get("Secret", "")[:50],
                detected_by="Gitleaks"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts["critical"] += 1
        
        # Process Trivy results
        for dep in trivy_results:
            severity = normalize_severity(dep.get("Severity", "MEDIUM"))
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=dep.get("PkgName", "dependency"),
                line_start=0,
                line_end=0,
                severity=severity,
                category="vulnerable-dependency",
                owasp_category="A06",
                title=dep.get("Title", "Vulnerable Dependency"),
                description=dep.get("Description", ""),
                code_snippet=f"{dep.get('PkgName', '')}@{dep.get('InstalledVersion', '')}",
                cwe=dep.get("CweIDs", [""])[0] if dep.get("CweIDs") else None,
                cvss_score=dep.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                detected_by="Trivy"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Process Checkov results
        for check in checkov_results:
            severity = normalize_severity(check.get("check_result", {}).get("result", {}).get("severity", "MEDIUM"))
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=check.get("file_path", "unknown"),
                line_start=check.get("file_line_range", [0, 0])[0],
                line_end=check.get("file_line_range", [0, 0])[1],
                severity=severity,
                category="iac-misconfiguration",
                owasp_category="A05",
                title=check.get("check_name", "IaC Misconfiguration"),
                description=check.get("check_result", {}).get("result", {}).get("evaluated_keys", [""])[0],
                code_snippet="",
                detected_by="Checkov"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process Bandit results (Python security)
        for finding in bandit_results:
            vuln_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc)
            }
            vulnerabilities.append(vuln_dict)
            severity = normalize_severity(finding.get("severity", "medium"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process TruffleHog results (secret detection)
        for finding in trufflehog_results:
            vuln_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc)
            }
            vulnerabilities.append(vuln_dict)
            severity = normalize_severity(finding.get("severity", "critical"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process Grype results (dependency vulnerabilities)
        for finding in grype_results:
            vuln_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc)
            }
            vulnerabilities.append(vuln_dict)
            severity = normalize_severity(finding.get("severity", "medium"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process ESLint results (JavaScript/TypeScript security)
        for finding in eslint_results:
            vuln_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc)
            }
            vulnerabilities.append(vuln_dict)
            severity = normalize_severity(finding.get("severity", "medium"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process quality scanner results (including new enhanced scanners)
        for finding in (pylint_results + flake8_results + radon_results + shellcheck_results +
                       hadolint_results + sqlfluff_results + pydeps_results):
            quality_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc),
                "issue_type": "quality"
            }
            quality_issues.append(quality_dict)

        # Process Nuclei configuration findings
        for finding in nuclei_results:
            vuln_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc)
            }
            vulnerabilities.append(vuln_dict)
            severity = normalize_severity(finding.get("severity", "medium"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process enhanced scanner results (High Value Additions)
        enhanced_security_results = (
            snyk_results + gosec_results + cargo_audit_results +
            spotbugs_results + pyre_results + zap_results + api_fuzzer_results + horusec_results
        )
        for finding in enhanced_security_results:
            vuln_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc)
            }
            vulnerabilities.append(vuln_dict)
            severity = normalize_severity(finding.get("severity", "medium"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process compliance scanner results (pip-audit, npm-audit are security vulns)
        for finding in pip_audit_results + npm_audit_results:
            vuln_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc)
            }
            vulnerabilities.append(vuln_dict)
            severity = normalize_severity(finding.get("severity", "medium"))
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process Syft license compliance results
        for finding in syft_results:
            compliance_dict = {
                **finding,
                "repo_id": repo_id,
                "scan_id": scan_id,
                "id": str(uuid.uuid4()),
                "created_at": datetime.now(timezone.utc),
                "issue_type": "compliance"
            }
            compliance_issues.append(compliance_dict)

        # ===== PROCESS AI-POWERED SCANNER RESULTS =====

        # Process Zero-Day Detector results (ML Anomaly Detection)
        for anomaly in zero_day_results:
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=anomaly.file_path,
                line_start=anomaly.line_number,
                line_end=anomaly.line_number,
                severity=anomaly.severity,
                category=f"zero-day-{anomaly.type}",
                owasp_category=map_to_owasp(anomaly.type, anomaly.description, ""),
                title=anomaly.title,
                description=f"{anomaly.description}\n\nAnomaly Score: {anomaly.anomaly_score:.2f}\nConfidence: {anomaly.confidence:.2f}",
                code_snippet=anomaly.code_snippet,
                detected_by="Zero-Day Detector (AI)"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts[anomaly.severity] = severity_counts.get(anomaly.severity, 0) + 1

        # Process Business Logic Scanner results
        for violation in business_logic_results:
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=violation.file_path,
                line_start=violation.line_number,
                line_end=violation.line_number,
                severity=violation.severity,
                category=f"business-logic-{violation.type}",
                owasp_category=map_to_owasp(violation.type, violation.description, ""),
                title=violation.title,
                description=f"{violation.description}\n\n**Attack Scenario:**\n{violation.attack_scenario}\n\n**Recommendation:**\n{violation.recommendation}",
                code_snippet=violation.proof_of_concept or f"Endpoint: {violation.endpoint}",
                detected_by="Business Logic Scanner (AI)"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts[violation.severity] = severity_counts.get(violation.severity, 0) + 1

        # Process LLM Security Scanner results
        for llm_vuln in llm_security_results:
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=llm_vuln.endpoint_file,
                line_start=llm_vuln.endpoint_line,
                line_end=llm_vuln.endpoint_line,
                severity=llm_vuln.severity,
                category=f"llm-security-{llm_vuln.vulnerability_type}",
                owasp_category="A03",  # LLM vulnerabilities often relate to injection
                title=llm_vuln.title,
                description=f"{llm_vuln.description}\n\n**Risk Assessment:**\n"
                           f"- Jailbreak Risk: {llm_vuln.jailbreak_risk:.2%}\n"
                           f"- Data Leak Probability: {llm_vuln.data_leak_probability:.2%}\n"
                           f"- Permission Abuse Risk: {llm_vuln.permission_abuse_risk:.2%}\n\n"
                           f"**Remediation:**\n{llm_vuln.remediation}",
                code_snippet=f"Successful Payload:\n{llm_vuln.successful_payload[:200]}...",
                detected_by="LLM Security Scanner (AI)"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts[llm_vuln.severity] = severity_counts.get(llm_vuln.severity, 0) + 1

        # Process Auth Scanner results
        for auth_vuln in auth_scanner_results:
            vuln = Vulnerability(
                repo_id=repo_id,
                scan_id=scan_id,
                file_path=auth_vuln.file_path,
                line_start=auth_vuln.line_number,
                line_end=auth_vuln.line_number,
                severity=auth_vuln.severity,
                category=f"auth-{auth_vuln.type}",
                owasp_category="A07",  # Auth vulnerabilities are A07: Identification and Authentication Failures
                title=auth_vuln.title,
                description=f"{auth_vuln.description}\n\n**Attack Scenario:**\n{auth_vuln.attack_scenario}\n\n**Remediation:**\n{auth_vuln.remediation}\n\n**Confidence:** {auth_vuln.confidence:.0%}",
                code_snippet=auth_vuln.code_snippet or "",
                detected_by="Auth Scanner (AI)"
            )
            vulnerabilities.append(vuln.model_dump())
            severity_counts[auth_vuln.severity] = severity_counts.get(auth_vuln.severity, 0) + 1

        # Apply false positive filtering
        original_vuln_count = len(vulnerabilities)
        if vulnerabilities:
            logger.info(f"Applying false positive filters to {original_vuln_count} vulnerabilities...")
            vulnerabilities = filter_false_positives(
                vulnerabilities,
                confidence_threshold="medium",  # Show medium+ confidence issues
                enable_deduplication=True,
                enable_context_filtering=True
            )
            filter_stats = get_filter_stats(original_vuln_count, len(vulnerabilities))
            logger.info(f"False positive filtering: {original_vuln_count} → {len(vulnerabilities)} issues "
                       f"({filter_stats['reduction_percent']}% reduction)")

        # Perform context-aware analysis and enrichment
        enriched_vulns = None  # Track whether enrichment succeeded
        context_analysis_succeeded = False

        if vulnerabilities and os.path.exists(repo_path):
            logger.info("Starting context-aware analysis...")
            context_analyzer = ContextAnalyzer()

            try:
                # Analyze repository structure with timeout
                repo_structure = await asyncio.wait_for(
                    context_analyzer.analyze_repository_structure(repo_path),
                    timeout=60  # 1 minute timeout for structure analysis
                )
                logger.info(f"Repository structure analyzed: {repo_structure.get('total_files', 0)} files")

                # Enrich and prioritize vulnerabilities with timeout
                enriched_vulns = await asyncio.wait_for(
                    context_analyzer.prioritize_vulnerabilities(vulnerabilities, repo_path),
                    timeout=120  # 2 minute timeout for prioritization
                )

                # Replace vulnerabilities with enriched versions only if we got valid results
                if enriched_vulns is not None and len(enriched_vulns) > 0:
                    vulnerabilities = enriched_vulns
                    context_analysis_succeeded = True
                    logger.info(f"Context enrichment applied to {len(vulnerabilities)} vulnerabilities")
                else:
                    logger.warning("Context analyzer returned empty results, using original vulnerabilities")

            except asyncio.TimeoutError:
                logger.warning("Context analysis timed out, using original vulnerabilities without enrichment")
                execution_report.record_scanner_result(
                    "context_analyzer", success=False, error_message="Timed out"
                )
            except Exception as e:
                logger.error(f"Context analysis failed: {str(e)}, using original vulnerabilities")
                execution_report.record_scanner_result(
                    "context_analyzer", success=False, error_message=str(e)
                )
                # Continue with original vulnerabilities

        # Recalculate severity counts (works for both enriched and original vulns)
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vuln in vulnerabilities:
            # Ensure every vulnerability has a severity
            severity_value = vuln.get("severity", "medium")
            # Handle case where severity might be a list
            if isinstance(severity_value, list):
                severity = severity_value[0].lower() if severity_value else "medium"
            elif isinstance(severity_value, str):
                severity = severity_value.lower()
            else:
                severity = "medium"

            # Normalize and validate severity
            if severity not in severity_counts:
                severity = "medium"  # Default to medium if invalid

            # Ensure the vulnerability has a valid severity string
            vuln["severity"] = severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Generate priority report only if context analysis succeeded
        if context_analysis_succeeded and enriched_vulns:
            try:
                priority_report = context_analyzer.generate_priority_report(enriched_vulns)
                logger.info(f"Priority analysis complete: {priority_report.get('critical_priority', 0)} critical, "
                           f"{priority_report.get('high_priority', 0)} high priority issues")
            except Exception as e:
                logger.warning(f"Failed to generate priority report: {e}")

        # Store vulnerabilities
        if vulnerabilities:
            for vuln in vulnerabilities:
                if isinstance(vuln.get('created_at'), datetime):
                    vuln['created_at'] = vuln['created_at'].isoformat()
            await db.vulnerabilities.insert_many(vulnerabilities)

        # Store quality issues in separate collection
        if quality_issues:
            for issue in quality_issues:
                if isinstance(issue.get('created_at'), datetime):
                    issue['created_at'] = issue['created_at'].isoformat()
            await db.quality_issues.insert_many(quality_issues)

        # Store compliance issues in separate collection
        if compliance_issues:
            for issue in compliance_issues:
                if isinstance(issue.get('created_at'), datetime):
                    issue['created_at'] = issue['created_at'].isoformat()
            await db.compliance_issues.insert_many(compliance_issues)

        # Calculate security score
        security_score = calculate_security_score(
            severity_counts.get("critical", 0),
            severity_counts.get("high", 0),
            severity_counts.get("medium", 0),
            severity_counts.get("low", 0)
        )

        # Calculate quality score
        quality_score = calculate_quality_score(quality_issues)

        # Calculate compliance score
        compliance_score = calculate_compliance_score(compliance_issues)

        # Count files
        total_files = sum(1 for _ in Path(repo_path).rglob("*") if _.is_file())

        # Check for high scanner failure rate and warn
        if execution_report.should_warn_about_failures(threshold=50.0):
            logger.warning(execution_report.get_summary_message())
            # Mark scan as having issues but still completed
            scan_status = "completed_with_warnings"
        else:
            scan_status = "completed"
            logger.info(execution_report.get_summary_message())

        # Update scan with execution report
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": scan_status,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "total_files": total_files,
                "vulnerabilities_count": len(vulnerabilities),
                "quality_issues_count": len(quality_issues),
                "compliance_issues_count": len(compliance_issues),
                "critical_count": severity_counts.get("critical", 0),
                "high_count": severity_counts.get("high", 0),
                "medium_count": severity_counts.get("medium", 0),
                "low_count": severity_counts.get("low", 0),
                "security_score": security_score,
                "quality_score": quality_score,
                "compliance_score": compliance_score,
                "scan_results": {
                    "semgrep": len(semgrep_results),
                    "gitleaks": len(gitleaks_results),
                    "trivy": len(trivy_results),
                    "checkov": len(checkov_results),
                    "bandit": len(bandit_results),
                    "trufflehog": len(trufflehog_results),
                    "grype": len(grype_results),
                    "eslint": len(eslint_results),
                    "pylint": len(pylint_results),
                    "flake8": len(flake8_results),
                    "radon": len(radon_results),
                    "shellcheck": len(shellcheck_results),
                    "hadolint": len(hadolint_results),
                    "sqlfluff": len(sqlfluff_results),
                    "pydeps": len(pydeps_results),
                    "nuclei": len(nuclei_results),
                    "snyk": len(snyk_results),
                    "gosec": len(gosec_results),
                    "cargo_audit": len(cargo_audit_results),
                    "spotbugs": len(spotbugs_results),
                    "pyre": len(pyre_results),
                    "zap": len(zap_results),
                    "api_fuzzer": len(api_fuzzer_results),
                    "horusec": len(horusec_results),
                    "pip_audit": len(pip_audit_results),
                    "npm_audit": len(npm_audit_results),
                    "syft": len(syft_results),
                    # AI-Powered Scanners
                    "zero_day": len(zero_day_results),
                    "business_logic": len(business_logic_results),
                    "llm_security": len(llm_security_results),
                    "auth_scanner": len(auth_scanner_results)
                },
                # Add execution report for visibility into scanner success/failures
                "execution_report": execution_report.to_dict()
            }}
        )

        # Update repository
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {
                "last_scan": datetime.now(timezone.utc).isoformat(),
                "scan_status": scan_status
            }}
        )

        # Cleanup
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)

        logger.info(f"Scan {scan_id} completed with {len(vulnerabilities)} vulnerabilities")

    except asyncio.TimeoutError:
        logger.error(f"Scan {scan_id} timed out after exceeding total scan timeout")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "timeout",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": "Scan exceeded maximum allowed time",
                "execution_report": execution_report.to_dict() if execution_report else None
            }}
        )
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {"scan_status": "timeout"}}
        )
        # Cleanup on timeout
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)

    except Exception as e:
        logger.error(f"Error processing scan: {str(e)}")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "error_message": str(e),
                "execution_report": execution_report.to_dict() if execution_report else None
            }}
        )
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {"scan_status": "failed"}}
        )
        # Cleanup on failure
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Security Intelligence Platform API", "version": "1.0.0"}


@api_router.get("/health")
async def health_check():
    """Health check endpoint with database and scanner status"""
    health = {
        "status": "healthy",
        "database": "unknown",
        "scanners": None
    }

    # Check database connection
    try:
        await client.admin.command('ping')
        health["database"] = "connected"
    except Exception as e:
        health["status"] = "unhealthy"
        health["database"] = f"disconnected: {str(e)}"

    # Include scanner health if available
    if _scanner_health_report:
        health["scanners"] = {
            "total": _scanner_health_report.total_scanners,
            "available": _scanner_health_report.available_count,
            "unavailable": _scanner_health_report.unavailable_count,
            "is_healthy": _scanner_health_report.is_healthy()
        }
        if not _scanner_health_report.is_healthy():
            health["status"] = "degraded"

    return health


@api_router.get("/scanners/health")
async def get_scanner_health():
    """Get detailed scanner health status"""
    if _scanner_health_report:
        return _scanner_health_report.to_dict()

    # Run fresh health check if not available
    try:
        scanner_settings = await settings_manager.get_scanner_settings()
        report = await check_all_scanners(scanner_settings)
        return report.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to check scanner health: {str(e)}")


# NOTE: Old create_repository endpoint removed - use the Git Integration endpoint below

@api_router.get("/repositories", response_model=List[Repository])
async def get_repositories():
    """Get all repositories with their latest security scores"""
    repos = await db.repositories.find({}, {"_id": 0}).to_list(1000)
    for repo in repos:
        if isinstance(repo.get('created_at'), str):
            repo['created_at'] = datetime.fromisoformat(repo['created_at'])

        # Get latest scan's security score for this repository
        latest_scan = await db.scans.find_one(
            {"repo_id": repo['id'], "status": "completed"},
            {"_id": 0, "security_score": 1, "vulnerabilities_count": 1, "critical_count": 1, "high_count": 1}
        )
        if latest_scan:
            repo['security_score'] = latest_scan.get('security_score', 0)
            repo['vulnerabilities_count'] = latest_scan.get('vulnerabilities_count', 0)
            repo['critical_count'] = latest_scan.get('critical_count', 0)
            repo['high_count'] = latest_scan.get('high_count', 0)
        else:
            repo['security_score'] = None  # No scan yet
            repo['vulnerabilities_count'] = 0
            repo['critical_count'] = 0
            repo['high_count'] = 0
    return repos

@api_router.get("/repositories/{repo_id}", response_model=Repository)
async def get_repository(repo_id: str):
    """Get repository by ID"""
    repo = await db.repositories.find_one({"id": repo_id}, {"_id": 0})
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    if isinstance(repo.get('created_at'), str):
        repo['created_at'] = datetime.fromisoformat(repo['created_at'])
    return repo

@api_router.delete("/repositories/{repo_id}")
async def delete_repository(repo_id: str):
    """Delete a repository and all associated data"""
    result = await db.repositories.delete_one({"id": repo_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Repository not found")

    # Get all scan IDs for this repository
    scans = await db.scans.find({"repo_id": repo_id}, {"id": 1}).to_list(1000)
    scan_ids = [scan["id"] for scan in scans]

    # Delete all related data
    if scan_ids:
        await db.vulnerabilities.delete_many({"scan_id": {"$in": scan_ids}})
        await db.quality_issues.delete_many({"scan_id": {"$in": scan_ids}})
        await db.compliance_issues.delete_many({"scan_id": {"$in": scan_ids}})

    await db.scans.delete_many({"repo_id": repo_id})

    logger.info(f"Deleted repository {repo_id} and all associated data")
    return {"message": "Repository deleted successfully"}

@api_router.post("/scans/{repo_id}")
async def start_scan(repo_id: str, background_tasks: BackgroundTasks):
    """Start a security scan for a repository"""
    try:
        # Get repository
        repo = await db.repositories.find_one({"id": repo_id}, {"_id": 0})
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")
        
        # Create scan record
        scan = Scan(repo_id=repo_id)
        scan_doc = scan.model_dump()
        scan_doc['started_at'] = scan_doc['started_at'].isoformat()
        await db.scans.insert_one(scan_doc)
        
        # Update repository status
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {"scan_status": "scanning"}}
        )
        
        # Clone repository
        repo_path = await clone_repository(
            repo['url'],
            repo['access_token'],
            repo['branch'],
            repo_id
        )
        
        if not repo_path:
            raise HTTPException(status_code=500, detail="Failed to clone repository")
        
        # Start background scan with timeout enforcement
        background_tasks.add_task(process_scan_with_timeout, repo_id, scan.id, repo_path)
        
        return {"scan_id": scan.id, "status": "started", "message": "Scan initiated successfully"}
    
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/scans/{repo_id}", response_model=List[Scan])
async def get_scans(repo_id: str):
    """Get all scans for a repository"""
    scans = await db.scans.find({"repo_id": repo_id}, {"_id": 0}).sort("started_at", -1).to_list(1000)
    for scan in scans:
        if isinstance(scan.get('started_at'), str):
            scan['started_at'] = datetime.fromisoformat(scan['started_at'])
        if scan.get('completed_at') and isinstance(scan['completed_at'], str):
            scan['completed_at'] = datetime.fromisoformat(scan['completed_at'])
    return scans

@api_router.get("/scans/detail/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    """Get scan by ID"""
    scan = await db.scans.find_one({"id": scan_id}, {"_id": 0})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if isinstance(scan.get('started_at'), str):
        scan['started_at'] = datetime.fromisoformat(scan['started_at'])
    if scan.get('completed_at') and isinstance(scan['completed_at'], str):
        scan['completed_at'] = datetime.fromisoformat(scan['completed_at'])
    return scan

@api_router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its associated vulnerabilities"""
    result = await db.scans.delete_one({"id": scan_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    # Also delete associated vulnerabilities
    await db.vulnerabilities.delete_many({"scan_id": scan_id})
    return {"message": "Scan deleted successfully"}

@api_router.get("/vulnerabilities/{scan_id}", response_model=List[Vulnerability])
async def get_vulnerabilities(scan_id: str):
    """Get all vulnerabilities for a scan"""
    vulns = await db.vulnerabilities.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)
    for vuln in vulns:
        if isinstance(vuln.get('created_at'), str):
            vuln['created_at'] = datetime.fromisoformat(vuln['created_at'])
    return vulns

@api_router.get("/vulnerabilities/repo/{repo_id}", response_model=List[Vulnerability])
async def get_vulnerabilities_by_repo(repo_id: str):
    """Get all vulnerabilities for a repository"""
    vulns = await db.vulnerabilities.find({"repo_id": repo_id}, {"_id": 0}).to_list(10000)
    for vuln in vulns:
        if isinstance(vuln.get('created_at'), str):
            vuln['created_at'] = datetime.fromisoformat(vuln['created_at'])
    return vulns

# Quality Issues Endpoints
@api_router.get("/quality/{scan_id}")
async def get_quality_issues(scan_id: str):
    """Get all quality issues for a scan"""
    issues = await db.quality_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)
    for issue in issues:
        if isinstance(issue.get('created_at'), str):
            issue['created_at'] = datetime.fromisoformat(issue['created_at'])
    return issues

@api_router.get("/quality/repo/{repo_id}")
async def get_quality_issues_by_repo(repo_id: str):
    """Get all quality issues for a repository"""
    issues = await db.quality_issues.find({"repo_id": repo_id}, {"_id": 0}).to_list(10000)
    for issue in issues:
        if isinstance(issue.get('created_at'), str):
            issue['created_at'] = datetime.fromisoformat(issue['created_at'])
    return issues

@api_router.get("/quality/summary/{scan_id}")
async def get_quality_summary(scan_id: str):
    """Get quality metrics summary for a scan"""
    issues = await db.quality_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)

    summary = {
        "total_issues": len(issues),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "by_category": {},
        "by_scanner": {},
        "quality_score": 100
    }

    for issue in issues:
        severity = issue.get("severity", "low").lower()
        category = issue.get("category", "other")
        scanner = issue.get("detected_by", "unknown")

        if severity in summary["by_severity"]:
            summary["by_severity"][severity] += 1
        summary["by_category"][category] = summary["by_category"].get(category, 0) + 1
        summary["by_scanner"][scanner] = summary["by_scanner"].get(scanner, 0) + 1

    # Calculate quality score
    summary["quality_score"] = calculate_quality_score(issues)

    return summary

# Compliance Issues Endpoints
@api_router.get("/compliance/{scan_id}")
async def get_compliance_issues(scan_id: str):
    """Get all compliance issues for a scan"""
    issues = await db.compliance_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)
    for issue in issues:
        if isinstance(issue.get('created_at'), str):
            issue['created_at'] = datetime.fromisoformat(issue['created_at'])
    return issues

@api_router.get("/compliance/repo/{repo_id}")
async def get_compliance_issues_by_repo(repo_id: str):
    """Get all compliance issues for a repository"""
    issues = await db.compliance_issues.find({"repo_id": repo_id}, {"_id": 0}).to_list(10000)
    for issue in issues:
        if isinstance(issue.get('created_at'), str):
            issue['created_at'] = datetime.fromisoformat(issue['created_at'])
    return issues

@api_router.get("/compliance/summary/{scan_id}")
async def get_compliance_summary(scan_id: str):
    """Get compliance metrics summary for a scan"""
    issues = await db.compliance_issues.find({"scan_id": scan_id}, {"_id": 0}).to_list(10000)

    summary = {
        "total_issues": len(issues),
        "by_risk_level": {"high": 0, "medium": 0, "low": 0, "unknown": 0},
        "by_license": {},
        "compliance_score": 100
    }

    for issue in issues:
        risk = issue.get("license_risk", "unknown").lower()
        license_name = issue.get("license", "unknown")

        if risk in summary["by_risk_level"]:
            summary["by_risk_level"][risk] += 1
        else:
            summary["by_risk_level"]["unknown"] += 1

        summary["by_license"][license_name] = summary["by_license"].get(license_name, 0) + 1

    # Calculate compliance score
    summary["compliance_score"] = calculate_compliance_score(issues)

    return summary

@api_router.get("/sbom/{repo_id}")
async def get_sbom(repo_id: str):
    """Get Software Bill of Materials for a repository"""
    # Get latest scan
    latest_scan = await db.scans.find_one(
        {"repo_id": repo_id, "status": "completed"},
        {"_id": 0},
        sort=[("started_at", -1)]
    )

    if not latest_scan:
        raise HTTPException(status_code=404, detail="No completed scans found")

    # Get compliance issues which contain package info
    issues = await db.compliance_issues.find(
        {"scan_id": latest_scan["id"]},
        {"_id": 0}
    ).to_list(10000)

    # Build SBOM structure
    packages = []
    for issue in issues:
        packages.append({
            "name": issue.get("package_name", "unknown"),
            "version": issue.get("package_version", ""),
            "type": issue.get("package_type", "unknown"),
            "license": issue.get("license", "unknown"),
            "license_risk": issue.get("license_risk", "unknown")
        })

    return {
        "repo_id": repo_id,
        "scan_id": latest_scan["id"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_packages": len(packages),
        "packages": packages
    }

@api_router.post("/ai/fix-recommendation")
async def get_ai_fix_recommendation(request: AIFixRequest):
    """Generate AI-powered fix recommendation for a vulnerability"""
    try:
        # Get vulnerability
        vuln = await db.vulnerabilities.find_one({"id": request.vulnerability_id}, {"_id": 0})
        if not vuln:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        
        # Prepare AI prompt
        prompt = f"""You are a security expert. Analyze this vulnerability and provide a detailed fix recommendation.

Vulnerability Details:
- Title: {vuln['title']}
- Severity: {vuln['severity']}
- OWASP Category: {vuln['owasp_category']} ({OWASP_CATEGORIES.get(vuln['owasp_category'], 'Unknown')})
- Description: {vuln['description']}
- File: {vuln['file_path']}
- Lines: {vuln['line_start']}-{vuln['line_end']}
- Code Snippet: {vuln['code_snippet']}

Provide:
1. Explanation of the vulnerability
2. Potential exploit scenarios
3. Step-by-step fix instructions
4. Secure code example
5. Prevention tips

Format your response in markdown."""

        # Initialize LLM orchestrator with database connection and settings manager
        orchestrator = LLMOrchestrator(db=db, settings_manager=settings_manager)

        # Determine model
        default_models = {
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-7-sonnet-20250219",
            "gemini": "gemini-2.0-flash"
        }
        model = request.model or default_models.get(request.provider, "claude-3-7-sonnet-20250219")

        # Get AI response using vulnerability-specific method
        response = await orchestrator.generate_vulnerability_fix(
            provider=request.provider,
            model=model,
            vulnerability=vuln
        )
        
        # Update vulnerability with fix recommendation
        await db.vulnerabilities.update_one(
            {"id": request.vulnerability_id},
            {"$set": {"fix_recommendation": response}}
        )
        
        return {
            "vulnerability_id": request.vulnerability_id,
            "provider": request.provider,
            "model": request.model,
            "recommendation": response
        }
    
    except Exception as e:
        logger.error(f"Error generating AI fix: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/owasp/categories")
async def get_owasp_categories():
    """Get OWASP Top 10 categories"""
    return OWASP_CATEGORIES

@api_router.get("/stats/{repo_id}")
async def get_repository_stats(repo_id: str):
    """Get repository statistics and trends"""
    try:
        # Get latest scan
        latest_scan = await db.scans.find_one(
            {"repo_id": repo_id, "status": "completed"},
            {"_id": 0},
            sort=[("started_at", -1)]
        )
        
        if not latest_scan:
            return {"message": "No completed scans found"}
        
        # Get vulnerability distribution by OWASP
        owasp_distribution = {}
        vulns = await db.vulnerabilities.find({"scan_id": latest_scan['id']}, {"_id": 0}).to_list(10000)
        
        for vuln in vulns:
            category = vuln['owasp_category']
            owasp_distribution[category] = owasp_distribution.get(category, 0) + 1
        
        # Get severity distribution
        severity_dist = {
            "critical": latest_scan.get('critical_count', 0),
            "high": latest_scan.get('high_count', 0),
            "medium": latest_scan.get('medium_count', 0),
            "low": latest_scan.get('low_count', 0)
        }
        
        # Get scan history
        scan_history = await db.scans.find(
            {"repo_id": repo_id, "status": "completed"},
            {"_id": 0, "id": 1, "started_at": 1, "security_score": 1, "vulnerabilities_count": 1}
        ).sort("started_at", -1).limit(10).to_list(10)
        
        return {
            "security_score": latest_scan.get('security_score', 0),
            "total_vulnerabilities": latest_scan.get('vulnerabilities_count', 0),
            "severity_distribution": severity_dist,
            "owasp_distribution": owasp_distribution,
            "scan_history": scan_history,
            "total_files_scanned": latest_scan.get('total_files', 0),
            "tools_used": latest_scan.get('scan_results', {})
        }
    
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# NOTE: Old duplicate api-keys endpoints removed - use /settings and /settings/api-keys below

@api_router.get("/settings/scanners")
async def get_scanner_status():
    """Get status of installed security scanners (26 total scanners)"""
    scanners = {
        # Security scanners (8)
        "semgrep": {"name": "Semgrep (Enhanced)", "type": "SAST", "installed": bool(shutil.which("semgrep"))},
        "gitleaks": {"name": "Gitleaks", "type": "Secrets", "installed": bool(shutil.which("gitleaks"))},
        "trivy": {"name": "Trivy", "type": "Dependencies", "installed": bool(shutil.which("trivy"))},
        "checkov": {"name": "Checkov", "type": "IaC", "installed": bool(shutil.which("checkov"))},
        "bandit": {"name": "Bandit", "type": "Python Security", "installed": bool(shutil.which("bandit"))},
        "trufflehog": {"name": "TruffleHog", "type": "Secrets", "installed": bool(shutil.which("trufflehog"))},
        "grype": {"name": "Grype", "type": "Dependencies", "installed": bool(shutil.which("grype"))},
        "eslint": {"name": "ESLint", "type": "JS/TS Security", "installed": bool(shutil.which("eslint"))},

        # Quality scanners (7)
        "pylint": {"name": "Pylint", "type": "Python Quality", "installed": bool(shutil.which("pylint"))},
        "flake8": {"name": "Flake8", "type": "Python Style", "installed": bool(shutil.which("flake8"))},
        "radon": {"name": "Radon", "type": "Complexity", "installed": bool(shutil.which("radon"))},
        "shellcheck": {"name": "ShellCheck", "type": "Shell Scripts", "installed": bool(shutil.which("shellcheck"))},
        "hadolint": {"name": "Hadolint", "type": "Docker", "installed": bool(shutil.which("hadolint"))},
        "sqlfluff": {"name": "SQLFluff", "type": "SQL Security", "installed": bool(shutil.which("sqlfluff"))},
        "pydeps": {"name": "pydeps", "type": "Architecture", "installed": bool(shutil.which("pydeps"))},

        # Compliance scanners (3)
        "pip_audit": {"name": "pip-audit", "type": "Python Deps", "installed": bool(shutil.which("pip-audit"))},
        "npm_audit": {"name": "npm-audit", "type": "JS/TS Deps", "installed": bool(shutil.which("npm"))},
        "syft": {"name": "Syft", "type": "SBOM/License", "installed": bool(shutil.which("syft"))},

        # Advanced scanners (1)
        "nuclei": {"name": "Nuclei", "type": "Template/CVE Scanner", "installed": bool(shutil.which("nuclei")) or os.path.exists("/usr/local/bin/nuclei") or os.path.exists("/opt/homebrew/bin/nuclei")},

        # High Value Addition scanners (5 active, 2 disabled)
        "snyk": {"name": "Snyk CLI", "type": "Modern Dependency Scanner", "installed": bool(shutil.which("snyk"))},
        "gosec": {"name": "Gosec", "type": "Go Security", "installed": bool(shutil.which("gosec"))},
        # "cargo_audit": {"name": "cargo-audit", "type": "Rust Security", "installed": False, "disabled": True},  # Rust-specific
        "spotbugs": {"name": "SpotBugs", "type": "Java Bytecode Analysis", "installed": bool(shutil.which("spotbugs"))},
        "pyre": {"name": "Pyre", "type": "Python Type Checker", "installed": bool(shutil.which("pyre"))},
        "zap": {"name": "OWASP ZAP (Static)", "type": "Web Security Patterns", "installed": True},  # Static analysis
        "api_fuzzer": {"name": "API Fuzzer", "type": "API Security Testing", "installed": True},  # Built-in
        "zap_dast": {"name": "OWASP ZAP (DAST)", "type": "Dynamic Web Security", "installed": bool(shutil.which("docker"))},  # Docker-based
        "horusec": {"name": "Horusec", "type": "Multi-Language SAST", "installed": bool(shutil.which("horusec"))},
    }
    return scanners

@api_router.post("/reports/generate")
async def generate_report(request: ReportRequest):
    """Generate security report"""
    try:
        # Get scan and vulnerabilities
        scan = await db.scans.find_one({"id": request.scan_id}, {"_id": 0})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        repo = await db.repositories.find_one({"id": request.repo_id}, {"_id": 0})
        vulns = await db.vulnerabilities.find({"scan_id": request.scan_id}, {"_id": 0}).to_list(10000)
        
        if request.format == "json":
            return {
                "repository": repo,
                "scan": scan,
                "vulnerabilities": vulns,
                "owasp_mapping": OWASP_CATEGORIES
            }
        elif request.format == "csv":
            # Return CSV data structure
            csv_data = []
            for vuln in vulns:
                csv_data.append({
                    "file": vuln['file_path'],
                    "line": f"{vuln['line_start']}-{vuln['line_end']}",
                    "severity": vuln['severity'],
                    "owasp": vuln['owasp_category'],
                    "title": vuln['title'],
                    "description": vuln['description'],
                    "tool": vuln['detected_by']
                })
            return {"format": "csv", "data": csv_data}
        elif request.format == "pdf":
            # Generate PDF report
            from reporting.pdf_report import PDFSecurityReport
            from fastapi.responses import Response

            pdf_generator = PDFSecurityReport()
            pdf_bytes = pdf_generator.generate_report(
                repo_data=repo,
                scan_data=scan,
                vulnerabilities=vulns
            )

            # Return PDF as downloadable file
            filename = f"security_report_{request.repo_id}_{request.scan_id}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}"
                }
            )
        else:
            return {"message": "Unsupported format. Use: json, csv, or pdf"}
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# SCAN LIMITS ENDPOINT
# ============================================

@api_router.get("/scan-limits")
async def get_current_scan_limits():
    """
    Get current scan limits configuration.
    These limits help handle large repositories efficiently.

    Configure via environment variables:
    - SCAN_MAX_FILES_AI: Max files for AI analysis (default: 500)
    - SCAN_MAX_FILE_SIZE_KB: Max file size in KB (default: 500)
    - SCAN_MAX_REPO_SIZE_MB: Max repo size warning threshold (default: 500)
    - SCAN_SCANNER_TIMEOUT: Per-scanner timeout in seconds (default: 300)
    - SCAN_AI_SCANNER_TIMEOUT: AI scanner timeout in seconds (default: 600)
    - SCAN_CLONE_TIMEOUT: Git clone timeout in seconds (default: 600)
    - SCAN_TOTAL_TIMEOUT: Total scan timeout in seconds (default: 3600)
    - SCAN_MAX_VULNS_AI: Max vulnerabilities for AI analysis (default: 100)
    - SCAN_LLM_BATCH_SIZE: LLM processing batch size (default: 10)
    - SCAN_LLM_REQUEST_TIMEOUT: Per-LLM request timeout (default: 60)
    """
    limits = get_scan_limits()
    return {
        "file_limits": {
            "max_files_for_ai_scan": limits.max_files_for_ai_scan,
            "max_file_size_kb": limits.max_file_size_kb,
            "max_total_repo_size_mb": limits.max_total_repo_size_mb
        },
        "timeout_limits": {
            "scanner_timeout_seconds": limits.scanner_timeout,
            "ai_scanner_timeout_seconds": limits.ai_scanner_timeout,
            "clone_timeout_seconds": limits.clone_timeout,
            "total_scan_timeout_seconds": limits.total_scan_timeout
        },
        "llm_limits": {
            "max_vulnerabilities_for_ai_analysis": limits.max_vulnerabilities_for_ai_analysis,
            "batch_size": limits.llm_batch_size,
            "request_timeout_seconds": limits.llm_request_timeout,
            "max_code_snippet_chars": limits.max_code_snippet_chars,
            "max_description_chars": limits.max_description_chars
        },
        "priority_settings": {
            "prioritize_security_files": limits.prioritize_security_files,
            "skip_test_files_for_ai": limits.skip_test_files_for_ai,
            "skip_vendor_dirs": limits.skip_vendor_dirs
        }
    }


# ============================================
# SETTINGS ENDPOINTS
# ============================================

@api_router.get("/settings", response_model=SettingsResponse)
async def get_settings():
    """
    Get all settings status (shows which keys are set, not the actual values)
    """
    try:
        return await settings_manager.get_all_settings()
    except Exception as e:
        logger.error(f"Error getting settings: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/settings/api-keys")
async def update_api_keys(request: UpdateAPIKeysRequest):
    """
    Update API keys for LLM services and scanners

    - **openai_api_key**: OpenAI API key for GPT models
    - **anthropic_api_key**: Anthropic API key for Claude models
    - **gemini_api_key**: Google Gemini API key
    - **github_token**: GitHub token for better rate limits
    - **snyk_token**: Snyk authentication token

    Note: Keys are encrypted before storage. Pass empty string to delete a key.
    """
    try:
        from settings.models import APIKeySetting

        logger.info(f"Received API key update request: {request.model_dump()}")

        api_keys = APIKeySetting(
            openai_api_key=request.openai_api_key,
            anthropic_api_key=request.anthropic_api_key,
            gemini_api_key=request.gemini_api_key,
            github_token=request.github_token,
            snyk_token=request.snyk_token
        )

        logger.info("Calling settings_manager.update_api_keys...")
        await settings_manager.update_api_keys(api_keys)
        logger.info("API keys updated")

        settings_response = await settings_manager.get_all_settings()
        logger.info(f"Settings response: {settings_response.model_dump()}")

        return {
            "message": "API keys updated successfully",
            "updated": settings_response.model_dump()
        }

    except Exception as e:
        logger.error(f"Error updating API keys: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/settings/api-keys")
async def get_api_keys_values():
    """
    Get actual API key values (for administrative purposes)
    WARNING: This endpoint returns decrypted keys - use with caution
    """
    try:
        keys = await settings_manager.get_api_keys()

        # Mask keys for security (show first 8 chars only)
        masked_keys = {}
        for key, value in keys.items():
            if value:
                masked_keys[key] = value[:8] + "..." if len(value) > 8 else "***"
            else:
                masked_keys[key] = None

        return masked_keys

    except Exception as e:
        logger.error(f"Error getting API keys: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/settings/ai-scanners", response_model=AIScannerSettings)
async def get_ai_scanner_settings():
    """
    Get AI scanner enable/disable settings

    Returns the current state of all AI-powered security scanners:
    - Zero-Day Detector (ML-based anomaly detection)
    - Business Logic Scanner (logic flaw detection)
    - LLM Security Scanner (prompt injection testing)
    - Auth Scanner (authentication vulnerability detection)
    """
    try:
        settings = await settings_manager.get_ai_scanner_settings()
        return AIScannerSettings(**settings)
    except Exception as e:
        logger.error(f"Error getting AI scanner settings: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/settings/ai-scanners")
async def update_ai_scanner_settings(request: UpdateAIScannerSettingsRequest):
    """
    Update AI scanner enable/disable settings

    - **enable_zero_day_detector**: Enable/disable ML-based zero-day detection
    - **enable_business_logic_scanner**: Enable/disable business logic flaw detection
    - **enable_llm_security_scanner**: Enable/disable LLM prompt injection testing
    - **enable_auth_scanner**: Enable/disable authentication vulnerability scanner

    Note: Only scanners with LLM API keys configured will run when enabled.
    """
    try:
        # Get current settings
        current_settings = await settings_manager.get_ai_scanner_settings()

        # Update only provided values
        update_dict = request.model_dump(exclude_unset=True)
        current_settings.update(update_dict)

        # Save updated settings
        success = await settings_manager.update_ai_scanner_settings(current_settings)

        if not success:
            raise HTTPException(status_code=500, detail="Failed to update AI scanner settings")

        # Clear cache to ensure fresh settings on next scan
        settings_manager.clear_cache()

        return {
            "message": "AI scanner settings updated successfully",
            "updated": current_settings
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating AI scanner settings: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/settings/scanners", response_model=ScannerSettings)
async def get_scanner_settings_api():
    """
    Get all scanner enable/disable settings

    Returns the current state of all 32 security scanners including:
    - Core Security Scanners (SAST): Semgrep, Bandit, Gitleaks, etc.
    - Quality Scanners: Pylint, Flake8, Radon, etc.
    - Compliance Scanners: pip-audit, npm-audit, Syft
    - Advanced Scanners: Nuclei, CodeQL
    - High-Value Scanners: Snyk, Gosec, SpotBugs, Pyre, Horusec
    - Web & API Security: OWASP ZAP (static & DAST), API Fuzzer
    - AI-Powered Scanners: Zero-Day Detector, Business Logic, LLM Security, Auth Scanner
    """
    try:
        settings = await settings_manager.get_scanner_settings()
        return settings
    except Exception as e:
        logger.error(f"Error getting scanner settings: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.put("/settings/scanners")
async def update_scanner_settings_api(request: UpdateScannerSettingsRequest):
    """
    Update scanner enable/disable settings

    Allows enabling or disabling any of the 32 security scanners.
    Only provide the fields you want to update - all fields are optional.

    Example:
    ```json
    {
        "enable_semgrep": true,
        "enable_zap_dast": false,
        "enable_api_fuzzer": true
    }
    ```

    Note:
    - Only enabled scanners will run during security scans
    - Some scanners require additional setup (e.g., ZAP DAST requires Docker)
    - Changes take effect immediately on next scan
    """
    try:
        updated_settings = await settings_manager.update_scanner_settings(request)

        # Clear cache to ensure fresh settings on next scan
        settings_manager.clear_cache()

        return {
            "message": "Scanner settings updated successfully",
            "updated": updated_settings.model_dump()
        }

    except Exception as e:
        logger.error(f"Error updating scanner settings: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# GNN Model Management Endpoints
# ============================================

@api_router.get("/model/status")
async def get_model_status():
    """
    Get GNN model and update service status

    Returns:
    - Model version and loading status
    - Update service status
    - Feedback collection stats
    """
    try:
        from engines.zero_day.model_manager import get_model_manager
        from engines.zero_day.model_updater import get_update_service

        model_manager = await get_model_manager()
        update_service = await get_update_service()

        return {
            "model": model_manager.get_status(),
            "update_service": update_service.get_status()
        }
    except Exception as e:
        logger.warning(f"Model status check failed: {e}")
        return {
            "model": {"model_loaded": False, "error": str(e)},
            "update_service": {"enabled": False}
        }


@api_router.post("/model/check-update")
async def check_model_update():
    """
    Manually trigger a model update check

    This will:
    1. Check the configured update source for new versions
    2. Download and install if a newer version is available
    3. Validate the new model before activation
    4. Automatically rollback if validation fails
    """
    try:
        from engines.zero_day.model_updater import get_update_service

        update_service = await get_update_service()
        result = await update_service.force_update()

        return {
            "success": True,
            "result": result
        }
    except Exception as e:
        logger.error(f"Model update check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/model/feedback")
async def submit_model_feedback(
    file_path: str,
    detected_vulns: list[str],
    confirmed_vulns: list[str] = [],
    false_positives: list[str] = [],
    missed_vulns: list[str] = []
):
    """
    Submit feedback on model detection results

    This feedback is used to improve future model versions.
    It does NOT trigger immediate retraining.

    - **file_path**: Path of the analyzed file
    - **detected_vulns**: Vulnerabilities the model detected
    - **confirmed_vulns**: Which detections were correct (true positives)
    - **false_positives**: Which detections were wrong
    - **missed_vulns**: Vulnerabilities the model should have found
    """
    try:
        from engines.zero_day.model_manager import get_model_manager

        model_manager = await get_model_manager()

        # We need the code content to hash it
        # In practice, this would come from the scan result
        code_placeholder = f"feedback_for_{file_path}"

        await model_manager.submit_feedback(
            code=code_placeholder,
            file_path=file_path,
            detected_vulns=detected_vulns,
            confirmed_vulns=confirmed_vulns,
            false_positives=false_positives,
            missed_vulns=missed_vulns
        )

        return {
            "success": True,
            "message": "Feedback recorded successfully",
            "feedback_count": model_manager.get_status().get('feedback_count', 0)
        }
    except Exception as e:
        logger.error(f"Feedback submission failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Git Integration Endpoints
# ============================================

@api_router.get("/integrations/git")
async def get_git_integrations():
    """Get all connected Git integrations"""
    try:
        integrations = await git_integration_service.get_integrations()
        return {"integrations": [i.model_dump() for i in integrations]}
    except Exception as e:
        logger.error(f"Error getting git integrations: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/integrations/git/connect")
async def connect_git_integration(request: ConnectGitIntegrationRequest):
    """Connect a Git provider (GitHub/GitLab)"""
    try:
        result = await git_integration_service.connect_integration(
            provider=request.provider,
            name=request.name,
            access_token=request.access_token,
            base_url=request.base_url
        )

        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error", "Connection failed"))

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error connecting git integration: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.delete("/integrations/git/{provider}")
async def disconnect_git_integration(provider: str, name: str = None):
    """Disconnect a Git provider"""
    try:
        git_provider = GitProvider(provider)
        result = await git_integration_service.disconnect_integration(git_provider, name or provider)

        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error", "Disconnection failed"))

        return result
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error disconnecting git integration: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/integrations/git/{provider}/repositories")
async def list_remote_repositories(provider: str, page: int = 1, per_page: int = 30):
    """List repositories from the connected Git provider"""
    try:
        git_provider = GitProvider(provider)
        result = await git_integration_service.list_remote_repositories(
            git_provider, page=page, per_page=per_page
        )

        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error"))

        return result
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing repositories: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# NOTE: Duplicate GET /repositories removed - using the main endpoint above that queries db.repositories

@api_router.post("/repositories")
async def add_repository(request: AddRepositoryRequest):
    """Add a repository for scanning (supports both public repos and private repos with tokens)"""
    try:
        # If marked as public, use public repository method (no auth needed)
        if request.is_public:
            result = await git_integration_service.add_public_repository(
                provider=request.provider,
                repo_url=request.repo_url,
                auto_scan=request.auto_scan,
                branch=request.branch,
                access_token=request.access_token
            )
        elif request.access_token:
            # Token provided directly - use it
            result = await git_integration_service.add_public_repository(
                provider=request.provider,
                repo_url=request.repo_url,
                auto_scan=request.auto_scan,
                branch=request.branch,
                access_token=request.access_token
            )
        else:
            # Private repo without token - use Git Integration's stored token
            result = await git_integration_service.add_repository(
                provider=request.provider,
                repo_url=request.repo_url,
                auto_scan=request.auto_scan,
                branch=request.branch
            )

        if not result["success"]:
            raise HTTPException(status_code=400, detail=result.get("error"))

        # Also add to the main repositories collection for Dashboard display
        repo_data = result.get("repository", {})
        if repo_data:
            main_repo = Repository(
                id=repo_data.get("repo_id"),
                name=repo_data.get("name"),
                url=repo_data.get("clone_url"),
                branch=repo_data.get("default_branch", "main"),
                security_score=None,
                access_token=request.access_token  # Store token if provided for private repos
            )
            doc = main_repo.model_dump()
            doc['created_at'] = doc['created_at'].isoformat()
            doc['provider'] = repo_data.get("provider")
            doc['full_name'] = repo_data.get("full_name")
            doc['added_via'] = repo_data.get("added_via", "git_integration")
            # Upsert to avoid duplicates
            await db.repositories.update_one(
                {"id": main_repo.id},
                {"$set": doc},
                upsert=True
            )

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding repository: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.delete("/repositories/{repo_id}")
async def remove_repository(repo_id: str):
    """Remove a repository"""
    try:
        # Remove from git_repositories collection
        result = await git_integration_service.remove_repository(repo_id)

        # Also remove from main repositories collection
        await db.repositories.delete_one({"id": repo_id})

        # Also delete associated scans and vulnerabilities
        await db.scans.delete_many({"repo_id": repo_id})
        await db.vulnerabilities.delete_many({"repo_id": repo_id})

        if not result["success"]:
            # Even if git integration repo wasn't found, we may have removed from main collection
            return {"success": True, "message": "Repository removed"}

        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error removing repository: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


class UnifiedScanRequest(BaseModel):
    """Request model for unified comprehensive scan"""
    # Scanner toggles
    enable_zero_day: bool = True
    enable_business_logic: bool = True
    enable_llm_security: bool = True
    enable_auth_scanner: bool = True
    enable_codeql: bool = True
    enable_docker: bool = False
    enable_iac: bool = False

    # Runtime testing
    enable_runtime_testing: bool = False
    base_url: Optional[str] = None
    auth_token: Optional[str] = None

    # LLM API keys
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None

    # Docker images
    docker_images: List[str] = []

    # IaC directories
    terraform_dirs: List[str] = []
    kubernetes_dirs: List[str] = []

    # Language detection
    language: Optional[str] = None


@api_router.post("/repositories/{repo_id}/unified-scan")
async def unified_scan_repository(repo_id: str, config: UnifiedScanRequest, background_tasks: BackgroundTasks):
    """
    Run comprehensive unified security scan with all AI-powered scanners
    """
    from engines.unified_scanner import UnifiedSecurityScanner, UnifiedScanConfig

    try:
        # Get repository details
        repo = await db.repositories.find_one({"id": repo_id})
        if not repo:
            raise HTTPException(status_code=404, detail="Repository not found")

        # Clone to temporary directory
        import tempfile
        temp_dir = tempfile.mkdtemp(prefix="fortknox_unified_scan_")

        clone_result = await git_integration_service.clone_repository(
            repo_id=repo_id,
            target_dir=temp_dir,
            branch=repo.get("branch", "main")
        )

        if not clone_result["success"]:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=clone_result.get("error"))

        # Update scan status
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {"scan_status": "running"}}
        )

        # Prepare scan configuration
        scan_config = UnifiedScanConfig(
            repo_path=temp_dir,
            language=config.language,
            enable_zero_day=config.enable_zero_day,
            enable_business_logic=config.enable_business_logic,
            enable_llm_security=config.enable_llm_security,
            enable_auth_scanner=config.enable_auth_scanner,
            enable_codeql=config.enable_codeql,
            enable_docker=config.enable_docker,
            enable_iac=config.enable_iac,
            enable_runtime_testing=config.enable_runtime_testing,
            base_url=config.base_url,
            auth_headers={"Authorization": f"Bearer {config.auth_token}"} if config.auth_token else None,
            llm_api_keys={
                "openai": config.openai_api_key,
                "anthropic": config.anthropic_api_key
            } if config.openai_api_key or config.anthropic_api_key else None,
            docker_images=config.docker_images,
            terraform_dirs=config.terraform_dirs,
            kubernetes_dirs=config.kubernetes_dirs
        )

        # Run unified scan
        scanner = UnifiedSecurityScanner(scan_config)
        scan_results = await scanner.run_comprehensive_scan()

        # Generate consolidated report
        report = scanner.generate_consolidated_report()

        # Store scan results
        scan_id = str(uuid.uuid4())
        scan_document = {
            "id": scan_id,
            "repo_id": repo_id,
            "timestamp": datetime.now(timezone.utc),
            "config": config.model_dump(),
            "results": report,
            "raw_findings": {
                "zero_day": [f.__dict__ for f in scan_results.zero_day_findings] if hasattr(scan_results.zero_day_findings[0] if scan_results.zero_day_findings else None, '__dict__') else scan_results.zero_day_findings,
                "business_logic": [f.__dict__ for f in scan_results.business_logic_findings] if hasattr(scan_results.business_logic_findings[0] if scan_results.business_logic_findings else None, '__dict__') else scan_results.business_logic_findings,
                "llm": [f.model_dump() if hasattr(f, 'model_dump') else f.__dict__ for f in scan_results.llm_findings],
                "auth": [f.__dict__ for f in scan_results.auth_findings] if hasattr(scan_results.auth_findings[0] if scan_results.auth_findings else None, '__dict__') else scan_results.auth_findings,
                "codeql": [f.__dict__ for f in scan_results.codeql_findings] if hasattr(scan_results.codeql_findings[0] if scan_results.codeql_findings else None, '__dict__') else scan_results.codeql_findings,
                "docker": [f.__dict__ for f in scan_results.docker_findings] if hasattr(scan_results.docker_findings[0] if scan_results.docker_findings else None, '__dict__') else scan_results.docker_findings,
                "iac": [f.__dict__ for f in scan_results.iac_findings] if hasattr(scan_results.iac_findings[0] if scan_results.iac_findings else None, '__dict__') else scan_results.iac_findings,
            }
        }

        await db.unified_scans.insert_one(scan_document)

        # Update repository with scan results
        await db.repositories.update_one(
            {"id": repo_id},
            {
                "$set": {
                    "last_scan": datetime.now(timezone.utc).isoformat(),
                    "scan_status": "completed",
                    "vulnerabilities_count": scan_results.total_vulnerabilities,
                    "critical_count": scan_results.critical_count,
                    "high_count": scan_results.high_count,
                    "security_score": max(0, 100 - report["risk_score"])
                }
            }
        )

        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)

        return {
            "success": True,
            "scan_id": scan_id,
            "report": report,
            "message": f"Comprehensive scan completed. Found {scan_results.total_vulnerabilities} vulnerabilities."
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in unified scan: {str(e)}", exc_info=True)
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {"scan_status": "failed"}}
        )
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/repositories/{repo_id}/latest-scan")
async def get_latest_scan(repo_id: str):
    """Get latest unified scan results for a repository"""
    try:
        scan = await db.unified_scans.find_one(
            {"repo_id": repo_id},
            sort=[("timestamp", -1)]
        )

        if not scan:
            raise HTTPException(status_code=404, detail="No scan results found")

        # Remove MongoDB _id field
        scan.pop("_id", None)

        return scan["results"]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching latest scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/repositories/{repo_id}/scan")
async def scan_repository(repo_id: str, branch: str = None):
    """Clone and scan a repository (legacy endpoint)"""
    import tempfile
    import shutil

    try:
        # Clone to temporary directory
        temp_dir = tempfile.mkdtemp(prefix="fortknox_scan_")

        clone_result = await git_integration_service.clone_repository(
            repo_id=repo_id,
            target_dir=temp_dir,
            branch=branch
        )

        if not clone_result["success"]:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=clone_result.get("error"))

        # The actual scanning would be triggered here
        # For now, return the cloned path for manual scanning
        return {
            "success": True,
            "message": f"Repository cloned to {temp_dir}",
            "path": temp_dir,
            "branch": clone_result.get("branch"),
            "note": "Use /repositories/{repo_id}/unified-scan for comprehensive AI-powered scanning"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error scanning repository: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB shutdown is now handled by the lifespan context manager above
