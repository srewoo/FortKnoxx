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

    # Publish singletons to api.deps for the route modules. Done after
    # the managers are wired up but before scanner health runs so any
    # extracted health route can read state during startup probes.
    # Single shared LLM orchestrator — used by autofix, triage, and the
    # legacy fix-recommendation route.
    llm_orchestrator = LLMOrchestrator(db=db, settings_manager=settings_manager)

    api_deps.bind(
        db=db,
        client=client,
        settings_manager=settings_manager,
        git_integration_service=git_integration_service,
        encryption_service=encryption_service,
        llm_orchestrator=llm_orchestrator,
    )

    # Run scanner health check at startup
    logger.info("Running scanner health check...")
    try:
        scanner_settings = await settings_manager.get_scanner_settings()
        _scanner_health_report = await check_all_scanners(scanner_settings)
        log_scanner_health_report(_scanner_health_report)
        api_deps.bind(scanner_health_report=_scanner_health_report)

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

    # Phase 2: Postgres engine (lazy, optional).
    # `db_client.get_engine()` reads POSTGRES_DSN from env. We swallow
    # the configuration error so existing Mongo-only deployments keep
    # working — Phase 2 is opt-in until the request path actually
    # depends on Postgres tables.
    pg_engine_loaded = False
    if os.environ.get("POSTGRES_DSN"):
        try:
            from db_client import get_engine

            get_engine()  # eager-init pool so request-path latency is unaffected
            pg_engine_loaded = True
            logger.info("Postgres engine initialised (Phase 2)")
        except Exception as exc:  # noqa: BLE001 — Phase 2 is optional today.
            logger.warning("Postgres engine init skipped: %s", exc)
    else:
        logger.info("POSTGRES_DSN not set; Phase 2 (Postgres) inactive — Mongo path only.")

    yield

    # Shutdown: stop update service, dispose Postgres pool, close Mongo.
    if update_service:
        await update_service.stop()
    if pg_engine_loaded:
        try:
            from db_client import dispose_engine

            await dispose_engine()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Postgres dispose failed: %s", exc)
    client.close()

# Create the main app without a prefix
app = FastAPI(
    title="FortKnoxx Security Intelligence Platform",
    description=(
        "Unified security scanning API: SAST, DAST, SCA, IaC, secrets, "
        "container, and AI-powered scanners (zero-day GNN, business "
        "logic, LLM adversarial, auth)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# OpenTelemetry tracing — no-op unless OTEL_EXPORTER_OTLP_ENDPOINT is set.
try:
    from utils.telemetry import init_telemetry
    init_telemetry(app=app)
except Exception as _otel_exc:
    logger.debug("OTel init skipped: %s", _otel_exc)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# OWASP Top 10 Mapping
# OWASP categories live in services.owasp (Phase 1.5).
from services.owasp import OWASP_CATEGORIES

# Define Models
# Schemas live in api.schemas now (Phase 1 decomposition). Re-exported
# here so the rest of server.py keeps working without changes.
from api.schemas import (
    AIFixRequest,
    ReportRequest,
    Repository,
    RepositoryCreate,
    Scan,
    Vulnerability,
)
from api import deps as api_deps
from services.result_safety import safe_findings

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

# Severity / OWASP normalisation moved to services.normalisation (Phase 1.5).
from services.normalisation import map_to_owasp, normalize_severity  # noqa: E402,F401

# Score calculations live in services.scoring (Phase 1.5).
from services.scoring import (
    calculate_compliance_score,
    calculate_quality_score,
    calculate_security_score,
)

async def process_scan_with_timeout(repo_id: str, scan_id: str, repo_path: str, tier: str | None = None):
    """
    Wrapper function that enforces total scan timeout.
    This prevents scans from running indefinitely.
    """
    scan_limits = get_scan_limits()
    total_timeout = scan_limits.total_scan_timeout  # Default: 3600 seconds (1 hour)

    try:
        await asyncio.wait_for(
            process_scan_results(repo_id, scan_id, repo_path, tier=tier),
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


async def process_scan_results(repo_id: str, scan_id: str, repo_path: str, tier: str | None = None):
    """Process all scan results and store vulnerabilities.

    ``tier`` ∈ {"fast", "deep", "auto", None}. When set, scanners outside
    the tier's allowlist are turned off for this scan only — user's saved
    enable/disable preferences are preserved otherwise.
    """

    # `normalize_severity` and `map_to_owasp` are imported at module
    # level from services.normalisation — no inline shadowing needed.

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

        # Apply tier override (fast vs deep) if requested. Resolved tier is
        # stored on the scan record so the UI can display which mode ran.
        if tier:
            from engines.tiers import resolve_tier, apply_tier
            decision = resolve_tier(tier, repo_path)
            scanner_settings = apply_tier(scanner_settings, decision.tier)
            logger.info(
                "Tier resolved: %s (reason=%s, diff_lines=%d, forced=%s)",
                decision.tier, decision.reason, decision.diff_lines, decision.forced,
            )
            await db.scans.update_one(
                {"id": scan_id},
                {"$set": {
                    "tier": decision.tier,
                    "tier_reason": decision.reason,
                    "tier_diff_lines": decision.diff_lines,
                }},
            )

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

        # Aggregate scanner results.
        # ScanAggregator owns the per-finding state (vulnerabilities,
        # quality_issues, compliance_issues, severity_counts) and has
        # one method per scanner. The class lives in
        # services/scan_aggregator.py and is unit-tested independently.
        from services.scan_aggregator import ScanAggregator

        aggregator = ScanAggregator(repo_id=repo_id, scan_id=scan_id)

        # Structured-output scanners.
        aggregator.add_semgrep(semgrep_results)
        aggregator.add_gitleaks(gitleaks_results)
        aggregator.add_trivy(trivy_results)
        aggregator.add_checkov(checkov_results)

        # Dict-shaped scanner outputs (already vuln-like).
        aggregator.add_bandit(bandit_results)
        aggregator.add_trufflehog(trufflehog_results)
        aggregator.add_grype(grype_results)
        aggregator.add_eslint(eslint_results)
        aggregator.add_quality(
            pylint_results + flake8_results + radon_results + shellcheck_results +
            hadolint_results + sqlfluff_results + pydeps_results
        )
        aggregator.add_nuclei(nuclei_results)
        aggregator.add_enhanced_security(
            snyk_results + gosec_results + cargo_audit_results +
            spotbugs_results + pyre_results + zap_results + api_fuzzer_results + horusec_results
        )
        aggregator.add_dep_audit(pip_audit_results + npm_audit_results)
        aggregator.add_compliance(syft_results)

        # AI-typed scanners (objects, not dicts).
        aggregator.add_zero_day(zero_day_results)
        aggregator.add_business_logic(business_logic_results)
        aggregator.add_llm_security(llm_security_results)
        aggregator.add_auth_scanner(auth_scanner_results)

        # Hand off to local names so the rest of process_scan_results
        # (false-positive filter, context analyzer, score calc, Mongo
        # writes) keeps working without changes.
        vulnerabilities = aggregator.vulnerabilities
        quality_issues = aggregator.quality_issues
        compliance_issues = aggregator.compliance_issues
        severity_counts = aggregator.severity_counts

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

        # Triage pipeline (cross-scanner dedup + LLM verdict cache + ignore.yml).
        # Opt-in via FORTKNOXX_TRIAGE=1 while we ramp up; defaults to off so
        # existing scan output stays byte-identical until we flip the switch.
        if vulnerabilities and os.environ.get("FORTKNOXX_TRIAGE") == "1":
            try:
                from engines.triage import run_triage
                pre = len(vulnerabilities)
                vulnerabilities, triage_meta = await run_triage(
                    vulnerabilities,
                    repo_path=repo_path,
                    db=db,
                    orchestrator=globals().get("llm_orchestrator"),
                    enable_llm=os.environ.get("FORTKNOXX_TRIAGE_LLM", "1") == "1",
                )
                logger.info(
                    "Triage: %d → %d findings (cache_hits=%d, llm_calls=%d, suppressed=%d)",
                    pre,
                    len(vulnerabilities),
                    triage_meta["llm_cache_hits"],
                    triage_meta["llm_calls"],
                    triage_meta["suppressed_count"],
                )
            except Exception as exc:
                logger.exception("Triage pipeline failed, falling back to legacy filter only: %s", exc)

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

        # The false-positive filter and context-analyzer enrichment can
        # reshape the vulnerabilities list. Push it back into the
        # aggregator and let it re-derive severity_counts in one place.
        aggregator.vulnerabilities = vulnerabilities
        aggregator.recompute_severity_counts()
        severity_counts = aggregator.severity_counts

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
        logger.exception(f"Error processing scan: {str(e)}")
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

# Health and root routes now live in api.routes.health (Phase 1.5).
from api.routes import health as _health_routes
api_router.include_router(_health_routes.router)

# Repository read + delete routes now live in api.routes.repositories
# (Phase 1.5). The previously duplicated DELETE handler at line ~2737
# (`remove_repository`) is consolidated into the extracted version.
from api.routes import repositories as _repository_routes
api_router.include_router(_repository_routes.router)

@api_router.post("/scans/{repo_id}")
async def start_scan(repo_id: str, background_tasks: BackgroundTasks, tier: str = "auto"):
    """Start a security scan for a repository.

    ``tier`` query param:
      • ``fast``  — secrets + linters + Semgrep/Bandit/ESLint (~seconds).
      • ``deep``  — full sweep including ML, DAST, runtime probes (minutes).
      • ``auto``  — pick fast for small diffs, deep for large/release branches.
    """
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
        background_tasks.add_task(process_scan_with_timeout, repo_id, scan.id, repo_path, tier)

        return {
            "scan_id": scan.id,
            "status": "started",
            "tier": tier,
            "message": "Scan initiated successfully",
        }
    
    except Exception as e:
        logger.error(f"Error starting scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Scan read/delete routes moved to api.routes.scans (Phase 1.5).
# POST /scans/{repo_id} (start_scan) above keeps living here until the
# scan orchestrator service is extracted in Phase 1.6.
from api.routes import scans as _scan_routes
api_router.include_router(_scan_routes.router)

# Findings list/summary/sbom routes moved to api.routes.findings (Phase 1.5).
from api.routes import findings as _findings_routes
api_router.include_router(_findings_routes.router)

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

        orchestrator = LLMOrchestrator(db=db, settings_manager=settings_manager)
        # The orchestrator resolves model IDs against llm.model_registry —
        # a None / unknown / legacy value is auto-migrated to the current
        # default for the requested provider.
        model = request.model or orchestrator.get_default_model(request.provider)

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

# Stats route now lives in api.routes.stats (Phase 1.5).
from api.routes import stats as _stats_routes
api_router.include_router(_stats_routes.router)

# Settings routes moved to api.routes.settings (Phase 1.5).
# Includes: /settings, /settings/api-keys (POST + GET masked),
# /settings/scanners (installed binaries) + /settings/scanners/config
# (persisted state) + PUT, /settings/ai-scanners (GET + POST).
# Duplicate GET /settings/scanners handler at line ~2064 of the
# pre-refactor file was consolidated.
from api.routes import settings as _settings_routes
api_router.include_router(_settings_routes.router)

# Report generation moved to api.routes.reports (Phase 1.5).
from api.routes import reports as _report_routes
api_router.include_router(_report_routes.router)

# Autofix: structured unified-diff fix generator with cache + git apply check.
from api.routes import autofix as _autofix_routes
api_router.include_router(_autofix_routes.router)

# Trend dashboard, owner breakdown, top-risk list, compliance evidence pack.
from api.routes import trends as _trend_routes
api_router.include_router(_trend_routes.router)


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


# Settings endpoints fully extracted to api.routes.settings (Phase 1.5).


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

# Git integration list/connect/disconnect routes moved to
# api.routes.integrations (Phase 1.5). The `POST /repositories`
# handler that cross-writes to the main repositories collection stays
# below until the repository service is extracted.
from api.routes import integrations as _integration_routes
api_router.include_router(_integration_routes.router)


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


# NOTE: Duplicate `remove_repository` handler removed — consolidated
# into api.routes.repositories.delete_repository.

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
