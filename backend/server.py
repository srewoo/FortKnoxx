from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
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
from scanners import cargo_audit_scanner
from scanners import spotbugs_scanner
from scanners import pyre_scanner
from scanners import zap_scanner
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

# Import LLM orchestrator
from llm.orchestrator import LLMOrchestrator

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Nothing needed
    yield
    # Shutdown: Close MongoDB connection
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
    access_token: str
    branch: str = "main"
    last_scan: Optional[str] = None
    scan_status: str = "pending"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Security metrics from latest scan
    security_score: Optional[int] = None
    vulnerabilities_count: int = 0
    critical_count: int = 0
    high_count: int = 0

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
    code_snippet: str
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    fix_recommendation: Optional[str] = None
    detected_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

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

class APIKeysUpdate(BaseModel):
    openai_key: Optional[str] = None
    anthropic_key: Optional[str] = None
    gemini_key: Optional[str] = None

# Utility Functions
async def clone_repository(repo_url: str, token: str, branch: str, repo_id: str) -> Optional[str]:
    """Clone repository to local directory with automatic branch detection"""
    try:
        # Validate repo_id to prevent path traversal
        if not repo_id or '/' in repo_id or '\\' in repo_id or '..' in repo_id:
            logger.error(f"Invalid repo_id: {repo_id}")
            return None

        clone_dir = f"/tmp/repos/{repo_id}"
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

async def process_scan_results(repo_id: str, scan_id: str, repo_path: str):
    """Process all scan results and store vulnerabilities"""
    try:
        # Update scan status
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "scanning"}}
        )
        
        # Run all scanners
        semgrep_results = await run_semgrep_scan(repo_path)
        gitleaks_results = await run_gitleaks_scan(repo_path)
        trivy_results = await run_trivy_scan(repo_path)
        checkov_results = await run_checkov_scan(repo_path)

        # Run new free security scanners
        bandit_scanner = BanditScanner()
        trufflehog_scanner = TruffleHogScanner()
        grype_scanner = GrypeScanner()
        eslint_scanner = ESLintSecurityScanner()

        bandit_results = []
        trufflehog_results = []
        grype_results = []
        eslint_results = []

        # Run Bandit if available (Python security)
        if await bandit_scanner.is_available():
            bandit_results = await bandit_scanner.scan(repo_path)
            logger.info(f"Bandit scan completed: {len(bandit_results)} issues found")

        # Run TruffleHog if available (secret detection)
        if await trufflehog_scanner.is_available():
            trufflehog_results = await trufflehog_scanner.scan(repo_path, scan_history=True)
            logger.info(f"TruffleHog scan completed: {len(trufflehog_results)} secrets found")

        # Run Grype if available (dependency vulnerabilities)
        if await grype_scanner.is_available():
            grype_results = await grype_scanner.scan(repo_path)
            logger.info(f"Grype scan completed: {len(grype_results)} vulnerabilities found")

        # Run ESLint if available (JavaScript/TypeScript security)
        if await eslint_scanner.is_available():
            eslint_results = await eslint_scanner.scan(repo_path)
            logger.info(f"ESLint scan completed: {len(eslint_results)} issues found")

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

        # Run quality scanners
        if await pylint_scanner.is_available():
            pylint_results = await pylint_scanner.scan(repo_path)
            logger.info(f"Pylint scan completed: {len(pylint_results)} issues found")

        if await flake8_scanner.is_available():
            flake8_results = await flake8_scanner.scan(repo_path)
            logger.info(f"Flake8 scan completed: {len(flake8_results)} issues found")

        if await radon_scanner.is_available():
            radon_results = await radon_scanner.scan(repo_path)
            logger.info(f"Radon scan completed: {len(radon_results)} complexity issues found")

        if await shellcheck_scanner.is_available():
            shellcheck_results = await shellcheck_scanner.scan(repo_path)
            logger.info(f"ShellCheck scan completed: {len(shellcheck_results)} issues found")

        if await hadolint_scanner.is_available():
            hadolint_results = await hadolint_scanner.scan(repo_path)
            logger.info(f"Hadolint scan completed: {len(hadolint_results)} Dockerfile issues found")

        # Run enhanced quality scanners
        sqlfluff_results = await sqlfluff_scanner.scan(repo_path)
        logger.info(f"SQLFluff scan completed: {len(sqlfluff_results)} SQL issues found")

        pydeps_results = await pydeps_scanner.scan(repo_path)
        logger.info(f"pydeps scan completed: {len(pydeps_results)} architecture issues found")

        # Run Nuclei for configuration and template-based scanning
        nuclei_results = await nuclei_scanner.scan(repo_path)
        logger.info(f"Nuclei scan completed: {len(nuclei_results)} configuration issues found")

        # Run enhanced security scanners (High Value Additions)
        snyk_results = await snyk_scanner.scan(repo_path)
        logger.info(f"Snyk scan completed: {len(snyk_results)} dependency/code issues found")

        gosec_results = await gosec_scanner.scan(repo_path)
        logger.info(f"Gosec scan completed: {len(gosec_results)} Go security issues found")

        cargo_audit_results = await cargo_audit_scanner.scan(repo_path)
        logger.info(f"cargo-audit scan completed: {len(cargo_audit_results)} Rust issues found")

        spotbugs_results = await spotbugs_scanner.scan(repo_path)
        logger.info(f"SpotBugs scan completed: {len(spotbugs_results)} Java issues found")

        pyre_results = await pyre_scanner.scan(repo_path)
        logger.info(f"Pyre scan completed: {len(pyre_results)} Python type issues found")

        zap_results = await zap_scanner.scan(repo_path)
        logger.info(f"ZAP scan completed: {len(zap_results)} web security issues found")

        horusec_results = await horusec_scanner.scan(repo_path)
        logger.info(f"Horusec scan completed: {len(horusec_results)} multi-language issues found")

        # Run compliance scanners
        if await pip_audit_scanner.is_available():
            pip_audit_results = await pip_audit_scanner.scan(repo_path)
            logger.info(f"pip-audit scan completed: {len(pip_audit_results)} vulnerabilities found")

        if await npm_audit_scanner.is_available():
            npm_audit_results = await npm_audit_scanner.scan(repo_path)
            logger.info(f"npm-audit scan completed: {len(npm_audit_results)} vulnerabilities found")

        if await syft_scanner.is_available():
            syft_results = await syft_scanner.scan(repo_path)
            logger.info(f"Syft scan completed: {len(syft_results)} license issues found")

        vulnerabilities = []
        quality_issues = []
        compliance_issues = []
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        # Process Semgrep results
        for finding in semgrep_results:
            severity = finding.get("extra", {}).get("severity", "medium").lower()
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
            severity = dep.get("Severity", "MEDIUM").lower()
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
            severity = check.get("check_result", {}).get("result", {}).get("severity", "MEDIUM").lower()
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
            severity = finding.get("severity", "medium")
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
            severity = finding.get("severity", "critical")
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
            severity = finding.get("severity", "medium")
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
            severity = finding.get("severity", "medium")
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
            severity = finding.get("severity", "medium")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Process enhanced scanner results (High Value Additions)
        enhanced_security_results = (
            snyk_results + gosec_results + cargo_audit_results +
            spotbugs_results + pyre_results + zap_results + horusec_results
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
            severity = finding.get("severity", "medium")
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
            severity = finding.get("severity", "medium")
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
        if vulnerabilities and os.path.exists(repo_path):
            logger.info("Starting context-aware analysis...")
            context_analyzer = ContextAnalyzer()

            # Analyze repository structure
            repo_structure = await context_analyzer.analyze_repository_structure(repo_path)
            logger.info(f"Repository structure analyzed: {repo_structure.get('total_files', 0)} files")

            # Enrich and prioritize vulnerabilities
            enriched_vulns = await context_analyzer.prioritize_vulnerabilities(
                vulnerabilities,
                repo_path
            )

            # Replace vulnerabilities with enriched versions
            vulnerabilities = enriched_vulns

            # Recalculate severity counts based on enriched data
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for vuln in vulnerabilities:
                # Ensure every vulnerability has a severity
                severity = vuln.get("severity", "medium").lower()
                if severity not in severity_counts:
                    severity = "medium"  # Default to medium if invalid
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Generate priority report
            priority_report = context_analyzer.generate_priority_report(enriched_vulns)
            logger.info(f"Priority analysis complete: {priority_report.get('critical_priority', 0)} critical, "
                       f"{priority_report.get('high_priority', 0)} high priority issues")
        else:
            # Ensure all vulnerabilities have severity even without context analysis
            for vuln in vulnerabilities:
                if "severity" not in vuln or not vuln["severity"]:
                    vuln["severity"] = "medium"  # Default severity

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

        # Update scan
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {
                "status": "completed",
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
                    "horusec": len(horusec_results),
                    "pip_audit": len(pip_audit_results),
                    "npm_audit": len(npm_audit_results),
                    "syft": len(syft_results)
                }
            }}
        )
        
        # Update repository
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {
                "last_scan": datetime.now(timezone.utc).isoformat(),
                "scan_status": "completed"
            }}
        )
        
        # Cleanup
        if os.path.exists(repo_path):
            shutil.rmtree(repo_path)
        
        logger.info(f"Scan {scan_id} completed with {len(vulnerabilities)} vulnerabilities")
        
    except Exception as e:
        logger.error(f"Error processing scan: {str(e)}")
        await db.scans.update_one(
            {"id": scan_id},
            {"$set": {"status": "failed", "completed_at": datetime.now(timezone.utc).isoformat()}}
        )
        await db.repositories.update_one(
            {"id": repo_id},
            {"$set": {"scan_status": "failed"}}
        )

# API Routes
@api_router.get("/")
async def root():
    return {"message": "Security Intelligence Platform API", "version": "1.0.0"}

@api_router.post("/repositories", response_model=Repository)
async def create_repository(repo: RepositoryCreate):
    """Create a new repository"""
    try:
        repo_obj = Repository(**repo.model_dump())
        doc = repo_obj.model_dump()
        doc['created_at'] = doc['created_at'].isoformat()
        await db.repositories.insert_one(doc)
        return repo_obj
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
        
        # Start background scan
        background_tasks.add_task(process_scan_results, repo_id, scan.id, repo_path)
        
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

        # Initialize LLM orchestrator with database connection
        orchestrator = LLMOrchestrator(db=db)

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

@api_router.get("/settings/api-keys")
async def get_api_keys_status():
    """Get status of configured API keys (not the actual keys)"""
    # Get keys from environment or database
    settings = await db.settings.find_one({"type": "api_keys"}, {"_id": 0})

    # Check environment variables as fallback
    openai_configured = bool(os.getenv("OPENAI_API_KEY")) or bool(settings and settings.get("openai_key"))
    anthropic_configured = bool(os.getenv("ANTHROPIC_API_KEY")) or bool(settings and settings.get("anthropic_key"))
    gemini_configured = bool(os.getenv("GEMINI_API_KEY")) or bool(settings and settings.get("gemini_key"))

    return {
        "openai": {"configured": openai_configured, "masked": "****" if openai_configured else None},
        "anthropic": {"configured": anthropic_configured, "masked": "****" if anthropic_configured else None},
        "gemini": {"configured": gemini_configured, "masked": "****" if gemini_configured else None}
    }

@api_router.post("/settings/api-keys")
async def update_api_keys(keys: APIKeysUpdate):
    """Update API keys in database"""
    try:
        update_data = {}
        if keys.openai_key:
            update_data["openai_key"] = keys.openai_key
            os.environ["OPENAI_API_KEY"] = keys.openai_key
        if keys.anthropic_key:
            update_data["anthropic_key"] = keys.anthropic_key
            os.environ["ANTHROPIC_API_KEY"] = keys.anthropic_key
        if keys.gemini_key:
            update_data["gemini_key"] = keys.gemini_key
            os.environ["GEMINI_API_KEY"] = keys.gemini_key

        if update_data:
            update_data["type"] = "api_keys"
            update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
            await db.settings.update_one(
                {"type": "api_keys"},
                {"$set": update_data},
                upsert=True
            )

        return {"message": "API keys updated successfully", "updated": list(update_data.keys())}
    except Exception as e:
        logger.error(f"Error updating API keys: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.delete("/settings/api-keys/{provider}")
async def delete_api_key(provider: str):
    """Delete an API key for a specific provider"""
    try:
        provider = provider.lower()
        key_map = {
            "openai": "openai_key",
            "anthropic": "anthropic_key",
            "gemini": "gemini_key"
        }

        if provider not in key_map:
            raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

        # Remove from database
        await db.settings.update_one(
            {"type": "api_keys"},
            {"$unset": {key_map[provider]: ""}}
        )

        # Remove from environment (if set via API)
        env_key = f"{provider.upper()}_API_KEY"
        if env_key in os.environ:
            del os.environ[env_key]

        return {"message": f"{provider} API key deleted successfully"}
    except Exception as e:
        logger.error(f"Error deleting API key: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

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

        # High Value Addition scanners (7)
        "snyk": {"name": "Snyk CLI", "type": "Modern Dependency Scanner", "installed": bool(shutil.which("snyk"))},
        "gosec": {"name": "Gosec", "type": "Go Security", "installed": bool(shutil.which("gosec"))},
        "cargo_audit": {"name": "cargo-audit", "type": "Rust Security", "installed": bool(shutil.which("cargo-audit") or shutil.which("cargo"))},
        "spotbugs": {"name": "SpotBugs", "type": "Java Bytecode Analysis", "installed": bool(shutil.which("spotbugs"))},
        "pyre": {"name": "Pyre", "type": "Python Type Checker", "installed": bool(shutil.which("pyre"))},
        "zap": {"name": "OWASP ZAP", "type": "Web Security (DAST)", "installed": bool(shutil.which("zap-baseline.py") or shutil.which("zaproxy"))},
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
        else:
            return {"message": "PDF generation not yet implemented"}
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
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
