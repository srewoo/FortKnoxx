"""
Universal Vulnerability Schema (UVS) for FortKnoxx
Standardized format for all vulnerability findings
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from enum import Enum
import uuid


class VulnerabilityCategory(str, Enum):
    """Vulnerability categories"""
    # Traditional security
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    SECRETS = "secrets"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"

    # Business logic (NEW)
    BUSINESS_LOGIC = "business_logic"
    IDOR = "idor"
    WORKFLOW_BYPASS = "workflow_bypass"
    RACE_CONDITION = "race_condition"
    PRICE_TAMPERING = "price_tampering"
    REPLAY_ATTACK = "replay_attack"

    # LLM-specific (NEW)
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_LEAKAGE = "data_leakage"
    LLM_PERMISSION_ABUSE = "llm_permission_abuse"
    MODEL_POISONING = "model_poisoning"

    # Code quality
    CODE_QUALITY = "code_quality"
    COMPLEXITY = "complexity"
    DEAD_CODE = "dead_code"

    # Other
    OTHER = "other"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExploitabilityLevel(str, Enum):
    """How easily a vulnerability can be exploited"""
    TRIVIAL = "trivial"  # Automated exploitation possible
    EASY = "easy"  # Basic technical knowledge required
    MODERATE = "moderate"  # Intermediate skills required
    DIFFICULT = "difficult"  # Advanced skills required
    THEORETICAL = "theoretical"  # Proof of concept only


class RemediationEffort(str, Enum):
    """Estimated effort to fix"""
    TRIVIAL = "trivial"  # < 1 hour
    LOW = "low"  # 1-4 hours
    MEDIUM = "medium"  # 1-3 days
    HIGH = "high"  # 1-2 weeks
    EXTENSIVE = "extensive"  # > 2 weeks


class OWASPMapping(BaseModel):
    """OWASP Top 10 mapping"""
    category: str  # e.g., "A01", "A03"
    name: str  # e.g., "Broken Access Control"
    year: int = 2021  # OWASP version


class CWEMapping(BaseModel):
    """Common Weakness Enumeration mapping"""
    cwe_id: str  # e.g., "CWE-89"
    name: str  # e.g., "SQL Injection"


class Remediation(BaseModel):
    """Remediation information"""
    recommended_fix: str
    ai_generated_patch: Optional[str] = None
    code_example: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    effort: RemediationEffort = RemediationEffort.MEDIUM


class UniversalVulnerability(BaseModel):
    """
    Universal Vulnerability Schema (UVS)
    Standardized representation of all security findings
    """
    model_config = ConfigDict(extra="ignore")

    # Core identification
    vuln_id: str = Field(default_factory=lambda: f"FX-{str(uuid.uuid4())[:8].upper()}")
    title: str
    description: str

    # Classification
    category: VulnerabilityCategory
    type: str  # Specific type (e.g., "sql_injection", "jwt_algorithm_confusion")
    severity: VulnerabilitySeverity
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)  # Detection confidence
    exploitability: ExploitabilityLevel = ExploitabilityLevel.MODERATE

    # Location
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    function_name: Optional[str] = None
    class_name: Optional[str] = None

    # Impact assessment
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None
    affected_components: List[str] = Field(default_factory=list)

    # Detection metadata
    detection_source: str  # e.g., "semgrep", "logic-engine", "llm-security"
    detection_timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scanner_version: Optional[str] = None

    # Standards mapping
    owasp_mappings: List[OWASPMapping] = Field(default_factory=list)
    cwe_mappings: List[CWEMapping] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    # Remediation
    remediation: Optional[Remediation] = None

    # LLM-specific fields
    ai_exploit_simulated: bool = False
    exploit_payload: Optional[str] = None
    attack_scenario: Optional[str] = None

    # Business logic specific
    flow_graph_node: Optional[str] = None
    violated_rule: Optional[str] = None

    # Status tracking
    status: str = "open"  # open, acknowledged, false_positive, fixed, wont_fix
    assigned_to: Optional[str] = None
    fixed_in_version: Optional[str] = None

    # Additional metadata
    repo_id: str
    scan_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # Audit trail
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_sarif(self) -> Dict[str, Any]:
        """Convert to SARIF format for IDE integration"""
        return {
            "ruleId": self.vuln_id,
            "level": self._severity_to_sarif_level(),
            "message": {
                "text": self.description
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": self.file_path
                    },
                    "region": {
                        "startLine": self.line_start,
                        "endLine": self.line_end or self.line_start
                    }
                }
            }]
        }

    def _severity_to_sarif_level(self) -> str:
        """Map severity to SARIF level"""
        mapping = {
            VulnerabilitySeverity.CRITICAL: "error",
            VulnerabilitySeverity.HIGH: "error",
            VulnerabilitySeverity.MEDIUM: "warning",
            VulnerabilitySeverity.LOW: "note",
            VulnerabilitySeverity.INFO: "note"
        }
        return mapping.get(self.severity, "warning")

    def calculate_risk_score(self) -> float:
        """
        Calculate composite risk score (0-100)
        Based on severity, exploitability, and confidence
        """
        # Severity weights
        severity_weights = {
            VulnerabilitySeverity.CRITICAL: 10,
            VulnerabilitySeverity.HIGH: 8,
            VulnerabilitySeverity.MEDIUM: 5,
            VulnerabilitySeverity.LOW: 2,
            VulnerabilitySeverity.INFO: 1
        }

        # Exploitability weights
        exploit_weights = {
            ExploitabilityLevel.TRIVIAL: 1.0,
            ExploitabilityLevel.EASY: 0.9,
            ExploitabilityLevel.MODERATE: 0.7,
            ExploitabilityLevel.DIFFICULT: 0.4,
            ExploitabilityLevel.THEORETICAL: 0.2
        }

        severity_score = severity_weights.get(self.severity, 5)
        exploit_mult = exploit_weights.get(self.exploitability, 0.7)

        risk = severity_score * exploit_mult * self.confidence * 10

        return min(100, max(0, risk))

    def is_high_priority(self) -> bool:
        """Determine if vulnerability is high priority"""
        return (
            self.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]
            and self.exploitability in [ExploitabilityLevel.TRIVIAL, ExploitabilityLevel.EASY]
            and self.confidence >= 0.7
        )


class VulnerabilityStats(BaseModel):
    """Statistics for vulnerability scanning results"""
    total_vulnerabilities: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_source: Dict[str, int] = Field(default_factory=dict)
    high_priority_count: int = 0
    average_confidence: float = 0.0
    average_risk_score: float = 0.0

    @classmethod
    def from_vulnerabilities(cls, vulnerabilities: List[UniversalVulnerability]) -> "VulnerabilityStats":
        """Generate statistics from vulnerability list"""
        stats = cls(total_vulnerabilities=len(vulnerabilities))

        if not vulnerabilities:
            return stats

        # Count by severity
        for vuln in vulnerabilities:
            severity = vuln.severity.value
            stats.by_severity[severity] = stats.by_severity.get(severity, 0) + 1

            category = vuln.category.value
            stats.by_category[category] = stats.by_category.get(category, 0) + 1

            source = vuln.detection_source
            stats.by_source[source] = stats.by_source.get(source, 0) + 1

            if vuln.is_high_priority():
                stats.high_priority_count += 1

        # Calculate averages
        stats.average_confidence = sum(v.confidence for v in vulnerabilities) / len(vulnerabilities)
        stats.average_risk_score = sum(v.calculate_risk_score() for v in vulnerabilities) / len(vulnerabilities)

        return stats
