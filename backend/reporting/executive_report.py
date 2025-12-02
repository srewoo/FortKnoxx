"""
Executive Security Reporting
Generates executive-level security dashboards and risk assessments
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)


class SecurityRiskIndex(BaseModel):
    """Overall security risk index (0-100)"""
    score: float  # 0 (secure) to 100 (critical risk)
    trend: str  # improving, stable, declining
    previous_score: Optional[float] = None


class BreachLikelihood(BaseModel):
    """Estimated breach likelihood"""
    probability: float  # 0-1
    timeframe: str  # e.g., "within 30 days"
    contributing_factors: List[str]


class ExecutiveSummary(BaseModel):
    """Executive summary of security posture"""
    scan_date: datetime
    repository_name: str

    # High-level metrics
    security_risk_index: SecurityRiskIndex
    breach_likelihood: BreachLikelihood

    # Vulnerability breakdown
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int

    # New categories
    business_logic_issues: int
    auth_vulnerabilities: int
    llm_security_issues: int
    zero_day_candidates: int

    # Priority actions
    top_priority_fixes: List[str]

    # Compliance status
    compliance_score: float  # 0-100
    regulatory_exposure: List[str]

    # Resource recommendations
    estimated_remediation_hours: int
    recommended_team_size: int


class ExecutiveReportGenerator:
    """Generates executive reports"""

    async def generate_report(
        self,
        repo_id: str,
        scan_id: str,
        vulnerabilities: List,
        db=None
    ) -> ExecutiveSummary:
        """Generate executive summary"""

        logger.info(f"Generating executive report for scan {scan_id}")

        # Calculate SRI
        sri = await self._calculate_security_risk_index(vulnerabilities)

        # Calculate breach likelihood
        breach = await self._calculate_breach_likelihood(vulnerabilities)

        # Count by severity
        critical = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'critical')
        high = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'high')
        medium = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'medium')
        low = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'low')

        # Count by category
        business_logic = sum(1 for v in vulnerabilities if 'logic' in str(getattr(v, 'category', '')).lower())
        auth = sum(1 for v in vulnerabilities if 'auth' in str(getattr(v, 'type', '')).lower())
        llm = sum(1 for v in vulnerabilities if 'llm' in str(getattr(v, 'type', '')).lower() or 'prompt' in str(getattr(v, 'type', '')).lower())
        zero_day = sum(1 for v in vulnerabilities if 'anomaly' in str(getattr(v, 'type', '')).lower())

        # Top priorities
        top_fixes = await self._identify_top_priorities(vulnerabilities)

        # Compliance
        compliance = await self._calculate_compliance_score(vulnerabilities)

        # Effort estimation
        hours = await self._estimate_remediation_effort(vulnerabilities)

        summary = ExecutiveSummary(
            scan_date=datetime.now(timezone.utc),
            repository_name=repo_id,
            security_risk_index=sri,
            breach_likelihood=breach,
            total_vulnerabilities=len(vulnerabilities),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            business_logic_issues=business_logic,
            auth_vulnerabilities=auth,
            llm_security_issues=llm,
            zero_day_candidates=zero_day,
            top_priority_fixes=top_fixes,
            compliance_score=compliance,
            regulatory_exposure=["SOC2", "ISO27001"] if critical + high > 10 else [],
            estimated_remediation_hours=hours,
            recommended_team_size=max(1, hours // 160)  # 160 hours per month per person
        )

        return summary

    async def _calculate_security_risk_index(self, vulnerabilities: List) -> SecurityRiskIndex:
        """Calculate Security Risk Index (0-100)"""
        if not vulnerabilities:
            return SecurityRiskIndex(score=0, trend="improving")

        # Weight by severity
        weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
        total_score = sum(weights.get(getattr(v, 'severity', 'low'), 1) for v in vulnerabilities)

        # Normalize to 0-100
        sri_score = min(100, total_score / len(vulnerabilities) * 10)

        return SecurityRiskIndex(
            score=sri_score,
            trend="stable",
            previous_score=None
        )

    async def _calculate_breach_likelihood(self, vulnerabilities: List) -> BreachLikelihood:
        """Calculate breach likelihood"""
        critical_count = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'critical')

        if critical_count >= 5:
            probability = 0.8
            timeframe = "within 7 days"
        elif critical_count >= 2:
            probability = 0.6
            timeframe = "within 30 days"
        elif len(vulnerabilities) > 10:
            probability = 0.4
            timeframe = "within 90 days"
        else:
            probability = 0.2
            timeframe = "within 6 months"

        factors = []
        if critical_count > 0:
            factors.append(f"{critical_count} critical vulnerabilities")
        if sum(1 for v in vulnerabilities if 'auth' in str(getattr(v, 'type', '')).lower()) > 0:
            factors.append("Authentication vulnerabilities present")
        if sum(1 for v in vulnerabilities if 'idor' in str(getattr(v, 'type', '')).lower()) > 0:
            factors.append("Data access control issues")

        return BreachLikelihood(
            probability=probability,
            timeframe=timeframe,
            contributing_factors=factors or ["No major risk factors"]
        )

    async def _identify_top_priorities(self, vulnerabilities: List) -> List[str]:
        """Identify top priority fixes"""
        priorities = []

        # Critical vulns first
        critical = [v for v in vulnerabilities if getattr(v, 'severity', '') == 'critical']
        for vuln in critical[:3]:
            priorities.append(getattr(vuln, 'title', 'Critical vulnerability'))

        return priorities or ["No critical issues found"]

    async def _calculate_compliance_score(self, vulnerabilities: List) -> float:
        """Calculate compliance score (0-100)"""
        if not vulnerabilities:
            return 100.0

        # Deduct points for vulnerabilities
        critical_count = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'critical')
        high_count = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'high')

        score = 100.0
        score -= critical_count * 15  # -15 per critical
        score -= high_count * 5  # -5 per high

        return max(0, score)

    async def _estimate_remediation_effort(self, vulnerabilities: List) -> int:
        """Estimate remediation effort in hours"""
        effort_map = {
            "critical": 8,  # 1 day per critical
            "high": 4,  # half day per high
            "medium": 2,  # few hours per medium
            "low": 1  # 1 hour per low
        }

        total_hours = sum(
            effort_map.get(getattr(v, 'severity', 'medium'), 2)
            for v in vulnerabilities
        )

        return total_hours
