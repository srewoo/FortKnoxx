"""
Compliance Framework Mapper
Maps vulnerabilities to compliance frameworks (SOC2, ISO27001, PCI-DSS, HIPAA)
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    OWASP_TOP10 = "owasp_top10"
    MITRE_ATTACK = "mitre_attack"


class ComplianceControl(BaseModel):
    """Compliance control mapping"""
    framework: ComplianceFramework
    control_id: str
    control_name: str
    status: str  # compliant, non_compliant, partial
    affected_vulnerabilities: List[str] = Field(default_factory=list)


class ComplianceReport(BaseModel):
    """Compliance status report"""
    framework: ComplianceFramework
    overall_compliance: float  # 0-100
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    controls: List[ComplianceControl] = Field(default_factory=list)


class ComplianceMapper:
    """Maps vulnerabilities to compliance requirements"""

    def __init__(self):
        # Mapping of vulnerability types to compliance controls
        self.mappings = {
            ComplianceFramework.OWASP_TOP10: {
                "A01": ["injection", "sql", "command"],
                "A02": ["crypto", "encryption", "tls"],
                "A03": ["injection", "xss", "sql"],
                "A04": ["design", "logic"],
                "A05": ["configuration", "default"],
                "A06": ["dependency", "outdated"],
                "A07": ["authentication", "auth"],
                "A08": ["integrity", "serialization"],
                "A09": ["logging", "monitoring"],
                "A10": ["ssrf", "redirect"]
            },
            ComplianceFramework.SOC2: {
                "CC6.1": ["authentication", "access control"],
                "CC6.6": ["encryption", "data protection"],
                "CC6.7": ["vulnerability management"],
                "CC7.2": ["monitoring", "logging"]
            },
            ComplianceFramework.ISO27001: {
                "A.9.2": ["authentication", "authorization"],
                "A.9.4": ["access control"],
                "A.10.1": ["cryptography"],
                "A.12.6": ["vulnerability management"],
                "A.14.2": ["secure development"]
            }
        }

    async def generate_compliance_reports(
        self,
        vulnerabilities: List,
        frameworks: List[ComplianceFramework]
    ) -> List[ComplianceReport]:
        """Generate compliance reports for specified frameworks"""

        reports = []

        for framework in frameworks:
            report = await self._generate_framework_report(framework, vulnerabilities)
            reports.append(report)

        return reports

    async def _generate_framework_report(
        self,
        framework: ComplianceFramework,
        vulnerabilities: List
    ) -> ComplianceReport:
        """Generate report for single framework"""

        controls = await self._map_to_controls(framework, vulnerabilities)

        compliant = sum(1 for c in controls if c.status == "compliant")
        non_compliant = sum(1 for c in controls if c.status == "non_compliant")

        compliance_pct = (compliant / len(controls) * 100) if controls else 100

        return ComplianceReport(
            framework=framework,
            overall_compliance=compliance_pct,
            total_controls=len(controls),
            compliant_controls=compliant,
            non_compliant_controls=non_compliant,
            controls=controls
        )

    async def _map_to_controls(
        self,
        framework: ComplianceFramework,
        vulnerabilities: List
    ) -> List[ComplianceControl]:
        """Map vulnerabilities to controls"""

        controls = []
        control_mappings = self.mappings.get(framework, {})

        for control_id, keywords in control_mappings.items():
            # Find vulns matching this control
            matching_vulns = []

            for vuln in vulnerabilities:
                vuln_str = str(getattr(vuln, 'type', '')) + str(getattr(vuln, 'category', ''))
                vuln_str = vuln_str.lower()

                if any(keyword in vuln_str for keyword in keywords):
                    matching_vulns.append(getattr(vuln, 'title', 'Unknown'))

            # Determine status
            if matching_vulns:
                status = "non_compliant"
            else:
                status = "compliant"

            control = ComplianceControl(
                framework=framework,
                control_id=control_id,
                control_name=self._get_control_name(framework, control_id),
                status=status,
                affected_vulnerabilities=matching_vulns
            )

            controls.append(control)

        return controls

    def _get_control_name(self, framework: ComplianceFramework, control_id: str) -> str:
        """Get human-readable control name"""
        names = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "CC6.1": "Logical Access Controls",
            "CC6.6": "Encryption of Sensitive Data",
            "A.9.2": "User Access Management",
        }
        return names.get(control_id, control_id)


class CICDGate:
    """CI/CD security gate"""

    async def should_block_deployment(
        self,
        vulnerabilities: List,
        threshold_config: Dict[str, int]
    ) -> tuple[bool, str]:
        """
        Determine if deployment should be blocked

        Args:
            vulnerabilities: List of vulnerabilities
            threshold_config: {"critical": 0, "high": 5}

        Returns:
            (should_block, reason)
        """

        critical = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'critical')
        high = sum(1 for v in vulnerabilities if getattr(v, 'severity', '') == 'high')

        max_critical = threshold_config.get('critical', 0)
        max_high = threshold_config.get('high', 5)

        if critical > max_critical:
            return True, f"Blocked: {critical} critical vulnerabilities (max: {max_critical})"

        if high > max_high:
            return True, f"Blocked: {high} high vulnerabilities (max: {max_high})"

        return False, "Passed security gates"
