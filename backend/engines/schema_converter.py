"""
Universal Schema Converter
Converts all scanner outputs to Universal Vulnerability Schema (UVS)
Ensures consistent output format across all scanners
"""

import logging
from typing import List, Dict, Any, Optional
from schemas.uvs import (
    UniversalVulnerability,
    VulnerabilityCategory,
    VulnerabilitySeverity,
    ExploitabilityLevel,
    Remediation,
    RemediationEffort,
    OWASPMapping,
    CWEMapping
)

logger = logging.getLogger(__name__)


class SchemaConverter:
    """
    Converts findings from various scanners to Universal Vulnerability Schema
    Ensures all scanners have consistent output format
    """

    def __init__(self, repo_id: str, scan_id: str):
        self.repo_id = repo_id
        self.scan_id = scan_id

    def convert_all(
        self,
        zero_day_findings: List[Any],
        business_logic_findings: List[Any],
        llm_findings: List[Any],
        auth_findings: List[Any],
        codeql_findings: List[Any],
        docker_findings: List[Any],
        iac_findings: List[Any]
    ) -> List[UniversalVulnerability]:
        """
        Convert all scanner findings to UVS format

        Returns:
            List of UniversalVulnerability objects
        """
        unified_findings = []

        # Convert each scanner type
        unified_findings.extend(self.convert_zero_day(zero_day_findings))
        unified_findings.extend(self.convert_business_logic(business_logic_findings))
        unified_findings.extend(self.convert_llm_security(llm_findings))
        unified_findings.extend(self.convert_auth_scanner(auth_findings))
        unified_findings.extend(self.convert_codeql(codeql_findings))
        unified_findings.extend(self.convert_docker(docker_findings))
        unified_findings.extend(self.convert_iac(iac_findings))

        logger.info(f"Converted {len(unified_findings)} findings to UVS format")

        return unified_findings

    def convert_zero_day(self, findings: List[Any]) -> List[UniversalVulnerability]:
        """Convert Zero-Day ML detector findings to UVS"""
        converted = []

        for finding in findings:
            try:
                vuln = UniversalVulnerability(
                    title=f"ML-Detected Anomaly: {getattr(finding, 'anomaly_type', 'Unknown')}",
                    description=getattr(finding, 'description', 'Machine learning detected a potential security anomaly'),
                    category=VulnerabilityCategory.OTHER,
                    type="ml_anomaly",
                    severity=self._map_severity(getattr(finding, 'severity', 'medium')),
                    confidence=getattr(finding, 'confidence', 0.7),
                    exploitability=ExploitabilityLevel.THEORETICAL,
                    file_path=getattr(finding, 'file_path', 'unknown'),
                    line_start=getattr(finding, 'line_number', 1),
                    code_snippet=getattr(finding, 'code_snippet', None),
                    detection_source="zero_day_ml",
                    business_impact="Potential novel vulnerability detected by ML",
                    metadata={
                        "anomaly_score": getattr(finding, 'anomaly_score', 0.0),
                        "graph_features": getattr(finding, 'graph_features', {}),
                        "model_version": "gnn-v1.0"
                    },
                    repo_id=self.repo_id,
                    scan_id=self.scan_id
                )
                converted.append(vuln)
            except Exception as e:
                logger.error(f"Error converting zero-day finding: {e}")

        return converted

    def convert_business_logic(self, findings: List[Any]) -> List[UniversalVulnerability]:
        """Convert Business Logic scanner findings to UVS"""
        converted = []

        for finding in findings:
            try:
                # Map business logic type to category
                logic_type = getattr(finding, 'vulnerability_type', 'business_logic')
                category_map = {
                    'idor': VulnerabilityCategory.IDOR,
                    'workflow_bypass': VulnerabilityCategory.WORKFLOW_BYPASS,
                    'race_condition': VulnerabilityCategory.RACE_CONDITION,
                    'price_manipulation': VulnerabilityCategory.PRICE_TAMPERING,
                    'replay_attack': VulnerabilityCategory.REPLAY_ATTACK
                }

                vuln = UniversalVulnerability(
                    title=getattr(finding, 'title', 'Business Logic Vulnerability'),
                    description=getattr(finding, 'description', 'Business logic flaw detected'),
                    category=category_map.get(logic_type, VulnerabilityCategory.BUSINESS_LOGIC),
                    type=logic_type,
                    severity=self._map_severity(getattr(finding, 'severity', 'high')),
                    confidence=getattr(finding, 'confidence', 0.8),
                    exploitability=ExploitabilityLevel.EASY if getattr(finding, 'verified', False) else ExploitabilityLevel.MODERATE,
                    file_path=getattr(finding, 'file_path', 'unknown'),
                    line_start=getattr(finding, 'line_number', 1),
                    code_snippet=getattr(finding, 'code_snippet', None),
                    function_name=getattr(finding, 'function_name', None),
                    detection_source="business_logic",
                    business_impact=getattr(finding, 'business_impact', None),
                    technical_impact=getattr(finding, 'technical_impact', None),
                    ai_exploit_simulated=getattr(finding, 'verified', False),
                    exploit_payload=getattr(finding, 'attack_payload', None),
                    attack_scenario=getattr(finding, 'attack_scenario', None),
                    flow_graph_node=getattr(finding, 'flow_node', None),
                    violated_rule=getattr(finding, 'rule_id', None),
                    remediation=self._create_remediation(finding),
                    repo_id=self.repo_id,
                    scan_id=self.scan_id
                )
                converted.append(vuln)
            except Exception as e:
                logger.error(f"Error converting business logic finding: {e}")

        return converted

    def convert_llm_security(self, findings: List[Any]) -> List[UniversalVulnerability]:
        """Convert LLM Security scanner findings to UVS"""
        converted = []

        for finding in findings:
            try:
                # Map LLM vulnerability types
                llm_type = getattr(finding, 'category', 'prompt_injection')
                category_map = {
                    'prompt_injection': VulnerabilityCategory.PROMPT_INJECTION,
                    'jailbreak': VulnerabilityCategory.JAILBREAK,
                    'data_leakage': VulnerabilityCategory.DATA_LEAKAGE,
                    'permission_escalation': VulnerabilityCategory.LLM_PERMISSION_ABUSE
                }

                vuln = UniversalVulnerability(
                    title=getattr(finding, 'title', f'LLM Security Issue: {llm_type}'),
                    description=getattr(finding, 'description', 'LLM security vulnerability detected'),
                    category=category_map.get(llm_type, VulnerabilityCategory.OTHER),
                    type=llm_type,
                    severity=self._map_severity(getattr(finding, 'severity', 'high')),
                    confidence=getattr(finding, 'confidence', 0.85),
                    exploitability=ExploitabilityLevel.EASY,
                    file_path=getattr(finding, 'endpoint_file', 'unknown'),
                    line_start=getattr(finding, 'line_number', 1),
                    code_snippet=getattr(finding, 'code_snippet', None),
                    function_name=getattr(finding, 'function_name', None),
                    detection_source="llm_security",
                    business_impact="Potential LLM manipulation or data exposure",
                    ai_exploit_simulated=getattr(finding, 'tested', False),
                    exploit_payload=getattr(finding, 'attack_payload', None),
                    attack_scenario=getattr(finding, 'expected_behavior', None),
                    metadata={
                        "model_response": getattr(finding, 'model_response', None),
                        "jailbreak_risk": getattr(finding, 'jailbreak_risk', 0.0),
                        "data_leak_probability": getattr(finding, 'data_leak_probability', 0.0)
                    },
                    repo_id=self.repo_id,
                    scan_id=self.scan_id
                )
                converted.append(vuln)
            except Exception as e:
                logger.error(f"Error converting LLM security finding: {e}")

        return converted

    def convert_auth_scanner(self, findings: List[Any]) -> List[UniversalVulnerability]:
        """Convert Auth scanner findings to UVS"""
        converted = []

        for finding in findings:
            try:
                vuln = UniversalVulnerability(
                    title=getattr(finding, 'title', 'Authentication Vulnerability'),
                    description=getattr(finding, 'description', 'Authentication security issue detected'),
                    category=VulnerabilityCategory.AUTHENTICATION,
                    type=getattr(finding, 'auth_type', 'auth_vulnerability'),
                    severity=self._map_severity(getattr(finding, 'severity', 'high')),
                    confidence=getattr(finding, 'confidence', 0.9),
                    exploitability=ExploitabilityLevel.EASY if getattr(finding, 'verified', False) else ExploitabilityLevel.MODERATE,
                    file_path=getattr(finding, 'file_path', 'unknown'),
                    line_start=getattr(finding, 'line_number', 1),
                    code_snippet=getattr(finding, 'code_snippet', None),
                    detection_source="auth_scanner",
                    business_impact="Unauthorized access or privilege escalation",
                    ai_exploit_simulated=getattr(finding, 'verified', False),
                    exploit_payload=getattr(finding, 'attack_payload', None),
                    remediation=self._create_remediation(finding),
                    owasp_mappings=[
                        OWASPMapping(category="A07", name="Identification and Authentication Failures", year=2021)
                    ],
                    repo_id=self.repo_id,
                    scan_id=self.scan_id
                )
                converted.append(vuln)
            except Exception as e:
                logger.error(f"Error converting auth scanner finding: {e}")

        return converted

    def convert_codeql(self, findings: List[Any]) -> List[UniversalVulnerability]:
        """Convert CodeQL findings to UVS"""
        converted = []

        for finding in findings:
            try:
                vuln = UniversalVulnerability(
                    title=getattr(finding, 'rule_name', 'CodeQL Finding'),
                    description=getattr(finding, 'message', 'Security issue detected by CodeQL'),
                    category=self._map_codeql_category(getattr(finding, 'rule_id', '')),
                    type=getattr(finding, 'rule_id', 'codeql_finding'),
                    severity=self._map_severity(getattr(finding, 'severity', 'medium')),
                    confidence=0.95,  # CodeQL has high confidence
                    exploitability=ExploitabilityLevel.MODERATE,
                    file_path=getattr(finding, 'file_path', 'unknown'),
                    line_start=getattr(finding, 'line', 1),
                    code_snippet=getattr(finding, 'code_snippet', None),
                    detection_source="codeql",
                    cwe_mappings=[
                        CWEMapping(cwe_id=getattr(finding, 'cwe_id', ''), name=getattr(finding, 'cwe_name', ''))
                    ] if hasattr(finding, 'cwe_id') else [],
                    remediation=Remediation(
                        recommended_fix=getattr(finding, 'recommendation', 'Review and fix according to CodeQL guidance'),
                        references=getattr(finding, 'references', []),
                        effort=RemediationEffort.MEDIUM
                    ),
                    repo_id=self.repo_id,
                    scan_id=self.scan_id
                )
                converted.append(vuln)
            except Exception as e:
                logger.error(f"Error converting CodeQL finding: {e}")

        return converted

    def convert_docker(self, findings: List[Any]) -> List[UniversalVulnerability]:
        """Convert Docker scanner findings to UVS"""
        converted = []

        for finding in findings:
            try:
                vuln = UniversalVulnerability(
                    title=getattr(finding, 'vulnerability_id', 'Container Vulnerability'),
                    description=getattr(finding, 'description', 'Container security issue detected'),
                    category=VulnerabilityCategory.DEPENDENCY,
                    type="container_vulnerability",
                    severity=self._map_severity(getattr(finding, 'severity', 'medium')),
                    confidence=1.0,  # CVE findings have high confidence
                    exploitability=ExploitabilityLevel.EASY if getattr(finding, 'exploit_available', False) else ExploitabilityLevel.MODERATE,
                    file_path=getattr(finding, 'dockerfile_path', 'Dockerfile'),
                    line_start=getattr(finding, 'line', 1),
                    detection_source="docker_security",
                    technical_impact=getattr(finding, 'impact', None),
                    metadata={
                        "package_name": getattr(finding, 'package_name', ''),
                        "installed_version": getattr(finding, 'installed_version', ''),
                        "fixed_version": getattr(finding, 'fixed_version', ''),
                        "cvss_score": getattr(finding, 'cvss_score', None)
                    },
                    cvss_score=getattr(finding, 'cvss_score', None),
                    remediation=Remediation(
                        recommended_fix=f"Update {getattr(finding, 'package_name', 'package')} to version {getattr(finding, 'fixed_version', 'latest')}",
                        effort=RemediationEffort.LOW
                    ),
                    repo_id=self.repo_id,
                    scan_id=self.scan_id
                )
                converted.append(vuln)
            except Exception as e:
                logger.error(f"Error converting Docker finding: {e}")

        return converted

    def convert_iac(self, findings: List[Any]) -> List[UniversalVulnerability]:
        """Convert IaC scanner findings to UVS"""
        converted = []

        for finding in findings:
            try:
                vuln = UniversalVulnerability(
                    title=getattr(finding, 'rule_name', 'IaC Misconfiguration'),
                    description=getattr(finding, 'description', 'Infrastructure as Code security issue'),
                    category=VulnerabilityCategory.CONFIGURATION,
                    type="iac_misconfiguration",
                    severity=self._map_severity(getattr(finding, 'severity', 'medium')),
                    confidence=0.9,
                    exploitability=ExploitabilityLevel.MODERATE,
                    file_path=getattr(finding, 'file_path', 'unknown'),
                    line_start=getattr(finding, 'line', 1),
                    code_snippet=getattr(finding, 'code_snippet', None),
                    detection_source="iac_scanner",
                    business_impact="Cloud infrastructure misconfiguration",
                    technical_impact=getattr(finding, 'impact', None),
                    metadata={
                        "platform": getattr(finding, 'platform', 'unknown'),  # terraform, kubernetes, etc.
                        "resource_type": getattr(finding, 'resource_type', ''),
                        "rule_id": getattr(finding, 'rule_id', '')
                    },
                    remediation=Remediation(
                        recommended_fix=getattr(finding, 'remediation', 'Fix IaC configuration according to best practices'),
                        references=getattr(finding, 'references', []),
                        effort=RemediationEffort.LOW
                    ),
                    repo_id=self.repo_id,
                    scan_id=self.scan_id
                )
                converted.append(vuln)
            except Exception as e:
                logger.error(f"Error converting IaC finding: {e}")

        return converted

    def _map_severity(self, severity: str) -> VulnerabilitySeverity:
        """Map string severity to enum"""
        severity_lower = str(severity).lower()

        if severity_lower in ['critical', 'crit']:
            return VulnerabilitySeverity.CRITICAL
        elif severity_lower in ['high']:
            return VulnerabilitySeverity.HIGH
        elif severity_lower in ['medium', 'med', 'moderate']:
            return VulnerabilitySeverity.MEDIUM
        elif severity_lower in ['low']:
            return VulnerabilitySeverity.LOW
        else:
            return VulnerabilitySeverity.INFO

    def _map_codeql_category(self, rule_id: str) -> VulnerabilityCategory:
        """Map CodeQL rule ID to vulnerability category"""
        rule_lower = rule_id.lower()

        if 'sql' in rule_lower or 'injection' in rule_lower:
            return VulnerabilityCategory.INJECTION
        elif 'xss' in rule_lower or 'cross-site' in rule_lower:
            return VulnerabilityCategory.XSS
        elif 'auth' in rule_lower:
            return VulnerabilityCategory.AUTHENTICATION
        elif 'crypto' in rule_lower:
            return VulnerabilityCategory.CRYPTOGRAPHY
        elif 'ssrf' in rule_lower:
            return VulnerabilityCategory.SSRF
        elif 'csrf' in rule_lower:
            return VulnerabilityCategory.CSRF
        else:
            return VulnerabilityCategory.OTHER

    def _create_remediation(self, finding: Any) -> Optional[Remediation]:
        """Create remediation object from finding"""
        remediation_text = getattr(finding, 'remediation', None)

        if remediation_text:
            return Remediation(
                recommended_fix=remediation_text,
                code_example=getattr(finding, 'fix_example', None),
                references=getattr(finding, 'references', []),
                effort=RemediationEffort.MEDIUM
            )

        return None


def get_parallel_execution_config() -> Dict[str, Any]:
    """
    Get configuration for parallel scanner execution
    Ensures all scanners run concurrently for optimal performance
    """
    return {
        "parallel_execution": True,
        "max_concurrent_scanners": 7,  # All 7 scanners can run at once
        "timeout_per_scanner": 300,  # 5 minutes max per scanner
        "failure_handling": "continue",  # Continue even if one fails
        "result_aggregation": "unified_schema",  # Use UVS for all
        "output_format": "json"
    }
