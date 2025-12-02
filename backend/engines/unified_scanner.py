"""
Unified Security Scanner
Orchestrates all specialized scanners and provides consolidated results
"""

import asyncio
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ScannerType(str, Enum):
    """Available scanner types"""
    ZERO_DAY = "zero_day"
    BUSINESS_LOGIC = "business_logic"
    LLM_SECURITY = "llm_security"
    AUTH_SCANNER = "auth_scanner"
    CODEQL = "codeql"
    DOCKER = "docker"
    IAC = "iac"


@dataclass
class UnifiedScanConfig:
    """Configuration for unified security scan"""

    # Repository details
    repo_path: str
    language: Optional[str] = None

    # Scanner toggles
    enable_zero_day: bool = True
    enable_business_logic: bool = True
    enable_llm_security: bool = True
    enable_auth_scanner: bool = True
    enable_codeql: bool = True
    enable_docker: bool = True
    enable_iac: bool = True

    # Runtime testing configs
    enable_runtime_testing: bool = True
    base_url: Optional[str] = None
    auth_headers: Optional[Dict[str, str]] = None

    # LLM API keys
    llm_api_keys: Optional[Dict[str, str]] = None

    # Docker images to scan
    docker_images: List[str] = field(default_factory=list)

    # IaC directories
    terraform_dirs: List[str] = field(default_factory=list)
    kubernetes_dirs: List[str] = field(default_factory=list)


@dataclass
class UnifiedScanResult:
    """Consolidated scan results from all scanners"""

    # Summary statistics
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Results by scanner (raw format)
    zero_day_findings: List[Any] = field(default_factory=list)
    business_logic_findings: List[Any] = field(default_factory=list)
    llm_findings: List[Any] = field(default_factory=list)
    auth_findings: List[Any] = field(default_factory=list)
    codeql_findings: List[Any] = field(default_factory=list)
    docker_findings: List[Any] = field(default_factory=list)
    iac_findings: List[Any] = field(default_factory=list)

    # Universal Vulnerability Schema (UVS) findings - CONSISTENT OUTPUT FORMAT
    # This list contains ALL findings converted to a standardized format
    unified_vulnerabilities: List[Any] = field(default_factory=list)

    # Execution metadata
    scan_duration_seconds: float = 0.0
    scanners_run: List[str] = field(default_factory=list)
    scanners_failed: List[str] = field(default_factory=list)


class UnifiedSecurityScanner:
    """
    Orchestrates all security scanners in FortKnoxx
    Provides unified interface and consolidated reporting
    """

    def __init__(self, config: UnifiedScanConfig):
        self.config = config
        self.results = UnifiedScanResult()

    async def run_comprehensive_scan(self) -> UnifiedScanResult:
        """
        Run comprehensive security scan with all enabled scanners

        All scanners run in PARALLEL for maximum performance
        Results are converted to Universal Vulnerability Schema (UVS) for consistency

        Returns:
            Consolidated scan results with standardized format
        """
        import time
        start_time = time.time()

        logger.info("="*80)
        logger.info("Starting Comprehensive Security Scan")
        logger.info("="*80)
        logger.info(f"Repository: {self.config.repo_path}")
        logger.info(f"Runtime Testing: {'Enabled' if self.config.enable_runtime_testing else 'Disabled'}")

        # Collect enabled scanners
        enabled_scanners = []

        if self.config.enable_zero_day:
            enabled_scanners.append("Zero-Day (GNN+CodeBERT)")
        if self.config.enable_business_logic:
            enabled_scanners.append("Business Logic")
        if self.config.enable_llm_security:
            enabled_scanners.append("LLM Security")
        if self.config.enable_auth_scanner:
            enabled_scanners.append("Auth Scanner")
        if self.config.enable_codeql:
            enabled_scanners.append("CodeQL")
        if self.config.enable_docker:
            enabled_scanners.append("Docker Security")
        if self.config.enable_iac:
            enabled_scanners.append("IaC Scanner")

        logger.info(f"Enabled Scanners ({len(enabled_scanners)}): {', '.join(enabled_scanners)}")
        logger.info("="*80)
        logger.info("⚡ PARALLEL EXECUTION: All scanners running concurrently")
        logger.info("="*80)

        # Run scanners in parallel for performance
        # All scanners execute simultaneously, not sequentially
        scan_tasks = []

        if self.config.enable_zero_day:
            scan_tasks.append(self._run_zero_day_scanner())

        if self.config.enable_business_logic:
            scan_tasks.append(self._run_business_logic_scanner())

        if self.config.enable_llm_security:
            scan_tasks.append(self._run_llm_scanner())

        if self.config.enable_auth_scanner:
            scan_tasks.append(self._run_auth_scanner())

        if self.config.enable_codeql:
            scan_tasks.append(self._run_codeql_scanner())

        if self.config.enable_docker and self.config.docker_images:
            scan_tasks.append(self._run_docker_scanner())

        if self.config.enable_iac and (self.config.terraform_dirs or self.config.kubernetes_dirs):
            scan_tasks.append(self._run_iac_scanner())

        # Execute all scanners concurrently using asyncio.gather
        # return_exceptions=True ensures one failure doesn't stop others
        logger.info(f"🚀 Launching {len(scan_tasks)} scanners in parallel...")
        await asyncio.gather(*scan_tasks, return_exceptions=True)

        # Convert all findings to Universal Vulnerability Schema (UVS)
        # This ensures consistent output format across all scanners
        logger.info("📋 Converting all findings to Universal Vulnerability Schema (UVS)...")
        self._convert_to_universal_schema()

        # Calculate totals
        self._calculate_summary_statistics()

        self.results.scan_duration_seconds = time.time() - start_time

        logger.info("="*80)
        logger.info("✅ Scan Completed Successfully")
        logger.info("="*80)
        logger.info(f"⏱️  Duration: {self.results.scan_duration_seconds:.2f}s")
        logger.info(f"📊 Total Vulnerabilities: {self.results.total_vulnerabilities}")
        logger.info(f"   🔴 Critical: {self.results.critical_count}")
        logger.info(f"   🟠 High: {self.results.high_count}")
        logger.info(f"   🟡 Medium: {self.results.medium_count}")
        logger.info(f"   🔵 Low: {self.results.low_count}")
        logger.info(f"✅ Scanners Completed: {len(self.results.scanners_run)}")
        logger.info(f"❌ Scanners Failed: {len(self.results.scanners_failed)}")
        logger.info("="*80)

        return self.results

    def _convert_to_universal_schema(self):
        """
        Convert all scanner findings to Universal Vulnerability Schema
        Ensures consistent output format across all scanners
        """
        from engines.schema_converter import SchemaConverter

        converter = SchemaConverter(
            repo_id=self.config.repo_path,  # Use repo_path as ID for now
            scan_id=f"scan_{int(time.time())}"
        )

        # Convert all findings
        unified_vulns = converter.convert_all(
            zero_day_findings=self.results.zero_day_findings,
            business_logic_findings=self.results.business_logic_findings,
            llm_findings=self.results.llm_findings,
            auth_findings=self.results.auth_findings,
            codeql_findings=self.results.codeql_findings,
            docker_findings=self.results.docker_findings,
            iac_findings=self.results.iac_findings
        )

        # Store unified findings
        self.results.unified_vulnerabilities = unified_vulns

        logger.info(f"✅ Converted {len(unified_vulns)} findings to UVS format")

    async def _run_zero_day_scanner(self):
        """Run Zero-Day ML detector"""
        try:
            logger.info("Running Zero-Day Detector (GNN + CodeBERT)...")
            from .zero_day.ml_detector import MLAnomalyDetector

            detector = MLAnomalyDetector(use_gnn=True)
            anomalies = await detector.analyze_repository(self.config.repo_path)

            self.results.zero_day_findings = anomalies
            self.results.scanners_run.append(ScannerType.ZERO_DAY.value)

            logger.info(f"Zero-Day Detector: {len(anomalies)} anomalies found")

        except Exception as e:
            logger.error(f"Zero-Day scanner failed: {str(e)}")
            self.results.scanners_failed.append(ScannerType.ZERO_DAY.value)

    async def _run_business_logic_scanner(self):
        """Run Business Logic scanner with runtime testing"""
        try:
            logger.info("Running Business Logic Scanner...")
            from .logic.attack_simulator import LogicAttackSimulator
            from .logic.flow_analyzer import FlowAnalyzer
            from .logic.rule_engine import LogicRuleEngine

            # Analyze flow
            analyzer = FlowAnalyzer()
            flow_graph = analyzer.analyze_repository(self.config.repo_path)

            # Detect violations
            rule_engine = LogicRuleEngine()
            violations = rule_engine.check_violations(flow_graph)

            # Simulate attacks (with optional runtime testing)
            simulator = LogicAttackSimulator(
                enable_runtime_testing=self.config.enable_runtime_testing
            )

            attack_results = await simulator.simulate_attacks(
                flow_graph,
                violations,
                base_url=self.config.base_url,
                auth_headers=self.config.auth_headers
            )

            self.results.business_logic_findings = attack_results
            self.results.scanners_run.append(ScannerType.BUSINESS_LOGIC.value)

            logger.info(f"Business Logic Scanner: {len(attack_results)} findings")

        except Exception as e:
            logger.error(f"Business Logic scanner failed: {str(e)}")
            self.results.scanners_failed.append(ScannerType.BUSINESS_LOGIC.value)

    async def _run_llm_scanner(self):
        """Run LLM Security scanner"""
        try:
            logger.info("Running LLM Security Scanner...")
            from .llm_security.surface_discovery import LLMSurfaceDiscovery
            from .llm_security.payload_generator import PayloadGenerator
            from .llm_security.adversarial_tester import AdversarialTester

            # Discover LLM endpoints
            discovery = LLMSurfaceDiscovery()
            endpoints = discovery.scan_repository(self.config.repo_path)

            if not endpoints:
                logger.info("No LLM endpoints found")
                return

            # Generate payloads
            generator = PayloadGenerator()
            payloads = generator.generate_comprehensive_payloads()

            # Test endpoints
            tester = AdversarialTester(
                api_keys=self.config.llm_api_keys or {},
                enable_real_testing=self.config.enable_runtime_testing and bool(self.config.llm_api_keys)
            )

            vulnerabilities = await tester.test_endpoints(endpoints, payloads, sample_size=50)

            self.results.llm_findings = vulnerabilities
            self.results.scanners_run.append(ScannerType.LLM_SECURITY.value)

            logger.info(f"LLM Security Scanner: {len(vulnerabilities)} vulnerabilities")

        except Exception as e:
            logger.error(f"LLM scanner failed: {str(e)}")
            self.results.scanners_failed.append(ScannerType.LLM_SECURITY.value)

    async def _run_auth_scanner(self):
        """Run Authentication scanner"""
        try:
            logger.info("Running Authentication Scanner...")
            from .auth_scanner.static_analyzer import AuthStaticAnalyzer
            from .auth_scanner.runtime_simulator import AuthAttackSimulator

            # Static analysis
            analyzer = AuthStaticAnalyzer()
            static_vulns = analyzer.scan_repository(self.config.repo_path)

            # Runtime testing (if configured)
            runtime_vulns = []
            if self.config.enable_runtime_testing and self.config.base_url:
                simulator = AuthAttackSimulator(enable_runtime_testing=True)

                # Note: Would need specific endpoint configs for full testing
                # For now, just static results
                runtime_vulns = await simulator.generate_attack_scenarios(static_vulns)

            self.results.auth_findings = static_vulns + runtime_vulns
            self.results.scanners_run.append(ScannerType.AUTH_SCANNER.value)

            logger.info(f"Auth Scanner: {len(static_vulns)} static + {len(runtime_vulns)} runtime findings")

        except Exception as e:
            logger.error(f"Auth scanner failed: {str(e)}")
            self.results.scanners_failed.append(ScannerType.AUTH_SCANNER.value)

    async def _run_codeql_scanner(self):
        """Run CodeQL semantic analysis"""
        try:
            logger.info("Running CodeQL Scanner...")
            from .specialized.codeql_scanner import CodeQLScanner, CodeQLLanguage

            # Determine language
            language_map = {
                "python": CodeQLLanguage.PYTHON,
                "javascript": CodeQLLanguage.JAVASCRIPT,
                "typescript": CodeQLLanguage.TYPESCRIPT,
                "java": CodeQLLanguage.JAVA,
                "go": CodeQLLanguage.GO
            }

            language = language_map.get(
                self.config.language.lower() if self.config.language else "python",
                CodeQLLanguage.PYTHON
            )

            scanner = CodeQLScanner()
            findings = await scanner.scan_repository(
                self.config.repo_path,
                language,
                query_suite="security-extended"
            )

            self.results.codeql_findings = findings
            self.results.scanners_run.append(ScannerType.CODEQL.value)

            logger.info(f"CodeQL Scanner: {len(findings)} findings")

        except Exception as e:
            logger.error(f"CodeQL scanner failed: {str(e)}")
            self.results.scanners_failed.append(ScannerType.CODEQL.value)

    async def _run_docker_scanner(self):
        """Run Docker/Container security scanner"""
        try:
            logger.info("Running Docker Security Scanner...")
            from .specialized.docker_scanner import DockerSecurityScanner

            scanner = DockerSecurityScanner()
            all_vulns = []

            for image in self.config.docker_images:
                vulns = await scanner.scan_container_image(image, use_trivy=True)
                all_vulns.extend(vulns)

            # Also scan Dockerfiles if present
            dockerfiles = list(Path(self.config.repo_path).rglob("Dockerfile*"))
            for dockerfile in dockerfiles:
                dockerfile_vulns = await scanner.scan_dockerfile(str(dockerfile))
                all_vulns.extend(dockerfile_vulns)

            self.results.docker_findings = all_vulns
            self.results.scanners_run.append(ScannerType.DOCKER.value)

            logger.info(f"Docker Scanner: {len(all_vulns)} vulnerabilities")

        except Exception as e:
            logger.error(f"Docker scanner failed: {str(e)}")
            self.results.scanners_failed.append(ScannerType.DOCKER.value)

    async def _run_iac_scanner(self):
        """Run Infrastructure as Code scanner"""
        try:
            logger.info("Running IaC Scanner...")
            from .specialized.iac_scanner import IaCScanner

            scanner = IaCScanner()
            all_findings = []

            # Scan Terraform
            for tf_dir in self.config.terraform_dirs:
                findings = await scanner.scan_terraform(tf_dir)
                all_findings.extend(findings)

            # Scan Kubernetes
            for k8s_dir in self.config.kubernetes_dirs:
                findings = await scanner.scan_kubernetes(k8s_dir)
                all_findings.extend(findings)

            self.results.iac_findings = all_findings
            self.results.scanners_run.append(ScannerType.IAC.value)

            logger.info(f"IaC Scanner: {len(all_findings)} findings")

        except Exception as e:
            logger.error(f"IaC scanner failed: {str(e)}")
            self.results.scanners_failed.append(ScannerType.IAC.value)

    def _calculate_summary_statistics(self):
        """Calculate summary statistics across all findings"""

        total = 0
        critical = 0
        high = 0
        medium = 0
        low = 0

        # Count findings from each scanner
        for findings_list in [
            self.results.zero_day_findings,
            self.results.business_logic_findings,
            self.results.llm_findings,
            self.results.auth_findings,
            self.results.codeql_findings,
            self.results.docker_findings,
            self.results.iac_findings
        ]:
            total += len(findings_list)

            for finding in findings_list:
                severity = getattr(finding, 'severity', '').lower()

                if 'critical' in severity:
                    critical += 1
                elif 'high' in severity:
                    high += 1
                elif 'medium' in severity or 'med' in severity:
                    medium += 1
                elif 'low' in severity:
                    low += 1

        self.results.total_vulnerabilities = total
        self.results.critical_count = critical
        self.results.high_count = high
        self.results.medium_count = medium
        self.results.low_count = low

    def generate_consolidated_report(self) -> Dict[str, Any]:
        """Generate consolidated security report"""

        return {
            "scan_metadata": {
                "repository": self.config.repo_path,
                "scan_duration_seconds": self.results.scan_duration_seconds,
                "scanners_run": self.results.scanners_run,
                "scanners_failed": self.results.scanners_failed,
                "runtime_testing_enabled": self.config.enable_runtime_testing
            },
            "summary": {
                "total_vulnerabilities": self.results.total_vulnerabilities,
                "by_severity": {
                    "critical": self.results.critical_count,
                    "high": self.results.high_count,
                    "medium": self.results.medium_count,
                    "low": self.results.low_count
                }
            },
            "findings_by_scanner": {
                "zero_day": len(self.results.zero_day_findings),
                "business_logic": len(self.results.business_logic_findings),
                "llm_security": len(self.results.llm_findings),
                "auth": len(self.results.auth_findings),
                "codeql": len(self.results.codeql_findings),
                "docker": len(self.results.docker_findings),
                "iac": len(self.results.iac_findings)
            },
            "risk_score": self._calculate_risk_score(),
            "recommendations": self._generate_recommendations()
        }

    def _calculate_risk_score(self) -> float:
        """Calculate overall security risk score (0-100, higher is worse)"""

        # Weighted scoring
        score = (
            self.results.critical_count * 10 +
            self.results.high_count * 5 +
            self.results.medium_count * 2 +
            self.results.low_count * 0.5
        )

        # Normalize to 0-100
        return min(100.0, score)

    def _generate_recommendations(self) -> List[str]:
        """Generate top security recommendations"""

        recommendations = []

        if self.results.critical_count > 0:
            recommendations.append(
                f"URGENT: Address {self.results.critical_count} critical vulnerabilities immediately"
            )

        if self.results.zero_day_findings:
            recommendations.append(
                "Review GNN-detected anomalies - these may be novel zero-day vulnerabilities"
            )

        if self.results.docker_findings:
            recommendations.append(
                "Update container base images and dependencies to patch known CVEs"
            )

        if self.results.iac_findings:
            recommendations.append(
                "Review IaC configurations for cloud security misconfigurations"
            )

        if self.results.auth_findings:
            recommendations.append(
                "Strengthen authentication and session management"
            )

        if self.results.llm_findings:
            recommendations.append(
                "Implement LLM security controls (input validation, output filtering)"
            )

        return recommendations[:10]  # Top 10 recommendations
