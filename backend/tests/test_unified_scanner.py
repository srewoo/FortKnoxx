"""
Comprehensive tests for Unified Security Scanner
Tests all scanner integrations and payload systems
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path

# Import scanner components
from engines.unified_scanner import (
    UnifiedSecurityScanner,
    UnifiedScanConfig,
    UnifiedScanResult,
    ScannerType
)
from engines.payloads.payload_generator import PayloadGenerator, PayloadCategory
from engines.payloads.strix_fuzzer import StrixFuzzer, FuzzTarget, MutationStrategy
from engines.payloads.unified_payload_manager import UnifiedPayloadManager


class TestPayloadGeneration:
    """Test payload generation systems"""

    def test_payload_library_completeness(self):
        """Test that all payload categories have payloads"""
        generator = PayloadGenerator()

        # Test SQL injection payloads
        sqli_payloads = generator.get_payloads_by_category(PayloadCategory.SQL_INJECTION)
        assert len(sqli_payloads) >= 10, "Should have at least 10 SQL injection payloads"

        # Test XSS payloads
        xss_payloads = generator.get_payloads_by_category(PayloadCategory.XSS)
        assert len(xss_payloads) >= 10, "Should have at least 10 XSS payloads"

        # Test all payloads
        all_payloads = generator.get_all_payloads()
        assert len(all_payloads) >= 50, "Should have at least 50 total payloads"

    def test_payload_severity_distribution(self):
        """Test that payloads have appropriate severity levels"""
        generator = PayloadGenerator()
        all_payloads = generator.get_all_payloads()

        critical_count = len([p for p in all_payloads if p.severity == "critical"])
        high_count = len([p for p in all_payloads if p.severity == "high"])

        assert critical_count > 0, "Should have critical severity payloads"
        assert high_count > 0, "Should have high severity payloads"

    def test_payload_encoding(self):
        """Test payload encoding capabilities"""
        generator = PayloadGenerator()

        test_payload = "<script>alert('XSS')</script>"

        # URL encoding
        url_encoded = generator.encode_payload(test_payload, "url")
        assert "%" in url_encoded, "URL encoded payload should contain % characters"

        # Base64 encoding
        b64_encoded = generator.encode_payload(test_payload, "base64")
        assert b64_encoded != test_payload, "Base64 encoded should differ from original"

    def test_bypass_payloads(self):
        """Test that bypass payloads are flagged correctly"""
        generator = PayloadGenerator()
        bypass_payloads = generator.get_bypass_payloads()

        assert len(bypass_payloads) > 0, "Should have bypass payloads"
        for payload in bypass_payloads:
            assert payload.detection_bypass == True, "Bypass payloads should be flagged"


class TestUnifiedPayloadManager:
    """Test unified payload management system"""

    @pytest.mark.asyncio
    async def test_get_all_payloads(self):
        """Test retrieving all payloads from all sources"""
        manager = UnifiedPayloadManager()
        all_payloads = await manager.get_all_payloads()

        assert len(all_payloads) >= 100, "Should have at least 100 combined payloads"

        # Check attack types
        web_payloads = [p for p in all_payloads if p.attack_type == "web"]
        llm_payloads = [p for p in all_payloads if p.attack_type == "llm"]

        assert len(web_payloads) > 0, "Should have web attack payloads"
        assert len(llm_payloads) > 0, "Should have LLM attack payloads"

    @pytest.mark.asyncio
    async def test_scanner_specific_payloads(self):
        """Test getting payloads for specific scanners"""
        manager = UnifiedPayloadManager()

        # LLM security scanner
        llm_payloads = await manager.get_payloads_for_scanner("llm_security")
        assert len(llm_payloads) > 0, "Should have LLM-specific payloads"

        # Auth scanner
        auth_payloads = await manager.get_payloads_for_scanner("auth_scanner")
        assert len(auth_payloads) > 0, "Should have auth-specific payloads"

    @pytest.mark.asyncio
    async def test_smart_payload_selection(self):
        """Test intelligent payload selection based on target info"""
        manager = UnifiedPayloadManager()

        # Python target
        python_target = {
            "language": "python",
            "framework": "flask",
            "features": ["database", "auth"]
        }

        selected = await manager.smart_payload_selection(python_target, max_payloads=20)
        assert len(selected) <= 20, "Should respect max_payloads limit"
        assert len(selected) > 0, "Should select at least some payloads"

    @pytest.mark.asyncio
    async def test_payload_statistics(self):
        """Test payload statistics generation"""
        manager = UnifiedPayloadManager()
        stats = await manager.get_payload_statistics()

        assert "total_payloads" in stats
        assert "by_category" in stats
        assert "by_severity" in stats
        assert "by_attack_type" in stats

        assert stats["total_payloads"] > 0


class TestStrixFuzzer:
    """Test Strix fuzzing engine"""

    def test_mutation_strategies(self):
        """Test different mutation strategies"""
        fuzzer = StrixFuzzer(max_iterations=10)

        test_input = "admin"

        # Bit flip
        mutated = fuzzer._mutate(test_input, MutationStrategy.BIT_FLIP)
        assert mutated != test_input or len(mutated) == len(test_input)

        # Repeat
        mutated = fuzzer._mutate(test_input, MutationStrategy.REPEAT)
        assert len(mutated) > len(test_input)

        # Truncate
        mutated = fuzzer._mutate(test_input, MutationStrategy.TRUNCATE)
        assert len(mutated) <= len(test_input)

    def test_interesting_values_generation(self):
        """Test generation of interesting test values"""
        fuzzer = StrixFuzzer()

        assert len(fuzzer.INTERESTING_INTEGERS) > 0
        assert len(fuzzer.INTERESTING_STRINGS) > 0
        assert len(fuzzer.BOUNDARY_VALUES) > 0

    def test_seed_input_generation(self):
        """Test seed input generation"""
        fuzzer = StrixFuzzer()
        seeds = fuzzer._generate_seed_inputs()

        assert len(seeds) > 0, "Should generate seed inputs"
        assert any(len(s) > 0 for s in seeds), "Should have non-empty seeds"


class TestUnifiedScanner:
    """Test Unified Security Scanner"""

    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Test scanner initialization"""
        config = UnifiedScanConfig(
            repo_path="/tmp/test_repo",
            language="python",
            enable_zero_day=True,
            enable_business_logic=True,
            enable_llm_security=False,  # Disable to avoid API calls
            enable_auth_scanner=True,
            enable_codeql=False,  # Disable CodeQL for faster tests
            enable_docker=False,
            enable_iac=False
        )

        scanner = UnifiedSecurityScanner(config)

        assert scanner.config == config
        assert isinstance(scanner.results, UnifiedScanResult)

    @pytest.mark.asyncio
    async def test_scanner_types_enum(self):
        """Test scanner type enumeration"""
        assert ScannerType.ZERO_DAY.value == "zero_day"
        assert ScannerType.BUSINESS_LOGIC.value == "business_logic"
        assert ScannerType.LLM_SECURITY.value == "llm_security"
        assert ScannerType.AUTH_SCANNER.value == "auth_scanner"
        assert ScannerType.CODEQL.value == "codeql"
        assert ScannerType.DOCKER.value == "docker"
        assert ScannerType.IAC.value == "iac"

    @pytest.mark.asyncio
    async def test_risk_score_calculation(self):
        """Test risk score calculation"""
        config = UnifiedScanConfig(repo_path="/tmp/test")
        scanner = UnifiedSecurityScanner(config)

        # Simulate findings
        scanner.results.critical_count = 5
        scanner.results.high_count = 10
        scanner.results.medium_count = 20
        scanner.results.low_count = 30

        risk_score = scanner._calculate_risk_score()

        assert risk_score > 0, "Risk score should be positive with vulnerabilities"
        assert risk_score <= 100, "Risk score should not exceed 100"

        # Critical vulnerabilities should heavily impact score
        assert risk_score >= 50, "5 critical vulnerabilities should result in high risk score"

    def test_recommendations_generation(self):
        """Test security recommendations generation"""
        config = UnifiedScanConfig(repo_path="/tmp/test")
        scanner = UnifiedSecurityScanner(config)

        # Simulate different findings
        scanner.results.critical_count = 3
        scanner.results.zero_day_findings = [{"test": "finding"}]
        scanner.results.llm_findings = [{"test": "finding"}]

        recommendations = scanner._generate_recommendations()

        assert len(recommendations) > 0, "Should generate recommendations"
        assert any("critical" in r.lower() for r in recommendations), "Should recommend addressing critical issues"

    def test_consolidated_report_structure(self):
        """Test consolidated report generation"""
        config = UnifiedScanConfig(repo_path="/tmp/test")
        scanner = UnifiedSecurityScanner(config)

        report = scanner.generate_consolidated_report()

        # Check required keys
        assert "scan_metadata" in report
        assert "summary" in report
        assert "findings_by_scanner" in report
        assert "risk_score" in report
        assert "recommendations" in report

        # Check metadata structure
        assert "repository" in report["scan_metadata"]
        assert "scan_duration_seconds" in report["scan_metadata"]

        # Check summary structure
        assert "total_vulnerabilities" in report["summary"]
        assert "by_severity" in report["summary"]

        # Check findings structure
        assert "zero_day" in report["findings_by_scanner"]
        assert "business_logic" in report["findings_by_scanner"]
        assert "llm_security" in report["findings_by_scanner"]


class TestIntegration:
    """Integration tests for the complete system"""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_payload_integration_with_scanner(self):
        """Test that payload library integrates with scanner"""
        manager = UnifiedPayloadManager()

        # Get LLM payloads
        llm_payloads = await manager.get_payloads_for_scanner("llm_security")

        assert len(llm_payloads) > 0, "Should get LLM payloads"

        # Verify payloads can be used for testing
        for payload in llm_payloads[:5]:  # Test first 5
            assert hasattr(payload, 'payload')
            assert hasattr(payload, 'description')
            assert hasattr(payload, 'severity')

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_end_to_end_payload_flow(self):
        """Test end-to-end payload generation and usage"""
        # Initialize manager
        manager = UnifiedPayloadManager()

        # Get high-severity payloads
        high_sev = manager.get_high_severity_payloads()
        assert len(high_sev) > 0

        # Get statistics
        stats = await manager.get_payload_statistics()
        assert stats["total_payloads"] > 0

        # Smart selection
        target = {"language": "javascript", "features": ["llm"]}
        selected = await manager.smart_payload_selection(target, max_payloads=10)
        assert len(selected) <= 10


class TestPerformance:
    """Performance and benchmarking tests"""

    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_payload_generation_performance(self):
        """Test payload generation performance"""
        import time

        manager = UnifiedPayloadManager()

        start = time.time()
        all_payloads = await manager.get_all_payloads()
        duration = time.time() - start

        assert duration < 5.0, f"Payload generation took {duration}s, should be < 5s"
        assert len(all_payloads) > 0

    @pytest.mark.asyncio
    @pytest.mark.benchmark
    async def test_smart_selection_performance(self):
        """Test smart payload selection performance"""
        import time

        manager = UnifiedPayloadManager()
        target_info = {
            "language": "python",
            "framework": "django",
            "features": ["database", "auth", "api"]
        }

        start = time.time()
        selected = await manager.smart_payload_selection(target_info, max_payloads=100)
        duration = time.time() - start

        assert duration < 2.0, f"Smart selection took {duration}s, should be < 2s"
        assert len(selected) > 0


@pytest.mark.asyncio
async def test_mutation_diversity():
    """Test that mutations produce diverse outputs"""
    manager = UnifiedPayloadManager()

    # Get base payloads
    base_payloads = manager.get_high_severity_payloads()[:5]

    # Generate mutations
    mutated = await manager.generate_mutated_payloads(base_payloads, mutation_count=5)

    # Check diversity
    unique_payloads = set(p.payload for p in mutated)
    assert len(unique_payloads) > len(base_payloads), "Mutations should increase diversity"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
