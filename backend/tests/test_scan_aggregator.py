"""Tests for services.scan_aggregator.ScanAggregator.

This is the workhorse aggregator that turns raw scanner output into
the Vulnerability dicts that get persisted to Mongo. It is also where
the original `'str' object has no attribute 'get'` incident lived.
The tests cover:

  - happy paths for each scanner shape (structured / dict / AI-typed),
  - resilience to malformed findings,
  - severity bumping rules,
  - the `recompute_severity_counts` helper that runs after the
    false-positive filter.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from services.scan_aggregator import ScanAggregator


@pytest.fixture
def agg():
    return ScanAggregator(repo_id="repo-1", scan_id="scan-1")


# ----------------------------------------------------------------- #
# Structured-output scanners
# ----------------------------------------------------------------- #


class TestSemgrep:
    def test_happy_path(self, agg):
        agg.add_semgrep(
            [
                {
                    "check_id": "python.lang.eval-detected",
                    "path": "app.py",
                    "start": {"line": 10},
                    "end": {"line": 11},
                    "extra": {
                        "severity": "ERROR",
                        "message": "eval() detected",
                        "lines": "eval(user_input)",
                    },
                }
            ]
        )
        assert len(agg.vulnerabilities) == 1
        v = agg.vulnerabilities[0]
        assert v["severity"] == "error"  # lowercased; mapped severity falls outside critical/high/medium/low
        # severity_counts should still be sane (non-canonical sev -> medium bucket)
        assert agg.severity_counts["medium"] == 1
        assert v["detected_by"] == "Semgrep"
        assert v["file_path"] == "app.py"

    def test_skips_non_dict_finding(self, agg):
        agg.add_semgrep(
            [
                "bogus",
                None,
                {"check_id": "x", "path": "a.py", "start": {"line": 1}, "end": {"line": 1}, "extra": {}},
            ]
        )
        assert len(agg.vulnerabilities) == 1

    def test_one_bad_finding_does_not_kill_the_rest(self, agg):
        # Missing `extra` would crash the access pattern under older code.
        # safe + try/except per finding means we keep the good ones.
        agg.add_semgrep(
            [
                {"check_id": "x", "path": "a.py", "start": "not-a-dict", "end": {"line": 1}, "extra": {}},
                {"check_id": "y", "path": "b.py", "start": {"line": 2}, "end": {"line": 2}, "extra": {}},
            ]
        )
        assert len(agg.vulnerabilities) == 1
        assert agg.vulnerabilities[0]["file_path"] == "b.py"


class TestGitleaks:
    def test_marks_critical(self, agg):
        agg.add_gitleaks(
            [
                {
                    "File": "config.yaml",
                    "StartLine": 5,
                    "EndLine": 5,
                    "Description": "AWS Access Key",
                    "Secret": "AKIAIOSFODNN7EXAMPLE",
                }
            ]
        )
        assert len(agg.vulnerabilities) == 1
        assert agg.vulnerabilities[0]["severity"] == "critical"
        assert agg.severity_counts["critical"] == 1
        assert agg.vulnerabilities[0]["owasp_category"] == "A02"

    def test_handles_missing_fields(self, agg):
        agg.add_gitleaks([{"File": "x"}])
        assert len(agg.vulnerabilities) == 1


class TestTrivy:
    def test_string_cvss_does_not_crash(self, agg):
        # The original incident: `dep["CVSS"]` arrived as a string.
        agg.add_trivy(
            [
                {
                    "Severity": "HIGH",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "Title": "CVE-2021-23337",
                    "CVSS": "7.5",  # <- the bug-trigger
                }
            ]
        )
        assert len(agg.vulnerabilities) == 1
        assert agg.vulnerabilities[0]["cvss_score"] is None
        assert agg.severity_counts["high"] == 1

    def test_proper_cvss_is_extracted(self, agg):
        agg.add_trivy(
            [
                {
                    "Severity": "MEDIUM",
                    "PkgName": "requests",
                    "InstalledVersion": "2.25.0",
                    "Title": "CVE-XXXX",
                    "CVSS": {"nvd": {"V3Score": 6.5}},
                    "CweIDs": ["CWE-89"],
                }
            ]
        )
        v = agg.vulnerabilities[0]
        assert v["cvss_score"] == 6.5
        assert v["cwe"] == "CWE-89"

    def test_cwe_ids_non_list_does_not_crash(self, agg):
        agg.add_trivy([{"Severity": "LOW", "PkgName": "x", "Title": "t", "CweIDs": "not-a-list"}])
        assert agg.vulnerabilities[0]["cwe"] is None


class TestCheckov:
    def test_happy_path(self, agg):
        agg.add_checkov(
            [
                {
                    "check_name": "CKV_AWS_8",
                    "file_path": "main.tf",
                    "file_line_range": [10, 20],
                    "check_result": {
                        "result": {"severity": "HIGH", "evaluated_keys": ["resource.aws_s3_bucket"]}
                    },
                }
            ]
        )
        assert agg.vulnerabilities[0]["severity"] == "high"
        assert agg.vulnerabilities[0]["line_start"] == 10
        assert agg.vulnerabilities[0]["line_end"] == 20

    def test_malformed_file_line_range(self, agg):
        agg.add_checkov(
            [{"check_name": "X", "file_path": "x.tf", "file_line_range": "not-a-list", "check_result": {}}]
        )
        v = agg.vulnerabilities[0]
        assert v["line_start"] == 0 and v["line_end"] == 0


# ----------------------------------------------------------------- #
# Dict-shaped scanners
# ----------------------------------------------------------------- #


def _dict_finding(severity="high"):
    return {
        "title": "x",
        "description": "y",
        "file_path": "a.py",
        "line_start": 1,
        "line_end": 1,
        "severity": severity,
        "category": "c",
        "owasp_category": "A03",
        "detected_by": "Custom",
    }


class TestDictShapedScanners:
    @pytest.mark.parametrize(
        "method_name",
        [
            "add_bandit",
            "add_trufflehog",
            "add_grype",
            "add_eslint",
            "add_nuclei",
            "add_enhanced_security",
            "add_dep_audit",
        ],
    )
    def test_each_method_appends_to_vulnerabilities(self, agg, method_name):
        getattr(agg, method_name)([_dict_finding()])
        assert len(agg.vulnerabilities) == 1
        assert agg.severity_counts["high"] == 1

    def test_quality_findings_go_to_quality_issues_no_severity_bump(self, agg):
        agg.add_quality([_dict_finding(severity="high")])
        assert len(agg.quality_issues) == 1
        assert len(agg.vulnerabilities) == 0
        # Quality issues don't bump severity_counts.
        assert agg.severity_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}
        assert agg.quality_issues[0]["issue_type"] == "quality"

    def test_compliance_findings_go_to_compliance_issues(self, agg):
        agg.add_compliance([{"package_name": "lodash", "license": "MIT"}])
        assert len(agg.compliance_issues) == 1
        assert agg.compliance_issues[0]["issue_type"] == "compliance"
        assert agg.severity_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_unknown_severity_lands_in_medium_bucket(self, agg):
        agg.add_bandit([_dict_finding(severity="exotic-tier")])
        # `exotic-tier` is not in the canonical bucket set; aggregator
        # falls back to "medium" so dashboard math still works.
        assert agg.severity_counts["medium"] == 1


# ----------------------------------------------------------------- #
# AI-typed scanners (objects, not dicts)
# ----------------------------------------------------------------- #


@dataclass
class _ZeroDayAnomaly:
    file_path: str = "a.py"
    line_number: int = 1
    severity: str = "high"
    type: str = "novel-pattern"
    title: str = "anomaly"
    description: str = "weird code"
    code_snippet: str = "x"
    anomaly_score: float = 0.92
    confidence: float = 0.85


@dataclass
class _BLViolation:
    file_path: str = "a.py"
    line_number: int = 1
    severity: str = "critical"
    type: str = "idor"
    title: str = "IDOR"
    description: str = "auth bypass"
    attack_scenario: str = "..."
    recommendation: str = "..."
    proof_of_concept: str | None = "POST /x"
    endpoint: str = "/x"


@dataclass
class _LLMVuln:
    endpoint_file: str = "a.py"
    endpoint_line: int = 1
    severity: str = "high"
    vulnerability_type: str = "prompt-injection"
    title: str = "PI"
    description: str = "..."
    jailbreak_risk: float = 0.4
    data_leak_probability: float = 0.6
    permission_abuse_risk: float = 0.2
    remediation: str = "..."
    successful_payload: str = "ignore previous instructions"


@dataclass
class _AuthVuln:
    file_path: str = "a.py"
    line_number: int = 1
    severity: str = "high"
    type: str = "jwt-alg-confusion"
    title: str = "JWT alg confusion"
    description: str = "..."
    attack_scenario: str = "..."
    remediation: str = "..."
    confidence: float = 0.9
    code_snippet: str | None = "x"


class TestAITypedScanners:
    def test_zero_day(self, agg):
        agg.add_zero_day([_ZeroDayAnomaly()])
        assert agg.vulnerabilities[0]["detected_by"] == "Zero-Day Detector (AI)"
        assert agg.severity_counts["high"] == 1

    def test_business_logic(self, agg):
        agg.add_business_logic([_BLViolation()])
        assert agg.vulnerabilities[0]["detected_by"] == "Business Logic Scanner (AI)"
        assert agg.severity_counts["critical"] == 1

    def test_llm_security(self, agg):
        agg.add_llm_security([_LLMVuln()])
        assert agg.vulnerabilities[0]["detected_by"] == "LLM Security Scanner (AI)"
        assert agg.vulnerabilities[0]["owasp_category"] == "A03"

    def test_auth_scanner(self, agg):
        agg.add_auth_scanner([_AuthVuln()])
        assert agg.vulnerabilities[0]["owasp_category"] == "A07"

    def test_handles_none_input(self, agg):
        # All AI methods accept None gracefully.
        agg.add_zero_day(None)
        agg.add_business_logic(None)
        agg.add_llm_security(None)
        agg.add_auth_scanner(None)
        assert agg.vulnerabilities == []

    def test_one_bad_object_does_not_stop_the_rest(self, agg):
        good = _ZeroDayAnomaly(file_path="good.py")

        class _Broken:
            # Missing all the attributes Vulnerability needs.
            pass

        agg.add_zero_day([_Broken(), good])
        # Good one survives, bad one is logged + skipped.
        assert len(agg.vulnerabilities) == 1
        assert agg.vulnerabilities[0]["file_path"] == "good.py"


# ----------------------------------------------------------------- #
# recompute_severity_counts
# ----------------------------------------------------------------- #


class TestRecompute:
    def test_handles_list_severity(self, agg):
        agg.vulnerabilities = [{"severity": ["HIGH"]}]
        agg.recompute_severity_counts()
        assert agg.vulnerabilities[0]["severity"] == "high"
        assert agg.severity_counts["high"] == 1

    def test_handles_unknown_severity(self, agg):
        agg.vulnerabilities = [{"severity": "weird"}]
        agg.recompute_severity_counts()
        # weird falls back to medium for both the row and the count.
        assert agg.vulnerabilities[0]["severity"] == "medium"
        assert agg.severity_counts["medium"] == 1

    def test_handles_missing_severity(self, agg):
        agg.vulnerabilities = [{}]
        agg.recompute_severity_counts()
        assert agg.severity_counts["medium"] == 1

    def test_zeros_when_empty(self, agg):
        agg.vulnerabilities = []
        agg.recompute_severity_counts()
        assert agg.severity_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}
