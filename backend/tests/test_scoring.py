"""Tests for services.scoring — pure score functions extracted from server.py."""

from __future__ import annotations

from services.scoring import (
    calculate_compliance_score,
    calculate_quality_score,
    calculate_security_score,
)


class TestSecurityScore:
    def test_no_vulns_is_perfect(self):
        assert calculate_security_score(0, 0, 0, 0) == 100

    def test_one_critical_subtracts_15(self):
        assert calculate_security_score(1, 0, 0, 0) == 85

    def test_severity_weights(self):
        # Each tier should subtract more than the next.
        c = 100 - calculate_security_score(1, 0, 0, 0)
        h = 100 - calculate_security_score(0, 1, 0, 0)
        m = 100 - calculate_security_score(0, 0, 1, 0)
        low = 100 - calculate_security_score(0, 0, 0, 1)
        assert c > h > m > low > 0

    def test_volume_penalty_kicks_in_above_20(self):
        # 21 lows = -21 base, plus -5 volume penalty.
        assert calculate_security_score(0, 0, 0, 21) == max(0, 100 - 21 - 5)

    def test_floors_at_zero(self):
        assert calculate_security_score(100, 100, 100, 100) == 0


class TestQualityScore:
    def test_empty_is_perfect(self):
        assert calculate_quality_score([]) == 100

    def test_single_high_issue(self):
        assert calculate_quality_score([{"severity": "high"}]) == 95  # -5

    def test_lowercases_severity(self):
        # "HIGH" should match the "high" bucket.
        assert calculate_quality_score([{"severity": "HIGH"}]) == 95

    def test_unknown_severity_does_not_crash(self):
        # Falls into no bucket — still subtracts nothing.
        assert calculate_quality_score([{"severity": "weird"}]) == 100

    def test_volume_penalty_at_50(self):
        issues = [{"severity": "low"}] * 51
        # 51 low issues: -25.5 base, -5 volume → 70 (rounded down).
        assert calculate_quality_score(issues) == int(max(0, 100 - 25.5 - 5))


class TestComplianceScore:
    def test_empty_is_perfect(self):
        assert calculate_compliance_score([]) == 100

    def test_high_risk_subtracts_15(self):
        assert calculate_compliance_score([{"license_risk": "high"}]) == 85

    def test_unknown_risk_subtracts_3(self):
        assert calculate_compliance_score([{"license_risk": "totally-unknown"}]) == 97

    def test_low_risk_no_deduction(self):
        assert calculate_compliance_score([{"license_risk": "low"}]) == 100

    def test_floors_at_zero(self):
        many_high = [{"license_risk": "high"}] * 10
        assert calculate_compliance_score(many_high) == 0
