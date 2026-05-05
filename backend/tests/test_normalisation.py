"""Tests for services.normalisation — severity + OWASP normalisation."""

from __future__ import annotations

import pytest

from services.normalisation import map_to_owasp, normalize_severity


class TestNormalizeSeverity:
    def test_string_lowercases(self):
        assert normalize_severity("HIGH") == "high"

    def test_list_picks_first_element(self):
        assert normalize_severity(["Critical", "High"]) == "critical"

    def test_empty_list_returns_default(self):
        assert normalize_severity([]) == "medium"

    def test_explicit_default(self):
        assert normalize_severity([], default="info") == "info"

    def test_none_returns_default(self):
        assert normalize_severity(None) == "medium"

    def test_int_returns_default(self):
        # Some scanners return numeric scores; we don't try to map
        # them — caller is responsible for using cvss_score etc.
        assert normalize_severity(7) == "medium"

    def test_list_with_none_first_returns_default(self):
        assert normalize_severity([None, "high"]) == "medium"


class TestMapToOwasp:
    @pytest.mark.parametrize(
        "category,title,description,expected",
        [
            # A01 — access control
            ("authorization", "missing access check", "", "A01"),
            # A02 — crypto / secrets
            ("crypto", "weak hash", "", "A02"),
            ("misc", "hardcoded password", "", "A02"),
            # A03 — injection
            ("injection", "SQL injection", "", "A03"),
            ("xss", "reflected XSS", "", "A03"),
            ("misc", "command injection in shell", "", "A03"),
            # A04 — design / business logic
            ("logic", "business logic flaw", "", "A04"),
            # A05 — misconfig (also the default)
            ("config", "debug mode on in prod", "", "A05"),
            ("totally-novel-category", "totally novel issue", "", "A05"),
            # A06 — vulnerable components
            ("dependency", "outdated library", "", "A06"),
            # A07 — auth
            ("session", "token reuse", "", "A07"),
            # A08 — integrity
            ("misc", "insecure deserialization", "", "A08"),
            # A09 — logging
            ("monitor", "missing audit log", "", "A09"),
            # A10 — SSRF
            ("misc", "ssrf in image proxy", "", "A10"),
        ],
    )
    def test_keyword_routes_to_expected_bucket(self, category, title, description, expected):
        assert map_to_owasp(category, title, description) == expected

    def test_description_is_searched_when_other_fields_silent(self):
        assert map_to_owasp("misc", "general issue", "vulnerable to SSRF") == "A10"

    def test_first_match_wins(self):
        # Both "access" (A01) and "injection" (A03) appear; A01 matches first.
        assert map_to_owasp("access-injection", "broken authorization", "") == "A01"

    def test_default_is_misconfig(self):
        assert map_to_owasp("nothing-relevant", "boring", "boring") == "A05"
