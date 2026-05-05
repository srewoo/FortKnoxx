"""Tests for services.result_safety — the helper that protects scan
aggregation from a single bad scanner finding tanking the whole scan."""

from __future__ import annotations

import logging

from services.result_safety import process_findings, safe_findings


class TestSafeFindings:
    def test_yields_only_dict_entries(self, caplog):
        caplog.set_level(logging.WARNING)
        mixed = [{"a": 1}, "oops", None, {"b": 2}, ["a", "list"]]
        out = list(safe_findings(mixed, "TestScanner"))
        assert out == [{"a": 1}, {"b": 2}]

    def test_logs_warning_for_each_non_dict(self, caplog):
        caplog.set_level(logging.WARNING)
        list(safe_findings(["bad", None, 42], "TestScanner"))
        warnings = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
        assert len(warnings) == 3
        assert all("non-dict TestScanner" in rec.message for rec in warnings)

    def test_handles_none_input(self):
        assert list(safe_findings(None, "TestScanner")) == []

    def test_handles_empty_input(self):
        assert list(safe_findings([], "TestScanner")) == []


class TestProcessFindings:
    def test_processes_each_dict_finding(self):
        seen: list[dict] = []
        process_findings([{"x": 1}, {"x": 2}], "TestScanner", seen.append)
        assert seen == [{"x": 1}, {"x": 2}]

    def test_skips_non_dict_findings(self):
        seen: list[dict] = []
        process_findings([{"x": 1}, "bad", {"x": 2}], "TestScanner", seen.append)
        assert seen == [{"x": 1}, {"x": 2}]

    def test_one_bad_finding_does_not_stop_others(self, caplog):
        caplog.set_level(logging.WARNING)

        def handler(finding):
            if finding["x"] == 2:
                raise ValueError("simulated scanner shape mismatch")
            seen.append(finding)

        seen: list[dict] = []
        count = process_findings(
            [{"x": 1}, {"x": 2}, {"x": 3}],
            "TestScanner",
            handler,
        )
        assert seen == [{"x": 1}, {"x": 3}]
        assert count == 2
        assert any("Failed to process TestScanner finding" in rec.message for rec in caplog.records)

    def test_returns_count_of_processed_findings(self):
        count = process_findings(
            [{"x": 1}, "bad", {"x": 2}],
            "TestScanner",
            lambda _: None,
        )
        assert count == 2
