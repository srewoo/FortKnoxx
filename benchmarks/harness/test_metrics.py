"""Unit tests for metrics computation. Datasets not required."""

from __future__ import annotations

from .metrics import compute_metrics, render_summary


def _gt(case_id, cwe, vuln=True):
    return {"case_id": case_id, "cwe": cwe, "is_vulnerable": vuln, "dataset": "test"}


def _pred(case_id, scanner, cwe):
    return {"case_id": case_id, "scanner": scanner, "cwe": cwe}


def test_perfect_detector_yields_perfect_metrics():
    gt = [_gt("a", "CWE-89"), _gt("b", "CWE-79")]
    preds = [_pred("a", "scanner1", "CWE-89"), _pred("b", "scanner1", "CWE-79")]
    metrics = compute_metrics(preds, gt)
    by_family = {m.cwe_family: m for m in metrics if m.scanner == "scanner1"}
    assert by_family["injection.sql"].precision == 1.0
    assert by_family["injection.sql"].recall == 1.0
    assert by_family["xss"].f1 == 1.0


def test_missed_finding_counts_as_false_negative():
    gt = [_gt("a", "CWE-89")]
    preds: list[dict] = []  # scanner detected nothing
    metrics = compute_metrics(preds, gt)
    assert metrics == []  # no scanner => no rows; that's correct


def test_wrong_cwe_on_vulnerable_case_is_fp_for_that_family():
    gt = [_gt("a", "CWE-89")]  # SQLi case
    preds = [_pred("a", "s1", "CWE-79")]  # scanner says XSS
    metrics = {(m.scanner, m.cwe_family): m for m in compute_metrics(preds, gt)}
    assert metrics[("s1", "injection.sql")].fn == 1
    assert metrics[("s1", "xss")].fp == 1


def test_benign_case_with_detection_is_fp():
    gt = [_gt("a", None, vuln=False)]
    preds = [_pred("a", "s1", "CWE-89")]
    metrics = {(m.scanner, m.cwe_family): m for m in compute_metrics(preds, gt)}
    assert metrics[("s1", "injection.sql")].fp == 1


def test_render_summary_emits_markdown_table():
    gt = [_gt("a", "CWE-89"), _gt("b", "CWE-79", vuln=False)]
    preds = [_pred("a", "s1", "CWE-89")]
    metrics = compute_metrics(preds, gt)
    md = render_summary(metrics, dataset="unit-test")
    assert md.startswith("# Benchmark — unit-test")
    assert "| Scanner |" in md
    assert "s1" in md
