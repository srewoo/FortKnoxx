"""Unit tests for the triage engine."""

from __future__ import annotations

import asyncio

import pytest

from engines.triage import (
    build_fingerprint,
    canonical_cwe_family,
    deduplicate,
    run_triage,
)
from engines.triage.ignore import apply_ignore_rules
from engines.triage.llm_triage import _parse_verdict, _summarise


# --------------------------------------------------------------------------- fingerprint


def test_fingerprint_collapses_path_normalisation_and_whitespace():
    a = {"file_path": "app.py", "line_start": 42, "cwe": "CWE-89", "code": "x  =  1"}
    b = {"file_path": "./app.py", "line": 44, "cwe_id": "CWE-89", "snippet": "x = 1"}
    assert build_fingerprint(a) == build_fingerprint(b)


def test_fingerprint_collapses_cwe_family_aliases():
    a = {"file_path": "x.py", "line_start": 1, "cwe": "CWE-89", "code": "q"}
    b = {"file_path": "x.py", "line_start": 1, "cwe_id": "CWE-564", "code": "q"}
    assert build_fingerprint(a) == build_fingerprint(b)


def test_fingerprint_differs_on_distinct_files():
    a = {"file_path": "a.py", "line_start": 1, "cwe": "CWE-89", "code": "q"}
    b = {"file_path": "b.py", "line_start": 1, "cwe": "CWE-89", "code": "q"}
    assert build_fingerprint(a) != build_fingerprint(b)


# --------------------------------------------------------------------------- cwe map


def test_canonical_cwe_family_known():
    assert canonical_cwe_family("CWE-89") == "injection.sql"
    assert canonical_cwe_family("CWE-79") == "xss"
    assert canonical_cwe_family("CWE-22") == "path_traversal"


def test_canonical_cwe_family_unknown_keeps_id():
    assert canonical_cwe_family("CWE-9999") == "cwe.cwe-9999"


def test_canonical_cwe_family_handles_empty():
    assert canonical_cwe_family(None) == "unclassified"
    assert canonical_cwe_family("") == "unclassified"


# --------------------------------------------------------------------------- dedup


def test_dedup_merges_cross_scanner_findings():
    a = {"file_path": "app.py", "line_start": 10, "cwe": "CWE-89",
         "detected_by": "bandit", "severity": "medium", "code": "q"}
    b = {"file_path": "app.py", "line_start": 12, "cwe": "CWE-89",
         "detected_by": "semgrep", "severity": "high", "code": "q"}
    out = deduplicate([a, b])
    assert len(out) == 1
    assert out[0]["sources"] == ["bandit", "semgrep"]
    assert out[0]["severity"] == "high"  # worst case wins
    assert out[0]["confidence_score"] >= 0.7


def test_dedup_preserves_distinct_findings():
    a = {"file_path": "a.py", "line_start": 1, "cwe": "CWE-89",
         "detected_by": "bandit", "severity": "low"}
    b = {"file_path": "b.py", "line_start": 1, "cwe": "CWE-79",
         "detected_by": "bandit", "severity": "low"}
    assert len(deduplicate([a, b])) == 2


def test_dedup_empty_list():
    assert deduplicate([]) == []


# --------------------------------------------------------------------------- ignore


def test_ignore_rules_suppress_by_fingerprint(tmp_path):
    fortknoxx_dir = tmp_path / ".fortknoxx"
    fortknoxx_dir.mkdir()
    (fortknoxx_dir / "ignore.yml").write_text(
        "rules:\n"
        "  - fingerprint: deadbeefdeadbeef\n"
        "    justification: test\n"
    )
    findings = [
        {"fingerprint": "deadbeefdeadbeef", "file_path": "x.py"},
        {"fingerprint": "cafebabecafebabe", "file_path": "y.py"},
    ]
    kept, meta = apply_ignore_rules(findings, str(tmp_path))
    assert len(kept) == 1
    assert kept[0]["fingerprint"] == "cafebabecafebabe"
    assert len(meta["suppressed"]) == 1


def test_ignore_rules_suppress_by_cwe_family_with_glob(tmp_path):
    fortknoxx_dir = tmp_path / ".fortknoxx"
    fortknoxx_dir.mkdir()
    (fortknoxx_dir / "ignore.yml").write_text(
        "rules:\n"
        "  - cwe_family: xss\n"
        "    path_glob: '**/test/**'\n"
        "    justification: test fixtures\n"
    )
    findings = [
        {"fingerprint": "1", "cwe_family": "xss", "file_path": "src/test/foo.py"},
        {"fingerprint": "2", "cwe_family": "xss", "file_path": "src/main/foo.py"},
        {"fingerprint": "3", "cwe_family": "injection.sql", "file_path": "src/test/foo.py"},
    ]
    kept, _ = apply_ignore_rules(findings, str(tmp_path))
    fps = {f["fingerprint"] for f in kept}
    assert fps == {"2", "3"}


def test_ignore_rules_no_file_returns_input(tmp_path):
    findings = [{"fingerprint": "x"}]
    kept, meta = apply_ignore_rules(findings, str(tmp_path))
    assert kept == findings
    assert meta["suppressed"] == []


# --------------------------------------------------------------------------- llm helpers


def test_parse_verdict_handles_markdown_wrapping():
    raw = '```json\n{"verdict": "true_positive", "confidence": 0.9, "reason": "raw sql"}\n```'
    v = _parse_verdict(raw)
    assert v["verdict"] == "true_positive"
    assert v["confidence"] == 0.9


def test_parse_verdict_clamps_invalid_inputs():
    v = _parse_verdict('{"verdict": "definitely", "confidence": 5.0, "reason": "x"}')
    assert v["verdict"] == "needs_context"
    assert v["confidence"] == 1.0


def test_parse_verdict_empty():
    v = _parse_verdict("")
    assert v["verdict"] == "needs_context"


def test_summarise_is_deterministic():
    f = {"file_path": "a.py", "line_start": 1, "cwe": "CWE-89",
         "title": "SQLi", "detected_by": "bandit"}
    assert _summarise(f) == _summarise(f)


# --------------------------------------------------------------------------- pipeline


def test_run_triage_dedups_and_skips_llm_when_unavailable(tmp_path):
    findings = [
        {"file_path": "app.py", "line_start": 10, "cwe": "CWE-89",
         "detected_by": "bandit", "severity": "medium", "code": "q"},
        {"file_path": "app.py", "line_start": 12, "cwe_id": "CWE-564",
         "detected_by": "semgrep", "severity": "high", "code": "q"},
    ]
    kept, meta = asyncio.run(
        run_triage(findings, repo_path=str(tmp_path), db=None, orchestrator=None)
    )
    assert len(kept) == 1
    assert meta["original_count"] == 2
    assert meta["deduped_count"] == 1
    assert meta["llm_calls"] == 0
