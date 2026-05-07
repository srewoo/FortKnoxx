"""Unit tests for risk_score + blame attribution."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from services import blame
from services.risk_score import score_finding, score_findings


# --------------------------------------------------------------------------- risk_score


def test_severity_drives_baseline_score():
    crit = asyncio.run(score_finding({"severity": "critical"}))
    low = asyncio.run(score_finding({"severity": "low"}))
    assert crit > low


def test_reachable_finding_scores_higher_than_unreachable():
    base = {"severity": "high"}
    high_reach = asyncio.run(score_finding({**base, "reachable": True}))
    no_reach = asyncio.run(score_finding({**base, "reachable": False}))
    assert high_reach > no_reach


def test_asset_criticality_modifies_score():
    f = {"severity": "high"}
    crit_asset = asyncio.run(score_finding(f, asset_criticality="critical"))
    low_asset = asyncio.run(score_finding(f, asset_criticality="low"))
    assert crit_asset > low_asset


def test_score_findings_in_place_assigns_risk_score():
    findings = [{"severity": "critical"}, {"severity": "low"}]
    out = asyncio.run(score_findings(findings))
    assert all("risk_score" in f for f in out)
    assert 0 <= out[0]["risk_score"] <= 100


def test_score_finding_no_cve_returns_finite_score():
    score = asyncio.run(score_finding({"severity": "medium"}))
    assert isinstance(score, int)
    assert 0 <= score <= 100


# --------------------------------------------------------------------------- blame


def _git_repo_with_blame(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "alice@example.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Alice"], check=True)
    (tmp_path / "vuln.py").write_text("a = 1\nbad_sql_query = 'SELECT * FROM t'\nc = 3\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "vuln.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    return tmp_path


def test_attribute_returns_owner(tmp_path):
    repo = _git_repo_with_blame(tmp_path)
    info = blame.attribute(str(repo), "vuln.py", 2)
    assert info is not None
    assert info["owner_email"] == "alice@example.com"
    assert info["owner_name"] == "Alice"
    assert info["last_modified_unix"]


def test_attribute_returns_none_when_file_missing(tmp_path):
    repo = _git_repo_with_blame(tmp_path)
    assert blame.attribute(str(repo), "no_such_file.py", 1) is None


def test_attribute_findings_annotates_in_place(tmp_path):
    repo = _git_repo_with_blame(tmp_path)
    findings = [{"file_path": "vuln.py", "line_start": 2}]
    blame.attribute_findings(findings, str(repo))
    assert findings[0]["owner_email"] == "alice@example.com"
