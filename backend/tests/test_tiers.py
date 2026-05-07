"""Unit tests for the two-tier scan model."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from engines.tiers import (
    ALWAYS_ON,
    DEEP_ONLY_SCANNERS,
    FAST_SCANNERS,
    apply_tier,
    resolve_tier,
)
from settings.models import ScannerSettings


# --------------------------------------------------------------------------- resolve_tier


def _make_repo(tmp_path: Path, *, lines_to_add: int = 0) -> Path:
    """Init a tiny git repo and optionally add a diff of N lines."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "t@t.com"], check=True
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True
    )
    (tmp_path / "a.py").write_text("x = 1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "a.py"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True
    )
    if lines_to_add:
        (tmp_path / "a.py").write_text("x = 1\n" + "y = 1\n" * lines_to_add)
        subprocess.run(["git", "-C", str(tmp_path), "add", "a.py"], check=True)
        subprocess.run(
            ["git", "-C", str(tmp_path), "commit", "-q", "-m", "edit"], check=True
        )
    return tmp_path


def test_resolve_tier_explicit_fast():
    decision = resolve_tier("fast", "/tmp")
    assert decision.tier == "fast"
    assert decision.forced is True


def test_resolve_tier_explicit_deep():
    decision = resolve_tier("deep", "/tmp")
    assert decision.tier == "deep"
    assert decision.forced is True


def test_resolve_tier_auto_small_diff_picks_fast(tmp_path):
    repo = _make_repo(tmp_path, lines_to_add=10)
    decision = resolve_tier("auto", str(repo), auto_threshold=500)
    assert decision.tier == "fast"
    assert decision.diff_lines >= 10
    assert decision.forced is False


def test_resolve_tier_auto_large_diff_picks_deep(tmp_path):
    repo = _make_repo(tmp_path, lines_to_add=600)
    decision = resolve_tier("auto", str(repo), auto_threshold=500)
    assert decision.tier == "deep"
    assert decision.diff_lines >= 600


def test_resolve_tier_no_git_falls_back_to_deep(tmp_path):
    decision = resolve_tier("auto", str(tmp_path))
    assert decision.tier == "deep"
    assert decision.diff_lines == -1


# --------------------------------------------------------------------------- apply_tier


def test_apply_tier_fast_disables_deep_only_scanners():
    settings = ScannerSettings()  # all defaults — most scanners enabled
    fast = apply_tier(settings, "fast")
    for flag in DEEP_ONLY_SCANNERS:
        assert getattr(fast, flag) is False, f"{flag} should be off in fast tier"


def test_apply_tier_fast_keeps_fast_scanners_on():
    settings = ScannerSettings()
    fast = apply_tier(settings, "fast")
    # Pick a couple that ship default-on.
    assert fast.enable_semgrep is True
    assert fast.enable_bandit is True
    assert fast.enable_gitleaks is True


def test_apply_tier_fast_keeps_always_on_scanners():
    settings = ScannerSettings()
    fast = apply_tier(settings, "fast")
    for flag in ALWAYS_ON:
        original = getattr(settings, flag)
        if original:  # only assert preservation for things that were on
            assert getattr(fast, flag) is True


def test_apply_tier_fast_does_not_re_enable_user_disabled():
    settings = ScannerSettings(enable_semgrep=False)
    fast = apply_tier(settings, "fast")
    assert fast.enable_semgrep is False  # user disabled stays disabled


def test_apply_tier_deep_is_passthrough():
    settings = ScannerSettings(enable_semgrep=False, enable_codeql=True)
    deep = apply_tier(settings, "deep")
    assert deep.enable_semgrep is False
    assert deep.enable_codeql is True


def test_apply_tier_unknown_tier_returns_input():
    settings = ScannerSettings()
    out = apply_tier(settings, "magic")
    assert out is settings


def test_fast_and_deep_only_are_disjoint():
    """Catch accidental dual-listing as the registry grows."""
    assert FAST_SCANNERS.isdisjoint(DEEP_ONLY_SCANNERS)
