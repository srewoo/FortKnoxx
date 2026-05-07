"""Unit tests for the autofix service."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from services.autofix import (
    _git_apply_check,
    _looks_like_unified_diff,
    _strip_fences,
    generate_autofix,
)


# --------------------------------------------------------------------------- helpers


def _init_repo(tmp_path: Path, file_content: str = "x = 1\ny = 2\nz = 3\n") -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "t@t.com"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "t"], check=True)
    (tmp_path / "app.py").write_text(file_content)
    subprocess.run(["git", "-C", str(tmp_path), "add", "app.py"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True)
    return tmp_path


_GOOD_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -1,3 +1,3 @@
 x = 1
-y = 2
+y = 99
 z = 3
"""

_BAD_DIFF = """\
--- a/app.py
+++ b/app.py
@@ -10,3 +10,3 @@
 not even close to actual file content
-this line does not exist
+replacement
"""


# --------------------------------------------------------------------------- pure functions


def test_strip_fences_removes_diff_fence():
    text = "```diff\n--- a/x\n+++ b/x\n```"
    assert "```" not in _strip_fences(text)
    assert "--- a/x" in _strip_fences(text)


def test_strip_fences_no_op_on_plain_diff():
    assert _strip_fences("--- a\n+++ b\n@@ @@\n").startswith("--- a")


def test_looks_like_unified_diff_positive():
    assert _looks_like_unified_diff(_GOOD_DIFF)


def test_looks_like_unified_diff_negative():
    assert not _looks_like_unified_diff("just some text")
    assert not _looks_like_unified_diff("")


# --------------------------------------------------------------------------- git apply check


def test_git_apply_check_accepts_valid_diff(tmp_path):
    repo = _init_repo(tmp_path)
    ok, err = _git_apply_check(str(repo), _GOOD_DIFF)
    assert ok, f"unexpected error: {err}"


def test_git_apply_check_rejects_invalid_diff(tmp_path):
    repo = _init_repo(tmp_path)
    ok, err = _git_apply_check(str(repo), _BAD_DIFF)
    assert ok is False
    assert err  # some error message present


def test_git_apply_check_rejects_empty():
    ok, err = _git_apply_check("/tmp", "")
    assert ok is False
    assert err == "empty diff"


# --------------------------------------------------------------------------- end-to-end


def _fake_orchestrator(diff_to_return: str):
    orch = MagicMock()
    orch.generate_completion = AsyncMock(return_value=diff_to_return)
    orch.is_provider_available = MagicMock(return_value=True)
    return orch


def _fake_db():
    """Minimal Mongo-like double with autofix_cache collection in memory."""
    store: dict[str, dict] = {}

    class _Coll:
        async def find_one(self, q):
            return store.get(q.get("_id"))

        async def update_one(self, q, update, upsert=False):
            doc = store.setdefault(q["_id"], {})
            doc.update(update["$set"])

    db = MagicMock()
    db.__getitem__.side_effect = lambda _name: _Coll()
    return db, store


def test_generate_autofix_applies_and_caches(tmp_path):
    repo = _init_repo(tmp_path)
    finding = {
        "fingerprint": "fp123",
        "file_path": "app.py",
        "line_start": 2,
        "title": "use better value",
        "cwe": "CWE-1004",
        "severity": "low",
    }
    orch = _fake_orchestrator(_GOOD_DIFF)
    db, store = _fake_db()

    res = asyncio.run(
        generate_autofix(finding, repo_path=str(repo), db=db, orchestrator=orch)
    )
    assert res.applies_cleanly is True
    assert res.cached is False
    assert "+y = 99" in res.diff
    assert orch.generate_completion.await_count == 1

    # Second call should hit the cache and skip the LLM.
    res2 = asyncio.run(
        generate_autofix(finding, repo_path=str(repo), db=db, orchestrator=orch)
    )
    assert res2.cached is True
    assert orch.generate_completion.await_count == 1  # no extra call


def test_generate_autofix_does_not_cache_failing_diff(tmp_path):
    repo = _init_repo(tmp_path)
    finding = {"fingerprint": "fp_bad", "file_path": "app.py", "line_start": 1}
    orch = _fake_orchestrator(_BAD_DIFF)
    db, store = _fake_db()

    res = asyncio.run(
        generate_autofix(finding, repo_path=str(repo), db=db, orchestrator=orch)
    )
    assert res.applies_cleanly is False
    assert res.error
    assert "fp_bad" not in store  # never cached


def test_generate_autofix_handles_non_diff_response(tmp_path):
    repo = _init_repo(tmp_path)
    finding = {"fingerprint": "fp_text", "file_path": "app.py", "line_start": 1}
    orch = _fake_orchestrator("Sure! Here's how to fix it: ...")
    db, _ = _fake_db()

    res = asyncio.run(
        generate_autofix(finding, repo_path=str(repo), db=db, orchestrator=orch)
    )
    assert res.applies_cleanly is False
    assert "did not return a unified diff" in (res.error or "")


def test_generate_autofix_no_orchestrator_returns_error(tmp_path):
    repo = _init_repo(tmp_path)
    finding = {"fingerprint": "fp_x", "file_path": "app.py", "line_start": 1}
    res = asyncio.run(
        generate_autofix(finding, repo_path=str(repo), db=None, orchestrator=None)
    )
    assert res.diff == ""
    assert res.error and "no LLM orchestrator" in res.error
