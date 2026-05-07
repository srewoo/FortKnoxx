"""
LLM-powered autofix.

Produces a *unified diff* (not free-form advice) for a confirmed finding,
caches it forever by ``(fingerprint, file_hash)`` so repeated requests on
the same vulnerable file are free, and refuses to surface fixes that fail
``git apply --check``.

Why git apply check, not "compile":
  • Compiling means installing the target repo's toolchain inside the
    backend container — heavy, slow, polyglot. Not viable for free.
  • A diff that doesn't apply cleanly is *guaranteed* useless. A diff that
    applies but breaks compilation is the user's call to evaluate before
    accepting in their PR — same UX as Copilot/Snyk Fix today.

Provider fallback:
  • Default: whatever orchestrator picks (`anthropic` etc.).
  • If ``FORTKNOXX_AUTOFIX_LLM=ollama`` is set, route to a local model
    via the existing orchestrator's openai-compatible path (Ollama
    exposes one) — fully zero-cost mode.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_CACHE_COLLECTION = "autofix_cache"

_SYSTEM_PROMPT = (
    "You are a senior software engineer producing the smallest possible "
    "patch that fixes a security vulnerability. Output ONLY a valid "
    "unified diff that can be applied with `git apply`. Do not include "
    "explanations, markdown fences, or commentary outside the diff. "
    "Preserve formatting and indentation. Keep changes minimal — never "
    "refactor unrelated code."
)

_DIFF_HEADER_RE = re.compile(r"^(--- |\+\+\+ |@@ )", re.MULTILINE)
_FENCE_RE = re.compile(r"^```(?:diff|patch)?\s*\n|\n```\s*$", re.MULTILINE)


@dataclass
class AutofixResult:
    """Returned to callers / surfaced in the UI."""

    fingerprint: str
    file_hash: str
    diff: str            # unified diff text
    applies_cleanly: bool
    cached: bool
    provider: str
    model: Optional[str]
    error: Optional[str] = None


# ----------------------------------------------------------------- internals


def _file_hash(file_path: Path) -> str:
    if not file_path.is_file():
        return "missing"
    h = hashlib.sha1()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()[:12]


def _strip_fences(text: str) -> str:
    """LLMs love wrapping diffs in ```diff fences; remove them."""
    return _FENCE_RE.sub("", text or "").strip()


def _looks_like_unified_diff(text: str) -> bool:
    return bool(_DIFF_HEADER_RE.search(text or ""))


def _git_apply_check(repo_path: str, diff_text: str) -> tuple[bool, str]:
    """Run `git apply --check` against the repo. Returns (ok, stderr)."""
    if not diff_text.strip():
        return False, "empty diff"
    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as fh:
        fh.write(diff_text if diff_text.endswith("\n") else diff_text + "\n")
        patch_path = fh.name
    try:
        proc = subprocess.run(
            ["git", "-C", repo_path, "apply", "--check", "--whitespace=nowarn", patch_path],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return proc.returncode == 0, proc.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    finally:
        try:
            os.unlink(patch_path)
        except OSError:
            pass


def _build_prompt(finding: dict, file_excerpt: str) -> str:
    return (
        f"Vulnerability: {finding.get('title') or finding.get('rule_id') or 'unknown'}\n"
        f"CWE: {finding.get('cwe') or finding.get('cwe_id') or 'unknown'}\n"
        f"Severity: {finding.get('severity', 'medium')}\n"
        f"File: {finding.get('file_path')}\n"
        f"Line: {finding.get('line_start') or finding.get('line') or '?'}\n"
        f"Description: {(finding.get('description') or '')[:600]}\n"
        f"\n"
        f"--- Current file content (excerpt) ---\n"
        f"{file_excerpt}\n"
        f"--- end ---\n"
        f"\n"
        f"Produce a minimal unified diff that fixes ONLY this vulnerability. "
        f"The diff's `---`/`+++` paths must be `a/{finding.get('file_path')}` "
        f"and `b/{finding.get('file_path')}` so it applies from the repo root."
    )


def _read_excerpt(repo_path: str, rel_path: str, line: int, *, window: int = 40) -> str:
    full = Path(repo_path) / rel_path.lstrip("/")
    if not full.is_file() or full.stat().st_size > 500_000:
        return ""
    try:
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    lo = max(0, int(line) - window // 2)
    hi = min(len(lines), int(line) + window // 2)
    numbered = [f"{i + 1:5d} | {lines[i]}" for i in range(lo, hi)]
    return "\n".join(numbered)


# ----------------------------------------------------------------- public API


async def generate_autofix(
    finding: dict,
    *,
    repo_path: str,
    db=None,
    orchestrator=None,
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> AutofixResult:
    """Generate a unified diff that fixes ``finding``. Cached per-fingerprint."""
    fingerprint = finding.get("fingerprint") or "no-fp"
    rel_path = finding.get("file_path") or ""
    file_hash = _file_hash(Path(repo_path) / rel_path.lstrip("/")) if rel_path else "no-file"

    # Provider selection (env override → arg → orchestrator default).
    chosen_provider = (
        os.environ.get("FORTKNOXX_AUTOFIX_LLM") or provider or "anthropic"
    ).lower()

    # 1. Cache hit: same fingerprint + same file hash → reuse.
    if db is not None:
        try:
            doc = await db[_CACHE_COLLECTION].find_one({"_id": fingerprint})
        except Exception as exc:
            logger.debug("autofix cache read failed: %s", exc)
            doc = None
        if doc and doc.get("file_hash") == file_hash and doc.get("diff"):
            return AutofixResult(
                fingerprint=fingerprint,
                file_hash=file_hash,
                diff=doc["diff"],
                applies_cleanly=bool(doc.get("applies_cleanly")),
                cached=True,
                provider=doc.get("provider", chosen_provider),
                model=doc.get("model"),
            )

    if orchestrator is None:
        return AutofixResult(
            fingerprint=fingerprint, file_hash=file_hash, diff="",
            applies_cleanly=False, cached=False, provider=chosen_provider,
            model=model, error="no LLM orchestrator available",
        )

    # 2. Generate.
    excerpt = _read_excerpt(
        repo_path,
        rel_path,
        int(finding.get("line_start") or finding.get("line") or 0),
    )
    try:
        raw = await orchestrator.generate_completion(
            provider=chosen_provider,
            model=model,
            messages=[{"role": "user", "content": _build_prompt(finding, excerpt)}],
            system_message=_SYSTEM_PROMPT,
            temperature=0.0,
            max_tokens=1500,
        )
    except Exception as exc:
        logger.warning("autofix LLM call failed: %s", exc)
        return AutofixResult(
            fingerprint=fingerprint, file_hash=file_hash, diff="",
            applies_cleanly=False, cached=False, provider=chosen_provider,
            model=model, error=f"llm error: {exc}",
        )

    diff = _strip_fences(raw)
    if not _looks_like_unified_diff(diff):
        return AutofixResult(
            fingerprint=fingerprint, file_hash=file_hash, diff=diff,
            applies_cleanly=False, cached=False, provider=chosen_provider,
            model=model, error="LLM did not return a unified diff",
        )

    # 3. Validate with git apply --check.
    applies_cleanly, apply_err = _git_apply_check(repo_path, diff)
    if not applies_cleanly:
        logger.info("Autofix diff failed git apply --check: %s", apply_err)

    result = AutofixResult(
        fingerprint=fingerprint,
        file_hash=file_hash,
        diff=diff,
        applies_cleanly=applies_cleanly,
        cached=False,
        provider=chosen_provider,
        model=model,
        error=None if applies_cleanly else f"git apply --check: {apply_err}",
    )

    # 4. Persist (only when the diff applies — never poison the cache).
    if db is not None and applies_cleanly:
        try:
            await db[_CACHE_COLLECTION].update_one(
                {"_id": fingerprint},
                {"$set": {**asdict(result), "fingerprint": fingerprint}},
                upsert=True,
            )
        except Exception as exc:
            logger.debug("autofix cache write failed: %s", exc)

    return result
