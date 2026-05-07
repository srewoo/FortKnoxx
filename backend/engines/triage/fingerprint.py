"""
Canonical finding fingerprint.

Goal: a finding produced by Bandit *and* Semgrep on the same SQLi must
hash to the same fingerprint. The fingerprint must also be stable across:
  • Trivial reformatting (whitespace, blank lines, comments).
  • Small line-number drift (insertion of unrelated lines above).
  • File path normalization (./ prefix, OS separators).

Inputs are heterogeneous Dicts coming from many scanners; we coerce them
through a small adapter rather than forcing every scanner to emit the
same schema.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

from .cwe_map import canonical_cwe_family

_LINE_BUCKET = 5  # Two findings within ±5 lines collapse if everything else matches.

# Strip noise that varies between scanners but doesn't change the finding identity.
_WS_RE = re.compile(r"\s+")
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_NUM_RE = re.compile(r"\b\d+\b")


_NUM_SEGMENT_RE = re.compile(r"/\d+(?=/|$)")
_UUID_SEGMENT_RE = re.compile(
    r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?=/|$)"
)
# OpenAPI/Schemathesis-style ``/{id}`` path parameters.
_BRACE_SEGMENT_RE = re.compile(r"/\{[^/]+?\}(?=/|$)")


def _normalise_path(path: str | None) -> str:
    """Stable path key for both source files and DAST URLs.

    For URLs we strip scheme+host, drop the query string, collapse
    numeric and UUID path segments to placeholders, and lower-case the
    result. That way ZAP's ``http://app/api/users/42`` and Nuclei's
    ``/api/users/99`` both fingerprint the same endpoint.
    """
    if not path:
        return "unknown"

    p = path.replace("\\", "/").strip()
    # Looks like a URL? Take the path portion only.
    if "://" in p:
        from urllib.parse import urlsplit
        parts = urlsplit(p)
        p = parts.path or "/"
    # Drop query/fragment if a caller passed a full URI here.
    p = p.split("?", 1)[0].split("#", 1)[0]

    p = p.lstrip("./")
    p = re.sub(r"^/.*?/(?=[^/]+/)", "", p) if p.startswith("/") else p

    # Collapse path-parameter style segments so endpoints match across
    # scanners that report concrete vs. parameterised forms.
    p = _UUID_SEGMENT_RE.sub("/{id}", p)
    p = _BRACE_SEGMENT_RE.sub("/{id}", p)
    p = _NUM_SEGMENT_RE.sub("/{id}", p)

    return p.lower()


_BRACE_TOKEN_RE = re.compile(r"\{[^{}\s]+?\}")


def _normalise_code(snippet: str | None) -> str:
    """Collapse whitespace, hex literals, numbers, and OpenAPI-style
    ``{id}`` path placeholders so cosmetic edits don't break the
    fingerprint."""
    if not snippet:
        return ""
    s = snippet.strip()
    s = _WS_RE.sub(" ", s)
    s = _HEX_RE.sub("0xN", s)
    s = _BRACE_TOKEN_RE.sub("N", s)
    s = _NUM_RE.sub("N", s)
    return s.lower()


def _line_bucket(line: Any) -> int:
    try:
        n = int(line or 0)
    except (TypeError, ValueError):
        n = 0
    return (n // _LINE_BUCKET) * _LINE_BUCKET


def _read_context(repo_path: str | None, file_path: str | None, line: int | None) -> str:
    """Read ±2 lines around the finding to anchor the fingerprint to code,
    not a raw line number. Best-effort: returns empty string on any error.
    """
    if not (repo_path and file_path and line):
        return ""
    try:
        full = Path(repo_path) / file_path.lstrip("/")
        if not full.is_file() or full.stat().st_size > 2_000_000:
            return ""
        with full.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        lo = max(0, int(line) - 3)
        hi = min(len(lines), int(line) + 2)
        return "".join(lines[lo:hi])
    except Exception:
        return ""


def build_fingerprint(finding: dict, repo_path: str | None = None) -> str:
    """Return a stable 16-char hex fingerprint for a finding dict.

    The dict is expected to contain *some* of:
      file_path / file, line_start / line, cwe / cwe_id, category,
      rule_id / id, code / snippet.
    Missing fields degrade gracefully — fingerprints stay stable for the
    same finding across runs even when only a subset is populated.
    """
    file_path = _normalise_path(
        finding.get("file_path") or finding.get("file") or finding.get("path")
    )
    line = finding.get("line_start") or finding.get("line") or finding.get("start_line")
    bucket = _line_bucket(line)

    cwe_raw = finding.get("cwe") or finding.get("cwe_id") or finding.get("category", "")
    family = canonical_cwe_family(str(cwe_raw) if cwe_raw else None)

    snippet = (
        finding.get("code")
        or finding.get("snippet")
        or finding.get("matched_text")
        or _read_context(repo_path, file_path, line)
    )
    code_hash = hashlib.sha1(_normalise_code(snippet).encode("utf-8")).hexdigest()[:10]

    raw = f"{file_path}|{bucket}|{family}|{code_hash}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]
