"""Severity + OWASP-category normalisation helpers.

WHY a separate module: scanner output shapes differ across versions
(severity arrives as a list, a string, or — rarely — a number).
These helpers normalise both severity tier and OWASP category in one
place so the scan aggregator stays focused on persistence.

Used by:
  - server.py's `process_scan_results` (today)
  - api/routes/* once the orchestrator is fully extracted (next)
  - any future scanner-worker that produces a Vulnerability dict
"""

from __future__ import annotations

from typing import Any

# OWASP keyword maps. Order matters: the first match wins, mirroring
# the original logic in server.py. Each tuple is
# (owasp_code, list_of_keyword_snippets).
_OWASP_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("A01", ("access", "authorization", "permission", "privilege")),
    ("A02", ("crypto", "encryption", "hash", "password", "secret")),
    ("A03", ("injection", "sql", "xss", "command", "ldap", "xpath")),
    ("A04", ("design", "logic", "business")),
    ("A05", ("config", "default", "debug", "error")),
    ("A06", ("dependency", "component", "library", "cve", "outdated")),
    ("A07", ("auth", "session", "token", "credential")),
    ("A08", ("integrity", "deserialization", "update")),
    ("A09", ("log", "monitor", "audit")),
    ("A10", ("ssrf", "request forgery")),
]


def normalize_severity(severity_value: Any, default: str = "medium") -> str:
    """Coerce scanner severity output into a lowercase string.

    - list   → first element, lowercased; empty list → ``default``.
    - string → lowercased.
    - anything else (None, int) → ``default``.
    """
    if isinstance(severity_value, list):
        if not severity_value:
            return default
        first = severity_value[0]
        return str(first).lower() if first is not None else default
    if isinstance(severity_value, str):
        return severity_value.lower()
    return default


def map_to_owasp(category: str, title: str, description: str) -> str:
    """Map a finding to its OWASP Top 10 (2021) bucket.

    Matches keywords across the three input strings; defaults to
    ``A05`` (security misconfiguration) when nothing matches.
    """
    haystack = f"{category} {title} {description}".lower()
    for code, keywords in _OWASP_RULES:
        if any(keyword in haystack for keyword in keywords):
            return code
    return "A05"
