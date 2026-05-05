"""OWASP Top 10 (2021) category labels.

WHY a separate module: the mapping is referenced from server.py, the
report generator, the AI fix prompt, and any future MCP tool. Keeping
it in one place stops it drifting when OWASP publishes a new edition.
"""

from __future__ import annotations

OWASP_CATEGORIES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}


def label_for(code: str) -> str:
    """Human-readable label for an OWASP A0X code, or "Unknown"."""
    return OWASP_CATEGORIES.get(code, "Unknown")
