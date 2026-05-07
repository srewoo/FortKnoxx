"""
CWE family mapping.

Different scanners report different CWE IDs for the same underlying weakness
(e.g. Bandit emits CWE-89 for SQLi, Semgrep emits CWE-564, Snyk emits CWE-943).
We collapse them to a small set of canonical *families* so deduplication
can recognise cross-scanner duplicates.

Why families instead of full CWE → CWE remapping:
  • Stable: families rarely change; CWE additions are frequent.
  • Coarse-but-correct: triage UX cares about "this is SQLi", not the
    32-way taxonomy split underneath CWE-89.
  • Free: no external taxonomy service required.
"""

from __future__ import annotations

# Family -> set of CWE IDs that should collapse into it.
# Ordered roughly by triage priority. Add to this map as new scanners surface
# CWE ids that don't already appear; tests in test/ guard against drift.
_FAMILY_TO_CWES: dict[str, set[str]] = {
    "injection.sql": {"CWE-89", "CWE-564", "CWE-943"},
    "injection.command": {"CWE-77", "CWE-78", "CWE-88"},
    "injection.code": {"CWE-94", "CWE-95", "CWE-1336"},
    "injection.ldap": {"CWE-90"},
    "injection.xpath": {"CWE-643"},
    "injection.template": {"CWE-1336", "CWE-94"},
    "xss": {"CWE-79", "CWE-80", "CWE-83", "CWE-87"},
    "xxe": {"CWE-611", "CWE-827"},
    "ssrf": {"CWE-918"},
    "path_traversal": {"CWE-22", "CWE-23", "CWE-24", "CWE-36"},
    "open_redirect": {"CWE-601"},
    "deserialization": {"CWE-502"},
    "auth.broken": {"CWE-287", "CWE-306", "CWE-307", "CWE-798", "CWE-862"},
    "auth.session": {"CWE-384", "CWE-613", "CWE-384", "CWE-1004"},
    "auth.jwt": {"CWE-347", "CWE-345"},
    "authz.idor": {"CWE-639", "CWE-284", "CWE-285"},
    "crypto.weak": {"CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338"},
    "crypto.hardcoded_key": {"CWE-321", "CWE-798"},
    "secrets.exposed": {"CWE-200", "CWE-532", "CWE-798"},
    "csrf": {"CWE-352"},
    "cors.misconfig": {"CWE-942", "CWE-346"},
    "headers.missing": {"CWE-1021", "CWE-693"},
    "input.validation": {"CWE-20", "CWE-1284"},
    "race_condition": {"CWE-362", "CWE-367", "CWE-820"},
    "resource.exhaustion": {"CWE-400", "CWE-770", "CWE-789"},
    "logging.sensitive": {"CWE-532", "CWE-209"},
    "supply_chain.cve": {"CWE-1104", "CWE-937"},
    "iac.misconfig": {"CWE-1004", "CWE-732"},
    "container.config": {"CWE-250", "CWE-269"},
    "llm.prompt_injection": {"CWE-1426"},  # placeholder; CWE catalog is evolving
}

# Reverse index built once at import for O(1) lookups.
_CWE_TO_FAMILY: dict[str, str] = {
    cwe: family for family, cwes in _FAMILY_TO_CWES.items() for cwe in cwes
}


def canonical_cwe_family(cwe: str | None) -> str:
    """Return the family bucket for a CWE id.

    Falls back to a per-CWE family ('cwe.<id>') for unknown CWEs so that
    findings still group with themselves but don't bleed into unrelated
    findings. Empty/None input collapses to 'unclassified'.
    """
    if not cwe:
        return "unclassified"
    normalised = cwe.strip().upper()
    if not normalised.startswith("CWE-"):
        normalised = f"CWE-{normalised.lstrip('CWE-').lstrip('-')}"
    return _CWE_TO_FAMILY.get(normalised, f"cwe.{normalised.lower()}")


def known_families() -> list[str]:
    """List the canonical families. Useful for UI filters and tests."""
    return sorted(_FAMILY_TO_CWES.keys())
