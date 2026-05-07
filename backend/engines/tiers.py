"""
Two-tier scan model.

FAST tier   — runs in seconds. Used for pre-commit, PR-on-push, and small diffs.
              Only includes scanners with low setup cost and sub-minute runtimes.

DEEP tier   — full sweep. Used for nightly builds, release branches, and large
              diffs. Includes everything FAST does, plus heavy ML/runtime scanners.

The tier is applied as an *override* on the user's saved scanner_settings:
  • disabled scanners stay disabled (user intent wins)
  • scanners outside the tier set are forced off for that scan
  • fast scanners always stay on for a deep run

This way the tier is purely additive/subtractive — it never violates a
user's explicit "I don't want gosec" preference.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

# ScannerSettings flag names that participate in the FAST tier.
# Curated for: low setup cost, no Docker, no model load, sub-second per file.
FAST_SCANNERS: frozenset[str] = frozenset({
    "enable_semgrep",
    "enable_bandit",
    "enable_eslint",
    "enable_gitleaks",
    "enable_trufflehog",
    "enable_shellcheck",
    "enable_hadolint",
    "enable_pylint",
    "enable_flake8",
    "enable_sqlfluff",
})

# Heavy / slow / network-bound scanners — DEEP-only.
DEEP_ONLY_SCANNERS: frozenset[str] = frozenset({
    "enable_zero_day_detector",      # ML model load
    "enable_business_logic_scanner",  # runtime testing
    "enable_llm_security_scanner",    # LLM API calls
    "enable_auth_scanner",            # runtime auth flow probing
    "enable_codeql",                  # multi-minute database build
    "enable_zap_dast",                # docker pull + spider
    "enable_api_fuzzer",              # network requests
    "enable_schemathesis",            # property-based fuzz
    "enable_garak",                   # LLM red-team
    "enable_promptfoo",               # LLM regression eval
    "enable_nuclei",                  # template-driven CVE scan
    "enable_prowler",                 # cloud audit
    "enable_kube_bench",
    "enable_kube_hunter",
    "enable_spotbugs",                # JVM startup + bytecode analysis
    "enable_pyre",                    # type-graph build
    "enable_horusec",                 # docker pull
    "enable_snyk",                    # cloud API
})

# Scanners that always run regardless of tier (cheap + universally useful).
ALWAYS_ON: frozenset[str] = frozenset({
    "enable_grype",        # local CVE DB; very fast
    "enable_trivy",        # local CVE DB; very fast
    "enable_checkov",      # IaC pattern match; fast
    "enable_osv_scanner",  # offline OSV DB
    "enable_license_scanner",
    "enable_cyclonedx",
})


@dataclass
class TierDecision:
    """Result of resolving a tier."""

    tier: str           # "fast" | "deep"
    reason: str         # human-readable why we picked it
    diff_lines: int     # measured diff size; -1 if not measured
    forced: bool        # True if explicitly requested by caller


def _git_diff_lines(repo_path: str, base_ref: str = "HEAD~1") -> int:
    """Return the number of changed lines vs ``base_ref``. -1 if git fails."""
    try:
        out = subprocess.check_output(
            ["git", "-C", repo_path, "diff", "--shortstat", base_ref],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return -1

    # Output: " 3 files changed, 42 insertions(+), 7 deletions(-)"
    total = 0
    for token in out.split(","):
        token = token.strip()
        digits = "".join(c for c in token if c.isdigit())
        if not digits:
            continue
        if "insertion" in token or "deletion" in token:
            total += int(digits)
    return total


def resolve_tier(
    requested: str | None,
    repo_path: str,
    *,
    auto_threshold: int = 500,
) -> TierDecision:
    """Decide which tier to run.

    requested ∈ {"fast", "deep", "auto", None}.
    auto_threshold: lines of diff above which auto promotes to deep.
    """
    req = (requested or "auto").lower()
    if req in ("fast", "deep"):
        return TierDecision(tier=req, reason=f"explicit ({req})", diff_lines=-1, forced=True)

    diff = _git_diff_lines(repo_path)
    if diff < 0:
        # No git history → safest assumption is a full deep scan.
        return TierDecision(tier="deep", reason="no git diff available", diff_lines=-1, forced=False)

    if diff >= auto_threshold:
        return TierDecision(
            tier="deep",
            reason=f"diff {diff} ≥ threshold {auto_threshold}",
            diff_lines=diff,
            forced=False,
        )
    return TierDecision(
        tier="fast",
        reason=f"diff {diff} < threshold {auto_threshold}",
        diff_lines=diff,
        forced=False,
    )


def apply_tier(scanner_settings, tier: str):
    """Mutate a copy of scanner_settings for the chosen tier and return it.

    Never enables a scanner the user disabled. Disables tier-incompatible
    scanners only.
    """
    if tier not in ("fast", "deep"):
        return scanner_settings

    # pydantic v2 BaseModel — work on a deep copy.
    overridden = scanner_settings.model_copy(deep=True)

    if tier == "fast":
        for field_name in _flag_fields(overridden):
            if field_name in ALWAYS_ON or field_name in FAST_SCANNERS:
                continue
            if getattr(overridden, field_name, False):
                setattr(overridden, field_name, False)
    # tier == "deep": leave user's saved settings as-is. Deep means
    # "everything the user has enabled stays enabled."

    return overridden


def _flag_fields(settings) -> Iterable[str]:
    return [name for name in type(settings).model_fields if name.startswith("enable_")]
