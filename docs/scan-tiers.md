# Scan Tiers — Fast vs Deep

Two-tier scan model so developers see findings in seconds while security
gets a full sweep nightly.

## Tiers

| Tier  | Runtime target | Scanners | When to use |
| ----- | -------------- | -------- | ----------- |
| FAST  | < 60s on a typical service repo | Semgrep, Bandit, ESLint, Gitleaks, TruffleHog, ShellCheck, Hadolint, Pylint, Flake8, SQLFluff, plus always-on (Grype, Trivy, Checkov, OSV, license, CycloneDX) | Pre-commit, PR-on-push, small diffs |
| DEEP  | Multi-minute, full coverage | Everything in FAST, plus Zero-day GNN, Business Logic, LLM Security, Auth Scanner, CodeQL, ZAP DAST, API Fuzzer, Schemathesis, Garak, Promptfoo, Nuclei, Prowler, kube-bench, kube-hunter, SpotBugs, Pyre, Horusec, Snyk | Nightly builds, release branches, large diffs |

## Auto mode

`POST /api/scans/{repo_id}?tier=auto` (the default) decides at scan time:

```
git diff --shortstat HEAD~1 → total changed lines
  ≥ 500 lines  → deep
  <  500 lines → fast
  no git diff  → deep (safe default)
```

Threshold is configurable via the `auto_threshold` arg of
`engines.tiers.resolve_tier`.

## API

```
POST /api/scans/{repo_id}?tier=fast        # explicit fast
POST /api/scans/{repo_id}?tier=deep        # explicit deep
POST /api/scans/{repo_id}?tier=auto        # default
POST /api/scans/{repo_id}                  # equivalent to ?tier=auto
```

Response includes the resolved tier:

```json
{
  "scan_id": "…",
  "status": "started",
  "tier": "auto",
  "message": "Scan initiated successfully"
}
```

The scan record stores `tier`, `tier_reason` (`"diff 42 < threshold 500"`),
and `tier_diff_lines` for the UI to display.

## Tier override semantics

The tier is layered on top of the user's saved scanner settings:

* If the user disabled `semgrep`, it stays disabled in both tiers.
* In FAST, scanners outside the FAST allowlist are forced off **for that
  scan only**. Saved settings are never mutated.
* DEEP is a pass-through — every scanner the user enabled runs.

This way nothing in this feature can sneak past a user's "I don't want
this scanner running" decision.

## Scanner classification

Source of truth: `backend/engines/tiers.py`.

* `FAST_SCANNERS` — low setup, sub-minute, no Docker, no model load.
* `DEEP_ONLY_SCANNERS` — heavy ML / runtime / network-bound.
* `ALWAYS_ON` — cheap CVE/SBOM/IaC pattern matchers; both tiers run them.

Adding a new scanner: add its `enable_<name>` flag to exactly one of those
sets. The `test_fast_and_deep_only_are_disjoint` test guards against
accidentally listing it in both.

## Tests

```bash
cd backend && venv/bin/python -m pytest tests/test_tiers.py -q
```

12 tests cover explicit tiers, auto-resolution by diff size, no-git
fallback, user-preference preservation, and the fast/deep allowlist
disjointness invariant.
