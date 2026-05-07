# FortKnoxx Triage Engine

Cross-scanner deduplication, fingerprint-based LLM triage cache, and
declarative finding suppression.

## Pipeline

```
raw findings ─▶ fingerprint ─▶ dedup (by fingerprint)
            ─▶ apply .fortknoxx/ignore.yml
            ─▶ LLM triage (cached per fingerprint)
            ─▶ enriched findings + meta
```

Implemented in `backend/engines/triage/`. Single entry point:
`engines.triage.run_triage()`.

## Enabling

Off by default during rollout. Set on the backend:

```bash
FORTKNOXX_TRIAGE=1
FORTKNOXX_TRIAGE_LLM=1   # optional; defaults on when triage is on
```

When triage is on without an LLM provider configured, dedup + ignore
still run and findings are marked `triage.verdict = "uncertain"`.

## Fingerprint design

`build_fingerprint()` collapses:

- File path normalization (`./app.py` ≡ `app.py`).
- Line drift up to ±5 lines (handles inserts above the finding).
- Whitespace, hex literals, and integer literals in the matched code.
- CWE family aliases (Bandit's `CWE-89` ≡ Semgrep's `CWE-564` for SQLi).

The result is a 16-char SHA-1 prefix that survives reformatting and
re-scans.

## CWE family map

`engines/triage/cwe_map.py` collapses ~80 CWE IDs into ~25 families
(`injection.sql`, `xss`, `auth.jwt`, `secrets.exposed`, etc.). Add new
mappings there as scanners surface unmapped CWEs.

## LLM triage cache

One LLM call per *unique* fingerprint, ever. Verdicts are stored in
the `triage_cache` Mongo collection keyed by fingerprint. Re-scans of
the same repo cost $0.

Verdict shape:

```json
{
  "verdict": "true_positive | likely_fp | needs_context",
  "confidence": 0.0,
  "reason": "<= 200 chars"
}
```

The prompt is fully deterministic (temperature 0, no random ordering)
so providers with prompt-side caching also amortise calls.

## .fortknoxx/ignore.yml

Per-repository suppression rules, version-controlled with the code.

```yaml
rules:
  - fingerprint: 9f3a1c0e2b8d4f60
    justification: "Reviewed 2026-04-12 — false positive in fixtures."
    owner: sharaj@mindtickle.com
    expires_at: 2026-07-12         # ISO date; expired rules emit a warning

  - cwe_family: xss
    path_glob: "**/test/**"
    justification: "XSS in tests is intentional fuzz input."
    expires_at: 2026-12-31
```

Rules match either by exact fingerprint *or* by `(cwe_family + path_glob)`.
Expired rules are not enforced but are reported in `triage.expired_rules`
so CI can fail loudly.

## Tests

```bash
cd backend && venv/bin/python -m pytest tests/test_triage.py -q
```

17 unit tests covering fingerprint stability, CWE mapping, dedup,
ignore rules, LLM verdict parsing, and the end-to-end pipeline with no
LLM provider available.
