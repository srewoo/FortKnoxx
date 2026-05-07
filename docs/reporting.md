# Reporting Upgrades

Trend dashboards, owner attribution, EPSS-weighted risk scoring, and a
SOC2/PCI evidence pack export. Pure read-side endpoints — no scanner
work happens here.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/trends/findings?repo_id=<id>&days=30` | Findings introduced per day |
| GET | `/api/trends/top-risk?repo_id=<id>&limit=20` | Top-N findings by risk score |
| GET | `/api/trends/owners?repo_id=<id>` | Findings grouped by `owner_email` |
| GET | `/api/reports/evidence-pack?repo_id=<id>&scan_id=<id>` | ZIP export for auditors |

## Risk score (0–100)

```
risk = severity × reachability × (0.5 + 0.5·EPSS) × asset_criticality
```

* **severity** — critical 1.0, high 0.8, medium 0.5, low 0.2, info 0.05
* **reachability** — `True` 1.0, unknown 0.4, `False` 0.1
* **EPSS** — Exploit Prediction Scoring System (FIRST.org free API),
  cached 24h per CVE in MongoDB
* **asset_criticality** — repo tag in `{critical, high, medium, low}`

Implemented in `services/risk_score.py`. Run on findings before persisting
so the dashboards can sort by `risk_score` directly.

## Owner attribution

`services/blame.py` shells out to `git blame --porcelain -L <line>,<line>`
on the cloned repo. Adds `owner_name`, `owner_email`, `last_modified_unix`
to each finding.

* No SSO/Slack/Auth integration required — email is the identity key.
* Falls back gracefully if git is unavailable or the file/line is missing.

## Evidence pack

`/api/reports/evidence-pack` returns a ZIP with:

* `manifest.json` — repo metadata, scan timestamps, control mapping
  (SOC2 CC7.1/CC7.2, PCI 6.5/11.3), totals
* `findings.json` — full finding list including risk + owner annotations
* `summary.md` — human-readable overview for auditors
* `scanner_health.json` — which scanners ran, which didn't

Designed to be self-contained: no calls back to the FortKnoxx server are
required to verify the evidence later.

## Tests

```bash
cd backend && venv/bin/python -m pytest tests/test_reporting.py -q
```

8 tests cover: severity/reachability/asset weighting, in-place annotation,
real-git-repo blame attribution, missing-file fallback.
