# Dashboard — Triage + Code Review UX

Two new self-contained React pages that surface the v1.1 backend
signals in the UI. Built as standalone components so we don't churn
`frontend/src/App.js` (a 2 800-line monolith).

## Pages

### `/repository/:repoId/triage` — Triage dashboard

`frontend/src/components/TriageDashboard.jsx`. One page that shows:

* **Quality Gate** — Sonar-style PASSED / FAILED banner. Default rules:
  no critical findings, < 5 high findings, < 20 confirmed true positives.
  Wire into required PR checks.
* **Highest current risk** — circular gauge fed by `risk_score` from
  `services/risk_score.py`.
* **Dedup snapshot** — number of confirmed-by-≥2-scanners findings,
  cache-hit count from the LLM verdict cache.
* **Trend chart** — daily findings introduced over a configurable
  window (7 / 30 / 90 days). Pure inline SVG, no chart deps.
* **Top-risk list** — 20 highest-risk findings with severity badge,
  triage verdict pill, dedup source pills, owner email, one-click
  Autofix button.
* **Owner heatmap** — bar per `owner_email` from `git blame`,
  segmented red (critical) / orange (high) / muted (other).
* **Evidence-pack** download — calls
  `/api/reports/evidence-pack` and streams the SOC2/PCI ZIP.

Reads from:

```
GET /api/trends/findings?repo_id=…&days=…
GET /api/trends/top-risk?repo_id=…&limit=20
GET /api/trends/owners?repo_id=…
GET /api/scans/{repo_id}
GET /api/reports/evidence-pack
POST /api/autofix
```

### `/repository/:repoId/file?path=…` — Code review view

`frontend/src/components/CodeReviewView.jsx`. Sonar-grade dev-loop UX:

* **File header** — severity counts as badges, A–E quality grade
  computed from `findings`. Grade weights live in `computeQualityScore`.
* **Hotspot cards** — one card per finding: title, severity, CWE,
  CWE family, dedup sources, code snippet, risk score, owner,
  Confirm / Mark safe / Needs review buttons, Autofix shortcut.
* **Annotated source** — full file rendered with line numbers; lines
  with findings get a left-border severity colour and a per-line
  badge with the count.

Triage verdicts are persisted via
`POST /api/findings/{id}/triage { verdict }` (optional during rollout —
the UI degrades gracefully when the endpoint isn't there).

## Why no chart library

We deliberately ship the dashboard with zero new npm dependencies. The
sparkline is a one-line SVG `<polyline>`, the gauge is two `<circle>`s
with `strokeDasharray`. Anyone reviewing the bundle won't see Recharts
or Victory ballooning the build.

## Wiring

Two `<Route>` lines added to `App.js`:

```jsx
<Route path="/repository/:repoId/triage" element={<TriageDashboard />} />
<Route path="/repository/:repoId/file"   element={<CodeReviewView />} />
```

Plus a "Triage" button next to "Start Scan" on the existing
`RepositoryDetail` page so the dashboard is reachable from the main
flow.

## What this closes from the v1.1 gap analysis

* **Gap #2 — Triage UX in React dashboard.** All v1.1 backend signals
  (risk score, owner attribution, trend, top-N, dedup metadata,
  triage verdicts, evidence pack, autofix) now have UI surfaces.
* **Gap #6 — SAST quality + code-review UX.** Quality Gate (PASSED /
  FAILED) and the Sonar-style file viewer with inline annotations and
  a hotspot review workflow give us the dev-loop UX Sonar built its
  reputation on, on top of FortKnoxx's broader detection stack.
