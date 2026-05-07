# FortKnoxx 🔒

**Next-Generation AI-Powered Security Scanner** — combines traditional SAST,
AI-powered zero-day detection, runtime verification, 500+ attack payloads,
and a triage / autofix / benchmark stack that turns AI scanner claims into
measurable evidence.

---

## ✨ What's New in v1.1

Shipped on top of the v1.0 scanner platform:

| Feature | What it does | Docs |
| --- | --- | --- |
| **Docker Compose stack** | `make up` runs mongo + redis + backend + frontend with healthchecks | [`docker-compose.yml`](docker-compose.yml) |
| **Triage engine** | Cross-scanner dedup via fingerprint + CWE family map, LLM verdict cache, `.fortknoxx/ignore.yml` | [`docs/triage.md`](docs/triage.md) |
| **Two-tier scan model** | `?tier=fast\|deep\|auto` — secs for PR builds, minutes for nightlies | [`docs/scan-tiers.md`](docs/scan-tiers.md) |
| **LLM autofix** | Returns *unified diffs* validated by `git apply --check`, cached per `(fingerprint, file_hash)`, Ollama fallback | [`docs/autofix.md`](docs/autofix.md) |
| **OWASP Benchmark harness** | `make benchmark` against OWASP Benchmark / Juliet / SecurityEval / BigVul → precision / recall / F1 | [`docs/benchmarks/`](docs/benchmarks/) |
| **Risk + trends + owners** | EPSS-weighted risk score, `git blame` owner attribution, trend dashboard, SOC2/PCI evidence ZIP | [`docs/reporting.md`](docs/reporting.md) |
| **CNAPP-lite + OTel** | Code↔cloud correlation via IaC resources; OpenTelemetry tracing on FastAPI + scanner / LLM spans | [`docs/cnapp-and-otel.md`](docs/cnapp-and-otel.md) |
| **ZAP DAST overhaul** | Automation Framework YAML, real auth (form / JWT / OAuth2-cc), AJAX spider, OpenAPI auto-discovery, session reuse, triage dedup | [`docs/zap-dast.md`](docs/zap-dast.md) |

**Test coverage:** 73 unit tests across triage, tiers, autofix, reporting,
CNAPP, ZAP + 5 benchmark metrics tests = **78 green**.

**Cost ceiling:** every LLM-using feature has fingerprint caching + an
Ollama fallback. Every cloud feature uses free OSS or free APIs (FIRST
EPSS, OTel collector). Marginal LLM cost only.

---

## 🌟 Key Features

### 🤖 AI-Powered Security Scanners (Unique to FortKnoxx)

#### 1. Zero-Day Detector (ML-Based)
- **Graph Neural Networks (GNN)** for code property graph analysis
- **CodeBERT** transformer model for semantic understanding
- Detects **novel vulnerabilities** that signature-based tools miss
- Anomaly scoring with confidence levels

#### 2. Business Logic Scanner (Runtime Testing)
- Detects: IDOR, workflow bypass, race conditions, price manipulation
- **Static Flow Analysis** + **Runtime Verification**
- 10+ business logic vulnerability patterns
- Actual HTTP requests to verify exploitability

#### 3. LLM Security Scanner (Adversarial Testing)
- **ONLY** general-purpose security tool with dedicated LLM testing
- 1 000+ adversarial payloads (prompt injection, jailbreak, data leakage)
- Real API testing (OpenAI, Anthropic, Gemini)
- 8 attack categories: injection, jailbreak, prompt extraction, tool abuse, …

#### 4. Auth/AuthZ Scanner (Runtime Testing)
- **JWT**: algorithm confusion, weak secrets, signature bypass
- **OAuth 2.0**: redirect URI manipulation, PKCE enforcement, scope escalation
- **Session**: cookie security, fixation, hijacking
- Drives actual authentication flow probes

### 💥 PayloadsAllTheThings Integration
- 500+ attack payloads across 13 categories
- WAF evasion, encoding variants, obfuscation
- Smart payload selection driven by detected language/framework

### 🎯 Strix-Inspired Fuzzing
- 10 mutation strategies, coverage-guided
- Property-based testing, anomaly detection, concurrent fuzzing

### 🔧 Specialized Scanner Integrations
- **CodeQL** — 1 000+ semantic queries (Python/JS/Java/Go/C++/Ruby/C#)
- **Docker Security** — Trivy CVE, hadolint, CIS benchmarks
- **IaC** — Terraform (tfsec, checkov), Kubernetes (kube-score, kube-bench), CloudFormation (cfn-lint, cfn_nag)
- **OWASP ZAP DAST** — full Automation Framework with auth + SPA crawl + OpenAPI auto-discovery

### 📊 Unified Security Platform
- 7 specialized scanner families running in parallel + 25+ external tool wrappers
- Risk scoring 0–100 with EPSS, reachability, asset criticality
- Compliance mapping: OWASP Top 10, CWE, MITRE ATT&CK, PCI-DSS, HIPAA, SOC 2
- Trend dashboards, owner attribution, top-risk lists
- Export formats: JSON, SARIF, PDF, CSV, evidence-pack ZIP

### 🎨 Modern Web Interface
- React dashboard with shadcn/ui
- Real-time scan progress, risk gauges, code-snippet drill-down
- Settings UI with encrypted API-key storage

---

## 🚀 Quick Start

### Prerequisites

- **Docker + Docker Compose** (recommended path)
- *or* Python 3.10+ / MongoDB / Node.js 16+ / Yarn (manual path)
- **Redis** (optional — used for the triage / autofix cache and job queue)

### Option A — Docker (recommended)

```bash
git clone https://github.com/your-org/FortKnoxx.git
cd FortKnoxx

# 1. Configure secrets
cp env.sample .env
openssl rand -hex 32                                                 # JWT_SECRET_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # ENCRYPTION_MASTER_KEY
# edit .env, paste both values

# 2. Bring up the full stack
make up                       # mongo + redis + backend + frontend
make logs                     # tail everything
make down                     # stop
```

Then open **http://localhost:3000**. The Makefile also has `make build`,
`make rebuild`, `make shell-backend`, `make benchmark`, `make clean`.

### Option B — Local install

```bash
# install scanners + Python deps
chmod +x install_all_scanners.sh
./install_all_scanners.sh

# configure
cp .env.sample backend/.env   # then edit it as above

# start
./start_servers.sh            # mongo + backend (8000) + frontend (3000)
./stop_servers.sh             # stop
```

---

## ⚙️ Configuration

`.env` lives at the repo root for the docker stack and at `backend/.env`
for the manual stack. Required keys:

```env
# Database
MONGO_URL=mongodb://localhost:27017
DB_NAME=fortknox_db

# Required security keys
JWT_SECRET_KEY=<openssl rand -hex 32>
ENCRYPTION_MASTER_KEY=<Fernet.generate_key>

# Optional job queue + triage cache
REDIS_URL=redis://localhost:6379

# Optional LLM keys (BYOK — also configurable via Settings UI)
# OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
# GEMINI_API_KEY=AIza...

# Scanner tokens
# GITHUB_TOKEN=ghp_...
# SNYK_TOKEN=...
```

### v1.1 feature flags

| Variable | What it controls | Default |
| --- | --- | --- |
| `FORTKNOXX_TRIAGE` | Enable cross-scanner dedup + LLM triage pipeline (off during rollout) | unset |
| `FORTKNOXX_TRIAGE_LLM` | Use LLM for verdict generation (cached forever per fingerprint) | `1` when triage is on |
| `FORTKNOXX_AUTOFIX_LLM` | Override autofix provider; set to `ollama` for zero-cost local fixes | unset |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Enable OpenTelemetry tracing → ship spans to a collector | unset (off) |

### API keys via Settings UI

1. Start the app, navigate to **Settings** (`/settings`).
2. Add keys for OpenAI / Anthropic / Gemini / GitHub / Snyk.
3. All keys are AES-256 encrypted and stored in MongoDB.

---

## 🎯 Usage

### Add a repository

```
POST /api/repositories
{
  "name": "my-app",
  "url": "https://github.com/user/repo",
  "access_token": "ghp_...",
  "branch": "main"
}
```

### Run a scan

```
POST /api/scans/{repo_id}?tier=auto      # default
POST /api/scans/{repo_id}?tier=fast      # secs — Semgrep + Bandit + secrets + linters
POST /api/scans/{repo_id}?tier=deep      # full sweep including ML, DAST, LLM
```

`tier=auto` chooses fast / deep based on `git diff --shortstat HEAD~1` size
(threshold 500 lines). User-disabled scanners stay disabled.

### Inspect findings

```
GET  /api/scans/{repo_id}                      # list scans
GET  /api/findings?repo_id={id}                # per-repo findings
GET  /api/trends/findings?repo_id={id}&days=30 # introduced-per-day series
GET  /api/trends/top-risk?repo_id={id}&limit=20
GET  /api/trends/owners?repo_id={id}
```

### Generate a fix (unified diff, cached)

```
POST /api/autofix
{
  "vulnerability_id": "<finding id>",
  "repo_path": "/tmp/fortknoxx_repos/<repo_id>",
  "provider": "anthropic"
}
```

Returns `{ diff, applies_cleanly, cached, … }`. The UI surfaces an
"Apply fix" button only when `applies_cleanly: true`. Set
`FORTKNOXX_AUTOFIX_LLM=ollama` to run fully on a local model.

### Export evidence pack (SOC2 / PCI auditors)

```
GET /api/reports/evidence-pack?repo_id={id}&scan_id={id}
```

Streams a ZIP with `manifest.json`, `findings.json`, `summary.md`, and
`scanner_health.json` mapped to SOC2 CC7.1/CC7.2 + PCI 6.5/11.3.

Full Swagger UI: **http://localhost:8000/docs**

---

## 🪜 Tiered Scans

`backend/engines/tiers.py` classifies every scanner into one of three sets:

| Set | Scanners | Tier policy |
| --- | --- | --- |
| `FAST_SCANNERS` | Semgrep, Bandit, ESLint, Gitleaks, TruffleHog, ShellCheck, Hadolint, Pylint, Flake8, SQLFluff | runs in fast and deep |
| `DEEP_ONLY_SCANNERS` | Zero-day GNN, Business Logic, LLM, Auth, CodeQL, ZAP DAST, API Fuzzer, Schemathesis, Garak, Promptfoo, Nuclei, Prowler, kube-bench, kube-hunter, SpotBugs, Pyre, Horusec, Snyk | deep only |
| `ALWAYS_ON` | Grype, Trivy, Checkov, OSV, license, CycloneDX | both tiers |

The tier is layered on top of the user's saved settings — if you've
disabled `gosec`, it stays disabled, regardless of tier.

---

## 🧹 Triage Engine

After every scan FortKnoxx can run `engines.triage.run_triage()` (opt-in
via `FORTKNOXX_TRIAGE=1`):

1. **Fingerprint** — stable 16-char hash that survives whitespace edits,
   line drift up to ±5 lines, and CWE-family aliases (Bandit's `CWE-89`
   == Semgrep's `CWE-564` for SQLi). URLs are normalised — `/api/users/123`,
   `http://app/api/users/9999`, and `/api/users/{id}` all collapse so ZAP
   / Nuclei / Schemathesis findings on the same endpoint dedupe.
2. **Dedup** — worst-severity wins, sources merged, confidence boosted.
3. **Ignore rules** — `.fortknoxx/ignore.yml` per-repo with optional
   `expires_at` so suppressions don't rot.
4. **LLM triage** — one call per fingerprint, cached forever in
   `triage_cache`. Re-scans of the same repo cost $0.

---

## 🛠️ LLM Autofix

`POST /api/autofix` returns a *verified unified diff*, not free-form
prose. The flow:

```
finding ─▶ fingerprint+file_hash cache lookup
       ─▶ LLM call (temperature 0, deterministic prompt)
       ─▶ git apply --check against the cloned repo
       ─▶ persist on success only (no poison cache)
       ─▶ return { diff, applies_cleanly, cached, provider, model }
```

`FORTKNOXX_AUTOFIX_LLM=ollama` routes every call to a local model. The
fingerprint cache means even paid-LLM mode amortises to nearly zero
cost across re-scans.

---

## 📈 Risk-Based Reporting

```
risk = severity × reachability × (0.5 + 0.5·EPSS) × asset_criticality
```

* **EPSS** — pulled from FIRST.org's free API, cached 24h per CVE.
* **Reachability** — set by the existing reachability heuristic (or
  `unknown` → 0.4 weight).
* **Asset criticality** — repo tag in `{critical, high, medium, low}`.

Output normalised to 0–100. The dashboard sorts findings by `risk_score`
directly.

`services/blame.py` shells out to `git blame --porcelain` to add
`owner_email` / `owner_name` / `last_modified_unix` to every finding —
no SSO/Slack integration required.

---

## 🧪 Benchmark Harness

```bash
make benchmark                                   # all datasets, default scanners
make benchmark DATASETS=owasp_benchmark          # one dataset
make benchmark SCANNERS=semgrep,bandit,gosec     # scanner subset
```

Datasets:

| Dataset | Language | Cases | Use |
| --- | --- | --- | --- |
| OWASP Benchmark v1.2 | Java | ~3 000 | SAST primary |
| Juliet (NIST) | Java/C/C++ | ~64 000 | Cross-language |
| SecurityEval | Python | ~130 | LLM-vuln targeted |
| BigVul | C/C++ | ~3 700 real CVEs | Real-world |

Outputs land under `benchmarks/results/<timestamp>/` with `raw.json`
+ `summary.md` per dataset. `docs/benchmarks/latest.md` is overwritten
on every run so the docs always show current numbers.

---

## 🔭 Observability (OpenTelemetry)

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 make up
```

Auto-instruments every FastAPI request. Use the convenience context
managers from `utils.telemetry` for explicit spans:

```python
from utils.telemetry import scanner_span, llm_span, span

async with scanner_span("semgrep", repo_id=rid):
    await run_semgrep(...)

with llm_span("anthropic", model="claude-opus-4-7", kind="autofix"):
    diff = await orchestrator.generate_completion(...)
```

Point the collector at Tempo / Jaeger for traces, or tee to Prometheus
for metrics. No second instrumentation layer required.

---

## 🏗️ Architecture

```
FortKnoxx/
├── backend/
│   ├── server.py                       # FastAPI app + scan orchestration
│   ├── api/
│   │   ├── deps.py                     # DI container
│   │   ├── routes/
│   │   │   ├── scans.py
│   │   │   ├── findings.py
│   │   │   ├── repositories.py
│   │   │   ├── settings.py
│   │   │   ├── reports.py
│   │   │   ├── autofix.py              # v1.1
│   │   │   ├── trends.py               # v1.1 (trends + evidence pack)
│   │   │   └── health.py
│   │   └── schemas/
│   ├── engines/
│   │   ├── triage/                     # v1.1 (dedup + LLM verdict cache + ignore.yml)
│   │   ├── cnapp/                      # v1.1 (code↔cloud correlation)
│   │   ├── tiers.py                    # v1.1 (fast / deep)
│   │   ├── auth_scanner/               # JWT / OAuth2 / session
│   │   ├── logic/                      # business-logic flaws
│   │   ├── llm_security/               # adversarial LLM testing
│   │   ├── zero_day/                   # GNN + CodeBERT
│   │   ├── payloads/                   # 500+ attack payloads
│   │   └── specialized/                # external scanner adapters
│   ├── scanners/
│   │   ├── zap/                        # v1.1 (config + AF YAML + OpenAPI discovery)
│   │   └── (24 other scanner wrappers)
│   ├── services/
│   │   ├── autofix.py                  # v1.1 (unified-diff fixes, cached)
│   │   ├── risk_score.py               # v1.1 (severity × reach × EPSS × asset)
│   │   ├── blame.py                    # v1.1 (git-blame owner attribution)
│   │   └── (existing services)
│   ├── llm/                            # provider orchestrator + model registry
│   ├── utils/
│   │   └── telemetry.py                # v1.1 (OTel)
│   ├── settings/
│   ├── auth/
│   ├── jobs/
│   ├── reporting/                      # PDF / executive / compliance
│   └── tests/                          # 73 unit tests
├── frontend/
│   ├── Dockerfile                      # v1.1
│   ├── nginx.conf                      # v1.1
│   └── src/
├── benchmarks/                         # v1.1
│   ├── harness/                        # runner + adapters + metrics
│   ├── datasets/                       # gitignored, populated by fetch.sh
│   └── results/                        # gitignored
├── docs/
│   ├── triage.md                       # v1.1
│   ├── scan-tiers.md                   # v1.1
│   ├── autofix.md                      # v1.1
│   ├── reporting.md                    # v1.1
│   ├── cnapp-and-otel.md               # v1.1
│   ├── zap-dast.md                     # v1.1
│   └── benchmarks/                     # latest.md auto-generated
├── docker-compose.yml                  # v1.1
├── Makefile                            # v1.1
├── install_all_scanners.sh
├── start_servers.sh / stop_servers.sh
├── env.sample
└── README.md
```

---

## 🛠️ Development

### Backend

```bash
cd backend
source venv/bin/activate

uvicorn server:app --reload --port 8000

# Tests
venv/bin/python -m pytest tests/ -q
venv/bin/python -m pytest tests/test_triage.py tests/test_zap.py -q

# Lint + format
ruff check .
ruff format .
```

### Frontend

```bash
cd frontend
yarn install
yarn start                  # dev
yarn build                  # production
yarn test
```

### Adding a new scanner

1. Add `backend/scanners/<name>_scanner.py` with an async `scan(repo_path)` returning a list of findings.
2. Register the toggle in `backend/settings/models.py` (`enable_<name>: bool`).
3. Classify it in `backend/engines/tiers.py` — exactly one of
   `FAST_SCANNERS`, `DEEP_ONLY_SCANNERS`, or `ALWAYS_ON`.
4. Wire it into `process_scan_results` in `server.py`.
5. Add a row to `install_all_scanners.sh` if it has a CLI dependency.

---

## 🐛 Troubleshooting

### MongoDB connection error

```bash
# macOS
brew services start mongodb-community
# Linux
sudo systemctl start mongod
mongosh --eval "db.adminCommand('ping')"
```

### Scanner not found warnings

```bash
./install_all_scanners.sh
```

### Frontend can't reach backend

```bash
lsof -i :8000
docker compose ps          # if using the compose stack
```

### Encryption error after key rotation

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# update ENCRYPTION_MASTER_KEY in .env
mongosh fortknox_db --eval "db.settings.deleteMany({})"
```

### Logs

```bash
tail -f backend/backend.log
docker compose logs -f backend
```

---

## 📝 API Reference

### Auth

```
POST /api/auth/register          # register user
POST /api/auth/login             # → { access_token, token_type, user }
```

### Repositories + scans

```
GET    /api/repositories
POST   /api/repositories         # add repo
POST   /api/scans/{repo_id}      # ?tier=fast|deep|auto
GET    /api/scans/{repo_id}      # list scans
GET    /api/scans/detail/{scan_id}
DELETE /api/scans/{scan_id}
```

### Findings + reporting

```
GET  /api/findings?repo_id=…
POST /api/reports/generate                              # legacy JSON/CSV/PDF
GET  /api/reports/evidence-pack?repo_id=…&scan_id=…     # v1.1 SOC2/PCI ZIP
GET  /api/trends/findings?repo_id=…&days=30             # v1.1
GET  /api/trends/top-risk?repo_id=…&limit=20            # v1.1
GET  /api/trends/owners?repo_id=…                       # v1.1
```

### Autofix

```
POST /api/autofix                                       # v1.1
{ "vulnerability_id": "…", "repo_path": "/tmp/fortknoxx_repos/<id>" }
```

### Settings

```
GET  /api/settings
POST /api/settings/api-keys
GET  /api/settings/scanners        # installed binaries
GET  /api/settings/scanners/config
PUT  /api/settings/scanners/config
```

Full Swagger UI: **http://localhost:8000/docs**

---

## 🤖 What Makes FortKnoxx Different?

### vs Traditional SAST Tools

| Feature | FortKnoxx | Traditional SAST |
| --- | --- | --- |
| Zero-day detection | ✅ GNN + CodeBERT | ❌ Signature-only |
| Business logic bugs | ✅ Runtime testing | ❌ Limited |
| LLM security | ✅ Dedicated scanner | ❌ Not supported |
| Runtime verification | ✅ Real HTTP probes | ❌ Static only |
| Attack payloads | ✅ 500+ with mutations | ❌ Limited |
| Coverage-guided fuzzing | ✅ 10 strategies | ❌ Basic / none |
| Cross-scanner dedup | ✅ CWE-family fingerprint | ❌ None |
| Triage cache | ✅ One LLM call per fingerprint, ever | ❌ N/A |
| Verified autofix diffs | ✅ `git apply --check` gated | ⚠ Markdown advice |
| Published benchmark numbers | ✅ OWASP/Juliet/SecurityEval/BigVul | ⚠ Vendor-self-reported |
| Free / OSS | ✅ LLM cost only | ❌ Per-seat pricing |

### vs Wiz / Prisma Cloud / Aqua (CNAPP)

* FortKnoxx isn't a full CNAPP. CNAPP-lite gives you code↔cloud
  correlation and SBOM watch on top of free OSS scanners — most of the
  user-visible Wiz pitch, none of the agent-mesh complexity.
* Best fit when you want one tool that covers SAST + DAST + SCA + IaC
  + container + LLM + cloud-finding-correlation, and you're willing
  to host it yourself.

---

## 💡 Use Cases

1. **Pre-commit / PR security** — `tier=fast` runs in seconds.
2. **CI/CD** — autofix branch suggestions per finding.
3. **Pentesting** — runtime verification + 500-payload library.
4. **Compliance audits** — `evidence-pack` ZIP for SOC2/PCI.
5. **AI/LLM apps** — dedicated prompt-injection / jailbreak scanner.
6. **Zero-day research** — GNN + CodeBERT anomaly detection.
7. **Vendor evaluation** — `make benchmark` produces numbers you can compare.

---

## 🤝 Contributing

We welcome contributions! Areas with the highest leverage right now:

1. **Scanner adapters** — anything missing from
   [`backend/scanners/`](backend/scanners). Classify it in `engines/tiers.py`.
2. **CWE family map** — extend
   [`backend/engines/triage/cwe_map.py`](backend/engines/triage/cwe_map.py)
   when scanners surface unmapped CWE IDs.
3. **Benchmark adapters** — new datasets in
   [`benchmarks/harness/ground_truth.py`](benchmarks/harness/ground_truth.py).
4. **AJAX spider tunables** — better SPA detection, framework-specific defaults.

See `docs/` for module-level guides before opening an MR.

---

## 📚 Documentation

- [`docs/triage.md`](docs/triage.md) — fingerprinting, dedup, LLM verdict cache, ignore rules
- [`docs/scan-tiers.md`](docs/scan-tiers.md) — fast vs deep allowlists, auto-resolution
- [`docs/autofix.md`](docs/autofix.md) — unified-diff generation + cache + Ollama mode
- [`docs/reporting.md`](docs/reporting.md) — risk score, blame attribution, evidence pack
- [`docs/cnapp-and-otel.md`](docs/cnapp-and-otel.md) — code↔cloud correlation + tracing
- [`docs/zap-dast.md`](docs/zap-dast.md) — ZAP AF YAML, auth, AJAX spider, OpenAPI discovery
- [`docs/benchmarks/`](docs/benchmarks) — published precision/recall/F1 per scanner
- **API Reference** — http://localhost:8000/docs (Swagger)

---

## 🗺️ Roadmap

### v1.1 (current)
- ✅ Docker Compose stack
- ✅ Triage engine with cross-scanner dedup + LLM verdict cache
- ✅ Two-tier (fast / deep / auto) scans
- ✅ LLM autofix returning verified unified diffs
- ✅ OWASP Benchmark / Juliet / SecurityEval / BigVul harness
- ✅ Risk + trends + owner attribution + evidence pack
- ✅ CNAPP-lite (code↔cloud correlation) + OpenTelemetry
- ✅ ZAP DAST overhaul (AF YAML, real auth, AJAX spider, OpenAPI auto-discovery)

### Upcoming v1.2
- ⏳ GitHub / GitLab Action with diff-aware PR comments
- ⏳ VS Code extension via the existing MCP server
- ⏳ SBOM watch loop (nightly diff vs Grype CVE feed)
- ⏳ Service split — api-gateway / scan-orchestrator / report-service over Redis Streams
- ⏳ Custom Semgrep rule pack maintained in-repo
- ⏳ Reachability filter for SCA findings

### Future v2.0
- 📅 SSO (SAML, OIDC)
- 📅 Active learning loop from user TP/FP feedback
- 📅 Visual threat modeling
- 📅 On-prem hardened deployment

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

## 🙏 Acknowledgments

- **OWASP** — Benchmark, Top 10, ZAP
- **PayloadsAllTheThings** — attack payload library
- **Strix** — fuzzing framework inspiration
- **CodeQL** (GitHub), **Semgrep** (r2c), **Trivy** (Aqua), **Grype** (Anchore), **Nuclei** (ProjectDiscovery), **Gitleaks**, **TruffleHog**, **gosec**, **Bandit**, **Pyre**, **SpotBugs**, **Horusec**, **Snyk**, **Checkov**, **kube-bench**, **kube-hunter**, **Prowler**
- **NIST** — Juliet test suite
- **Lab Datasets** — SecurityEval (s2e-lab), BigVul
- **FIRST.org** — EPSS API
- **OpenTelemetry**, **Anthropic / OpenAI / Google** — LLM APIs
- And every other open-source security tool we wrap

---

**Built with ❤️ for the security community.**

⭐ Star us on GitHub if FortKnoxx helps secure your code!
