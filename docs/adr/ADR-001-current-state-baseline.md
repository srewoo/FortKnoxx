# ADR-001: Current state of FortKnoxx (baseline)

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** baseline, snapshot

## Context

FortKnoxx is being prepared for Fortune-500 deployment behind the
company VPN. Before changing anything we record the current state so
future ADRs have a reference point and the migration plan
(ADR-002) has a clear "from".

## Current architecture

### Stack

- **Backend:** Python 3.11, FastAPI, monolithic (`server.py` ≈ 3,038 LOC).
- **Frontend:** React (CRA + craco), shadcn/ui, Tailwind. ~6.8K LOC.
- **Database:** MongoDB (motor) — single instance, single tenant, no
  migrations framework.
- **Cache / queue:** Redis declared in `requirements-base.txt`,
  not yet wired into request paths.
- **Process model:** Single FastAPI process started by
  `start_servers.sh`. No reverse proxy, no orchestrator.
- **Scanners:** ~30 external binaries invoked via `subprocess` from the
  API process (Bandit, Semgrep, Trivy, Gitleaks, Grype, Checkov, ZAP,
  Nuclei, …).
- **AI engines:** Optional GNN zero-day detector, business-logic flow
  analyzer, LLM adversarial tester, auth scanner. ML deps loaded with
  `try/except ImportError` fallback.

### What works

- Broad scanner coverage (~22 active, see `utils/scanner_health.py`).
- JWT auth scaffolding (`auth/`), Fernet-based secrets vault, RBAC
  policy code (not enforced at gateway).
- React dashboard with scan history, severity distribution, OWASP
  mapping, executive PDF reports.
- LLM security testing — a real differentiator.

### What does not work / does not exist

- **No multi-tenancy.** No `tenant_id` on records, no row-level
  isolation, no per-tenant key.
- **No microservices, no Kafka.** Single process, single DB.
- **No K8s / Helm / IaC.** Dev-grade shell scripts only.
- **No SSO/SAML/SCIM.** (Acceptable: deployment will sit behind VPN.)
- **No audit log.** State changes are not recorded.
- **No BYOK / KMS.** One Fernet master key for all data.
- **Test coverage ~ minimal.** One `backend_test.py` at root,
  sparse `tests/` dir. Far below CLAUDE.md §9 targets (80–95%).
- **No OpenAPI checked in.** Swagger UI only, no contract artifact.
- **Silent failures.** Grype JSON parse error logged ERROR but reports
  "0 vulnerabilities found"; ML deps missing → headline AI features
  return empty without telling the UI.
- **Observability:** stdout logs only. No structured logger, no
  Datadog/OTel, no metrics.
- **Repo hygiene issues** (resolved in this ADR cycle): `.DS_Store`
  files on disk, `=1.12.0` shell-redirect artifacts, no pre-commit.

## Constraints (going forward)

- Deploy behind company VPN (no SSO required, but everything else
  enterprise-grade).
- Honour CLAUDE.md as the authoritative engineering guide.
- Backwards compatibility for existing scan data and the public API
  shape during the migration.

## Options considered

### Option A — Rewrite from scratch

Pros: clean architecture day one. Cons: throws away working scanner
integrations, ML model assets, and frontend; 6+ months. **Rejected.**

### Option B — Incremental migration (this is what ADR-002 chooses)

Pros: keeps current users functional, ships value continuously, lets
us learn at each step. Cons: longer total elapsed time; dual-system
complexity during cutover.

### Option C — Do nothing (ship as-is to F500)

Pros: zero cost. Cons: would fail any F500 procurement / security
review on architecture, multi-tenancy, audit, and test coverage axes.
Score self-assessed at 4.5/10 (see `evaluation.md` notes).
**Rejected.**

## Trade-offs

| Dimension          | Rewrite | Incremental | Do nothing |
| ------------------ | ------- | ----------- | ---------- |
| Time to F500-ready | 6+ mo   | 12–14 wk    | never      |
| Risk of regression | high    | medium      | none       |
| Continuity for users | broken | preserved | preserved  |
| Cost (eng-weeks)   | ~80     | ~50         | 0          |

## Reversibility

This ADR is a **snapshot**, not a decision; it cannot be reversed.

## Decision

Adopt the **current state** described above as the baseline for the
F500-readiness migration. ADR-002 captures the migration plan.

## Consequences

- Future ADRs reference this document for "before" context.
- Any feature work shipped from this point onward is expected to
  conform to CLAUDE.md, even before the broader migration completes.

## Follow-ups

- [x] Phase 0 hygiene (this PR cycle)
- [ ] ADR-002 — migration plan
