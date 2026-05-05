# ADR-002: F500-readiness migration plan

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** migration, architecture, deployment

## Context

FortKnoxx today (see ADR-001) is a strong proof-of-concept with broad
scanner coverage but a monolithic, demo-grade architecture. Goal: lift
it to ~8/10 on Fortune-500 readiness while it is deployed behind the
company VPN. SSO/SAML/SCIM are explicitly **out of scope** because the
VPN provides perimeter authn.

## Constraints

- Deploy target: customer's K8s cluster behind VPN.
- Must preserve current data and not break the public API shape during
  cutover.
- Engineering capacity assumption: 2 senior backend, 1 senior frontend,
  1 DevOps, ~14 weeks.
- Must comply with CLAUDE.md (architecture rules, test coverage,
  observability, security).

## Options considered

### Option A — Big-bang rewrite

Replace the monolith with a fresh microservices repo, port features
across, swap DNS. Pros: clean cut. Cons: huge integration risk, halts
feature work during rewrite. **Rejected** (also see ADR-001 Option A).

### Option B — Phased migration (chosen)

Decompose `server.py`, introduce Postgres alongside Mongo, then peel
off services into Kafka-connected workers. Each phase ships
independently. **Selected.** Detailed phases below.

### Option C — Refactor in place, never split

Keep one process; just clean it up. Pros: minimal infra. Cons: cannot
hit horizontal-scaling, audit-log isolation, or scanner-sandboxing
goals required for F500 procurement. **Rejected.**

## Plan summary

| Phase | Title                                             | Weeks  |
| ----- | ------------------------------------------------- | ------ |
| 0     | Repo hygiene & foundations                        | 1      |
| 1     | Decompose `server.py` into layered modules        | 2–4    |
| 2     | Postgres + multi-tenancy + Alembic migrations     | 3–6    |
| 3     | Microservices + Kafka per CLAUDE.md §3, §7        | 5–10   |
| 4     | Sandboxed scanner workers (containerize binaries) | 8–12   |
| 5     | ML honesty — extract `ai-engine-service`          | 9      |
| 6     | Audit logging + RBAC at gateway and service       | 7–9    |
| 7     | K8s + Helm + Linkerd service mesh                 | 10–13  |
| 8     | BYO-key / KMS / per-tenant envelope encryption    | 11     |
| 9     | Test coverage to CLAUDE.md targets (continuous)   | 4–14   |
| 10    | Observability — structlog + OTel + Prometheus     | 6–8    |
| 11    | MCP server for IDE integration                    | 9–12   |
| 12    | CI/CD per service (Turborepo --filter)            | 10–13  |
| 13    | Documentation (continuous)                        | 1–14   |

Detailed plan lives in repository conversation history; sub-ADRs to be
written as each phase commits to specific tools.

## Trade-offs

| Dimension              | Big-bang | Phased | Refactor only |
| ---------------------- | -------- | ------ | ------------- |
| Time to first value    | 6+ mo    | 1 wk   | 1 wk          |
| Time to F500-ready     | 6 mo     | 14 wk  | never         |
| Cutover risk           | high     | medium | none          |
| Disruption to features | total    | low    | low           |
| Final architecture     | clean    | clean  | compromised   |

## Reversibility

**Mostly two-way.** Each phase is independently revertable:

- Phase 1 (decomposition): pure refactor, behaviour preserved by tests.
- Phase 2 (Postgres): tenancy added gradually; Mongo path still works.
- Phase 3 (Kafka): old sync paths kept until new async path is stable.
- Phase 4 (scanner sandboxing): binaries can be re-enabled if a sandbox
  fails.

**One-way doors** that need their own ADR before commit:

- Choice of Postgres vs MSSQL (CLAUDE.md prefers MSSQL; this project
  picks Postgres for ecosystem reasons — needs ADR-003).
- Service-mesh choice (Linkerd vs Istio — needs ADR).
- KMS choice (AWS KMS vs Vault — needs ADR).
- Per-service vs shared Kafka cluster — needs ADR.

## Decision

Execute Option B in priority order. Phase 0 is in flight at the time
this ADR is accepted. Each subsequent phase blocks on its predecessors
per the dependency graph, but phases without a hard dependency may run
in parallel.

## Consequences

- Repo will grow into a Turborepo monorepo (`apps/`, `packages/`,
  `infrastructure/`).
- CI complexity rises (per-service pipelines), but only for affected
  services thanks to Turbo's `--filter`.
- Operational footprint grows: more processes, Kafka, Postgres, Redis,
  K8s. Mitigated by Phase 7 IaC and Phase 10 observability.
- Engineering velocity dips during Phase 1–3 cutovers; recovers in
  Phase 4+ as services become independently deployable.

## Follow-ups

- [ ] ADR-003: Postgres choice rationale (overrides CLAUDE.md MSSQL
      preference)
- [ ] ADR-004: Kafka topic taxonomy and retention policy
- [ ] ADR-005: Service-mesh choice
- [ ] ADR-006: KMS / BYOK design
- [ ] ADR-007: MCP server auth model
