# ADR-003: Postgres for transactional data (override of CLAUDE.md MSSQL preference)

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** data, backend, deployment

## Context

ADR-002 commits to introducing a transactional database alongside the
existing MongoDB findings store, primarily to host: tenants, users,
roles, repository metadata, scan envelopes (id + status + timing), and
the append-only audit log.

CLAUDE.md §6 specifies **MSSQL as the preferred transactional engine**.
This ADR is needed because the FortKnoxx ecosystem and target
deployment do not align cleanly with that default — we want to record
the deviation rather than silently skip it.

## Constraints

- Deploy target: customer's K8s cluster behind VPN.
- Operator-managed (no DBA team) — must run with a Kubernetes operator.
- License-friendly for a security product (no vendor surprises that
  block resale or air-gapped installs).
- Must support row-level security or a comparable mechanism for
  multi-tenancy.
- Must integrate with the OSS scanner ecosystem (Trivy, Semgrep,
  Checkov, Snyk, etc.) — many of which assume Postgres for any
  database-backed feature.
- Engineering team experience: stronger on Postgres than MSSQL.

## Options considered

### Option A — MSSQL (CLAUDE.md default)

Pros:
- Centralised CLAUDE.md guidance — fewer per-team variations.
- Excellent tooling on Windows; T-SQL is mature for analytics.
- Strong AAD / Kerberos integration for those that need it.

Cons:
- Licensing: SQL Server Standard/Enterprise carries per-core costs
  that compound on K8s. Express edition is too capped for a security
  product (10 GB / DB; one socket).
- Containerisation story is weaker than Postgres on K8s — official
  images exist but K8s operators are immature.
- Scanner ecosystem assumes Postgres; integration we'd write
  ourselves: SBOM persistence, Snyk SARIF mirrors, OSS dashboards.
- Row-level security in MSSQL is real but ergonomically painful
  compared to PG's `RLS` policies.
- Engineering: weaker existing fluency.

### Option B — PostgreSQL 16 (selected)

Pros:
- Liberal licence (PostgreSQL Licence — BSD-style); no resale traps.
- Mature K8s operators (CloudNativePG, Zalando Postgres-Operator) —
  enterprise-grade HA, backup, point-in-time recovery, version
  upgrades, all declarative.
- First-class **Row-Level Security** policies — clean tenancy
  enforcement at the engine, not just at the app layer.
- `LISTEN/NOTIFY` for cheap pub-sub during early phases; replaceable
  with Kafka in Phase 3.
- JSONB fields cover the few cases where Mongo-style flexibility is
  useful, without a second database.
- Stronger ecosystem for the scanners we already use.
- Engineering: deeper team expertise.

Cons:
- Diverges from CLAUDE.md default — must be flagged in onboarding.
- Some F500 buyers default to "we use MSSQL"; we may need to
  document why Postgres meets their data-handling controls.

### Option C — Stay on MongoDB only (do nothing)

Pros: zero migration cost.
Cons:
- Multi-tenancy isolation in Mongo is collection-level, not row-level
  — auditors push back on this.
- No real transactions across collections without driver gymnastics.
- ACID requirements for billing / audit / RBAC are awkward.
- Fails CLAUDE.md §6 ("Each microservice owns its database — no shared
  DB. Transactional → MSSQL preferred").

**Rejected.**

### Option D — CockroachDB / YugabyteDB (Postgres-wire, distributed)

Pros: PG SQL surface, multi-region built in.
Cons:
- Operational complexity not justified for our scale (single-region
  VPN deploy).
- License changes in recent CockroachDB releases (BSL) introduce
  resale risk; Yugabyte is Apache 2 but smaller community.
- Postgres satisfies needs; "fewer moving parts" wins.

**Rejected** for this stage; revisit if multi-region becomes a
requirement.

## Trade-offs

| Dimension                           | MSSQL  | Postgres | Mongo only | CockroachDB |
| ----------------------------------- | ------ | -------- | ---------- | ----------- |
| License risk for resale             | medium | low      | low        | medium      |
| K8s-native operators (HA, backup)   | medium | high     | high       | high        |
| Row-level multi-tenancy             | medium | high     | low        | high        |
| Engineering fluency                 | low    | high     | high       | medium      |
| OSS scanner ecosystem fit           | low    | high     | medium     | high        |
| Migration cost from current Mongo   | high   | medium   | none       | medium      |
| Adherence to CLAUDE.md default      | yes    | **no**   | no         | no          |

## Reversibility

**Two-way door (with effort).** Postgres and MSSQL both speak SQL; the
Alembic migration tree is portable with adjustments to type names
(`SERIAL` vs `IDENTITY`, etc.) and RLS implementations. If a customer
mandates MSSQL in the future, we re-target the migration tree, not the
application code, provided we keep the data-access layer behind a thin
SQLAlchemy abstraction.

To preserve reversibility, this ADR commits to:

- **No Postgres-specific extensions in domain tables** unless wrapped
  in a `db_client` adapter. (Exceptions: `pgcrypto`, `uuid-ossp`,
  `citext` — well-behaved and easy to substitute.)
- **No raw SQL in services.** All DB access goes through SQLAlchemy
  models or the repository pattern.
- **Multi-tenancy at the column level** (`tenant_id` everywhere) so
  the policy layer is portable; RLS is a defense-in-depth not the
  sole enforcement.

## Decision

Adopt **PostgreSQL 16** as the transactional engine for FortKnoxx,
deployed via the **CloudNativePG** operator on the customer's K8s
cluster. MongoDB stays for findings / scan results.

This is an explicit override of CLAUDE.md §6 ("MSSQL preferred"). The
override is documented here; CLAUDE.md is not changed because that
guide is shared across projects with different constraints.

## Consequences

- New dependency in `requirements-base.txt`: `sqlalchemy[asyncio]`,
  `asyncpg`, `alembic`.
- New service in K8s manifests: Postgres cluster (3-node primary +
  replicas via CNPG).
- New module: `backend/db_client/` with `engine.py`, `session.py`,
  `models/`, plus an `alembic/` migration tree.
- Existing route handlers continue to read from Mongo for findings;
  Phase 2 introduces a parallel Postgres path for tenants, users,
  audit log, and scan metadata. Findings stay in Mongo through
  Phase 3 at minimum; revisit migration in ADR-008 once Phase 3 ships.
- New onboarding doc note: "this project deviates from CLAUDE.md §6
  on transactional DB choice — see ADR-003."

## Follow-ups

- [ ] Add `sqlalchemy`, `asyncpg`, `alembic` to `requirements-base.txt`
- [ ] Scaffold `backend/db_client/` (engine + session + base model)
- [ ] First migration: `tenants`, `users`, `audit_log`, `repositories_pg`
- [ ] CNPG cluster manifest in `infrastructure/helm/`
- [ ] Update `docs/runbooks/` with `postgres-down.md`
- [ ] ADR-004 (Kafka topology), ADR-005 (service mesh), ADR-006 (KMS)
  — listed in ADR-002 as still-open
