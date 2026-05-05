# ADR-008: Data-store split — what lives in Postgres vs MongoDB

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** data, architecture

## Context

ADR-003 picked Postgres as the transactional engine and committed to
keeping MongoDB for findings. ADR-002 listed "ADR-008: outbox table
location and Debezium configuration" as a follow-up. As Phase 2
wiring begins, we need a single page that **enumerates every
collection / table** and assigns it to one of the two stores so two
engineers don't pull the same data into different homes.

## Constraints

- Findings volume is high and bursty (one large monorepo scan can
  produce 10k+ vulnerability rows in a minute). Mongo's bulk-insert
  story is better suited.
- Audit queries need ACID guarantees and per-tenant `WHERE` clauses
  with row-level security — Postgres is the natural fit.
- We must keep both stores until Phase 3 ships; no flag-day cutover.
- Each FortKnoxx microservice owns its own schema (CLAUDE.md §3.3).
  This ADR predates the split, so for now both stores are shared
  across services. Future service extractions will partition further.

## Inventory and assignment

### Postgres (transactional state)

| Table              | Why Postgres                                   | Status |
| ------------------ | ---------------------------------------------- | ------ |
| `tenants`          | Identity root, RLS anchor                       | created in 0001_init |
| `users`            | RBAC, citext email                              | 0001_init |
| `audit_log`        | Immutable, per-tenant, time-range queries       | 0001_init |
| `repositories`     | Authoritative repo metadata + tenant ownership  | 0001_init |
| `pats`             | Personal Access Tokens for the MCP server       | Phase 6 |
| `git_integrations` | Provider tokens (encrypted), per tenant         | Phase 6 |
| `outbox_events`    | Transactional outbox → Kafka via Debezium       | Phase 3 |
| `scan_envelope`    | Scan id, status, started_at, completed_at       | Phase 3 |
| `feature_flags`    | Per-tenant flag overrides                       | Phase 6 |
| `kek_metadata`     | Vault KEK rotation log + version pointers       | Phase 8 |

### MongoDB (semi-structured / high-volume / read-heavy)

| Collection              | Why Mongo                                       | Status |
| ----------------------- | ----------------------------------------------- | ------ |
| `vulnerabilities`       | Variable shape across scanners; 10k+ docs/scan  | exists |
| `quality_issues`        | Same — Pylint/Flake8/Radon shapes differ        | exists |
| `compliance_issues`     | Syft license docs                               | exists |
| `scan_results_blob`     | Raw scanner JSON for forensic re-runs           | Phase 3 (new) |
| `repo_clones_metadata`  | Per-clone temp metadata; ephemeral              | exists |

### Both (intentional duplication during transition)

| Item            | Reason                                                |
| --------------- | ----------------------------------------------------- |
| `repositories`  | Mongo holds the live one today; Postgres mirror is built dual-write in Phase 2 wiring. Mongo doc becomes a derived projection from Postgres in Phase 3. |
| `scans` envelope | Same pattern — Postgres `scan_envelope` becomes the source of truth; Mongo `scans` doc is a denormalised view. |

## Migration phases

### Phase 2 (now)

- Postgres tables exist (0001_init).
- API path still reads/writes only Mongo.
- New `audit-service` consumer (Phase 6) writes to Postgres `audit_log`
  exclusively.

### Phase 3

- Add `outbox_events` and Debezium connector → Kafka.
- `repositories` / `scan_envelope` start dual-writing: Mongo first
  (existing path), Postgres second via outbox event consumed by a
  small projector service. A correctness check job runs nightly to
  flag drift.

### Phase 4–5

- Findings stay in Mongo. The new scanner-worker writes findings
  documents directly to Mongo (no change to data path) but emits a
  `findings.discovered` Kafka event for downstream consumers.

### Phase 9 / data hardening

- After 2+ weeks of clean dual-write metrics, flip `repositories` /
  `scan_envelope` reads to Postgres. Mongo collections stay as
  denormalised projection until the frontend has been updated to
  consume the new shape (longer tail).

## Trade-offs

| Concern                       | Postgres for X | Mongo for X |
| ----------------------------- | -------------- | ----------- |
| Audit-grade history           | strong         | weak        |
| Per-tenant RLS                | strong         | application-only |
| 10k+ rows/min bulk insert     | acceptable     | strong      |
| Schema flexibility            | weak           | strong      |
| ACID across "scan + finding"  | possible (single tx) | n/a |
| Tooling (psql, pg_stat_*)     | strong         | weaker      |

## Reversibility

**Per-row decisions are two-way doors.** Promoting `vulnerabilities`
from Mongo to Postgres later is "just" a migration job; the only
real risk is the throughput impact on the API write path, which
benchmarks must validate before we commit.

**The high-level split is a one-way door** — once customers depend
on a SQL view of `audit_log`, we cannot move it back to Mongo
without a flag-day API change. We accept that for `audit_log`,
`tenants`, `users`, and `repositories` (Postgres source of truth);
findings stay revertable.

## Decision

Adopt the assignment table above. The boundary rule is:

> **Postgres** owns identity, ownership, audit, and any state where
> ACID and per-tenant RLS matter.
> **Mongo** owns scanner output and any high-volume,
> variable-shape, read-heavy collection.

When in doubt: data that needs to survive a security audit goes to
Postgres; data that scales with scan throughput stays in Mongo.

## Consequences

- Phase 2 wiring is unblocked: the `audit-service` consumer is the
  first real Postgres writer.
- New CI guard: any new Mongo collection added to `db.<name>` in code
  must also have an entry in this ADR (either as a permanent home or
  a transitional dual-write target). Enforcement is via a
  `tests/architecture/test_data_store_inventory.py` check that grep's
  `db.<X>` references and asserts the `<X>` is documented here.
  (Implementation: Phase 2 follow-up.)
- The Kafka outbox table (`outbox_events`) blocks on Phase 3 ADR-009
  (Debezium configuration); placeholder created here.

## Follow-ups

- [ ] ADR-009: Debezium configuration + `outbox_events` schema
- [ ] Migration `0002_pats_and_git_integrations.py` (Phase 6)
- [ ] Migration `0003_outbox_events.py` (Phase 3)
- [ ] CI lint: undocumented Mongo collection names fail the build
- [ ] Postgres-projection consumer service for `repositories` /
      `scan_envelope` (Phase 3)
