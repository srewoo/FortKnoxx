# ADR-004: Kafka topic taxonomy, partitioning, and retention

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** data, messaging, microservices

## Context

Phase 3 of ADR-002 introduces Kafka as the backbone for inter-service
communication. Before any service starts producing or consuming, we
need agreed conventions for **naming, partitioning, retention, schema
registry use, and DLQ behaviour**. Without this, every team drifts
into ad-hoc topic shapes that are then expensive to migrate.

CLAUDE.md §7 prescribes a generic structure (`<domain>.<entity>.<action>`,
3+ partitions, replication factor ≥ 3, JSON schema registry, DLQ per
topic). This ADR concretises those rules for FortKnoxx and the
specific message types we expect.

## Constraints

- Single-region deployment behind customer VPN — no cross-region
  replication initially.
- Kafka deployed via the **Strimzi** operator on the same K8s cluster
  as the rest of FortKnoxx.
- Brokers: 3 replicas (RF = 3) for any topic carrying domain or audit
  events; RF = 1 acceptable for transient command topics (3-day
  retention).
- Schema registry: **Apicurio** (Apache 2.0, OSS, no licence
  surprises). Confluent Schema Registry rejected for licence reasons.
- Schema format: **JSON Schema** (Zod-generated where applicable;
  Avro reserved for analytics-grade topics in a later phase).

## Naming convention

```
<category>.<domain>.<action>
```

`category` ∈ `{ event, cmd, tracking, dlq }`.

Examples:

| Topic                          | Producer        | Consumer            |
| ------------------------------ | --------------- | ------------------- |
| `event.scan.started`           | scan-service    | reporting-service, audit-service |
| `event.scan.scanner.completed` | scanner-worker  | findings-service    |
| `event.scan.completed`         | findings-service| reporting, notification, audit |
| `event.findings.discovered`    | scanner-worker  | findings-service    |
| `event.audit.action`           | (any service)   | audit-service       |
| `cmd.scan.run`                 | api-gateway     | scanner-worker      |
| `tracking.usage.api`           | api-gateway     | analytics-service   |
| `tracking.usage.scan`          | scan-service    | analytics-service   |
| `dlq.<original-topic>`         | (auto)          | manual triage       |

Rules:

1. **Past tense for events.** `event.scan.started`, not
   `event.scan.start`. Events are facts that already happened.
2. **Imperative for commands.** `cmd.scan.run` requests an action;
   the receiver may legitimately reject it.
3. **No PII in topic names.** Topic names appear in logs, dashboards,
   and ACLs; tenant ids and user ids never go there.
4. **Multi-tenant isolation lives in the message body**, not the
   topic. We do not partition `event.scan.started` per tenant —
   doing so creates topic explosion.

## Partition strategy

| Topic family            | Partitions | Key                    | Why                                   |
| ----------------------- | ---------- | ---------------------- | ------------------------------------- |
| `event.scan.*`          | 12         | `scan_id`              | Ordering of one scan's lifecycle      |
| `event.findings.*`      | 12         | `scan_id`              | All findings for a scan to one consumer instance |
| `event.audit.action`    | 6          | `tenant_id`            | Per-tenant ordered audit replay       |
| `cmd.scan.run`          | 24         | `tenant_id`            | Bounded fairness; no tenant starves   |
| `tracking.usage.*`      | 6          | none (round-robin)     | Throughput; ordering not required     |
| `dlq.*`                 | same as parent | same as parent     | Trivial reprocessing                  |

Adjust upward only — Kafka does not allow partition count to decrease,
so start conservative and grow. 12 partitions per scan-related topic
is enough headroom for 100k scans/hour at our expected message size.

## Replication and acks

- All `event.*` and `event.audit.*` topics: RF = 3, `min.insync.replicas = 2`,
  producer `acks = all`.
- `cmd.*` topics: RF = 3, producer `acks = 1` (latency-sensitive,
  re-deliverable on failure since the API also returns 202 to caller).
- `tracking.*` topics: RF = 3, producer `acks = 1`,
  `enable.idempotence = false` (fire-and-forget; one-at-a-time loss
  acceptable for usage telemetry).
- `dlq.*`: RF = 3, `acks = all` (we do not lose dead-lettered events).

## Retention policy

| Topic family        | Retention | Why                                              |
| ------------------- | --------- | ------------------------------------------------ |
| `event.*`           | 7 days    | Replay window for consumer recovery / new svc    |
| `event.audit.action`| 30 days   | Audit needs longer hot replay; long-term store goes to Postgres `audit_log` table (7 years configurable per tenant) |
| `cmd.*`             | 3 days    | Long enough for retry storms to settle           |
| `tracking.*`        | 30 days   | Analytics queries reach back about a month       |
| `dlq.*`             | 14 days   | Long enough for an on-call engineer to triage    |

All retention is time-based (`retention.ms`), not size-based.
Compaction is **not** used by default; see "Special cases" below.

## Schema registry

- Every topic must have a JSON schema registered in Apicurio **before**
  the topic is created.
- Compatibility level: **BACKWARD** (consumer with old schema reads
  message produced with new schema). New required fields require a
  major-version bump.
- Schemas are versioned: `<topic>-value-v1`, `<topic>-value-v2`. The
  consumer specifies the schema version it expects; messages tagged
  with a newer schema are still readable thanks to BACKWARD
  compatibility.
- Schema source of truth: `packages/shared-types/` with Zod schemas
  generating the JSON Schema artifacts at CI time. CI fails if a topic
  is referenced in code but its schema is missing from the registry.

## DLQ contract

Every consumer group has a DLQ topic at `dlq.<original-topic>`.

Required envelope on a DLQ message:

```json
{
  "original_topic": "event.scan.started",
  "original_partition": 7,
  "original_offset": 12345,
  "first_failed_at": "2026-05-05T14:00:00Z",
  "last_failed_at": "2026-05-05T14:05:00Z",
  "attempt_count": 5,
  "error_class": "ValueError",
  "error_message": "scan_id is not a UUID",
  "consumer_group": "findings-service",
  "trace_id": "00-abcdef...",
  "payload_b64": "..."
}
```

Retry policy: 3–5 attempts in-process with exponential backoff
(`100ms, 500ms, 2s, 5s, 10s`), then publish to DLQ + alert. Never
retry indefinitely. **No exception is silently swallowed.**

## Producer / consumer rules

- Producers: `enable.idempotence = true` for any topic where ordering
  matters (everything except `tracking.*`).
- Consumers: commit offsets **only after** successful processing.
  Use the `enable.auto.commit = false` + manual commit pattern.
- Per-service consumer group naming: `<service>.<topic>.v<schema-major>`.
  This makes deploying a new schema as easy as starting a new consumer
  group.
- Headers: every message carries the W3C `traceparent` header so
  trace context propagates across producers, brokers, and consumers.

## Special cases

### Outbox → Kafka via Debezium

Postgres-resident state changes (audit log, scan envelope, repo CRUD)
publish through a **transactional outbox** table read by Debezium →
Kafka topic. This avoids the dual-write trap (commit to Postgres
succeeds but Kafka publish fails).

Outbox table: `tenants_db.outbox_events` (per-service or shared TBD —
will be ADR-008). Cleanup job purges rows older than 24h.

### Compacted topic for current-scan-state

`event.scan.state.snapshot` (proposed, **not** in initial roll-out)
will be a **log-compacted** topic where each scan id keeps only its
latest state. Reserved for the dashboard live-status feature; defer
to a follow-up ADR.

## Trade-offs

| Choice                         | Trade-off                                       |
| ------------------------------ | ----------------------------------------------- |
| 12 partitions for scan topics  | Higher throughput ceiling; slightly more rebalance churn on consumer scale-up. |
| BACKWARD compatibility default | Easy producer upgrades; complex breaking changes still need a v2 topic. |
| 7-day default event retention  | Long enough to debug; short enough to bound disk use on broker. |
| RF = 3 for everything serious  | Tolerates one broker loss without data loss. RF = 5 considered overkill at our scale. |

## Reversibility

- **Two-way door** for partition counts (can only increase, but
  splitting an existing topic into two is also possible with a
  migrator).
- **One-way door** for the naming convention. Renaming an in-use
  topic requires producer + consumer redeploy in lockstep. Once shipped,
  changes need their own ADR.
- **One-way door** for compatibility level (BACKWARD). Switching to
  FORWARD or NONE later breaks existing consumers.

## Decision

Adopt the conventions above for FortKnoxx Phase 3. The first topic to
be provisioned is `cmd.scan.run`, since it unblocks moving the
in-process `BackgroundTasks.add_task(...)` call out of the API process
and into a `scanner-worker` (Phase 4).

## Consequences

- New module `packages/kafka-client/` (added in Phase 3) — provides
  producer/consumer wrappers that enforce headers, schema validation,
  and DLQ routing.
- New section in `docs/runbooks/`:
  - `kafka-consumer-lag.md`
  - `kafka-dlq-non-empty.md`
  - `kafka-rebalance-storm.md`
- All new topics added through a code-reviewed `topics.yaml` manifest
  fed into Strimzi `KafkaTopic` resources — no `kafka-topics.sh`
  bypasses in production.
- Helm charts gain a Strimzi cluster definition + Apicurio
  deployment.

## Follow-ups

- [ ] ADR-005: Service-mesh choice (Linkerd vs Istio)
- [ ] ADR-006: KMS / BYOK design
- [ ] ADR-008: Outbox table location and Debezium configuration
- [ ] Bootstrap `topics.yaml` + Strimzi `KafkaTopic` manifests in
      `infrastructure/helm/fortknoxx/templates/kafka-topics/`
- [ ] Add three Kafka runbooks to `docs/runbooks/`
