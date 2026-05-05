# Runbook: Postgres unreachable / migrations failing

## TL;DR

- **Symptom:** `db_client` raises `RuntimeError: POSTGRES_DSN not set`
  on startup, or routes that touch Postgres return 500. `alembic
  upgrade head` hangs or errors.
- **Most likely cause:** Postgres pod not running, `POSTGRES_DSN`
  misconfigured, or migration tree is out of sync between deployed
  service and the cluster.
- **Fast fix:** `kubectl get pods -l app=fortknoxx-postgres`; if the
  pod is down, the CloudNativePG operator restarts it automatically —
  wait 60s before escalating.
- **Severity bump if:** customer data appears missing on
  `/api/repositories` after Postgres recovery (data loss path —
  follow disaster-recovery procedure, not this runbook).

## Detection

```bash
kubectl exec -it deploy/fortknoxx-api -- python -c \
  "from db_client import get_engine; get_engine()"

kubectl logs deploy/fortknoxx-api | grep -E "Postgres|POSTGRES_DSN"

# If Datadog is wired (post Phase 10):
# log query: service:fortknoxx-api status:error "Postgres"
# monitor:   PG_LIVENESS == 0
```

## Diagnosis

1. **Is the Postgres cluster up?**
   ```bash
   kubectl get clusters.postgresql.cnpg.io -A
   kubectl get pods -l cnpg.io/cluster=fortknoxx-postgres
   ```

2. **Is `POSTGRES_DSN` set in the API deployment?**
   ```bash
   kubectl get deploy fortknoxx-api -o yaml | grep -A1 POSTGRES_DSN
   ```

3. **Is the migration tree applied?**
   ```bash
   kubectl exec -it deploy/fortknoxx-api -- \
     alembic -c db_client/alembic.ini current
   ```
   Compare to the latest revision file under
   `backend/db_client/alembic/versions/`.

4. **Are connections pooled correctly?**
   Check `pg_stat_activity`:
   ```sql
   SELECT count(*), state FROM pg_stat_activity
    WHERE datname = current_database()
    GROUP BY state;
   ```
   Pool exhaustion (`idle in transaction` rising) means we have a
   connection leak — open a P2 ticket, do not just bounce the pod.

## Fix

### Postgres cluster down

CloudNativePG self-heals within ~60s. If after 2 minutes the cluster
is still red:

```bash
kubectl describe cluster fortknoxx-postgres
kubectl logs cnpg-controller-manager-... -n cnpg-system | tail -200
```

Common causes: PVC out of disk, taint preventing scheduling, network
policy blocking replicas. Address the root cause; do not delete the
cluster.

### `POSTGRES_DSN` missing or wrong

```bash
# Update the env var via the helm values for the environment.
helm upgrade fortknoxx ./infrastructure/helm/fortknoxx \
  --set api.env.POSTGRES_DSN=postgresql+asyncpg://...
```

API pods restart and reconnect; no DB-side change needed.

### Migration drift

```bash
# Show current vs head:
alembic -c db_client/alembic.ini current
alembic -c db_client/alembic.ini history --verbose | head

# Apply pending migrations (forward-only):
alembic -c db_client/alembic.ini upgrade head
```

If a migration has partially applied and aborted, follow the migration
recovery section of CLAUDE.md §6 — never run `downgrade` (forward-only).

## Rollback

Schema changes are forward-only by policy. If a fresh migration is
breaking the deploy:

1. Roll the **app** back to the previous image — older code can
   tolerate the newer schema (because every migration is additive
   per the three-step pattern).
2. Write a follow-up migration that reverses the breaking change.

## Verification

```bash
# Connectivity:
kubectl exec -it deploy/fortknoxx-api -- python -c \
  "import asyncio; from db_client import get_session; \
   async def go():\
     async with get_session() as s: print(await s.execute('SELECT 1'))\
   asyncio.run(go())"

# Schema state:
alembic -c db_client/alembic.ini current
```

## Postmortem trigger

- P0/P1 always.
- P2 if migration drift recurs in the same week — points to a CI gap.

## Last updated

2026-05-05 (initial draft, Phase 2 scaffold).
