# Runbook: MCP Personal Access Token (PAT) issuance, rotation, revocation

## TL;DR

- **Symptom (engineer side):** the IDE shows
  `❌ fortknoxx.<tool> failed: 401` or `FORTKNOXX_PAT not set`.
- **Symptom (admin side):** an engineer reports a leaked PAT, or the
  90-day rotation reminder fired.
- **Fast fix:** issue a new PAT in the FortKnoxx admin UI, paste it
  into the IDE secret store, restart the MCP transport.
- **Severity bump if:** the leaked PAT had `admin` role —
  immediately revoke and audit the audit-log table for any unusual
  actions in the leak window.

> **Status:** the PAT-issuance UI is on the Phase 11 backlog. Until
> it ships, PATs are issued out-of-band via a small script (see
> "Issue a new PAT — interim path" below).

## Detection

```bash
# Engineer-side — fast check from a working IDE shell:
$ env | grep FORTKNOXX_PAT
$ fortknoxx-mcp --help     # if you can't run the binary, the
                           # IDE's MCP config is stale.
```

In production:

- Datadog log query (post Phase 10):
  `service:fortknoxx-api status:warn "401" path:/api/`
- A spike of 401s clustered by `User-Agent: fortknoxx-mcp/*` ≈ a
  rotation event in flight or a leaked PAT being abused.

## PAT model (recap)

- One PAT per engineer per IDE host. **Do not share.**
- PAT carries the engineer's `tenant_id` and RBAC `role`. Scope to
  the *minimum* role needed (default `developer`; `admin` only for
  on-call security engineers).
- PATs expire after **90 days**; the issuance UI (and the interim
  script) sets the expiry.
- Stored hashed in Postgres `pats` table (table name TBD; lands with
  Phase 6 RBAC). Plaintext is shown to the user **once** at
  generation time and never again.

## Issue a new PAT

### Production path (Phase 11 GA)

1. Navigate to `https://fortknoxx.internal/settings/pats`.
2. Click **New PAT**, set name (e.g., `cursor-on-laptop-X`), role,
   expiry.
3. Copy the secret shown once.
4. In the IDE:
   - **Cursor:** Settings → MCP → fortknoxx → set
     `env.FORTKNOXX_PAT` to the new secret.
   - **Claude Code:** `claude mcp env set fortknoxx FORTKNOXX_PAT=<secret>`.
   - **Other IDEs:** consult their MCP / secret-store docs.
5. Restart the MCP server (most IDEs do this on env change; if not,
   "Reload MCP servers" from the IDE command palette).

### Interim path (until the UI ships)

```bash
# Run from a host that can talk to Postgres:
psql "$POSTGRES_DSN" \
  -v actor_email='engineer@example.com' \
  -v role='developer' \
  -v expiry='90 days' \
  -f scripts/issue-pat.sql

# The script returns one row; copy the `plaintext_pat` column,
# share it with the engineer over a 1:1 secure channel (1Password,
# Slack DM-with-disappearing, etc. — do NOT email).
```

The `scripts/issue-pat.sql` script is on the Phase 6 backlog
together with the `pats` table.

## Rotate a PAT

Scheduled (90-day expiry):

1. The audit-service emits an `event.audit.action` of type
   `pat.expiring_soon` 14 days before expiry.
2. The engineer issues a new PAT (above), updates the IDE secret,
   confirms the new PAT works (`fortknoxx-mcp` runs without error
   for at least one tool call), then revokes the old one.

Ad-hoc (suspected compromise):

1. **Revoke first**, ask questions later. See "Revoke a PAT" below.
2. Issue a new one.
3. Notify the engineer of the rotation (and the reason).

## Revoke a PAT

### Production

```bash
curl -X POST https://fortknoxx.internal/api/admin/pats/{pat_id}/revoke \
  -H "Authorization: Bearer $ADMIN_PAT"
```

### Interim

```sql
UPDATE pats SET revoked_at = NOW(), revoked_reason = 'leak suspected'
 WHERE id = '<pat_id>';
```

A revoked PAT returns `401` immediately on the next API request —
there is no caching window.

## Cleanup IDE secret store

After rotation, **delete the old PAT from the IDE secret store** so
engineers don't accidentally re-paste a stale value when the new one
expires. Cursor and Claude Code keep secrets in the OS keychain
(macOS Keychain / Windows Credential Manager / GNOME Keyring); search
for `FORTKNOXX_PAT` and remove dated entries.

## If a PAT was leaked

Open a security incident **before** doing the cleanup. Required
steps before the incident is closed:

1. Revoke the PAT.
2. Search the audit log for actions taken by that PAT in the leak
   window:
   ```sql
   SELECT occurred_at, action, target_type, target_id, trace_id
     FROM audit_log
    WHERE actor_id = '<pat_owner_user_id>'
      AND occurred_at >= '<estimated_leak_time>'
    ORDER BY occurred_at DESC;
   ```
3. If any row looks unusual (mass deletions, AI-fix triggers from
   off-hours, new git integrations connecting to unexpected hosts),
   escalate to incident-response procedure.
4. File a brief postmortem even if no abuse is observed —
   leak-event documentation matters for SOC2.

## Postmortem trigger

- Always for a leaked or stolen PAT (P1 minimum).
- Always for a PAT that survived past its 90-day expiry without
  rotation (process gap).
- P3 for a single 401 cluster from one engineer (transient
  configuration mistake).

## Last updated

2026-05-05 (initial draft alongside the Phase 11 MCP scaffold).
