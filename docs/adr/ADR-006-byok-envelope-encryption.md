# ADR-006: BYO-Key — per-tenant envelope encryption with HashiCorp Vault

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** security, compliance, data-at-rest

## Context

ADR-002 Phase 8 mandates per-tenant encryption with bring-your-own-key
(BYOK) controls. Today FortKnoxx encrypts the secrets vault with a
single Fernet master key (`secrets_vault/encryption.py`) — fine for a
single-tenant POC, fails any F500 review where a tenant wants to:

- Rotate keys on their own schedule (compliance).
- Revoke their key independently of others (cryptographic erasure).
- See proof their data was never accessible without their key.

We deploy behind a customer VPN, so the KMS provider is a deployment
choice — not every customer is on AWS. We need a model that does not
hardcode AWS KMS but works equally well there.

## Constraints

- Cryptographic erasure must be possible per tenant (revoke KEK →
  tenant data unreadable).
- Key rotation must not require re-encrypting payload (envelope
  encryption: rotate the wrapper, not the wrapped data).
- All data-key operations must be auditable (`audit_log`).
- Hot-path latency budget: encryption add ≤ 5ms per request.
- Operator must not see plaintext customer data even with DB access.
- License: must support OSS deployment for self-hosted F500 customers.
- Algorithms: AES-256-GCM for data; RSA-4096 or ECDSA-P256 for KEKs.

## Options considered

### Option A — HashiCorp Vault (Transit secrets engine), default; pluggable to AWS KMS or GCP KMS via abstraction (selected)

Pros:
- **OSS, Apache 2.0** — runs on the customer's K8s cluster, no
  external service dependency.
- **Transit engine** does not return plaintext keys to the
  application — `Encrypt` / `Decrypt` calls keep the KEK inside
  Vault. Application only handles DEKs in memory.
- **Per-tenant key isolation** via separate keyrings: `tenants/{id}/dek-wrap`.
- **Native rotation** via `transit/keys/{name}/rotate`.
- **Audit log** built in (file + syslog backends).
- **Single OSS surface** the operator already runs for secret storage.
- **Pluggable seal** — Vault itself can be sealed by a cloud KMS
  (AWS / Azure / GCP), so customers who already standardise on a
  cloud KMS still get the integration without our app caring.

Cons:
- Operating Vault HA correctly is non-trivial (Raft storage, unseal
  ceremony). Mitigated by using `bank-vaults` operator on K8s.
- Vault's audit log lives outside our Postgres `audit_log` table —
  we need to mirror or correlate.

### Option B — AWS KMS only

Pros: zero operational burden if customer is AWS-native; FIPS 140-2
validated; per-key IAM policies.

Cons:
- Locks self-hosted F500 customers to AWS, conflicting with the VPN
  / on-prem deployment goal.
- `Encrypt` API limited to 4 KB plaintext — forces envelope
  encryption anyway; doesn't simplify.
- Can be added behind the abstraction layer — chosen as one of the
  pluggable backends, not the default.

### Option C — GCP KMS or Azure Key Vault

Pros: per cloud, similar to AWS KMS.
Cons: same lock-in as AWS KMS; supported via the abstraction layer
once a customer asks.

### Option D — Application-managed keys (status quo, single Fernet)

Pros: zero infra change.
Cons: fails every constraint above (no per-tenant rotation, no
cryptographic erasure, plaintext key on every API host, no separation
between operator and tenant data). **Rejected.**

### Option E — Cloud-vendor HSM (CloudHSM / Dedicated HSM)

Pros: highest assurance.
Cons: cost (≥ $1.5k/month/region), F500 customers may already have
their own HSM and don't want ours; operationally heavy. Reserved for
customers who specifically request FIPS-validated hardware.

## Envelope encryption flow

```
            ┌──────────────────────────────────────────────┐
            │             Vault Transit engine             │
            │ keyring: tenants/{tenant_id}/dek-wrap        │
            │            (KEK never leaves Vault)          │
            └────────────────┬─────────────────────────────┘
                             │   Encrypt / Decrypt API
                             │   (DEK is the payload)
                             ▼
   write path                                           read path
┌────────────┐   1. generate DEK (32B)              ┌─────────────┐
│ application│   2. AES-256-GCM(plaintext, DEK)     │ application │
│            │   3. Vault.encrypt(DEK) → wrapped    │             │
│            │   4. store {ciphertext, nonce,       │             │
│            │              wrapped_dek, key_ver}   │             │
│            │                                      │             │
└────────────┘                                      └─────────────┘
                             │
                             ▼
                        Postgres / Mongo
```

Stored row shape (Postgres example, `vault.findings_secret`):

```sql
CREATE TABLE vault.findings_secret (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    ciphertext BYTEA NOT NULL,          -- AES-256-GCM output
    nonce BYTEA NOT NULL,                -- 96-bit random
    wrapped_dek BYTEA NOT NULL,          -- Vault Transit ciphertext
    kek_version INT NOT NULL,            -- snapshot at encrypt time
    encrypted_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Rotation strategy

- Periodic (default 90 days) **and** on-demand: `vault write -f
  transit/keys/tenants/{id}/dek-wrap/rotate`.
- The KEK version is recorded with each row; old wrapped DEKs remain
  readable until the customer explicitly **archives** an old version.
- **Cryptographic erasure** for a tenant = delete or
  `min_decryption_version` to a value past every existing row →
  every row becomes unreadable, payload bytes can be left in place
  (no copy / scrub needed).

## Trade-offs

| Concern                | Vault (selected) | AWS KMS only | App-managed | HSM        |
| ---------------------- | ---------------- | ------------ | ----------- | ---------- |
| Self-hostable          | yes              | no           | yes         | no         |
| Per-tenant erasure     | yes              | yes          | no          | yes        |
| Operator visibility    | minimal          | minimal      | full (bad)  | minimal    |
| Hot-path latency       | ~3ms             | ~5–10ms      | ~0.1ms      | ~10ms      |
| Operational burden     | medium           | low          | none        | high       |
| FIPS validation        | optional add-on  | yes          | no          | yes        |
| Lock-in                | none             | AWS          | none        | vendor HSM |

## Reversibility

**Two-way door** at the abstraction layer: routes call
`SecretsVault.encrypt(tenant_id, plaintext)` and
`SecretsVault.decrypt(tenant_id, blob)`. Vault is one implementation;
AWS KMS / GCP KMS / Azure Key Vault are pluggable behind the same
interface. Switching the default backend in a future ADR re-encrypts
existing data via a one-time migration job (the wrapped DEKs are
re-wrapped under the new KEK; ciphertext bytes do not change).

**One-way door** for the envelope-encryption shape itself — once
deployed, the storage layout above is what we have to maintain
forever.

## Decision

Adopt **HashiCorp Vault (OSS) Transit engine** as the default KEK
custodian, accessed through a `SecretsVault` interface that has
pluggable AWS-KMS / GCP-KMS / Azure-Key-Vault backends for customers
who require them. Replace the existing Fernet master-key path
(`backend/secrets_vault/encryption.py`) with this abstraction in a
follow-up.

## Consequences

- New deployment dependency: Vault HA cluster on the customer's
  K8s, sealed via a cloud KMS where possible.
- New module: `backend/secrets_vault/backends/` with one file per
  backend (`vault_transit.py`, `aws_kms.py`, `gcp_kms.py`,
  `azure_key_vault.py`).
- New audit-log action types: `secrets.encrypt`, `secrets.decrypt`,
  `secrets.kek_rotate`, `secrets.key_archive`.
- Helm chart adds Vault + Bank-Vaults operator.
- Two new runbooks: `vault-sealed.md`, `vault-kek-rotation.md`.
- New CI test: schema-shape check that no migration introduces a
  table with a column named like `*_secret`/`*_token` without the
  envelope-encryption columns.

## Follow-ups

- [ ] `backend/secrets_vault/` interface + Vault Transit backend
- [ ] Migration: `vault.findings_secret` table (or equivalent per
      sensitive table — to be decided in ADR-008)
- [ ] Helm chart for Vault HA + Bank-Vaults
- [ ] Runbooks: `vault-sealed.md`, `vault-kek-rotation.md`
- [ ] CI lint rule for sensitive column shapes
- [ ] ADR-007: Service-account auth between FortKnoxx services and
      Vault (Kubernetes auth method vs token method)
