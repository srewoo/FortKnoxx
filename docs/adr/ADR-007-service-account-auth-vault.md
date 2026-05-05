# ADR-007: Service-account authentication for FortKnoxx ↔ Vault

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** security, identity, deployment

## Context

ADR-006 picked HashiCorp Vault for per-tenant envelope encryption.
Every FortKnoxx service that performs `Encrypt` / `Decrypt` against
Vault Transit must authenticate. We need to pick **how** the API,
scanner-worker, audit-service, etc. prove their identity to Vault.

Wrong choices here lead to either:

- **Static long-lived tokens** sitting in K8s Secrets — common but
  trivial to exfiltrate via a single misconfigured pod.
- **Per-engineer tokens shared between humans and services** —
  blurs human-vs-service identity in audit logs.

We want service identity that:

- Rotates on its own.
- Cannot leave the cluster (a stolen token from a leaked pod log
  must die quickly).
- Is cheap to deploy across our planned ~10 microservices.

## Constraints

- Deployment is K8s on the customer's cluster (per ADR-002).
- Vault is co-located in the same cluster (per ADR-006).
- Each FortKnoxx service runs as a dedicated K8s `ServiceAccount`
  (per ADR-002 / Phase 7).
- mTLS at the service mesh (Linkerd, ADR-005) protects the wire,
  but not the application identity.
- We must also support Vault running outside the cluster for
  development environments without mocking the auth path.

## Options considered

### Option A — Vault Kubernetes auth method (selected)

Pros:
- Vault verifies the K8s **ServiceAccount JWT** that the pod
  receives by default (`/var/run/secrets/kubernetes.io/serviceaccount/token`).
- **No long-lived secrets** — the SA token is short-lived (1 h with
  projected service account tokens in modern K8s) and rotated
  automatically.
- Scoped: a Vault role binds the SA to a Vault policy that grants
  exactly `transit/encrypt/tenants/+/dek-wrap` and
  `transit/decrypt/tenants/+/dek-wrap`. No accidental access to
  other secrets.
- Cluster-local: a stolen SA token from a leaked log is useless
  outside the cluster (Vault verifies via the K8s API).
- Mature, widely deployed.

Cons:
- Depends on Vault's TokenReview API path being reachable from
  Vault to the K8s API (network policy needs to allow it).
- The Kubernetes auth method itself uses a Vault token to call
  TokenReview — we have to seed that one carefully (a chicken-and-egg
  bootstrap).

### Option B — AppRole

Pros: well-supported, works outside K8s.
Cons:
- The `secret_id` that pairs with a `role_id` is a long-lived
  credential. Even with response-wrapping, distributing it to pods
  needs External Secrets Operator + K8s Secret, which is what we
  are trying to avoid.
- Auditing per-pod is harder — multiple pods often share the same
  AppRole.

**Rejected** for production; kept as the dev-fallback option (see
"Dev environments" below).

### Option C — Static tokens in K8s Secrets

Pros: simplest.
Cons: long-lived, easy to exfiltrate, hard to rotate, reads as
"audit fail" in any F500 review. **Rejected** outright.

### Option D — JWT / OIDC auth method (workload identity from cloud
provider)

Pros: works across clusters, integrates with cloud IAM.
Cons: ties FortKnoxx to a specific cloud's workload identity model
(GKE Workload Identity, AWS IAM Roles for Service Accounts) and
breaks self-hosted F500 deployments. **Rejected** as the default;
revisit if a cloud-only deployment ever happens.

## Trade-offs

| Concern                          | K8s auth  | AppRole | Static | Cloud OIDC |
| -------------------------------- | --------- | ------- | ------ | ---------- |
| Long-lived secret in pod         | no        | yes     | yes    | no         |
| Auto-rotation                    | yes       | manual  | manual | yes        |
| Per-service identity audit       | clear     | murky   | murky  | clear      |
| Self-hostable                    | yes       | yes     | yes    | varies     |
| Bootstrap complexity             | medium    | low     | low    | medium     |
| Cloud-vendor lock-in             | none      | none    | none   | high       |

## Identity model

Each FortKnoxx service runs in its own namespace and uses its own
`ServiceAccount`:

```
namespace: fortknoxx
  ServiceAccount: api-gateway
  ServiceAccount: scan-service
  ServiceAccount: scanner-worker
  ServiceAccount: findings-service
  ServiceAccount: ai-engine-service
  ServiceAccount: reporting-service
  ServiceAccount: audit-service
  ServiceAccount: notification-service
  ServiceAccount: mcp-server
```

Each maps 1:1 to a Vault role:

```
vault write auth/kubernetes/role/api-gateway \
  bound_service_account_names=api-gateway \
  bound_service_account_namespaces=fortknoxx \
  policies=fortknoxx-encrypt-decrypt \
  ttl=1h
```

Policy `fortknoxx-encrypt-decrypt`:

```hcl
path "transit/encrypt/tenants/*/dek-wrap" { capabilities = ["update"] }
path "transit/decrypt/tenants/*/dek-wrap" { capabilities = ["update"] }
# Read-only access to the keyring listing for diagnostics.
path "transit/keys/tenants/*/dek-wrap"    { capabilities = ["read"] }
```

The audit-service additionally gets the `transit/keys/.../rotate`
capability so the rotation cron can run from a single, audited place.

## Bootstrap

Vault needs **one** privileged token at install time to call
TokenReview against the K8s API. We use the standard pattern: a
short-lived Vault root token from the unseal ceremony writes the
Kubernetes auth config once, then the root token is revoked. From
then on, no human or service holds a Vault root token.

```
# Done once per cluster, at install time:
vault auth enable kubernetes
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  kubernetes_ca_cert=@/path/to/ca.crt \
  token_reviewer_jwt=@/path/to/tokenreview.jwt
```

The `bank-vaults` operator runs this from a `Vault` CR; the unseal
ceremony is documented in `docs/runbooks/vault-sealed.md` (Phase 8).

## Dev environments

Engineers running the stack on a laptop (`docker compose` /
`minikube`) cannot easily produce a TokenReview-validated SA token.
The default fallback is **AppRole**:

- A long-lived `role_id` is committed to the dev compose file (no
  secret-ness — it's a public identifier).
- A short-lived `secret_id` is fetched at startup via
  `vault write -wrap-ttl=10m auth/approle/role/dev-fallback/secret-id`
  and unwrapped by the dev container at boot.

Production manifests **must not** include AppRole roles —
Helm guards this with a `values.production.disableAppRole: true`
default.

## Reversibility

**Two-way door at the application interface.** Services call
`SecretsVault.encrypt(...)` (introduced in ADR-006). The Vault
backend reads `VAULT_AUTH_METHOD=kubernetes|approle|cloud-oidc`
and switches code paths. Switching default in a future ADR is a
config change, not a code change — provided we don't add
auth-method-specific helpers in the service layer.

**One-way door for the policy shape.** Once a role's policy is
deployed and customers depend on the granted capabilities, removing
a capability is a breaking change.

## Decision

Adopt the **Vault Kubernetes auth method** as the default for all
FortKnoxx services in production K8s deployments. AppRole stays as
a dev-only fallback gated behind a Helm value. Cloud OIDC is
**not** a default but is admissible behind the same backend
abstraction if a customer asks.

## Consequences

- Helm chart additions:
  - Per-service `ServiceAccount` resources (already planned in
    ADR-005 / Phase 7).
  - Vault `Role` resources via `bank-vaults` Vault CR.
  - NetworkPolicy allowing Vault → K8s API for TokenReview.
- New file `infrastructure/vault/policies/fortknoxx-encrypt-decrypt.hcl`.
- Routes that touch Vault read `VAULT_AUTH_METHOD` at startup; the
  `kubernetes` path uses the projected SA token from the standard
  filesystem mount.
- New runbook `vault-sealed.md` (already on the Phase 8 backlog —
  this ADR adds bootstrap section).
- Audit-log action types added: `vault.auth.k8s.success`,
  `vault.auth.k8s.failure`.

## Follow-ups

- [ ] Helm chart updates (ServiceAccounts, Vault CR roles, NetworkPolicy)
- [ ] `infrastructure/vault/policies/fortknoxx-encrypt-decrypt.hcl`
- [ ] `backend/secrets_vault/backends/vault_transit.py` —
      kubernetes/approle auth selector
- [ ] Runbook: `vault-sealed.md` (bootstrap section)
- [ ] Runbook: `vault-token-review-failure.md`
