# ADR-005: Service mesh — Linkerd

- **Status:** Accepted
- **Date:** 2026-05-05
- **Deciders:** @sharaj
- **Tags:** networking, observability, security, deployment

## Context

ADR-002 Phase 7 introduces a service mesh on the customer's K8s
cluster. We want mTLS between every FortKnoxx service, automatic
retries with timeout budgets, golden-signal metrics for free, and a
clean way to gate traffic during canary rollouts. Doing this in
application code per service violates DRY and is error-prone.

A mesh choice is largely **one-way**: the cluster operator's mental
model becomes mesh-shaped, observability dashboards point at mesh
metrics, and rollout playbooks reference its CRDs. Switching costs
real engineering weeks.

## Constraints

- Single-cluster, single-region deployment behind the customer VPN.
- Operator team is small — we cannot afford a mesh that demands a
  full-time SRE.
- Must support mTLS with automatic certificate rotation.
- Must export Prometheus metrics out of the box.
- Must integrate with our (planned) ArgoCD / Flux GitOps flow.
- License must be permissive (Apache-2 or similar) — no surprises
  at customer resale.
- Deployment manifests live in `infrastructure/helm/`.

## Options considered

### Option A — Linkerd 2.x (selected)

Pros:
- **Operationally light.** Two pods per node (proxy + identity);
  Linkerd's proxy is a Rust binary, ~10MB, low CPU/memory. Real
  measured P50 added latency at scale: < 1ms.
- **Defaults are sensible.** mTLS on by default, identity rotated
  every 24h automatically.
- **Apache 2.0**, CNCF graduated.
- **Service profiles** are simple YAML — easy to review.
- **Multicluster works**, but we do not need it now (single VPN
  cluster). Lets us turn it on without re-architecting later.
- **Observability story** is excellent: built-in Prometheus + Grafana
  dashboards covering golden signals per service.
- **No `Sidecar` injection annotation gymnastics** — opt-in per
  namespace via a single label.

Cons:
- Less feature surface than Istio (no L7 traffic policy as expressive
  as Istio's `VirtualService` / `DestinationRule`).
- Smaller community, fewer Stack Overflow answers.

### Option B — Istio (sidecar mode)

Pros:
- Most feature-rich (rich routing, JWT validation at the mesh,
  WASM filters, multi-cluster with mTLS spanning).
- Largest community, most ecosystem integrations.

Cons:
- **Operationally heavy.** Envoy sidecar memory footprint is 4–10×
  Linkerd's. Control plane (`istiod`) needs careful tuning.
- mTLS, while supported, is not always on by default depending on
  installation profile — easy to misconfigure.
- License: Apache-2 ✓, but governance has had churn (see Solo
  takeover discussions) — minor risk for a security product.
- Much steeper operational learning curve.

### Option C — Istio (ambient mode)

Pros:
- Sidecar-less; lower per-pod overhead than classic Istio.
- Recently GA, promising direction.

Cons:
- Younger than Linkerd's stable mode; fewer published F500
  deployments.
- Some L7 features only work with the optional waypoint proxies, so
  the operational simplification is partly illusory.

**Rejected** at this stage; revisit in 12 months once ambient mode
has more production track record.

### Option D — No mesh; Envoy per pod via Helm chart

Pros: full control.
Cons: every team writes the same Envoy config; mTLS rotation,
metrics, routing all become bespoke. **Rejected** — defeats the
purpose of a mesh.

### Option E — Cilium service mesh (sidecar-less, eBPF)

Pros: zero-sidecar overhead, packet-level visibility.
Cons: requires Cilium as the cluster CNI (often customer-side
controlled), narrower ecosystem for L7 features. **Rejected** for
this iteration; revisit if Cilium ever becomes our CNI.

## Trade-offs

| Dimension                      | Linkerd  | Istio sidecar | Istio ambient | Bespoke Envoy | Cilium mesh |
| ------------------------------ | -------- | ------------- | ------------- | ------------- | ----------- |
| Per-pod CPU/RAM overhead       | low      | high          | low           | medium        | none        |
| mTLS by default                | yes      | depends       | yes           | manual        | yes         |
| L7 expressiveness              | medium   | high          | high          | full          | medium      |
| Operational complexity         | low      | high          | medium        | high          | medium      |
| Maturity for F500              | high     | very high     | medium        | n/a           | medium      |
| Licence                        | Apache-2 | Apache-2      | Apache-2      | Apache-2      | Apache-2    |

## Reversibility

**One-way door for the operator team's mental model**, but the
deployment artefacts are still revertable: services run with or
without a mesh; mesh CRDs can be deleted. Estimated cost to switch
mid-project: ~3 engineer-weeks for a small fleet of ~10 services.

## Decision

Adopt **Linkerd 2.x** as the FortKnoxx service mesh. Install via
Helm in `infrastructure/helm/linkerd/` with the `linkerd-control-plane`
chart and per-namespace data-plane injection.

## Consequences

- Every service deployment in `infrastructure/helm/fortknoxx/`
  receives the `linkerd.io/inject: enabled` annotation.
- Default policy: `proxy.disable-outbound-protocol-detect-timeout: 10s`,
  `proxy.opaquePorts` for Postgres / Mongo / Kafka so the mesh does
  not try to L7-parse their wire formats.
- Prometheus dashboards under `infrastructure/grafana/linkerd/`.
- New runbook `linkerd-control-plane-down.md` (Phase 7 task).
- Canary rollouts use Linkerd's `TrafficSplit` CRD; the existing
  rollout strategy in ADR-002 is valid.

## Follow-ups

- [ ] Helm chart for Linkerd in `infrastructure/helm/linkerd/`
- [ ] Per-service Helm values: `linkerd.io/inject`, opaque ports
- [ ] Canary rollout playbook update referencing Linkerd primitives
- [ ] Runbook: `linkerd-control-plane-down.md`
- [ ] Runbook: `mtls-cert-rotation-failure.md`
