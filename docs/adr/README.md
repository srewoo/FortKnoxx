# Architecture Decision Records

This directory contains the ADRs for FortKnoxx.

An ADR is a short document capturing a significant architectural choice
and the reasoning behind it. We follow the framework in CLAUDE.md §17:

> **Context → Constraints → Options (≥3, including "do nothing") →
> Trade-offs → Reversibility (one-way vs two-way door) → Decision**

## Index

| #   | Status   | Title                                                      |
| --- | -------- | ---------------------------------------------------------- |
| 001 | Accepted | Current state of FortKnoxx (snapshot, baseline)            |
| 002 | Accepted | Migration plan to Fortune-500 readiness                    |
| 003 | Accepted | Postgres for transactional data (override of MSSQL default) |
| 004 | Accepted | Kafka topic taxonomy, partitioning, and retention          |
| 005 | Accepted | Service mesh — Linkerd 2.x                                 |
| 006 | Accepted | BYO-Key — per-tenant envelope encryption with Vault        |
| 007 | Accepted | Service-account auth — Kubernetes auth method for Vault    |
| 008 | Accepted | Data-store split — Postgres for state, Mongo for findings  |

## How to add a new ADR

1. Copy `_template.md` to `ADR-NNN-short-title.md` (zero-pad the number).
2. Fill in every section. **Do not skip "Options considered"** — the
   value of an ADR is the reasoning, not the decision.
3. List in the index above with status `Proposed`.
4. Open a PR. Reviewers check that the trade-offs and reversibility
   analysis are honest, not that they agree with the decision.
5. Merge → status becomes `Accepted`.

## When to write an ADR

CLAUDE.md §17 calls these out specifically:

- New service boundary (creating or merging a microservice)
- Storage engine choice (Postgres vs Mongo vs Redis for a use case)
- Auth / authz strategy
- Framework adoption (e.g., Linkerd vs Istio)
- Major refactor that changes module ownership
- Any **one-way door** decision (hard to reverse, e.g., public API
  shape, data model with PII implications, cryptographic primitives)

Two-way door decisions usually do **not** need an ADR — just code.

## Format

- Markdown.
- Filename: `ADR-NNN-kebab-title.md`.
- Status values: `Proposed`, `Accepted`, `Superseded by ADR-XXX`,
  `Deprecated`.
- Never edit an Accepted ADR's decision section. Supersede it with a
  new ADR instead — preserves history.
