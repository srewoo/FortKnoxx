# ADR-NNN: Short Title

- **Status:** Proposed | Accepted | Superseded by ADR-XXX | Deprecated
- **Date:** YYYY-MM-DD
- **Deciders:** @handle1, @handle2
- **Tags:** e.g., backend, data, security, deployment

## Context

What problem are we solving? What is forcing the decision now? Stick to
facts: traffic levels, compliance requirements, incident reports, team
constraints. No solutions yet.

## Constraints

Hard constraints that any option must respect.

- Examples: VPN-only deployment, max budget, language/runtime, must
  integrate with existing X, no downtime during cutover.

## Options considered

At least three, including **"do nothing"**.

### Option A — `<name>`

Brief description. **Pros / Cons / Estimated cost (eng-weeks).**

### Option B — `<name>`

…

### Option C — Do nothing

What happens if we leave it as is. Always include this — it's the
baseline.

## Trade-offs

Explicit comparison: what each option gives up. Use a table when the
matrix is wide enough to be useful.

| Dimension      | Option A | Option B | Option C |
| -------------- | -------- | -------- | -------- |
| Latency impact | …        | …        | …        |
| Cost           | …        | …        | …        |
| Security       | …        | …        | …        |
| Reversibility  | …        | …        | …        |

## Reversibility

> "Type 1: one-way door. Slow down, gather data. Type 2: two-way door.
> Move fast." — Bezos.

State explicitly which kind this is. If one-way, justify why the
evidence is sufficient.

## Decision

Single chosen option, in one sentence. Link to follow-up tasks or
tickets that implement it.

## Consequences

What changes after this decision lands? Include both the wins and the
new costs (operational burden, on-call surface, doc debt).

## Follow-ups

- [ ] Concrete implementation tasks
- [ ] Tests/runbooks added
- [ ] Documentation updated
- [ ] Communication to affected teams
