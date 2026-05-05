# Runbook: <symptom in plain English>

## TL;DR

- **Symptom:** what users / monitors observe
- **Most likely cause:** one sentence
- **Fast fix:** one command or one click
- **Severity bump if:** condition that escalates this from P2 to P1

## Detection

Which alerts/dashboards/log queries fire when this happens.

```text
example: Datadog monitor "FortKnoxx scan failure rate > 5%"
example: log query: service:fortknoxx-api status:error "Error processing scan"
```

## Diagnosis

Step-by-step questions to narrow the cause. Each step ends with a
concrete next runbook section or fix.

1. Question → command → expected output → branch.
2. …

## Fix

Numbered, copy-pasteable commands. Include the **why** for each so the
on-call engineer learns the system instead of just running commands.

## Rollback

What to do if the fix makes things worse.

## Verification

How to confirm the system is healthy again. Specific signals, not
"check the dashboard".

## Postmortem trigger

When this incident requires a postmortem (per CLAUDE.md §10):

- P0/P1 always.
- P2 if it recurs within 7 days.

## Last updated

YYYY-MM-DD by @handle (incident link).
