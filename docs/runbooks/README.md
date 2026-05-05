# Runbooks

Operational playbooks for FortKnoxx incidents. Each runbook follows
the template in `_template.md` and is meant to be **followable at 3am
by an on-call engineer who has never seen the code**.

## Index

| Runbook                                  | When to use                                            |
| ---------------------------------------- | ------------------------------------------------------ |
| [scan-failure](./scan-failure.md)        | Scans complete with `Error processing scan` in logs    |
| [scanner-timeout](./scanner-timeout.md)  | Scans stall or exceed configured timeout              |
| [mongo-down](./mongo-down.md)            | API returns 5xx from `/api/repositories`, `/api/scans` |
| [postgres-down](./postgres-down.md)      | Postgres unreachable, migrations failing               |
| [model-fallback](./model-fallback.md)    | Zero-Day / AI scanners silently return 0 findings      |
| [mcp-pat-rotation](./mcp-pat-rotation.md)| MCP server PAT issuance, rotation, leak response       |

## Format rules

1. **TL;DR first.** Top of file: 3 lines on what to check, what to fix.
2. **Commands you can copy-paste.** No "see logs" — give the exact
   `kubectl logs ...` or `tail -f ...` command.
3. **Include rollback.** Every "do X" must have a "if X breaks, do Y".
4. **Link to detection.** What alert fires → what runbook to open.
5. **Update on every incident.** If a runbook didn't help, fix it
   before closing the postmortem.
