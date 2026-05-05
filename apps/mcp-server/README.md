# FortKnoxx MCP Server

Exposes FortKnoxx capabilities to engineers' IDEs via the
**Model Context Protocol** so an agent like Cursor or Claude Code can
trigger scans, fetch findings, and propose fixes inline.

See `docs/adr/ADR-002-migration-plan.md#phase-11`.

## Status

- **Scaffold** — Phase 11 of the F500 migration. Tools and resources
  are stubbed; wire-level transport works; integration with the API
  is via HTTP using a per-engineer Personal Access Token (PAT).
- Not yet deployed. Local stdio transport works today; SSE/HTTP
  ships in a follow-up alongside the K8s manifest.

## Tools exposed

| Tool                        | Purpose                                                |
| --------------------------- | ------------------------------------------------------ |
| `fortknoxx.scan_repo`       | Trigger a full scan against a repo URL or local path   |
| `fortknoxx.scan_diff`       | Scan only the staged or HEAD diff                      |
| `fortknoxx.get_findings`    | List findings for a scan, filterable by severity etc.  |
| `fortknoxx.get_finding_detail` | Full detail for one finding                          |
| `fortknoxx.suggest_fix`     | LLM-backed remediation patch proposal                  |
| `fortknoxx.suppress_finding`| Mark false-positive (audit-logged)                     |
| `fortknoxx.policy_check`    | "Would this PR pass our security gate?"                |

## Resources exposed

| Resource URI                                  | What it returns                  |
| --------------------------------------------- | -------------------------------- |
| `fortknoxx://repos/{id}/latest-scan`          | Latest scan summary              |
| `fortknoxx://compliance/{framework}`          | Tenant posture for that framework |
| `fortknoxx://policies/active`                 | Currently-enforced security gates |

## Run locally (stdio)

```bash
cd apps/mcp-server
pip install -e .
export FORTKNOXX_API_BASE=http://localhost:8000
export FORTKNOXX_PAT=<your-pat>
fortknoxx-mcp
```

Then point your IDE's MCP config at the `fortknoxx-mcp` binary.

## Auth model

Per ADR-002, deployment is behind the company VPN. Each engineer has
a Personal Access Token (PAT) issued by the FortKnoxx admin UI; the
PAT carries the engineer's RBAC role and tenant id. The MCP server is
**stateless** — every request authenticates against the FortKnoxx API
with the PAT it was started with.

PATs are stored in the IDE's secret store (Cursor / Claude Code both
provide one). Rotation procedure is documented in
`docs/runbooks/mcp-pat-rotation.md` (TODO).
