# Runbook: Scanner timeout / scan stalls

## TL;DR

- **Symptom:** scan status stays at `running` for longer than the
  configured timeout, or completes with `status: "timeout"`.
- **Most likely cause:** one heavy scanner (typically ZAP DAST, Nuclei,
  or CodeQL) on a large repo; or the API process is starved because
  another scan is pinning CPU.
- **Fast fix:** kill the in-flight scan, re-scan the same repo with
  the heavy scanner disabled.
- **Severity bump if:** API process becomes unresponsive to other
  routes (means the blocking scanner is starving the event loop).

## Detection

```bash
grep -E "Scan .* timed out|process_scan_with_timeout" backend/backend.log
grep -E "scan_status.*running" backend/backend.log | tail -20
```

In production (post Phase 10):

- Datadog: `service:fortknoxx-api status:warn "Scan .* timed out"`
- Monitor: scan p95 duration >2× baseline for 15m.

## Diagnosis

1. **Find the slow scanner.** The log lists each scanner's completion;
   the last completed scanner before the timeout is the culprit.

   ```bash
   grep -E "scan completed:|Scan .* timed out" backend/backend.log | tail -30
   ```

2. **Check repo size.** `utils/scan_limits.py` already analyses the
   repo; large repos (>500MB or >10K source files) should hit the
   `RepoAnalyzer` LIMITED bucket. If not, the analyser isn't being
   honoured.

3. **Check host pressure.** `top` / `htop` — is the API process at
   100% CPU on a single core? FastAPI runs scanners in threads;
   subprocess-heavy scanners can starve the event loop.

## Fix

### Fast

```bash
# Kill the stuck scan worker
lsof -ti:8000 | xargs kill -TERM
./start_servers.sh

# Re-scan with the heavy scanner disabled
curl -X PATCH http://localhost:8000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"enable_nuclei": false, "enable_zap_dast": false, "enable_codeql": false}'
curl -X POST http://localhost:8000/api/scans/<repo_id>
```

### Proper

After Phase 4 (containerized scanner workers), each scanner runs in a
K8s Job with its own CPU/memory limits and timeout. A single slow
scanner cannot stall the API. Until then:

- Tune `ScanLimits` per scanner in `utils/scan_limits.py`.
- Add per-scanner timeout to its wrapper (most scanners support a CLI
  flag — check `scanners/<name>_scanner.py`).
- Move heavy scanners to the optional list and require explicit opt-in
  per repo.

## Rollback

Re-enable scanners via `/api/settings`. Settings are persisted in
Mongo, so a restart preserves them.

## Verification

```bash
curl http://localhost:8000/api/scans/<repo_id> | jq '.status, .completed_at'
```

Expect `status: "completed"` (or `completed_with_warnings`) within the
configured timeout.

## Postmortem trigger

P1 if the API becomes unresponsive (event-loop starvation). Otherwise
P2 — track recurrence.

## Last updated

2026-05-05 (initial draft, Phase 0).
