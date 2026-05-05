# Runbook: Scan completes but UI shows zeros / Error processing scan

## TL;DR

- **Symptom:** UI dashboard shows blank Security Score / Total Vulns /
  Files Scanned for a repository whose scan log shows scanners actually
  found issues.
- **Most likely cause:** an exception during result aggregation in
  `process_scan_results()` (server.py) — one malformed scanner finding
  bubbles up and the whole scan record fails to persist.
- **Fast fix:** restart the API, re-scan; if it repeats, find the bad
  scanner and disable it in `/api/settings`.
- **Severity bump if:** affects more than one tenant or more than 10%
  of scans in a 1-hour window.

## Detection

```bash
# Local / dev
grep -E "Error processing scan|Scan .* completed with [0-9]+ vulnerabilities" \
  backend/backend.log | tail -50
```

In production (post Phase 10):

- Datadog log query: `service:fortknoxx-api "Error processing scan"`
- Monitor: `scans_failed_aggregation_rate > 0` over 5m.

## Diagnosis

1. **Confirm the scanners actually ran.** Look for per-scanner
   completion lines in the log:
   ```bash
   grep "scan completed:" backend/backend.log | tail -30
   ```
   If most scanners report N issues but the scan record is empty, the
   bug is in aggregation — proceed.

2. **Get the stack trace.** Phase 0 hardened the outer handler to use
   `logger.exception`. Search for the traceback right after the
   `Error processing scan` line. The first frame inside `server.py`
   tells you which scanner's processing block crashed.

3. **Common offenders:**
   - **Trivy CVSS shape mismatch** — `dep["CVSS"]` is sometimes a
     string, not a dict. Already guarded as of Phase 0.
   - **Grype JSON parse failure** — scanner returns invalid JSON; the
     scanner reports 0 findings but logs an ERROR. Hardening planned
     in Phase 1.
   - **Custom scanner returning a list of strings** instead of dicts.

4. **Identify the failing scanner.** From the traceback, note the
   variable name (`trivy_results`, `gitleaks_results`, etc.) and the
   field that crashed.

## Fix

### Fast (mitigate)

```bash
# Disable the problematic scanner via the settings API.
curl -X PATCH http://localhost:8000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"enable_<scanner>": false}'
```

Re-trigger the scan; the rest of the report will populate.

### Proper (fix)

Wrap the offending per-finding loop in `try/except` per the pattern
already applied to the Trivy block (server.py around the
`Process Trivy results` comment). Log the bad finding, skip it, do not
let it kill the whole aggregation.

```python
for finding in <scanner>_results:
    try:
        if not isinstance(finding, dict):
            logger.warning(f"Skipping non-dict finding: {type(finding).__name__}")
            continue
        # ... existing processing ...
    except Exception as e:
        logger.warning(f"Failed to process <scanner> finding, skipping: {e}")
```

After Phase 1 this pattern moves to a single `result_aggregator.py`
with one method per scanner, each individually testable.

## Rollback

The fix is additive (defensive try/except). If somehow it changes
behaviour, `git revert` the relevant commit and the original failure
mode returns — no data loss.

## Verification

```bash
# Re-scan and tail the log.
curl -X POST http://localhost:8000/api/scans/<repo_id>
tail -f backend/backend.log | grep -E "completed with|Error processing"
```

You want to see exactly one `Scan <id> completed with N vulnerabilities`
where N matches the sum of the per-scanner `scan completed:` lines.
The UI dashboard should now show non-zero `Total Vulnerabilities` and
populated severity distribution.

## Postmortem trigger

- Always for P0/P1.
- For P2/P3, only if the same scanner causes a second incident within
  7 days — that means our defensive wrappers are insufficient.

## Last updated

2026-05-05 (initial draft, Phase 0).
