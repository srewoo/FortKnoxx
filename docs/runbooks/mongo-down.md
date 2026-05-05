# Runbook: MongoDB unreachable / API returns 5xx

## TL;DR

- **Symptom:** `/api/repositories`, `/api/scans/*`, `/api/stats/*`
  return 500 or hang. Backend log shows `Validating MongoDB connection`
  followed by an exception.
- **Most likely cause:** MongoDB process not running, port 27017 not
  listening, or auth credentials rotated without updating `.env`.
- **Fast fix:** `brew services restart mongodb-community` (mac) /
  `sudo systemctl restart mongod` (Linux), confirm port 27017 is up,
  restart the API.
- **Severity bump if:** Mongo data directory is corrupt (logs show
  `*WiredTiger*` errors) — escalate to data-recovery procedures.

## Detection

```bash
# API liveness
curl -sf http://localhost:8000/api/health || echo "API DOWN"

# Mongo liveness
lsof -i:27017 || echo "Mongo not listening"
mongosh --eval 'db.runCommand({ ping: 1 })' --quiet 2>&1 | tail -5
```

In production:

- Datadog monitor: `service:mongodb is_up == 0`
- Datadog log query: `service:fortknoxx-api "MongoDB connection"` with
  `status:error`.

## Diagnosis

1. **Is Mongo even running?**
   ```bash
   pgrep -lf mongod
   ```
   If nothing, jump to Fix → Start Mongo.

2. **Is it on the expected port?**
   ```bash
   lsof -i:27017 -sTCP:LISTEN
   ```

3. **Are credentials right?**
   ```bash
   grep -E "MONGO_URL|DB_NAME" backend/.env
   ```
   Compare to `mongosh "<connection-string>"`.

4. **Is the disk full?**
   ```bash
   df -h $(brew --prefix)/var/mongodb 2>/dev/null || df -h /var/lib/mongo
   ```

5. **Check Mongo log for WiredTiger errors:**
   ```bash
   tail -200 /opt/homebrew/var/log/mongodb/mongo.log     # mac
   tail -200 /var/log/mongodb/mongod.log                  # linux
   ```

## Fix

### Mongo not running

```bash
# macOS
brew services start mongodb-community

# Linux (systemd)
sudo systemctl start mongod
```

Then restart the API so it re-establishes its connection pool:

```bash
lsof -ti:8000 | xargs kill -TERM
./start_servers.sh
```

### Auth failure

Update `backend/.env` with the correct `MONGO_URL`. Restart API.

### Disk full

Identify and remove old log/scan data **only** after backup. Old scan
data lives in `vulnerabilities`, `quality_issues`, `compliance_issues`
collections — each row carries `created_at`. After Phase 2 we'll
introduce a TTL index; until then, archive manually.

### WiredTiger / corruption

Stop Mongo, run `mongod --dbpath <path> --repair`. If that fails,
restore from the most recent backup. **Do not** continue running on a
corrupted data dir — that's how we lose more.

## Rollback

If a config change made it worse:

```bash
git diff backend/.env  # only useful if .env is tracked (it is gitignored)
# Manually restore the previous MONGO_URL value.
```

## Verification

```bash
# All three should return 200 with valid JSON
curl -sf http://localhost:8000/api/health | jq '.database'
curl -sf http://localhost:8000/api/repositories | jq 'length'
curl -sf http://localhost:8000/api/settings | jq '.enable_semgrep'
```

## Postmortem trigger

- Always for P0/P1 (any data loss is automatic P0).
- P2 if Mongo restarts more than twice in a week — points to underlying
  resource issue.

## Last updated

2026-05-05 (initial draft, Phase 0).
