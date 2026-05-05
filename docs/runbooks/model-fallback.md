# Runbook: Zero-Day / AI scanners report 0 — silent fallback

## TL;DR

- **Symptom:** Zero-Day Detector / Business Logic / LLM Security /
  Auth Scanner all report `0 findings` for repos that should have
  matches; the UI shows the AI section as "completed" but empty.
- **Most likely cause:** ML dependencies (`torch`, `torch-geometric`,
  `transformers`, `scikit-learn`) failed to import. `server.py`
  catches the `ImportError` and continues with a no-op detector.
- **Fast fix:** install `requirements-ml.txt` into the venv and
  restart the API.
- **Severity bump if:** customer is paying for the AI tier or the UI
  is showing a fake "AI scan complete" badge — that's a misleading
  product-truth issue, not just an ops issue.

## Detection

### At startup

```bash
grep -E "Zero-Day|Business Logic|LLM Security|Auth Scanner|ML.*not available" \
  backend/backend.log | head -20
```

You're looking for either:

```text
[OK]   GNN Model Manager initialized: {'model_loaded': True, ...}
[BAD]  ⚠️  Zero-Day ML Detector not available: No module named 'torch'
[BAD]  ⚠️  Business Logic Analyzer not available: No module named 'sklearn'
```

### At scan time

```bash
grep -E "ML anomaly detection|GNN enabled|Found 0 (Python files|code anomalies)" \
  backend/backend.log
```

If the logs say `Found 0 Python files to analyze` on a repo that
clearly has Python files, the file-discovery glob is the bug, not
the model. That's a separate issue (track in Phase 5).

## Diagnosis

1. **Confirm it's a missing dep, not a missing repo content.**
   ```bash
   ./venv/bin/python -c "import torch, torch_geometric, transformers, sklearn; \
     print('all ok')" 2>&1
   ```

2. **Check the version of the loaded model.** A loaded but stale model
   can also misbehave:
   ```bash
   grep "Inference engine ready" backend/backend.log | tail -1
   ```

3. **Check if the `engines/zero_day/models/model.pt` file exists** —
   missing model file ≠ missing deps; model file should be downloaded
   per `engines.zero_day.model_updater` config.

## Fix

### Install ML deps

```bash
cd backend
source venv/bin/activate
pip install -r requirements-ml.txt
```

This brings ~3 GB of `torch` + transformers. On networks where the
PyPI Torch wheel isn't accessible, use the official PyTorch index:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

Restart the API:

```bash
lsof -ti:8000 | xargs kill -TERM
./start_servers.sh
```

### Verify

```bash
grep "GNN Model Manager initialized" backend/backend.log | tail -1
# Expect: {'model_loaded': True, ...}
```

### Workaround if you cannot install ML

After Phase 5 we extract these scanners into a separate
`ai-engine-service` and surface a capability flag (`ai_available`)
the UI uses to **hide** the AI section instead of running it. Until
then, the right thing to do is **disable** the AI scanners so we don't
falsely report "completed":

```bash
curl -X PATCH http://localhost:8000/api/settings \
  -H 'Content-Type: application/json' \
  -d '{"enable_zero_day_detector": false, \
       "enable_business_logic_scanner": false, \
       "enable_llm_security_scanner": false, \
       "enable_auth_scanner": false}'
```

## Rollback

ML install is non-destructive — just `pip uninstall` the listed
packages if it broke other deps (it shouldn't).

## Verification

After installing and restarting, run a scan against a repo with known
issues (e.g., a repo with a hardcoded `eval()` call, a vulnerable
dependency, or a known LLM-injection sample). Expected:

```bash
grep -E "Zero-Day Detector completed|Business Logic Scanner completed|\
LLM Security Scanner|Auth Scanner completed" backend/backend.log | tail -10
```

You should see non-zero findings in at least one of these blocks.

## Postmortem trigger

- Any time this fires in production: P1. The marketing claim "AI-
  Powered Security Scanner" is part of the product promise; silent
  fallback is a product-truth issue that needs explicit communication
  to affected customers.
- Also: open a Phase-5 ticket if not already done — the real fix is
  to remove the silent fallback path entirely.

## Last updated

2026-05-05 (initial draft, Phase 0).
