# Autofix — Unified-diff Fixes for Findings

## Why a new endpoint

The legacy `/api/ai-fix` returns markdown advice. Useful for humans, but not
for automation. `/api/autofix` returns a *verified unified diff* that the UI
can apply with a single click and the CI can paste straight into a fix
branch.

## Endpoint

```
POST /api/autofix
{
  "vulnerability_id": "<finding id>",
  "repo_path": "/tmp/fortknoxx_repos/<repo_id>",   // optional; inferred
  "provider": "anthropic",                          // optional
  "model": null                                     // optional
}
```

Response:

```json
{
  "fingerprint": "a3c30ba4285abd45",
  "file_hash": "9f7c01e2",
  "diff": "--- a/app.py\n+++ b/app.py\n@@ ...",
  "applies_cleanly": true,
  "cached": false,
  "provider": "anthropic",
  "model": null,
  "error": null
}
```

## Cost model

* **One LLM call per `(fingerprint, file_hash)` pair.** A second request
  for the same finding on an unchanged file is served from MongoDB
  (`autofix_cache` collection) at zero LLM cost.
* **Failed diffs are not cached.** The next request will retry — no
  poisoned cache lock-in.
* **`FORTKNOXX_AUTOFIX_LLM=ollama`** routes calls to a local model via
  Ollama's OpenAI-compatible API for fully zero-cost mode.

## Validation

Every generated diff goes through `git apply --check` before being
returned. The result is shipped with `applies_cleanly: true|false` so
the UI can:

* Surface clean diffs as a "Apply fix" button.
* Surface dirty diffs as "Suggested fix (review manually)" — never
  silently fail.

We deliberately do *not* try to compile or run tests in the backend
container — that would require shipping every target language's
toolchain. The diff being syntactically valid + spatially correct is
checked here; semantic correctness is the user's call before merging.

## Prompt design

* Temperature 0 → identical findings produce identical prompts and (on
  providers with prompt-side caching) identical billable tokens.
* Excerpt window is ±20 lines around the finding line, with line
  numbers, so the LLM can produce stable hunk headers.
* The system prompt forbids markdown fences and free-form prose; we
  still strip fences defensively because LLMs sometimes ignore.

## Tests

```bash
cd backend && venv/bin/python -m pytest tests/test_autofix.py -q
```

13 tests covering: fence stripping, diff detection, `git apply --check`
against a real ephemeral repo, end-to-end with mocked orchestrator,
cache hit on second call, cache *not* populated for failing diffs,
graceful no-op when no orchestrator is wired up.
