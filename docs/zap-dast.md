# ZAP DAST — Authenticated, SPA-aware, Triage-friendly

The ZAP DAST scanner now runs ZAP via the **Automation Framework** (one
YAML plan, multiple jobs) instead of the legacy shell wrappers. This
unlocks the seven gaps called out earlier:

| # | Gap | Closed by |
| --- | --- | --- |
| 1 | Authenticated scans | `AuthConfig` (form / JWT / OAuth2 client_credentials) feeds an AF context with users + auth scripts |
| 2 | Spider depth + scope controls | `SpiderConfig` fields are exposed on `ScannerSettings` and rendered into the AF spider job |
| 3 | AJAX spider for SPAs | Auto-detected (`<div id="root\|app\|__next">` + bundle URL); manual override via `enable_ajax_spider` |
| 4 | OpenAPI auto-discovery | `discover_openapi_spec_url()` probes `/openapi.json /swagger.json /v3/api-docs /api-docs /openapi.yaml /swagger.yaml /swagger/v1/swagger.json` |
| 5 | Session reuse | `session_dir` mounts a host directory; AF `env.parameters.session` persists state across jobs and runs |
| 6 | AF YAML | One plan, version-controllable, native context+auth+openapi+spider+activeScan job graph |
| 7 | Triage dedup with Nuclei + Schemathesis | Fingerprint normaliser now strips scheme/host, drops query strings, and collapses `\d+`, UUID, and `{id}` path segments |

## Module layout

```
backend/scanners/zap/
├── __init__.py             # public surface (config dataclasses + discovery)
├── config.py               # SpiderConfig / AuthConfig / OpenApiConfig / ZapScanConfig
├── automation.py           # build_automation_plan() + render_yaml() (PyYAML or hand-rolled)
└── openapi_discovery.py    # async parallel probe of common spec paths
backend/scanners/zap_dast_scanner.py   # orchestrator (Docker run + report parse)
```

## API

```python
from scanners.zap_dast_scanner import ZAPDastScanner
from scanners.zap import ZapScanConfig, SpiderConfig, AuthConfig, JwtAuthConfig, OpenApiConfig

cfg = ZapScanConfig(
    target_url="https://staging.app.example.com",
    scan_type="combined",
    spider=SpiderConfig(
        max_depth=8,
        scope_includes=["https://staging.app.example.com/api/.*"],
        scope_excludes=[".*/logout", ".*/admin/.*"],
    ),
    auth=AuthConfig(jwt=JwtAuthConfig(token=os.environ["TEST_JWT"])),
    openapi=OpenApiConfig(auto_discover=True),
    session_dir="/var/lib/fortknoxx/zap-sessions/staging",
    timeout_seconds=900,
)
findings = await ZAPDastScanner().scan_with_config(cfg)
```

The legacy `scan_target(target_url, scan_type, api_spec_path, auth_config)`
signature still works — auth dicts coerce to `AuthConfig` automatically.

## SPA detection heuristic

Cheap GET on the target root + content sniff for:

* `id="root"`, `id="app"`, or `id="__next"`
* `.js` references under `/static/`, `/_next/`, or `/assets/`

When both match, the AJAX spider job is appended to the AF plan
automatically. `SpiderConfig.enable_ajax_spider=True` forces it.

## Auth scripts

`fortknoxx-jwt-header.js` and `fortknoxx-oauth-cc.js` are written into
the per-run work directory and referenced by name in the AF YAML. They
read credentials from the active user's stored credential map, so the
JWT / client secret never appears in the YAML on disk.

## Triage dedup

The triage fingerprint now treats URLs the same as file paths:

* `http://app/api/users/123`, `/api/users/9999`, and `/api/users/{id}`
  all collapse to `api/users/{id}`.
* Query strings and fragments are stripped before hashing.
* `_normalise_code` also folds `{id}`-style placeholders so
  Schemathesis-emitted snippets dedupe cleanly with ZAP/Nuclei evidence.

## Tests

```bash
cd backend && venv/bin/python -m pytest tests/test_zap.py -q
```

19 tests cover: AF YAML structure (baseline vs full vs api), AJAX
spider activation, OpenAPI job placement before active scan, scope +
spider tunable pass-through, all three auth methods, YAML emitter,
triage dedup across ZAP / Nuclei / Schemathesis, OpenAPI auto-discovery
hit and miss paths.
