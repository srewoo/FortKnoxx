# API Contracts

This directory holds the source-of-truth OpenAPI specification for the
FortKnoxx backend.

## Files

- `openapi.yaml` — generated from the running FastAPI app. Reviewed in
  every PR that touches a route or schema.

## Regenerate

```bash
cd backend
source venv/bin/activate
python scripts/export_openapi.py
```

This writes `docs/api/openapi.yaml`. Commit the result.

## CI gate

CI runs `python backend/scripts/export_openapi.py --check` and fails the
build if the on-disk file drifts from what the code generates. This
catches the common mistake of changing a route without updating the
contract.

## Viewing

- Local: `http://localhost:8000/docs` (Swagger UI) and `/redoc`.
- Static render of the committed file: open `openapi.yaml` in any
  Swagger/Redoc viewer, or paste into <https://editor.swagger.io>.

## Migration note

This contract will be split per microservice during Phase 3 of the
F500-readiness migration (see `docs/adr/ADR-002-migration-plan.md`).
At that point each service in `apps/` will own its own OpenAPI file
under `apps/<service>/openapi.yaml`, and this directory will become
the aggregated gateway-level spec.
