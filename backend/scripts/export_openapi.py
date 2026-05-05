"""Export FastAPI's OpenAPI schema to a versioned YAML file on disk.

WHY: FastAPI generates the OpenAPI spec at runtime, but for code review,
contract testing, and external SDK generation we need it as a checked-in
artifact. CI runs this and fails if the committed file drifts from the
generated one.

Usage:
    cd backend
    python scripts/export_openapi.py            # writes ../docs/api/openapi.yaml
    python scripts/export_openapi.py --check    # exits 1 if file is stale
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
OUT_PATH = ROOT / "docs" / "api" / "openapi.yaml"


def load_app():
    sys.path.insert(0, str(ROOT / "backend"))
    from server import app  # noqa: E402  -- import after path fix

    return app


def generate() -> str:
    app = load_app()
    schema = app.openapi()
    return yaml.safe_dump(schema, sort_keys=False, width=120)


def main() -> int:
    parser = argparse.ArgumentParser(description="Export OpenAPI schema.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail with exit 1 if the on-disk file is stale.",
    )
    args = parser.parse_args()

    new_content = generate()

    if args.check:
        if not OUT_PATH.exists():
            print(f"::error:: {OUT_PATH} is missing. Run scripts/export_openapi.py.")
            return 1
        on_disk = OUT_PATH.read_text(encoding="utf-8")
        if on_disk != new_content:
            print(
                f"::error:: {OUT_PATH} is out of date. "
                "Run `python backend/scripts/export_openapi.py` and commit the result."
            )
            return 1
        print(f"OK: {OUT_PATH} matches generated schema.")
        return 0

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(new_content, encoding="utf-8")
    print(f"Wrote {OUT_PATH} ({len(new_content)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
