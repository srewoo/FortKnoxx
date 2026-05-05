"""Parity check: frontend's modelMigration map mirrors the Python registry.

The frontend keeps a hand-maintained copy of `LEGACY_MODEL_MIGRATION`
inside `frontend/src/App.js` (the IDE has no module path to import the
backend's Python from). Drift between the two is silent and only
shows up as a 404 when a user with stale localStorage talks to a
freshly-upgraded backend.

This test parses the JS object literal out of `App.js` and asserts it
matches the Python source of truth. A new entry in `model_registry`
without a matching frontend entry will fail this test in CI.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from llm.model_registry import DEFAULT_MODEL_BY_PROVIDER, LEGACY_MODEL_MIGRATION

REPO_ROOT = Path(__file__).resolve().parents[2]
APP_JS = REPO_ROOT / "frontend" / "src" / "App.js"


def _extract_js_object(source: str, var_name: str) -> dict[str, str]:
    """Pull a `const X = {...}` map out of JS source.

    Tolerates trailing commas and unquoted keys. Not a real JS parser
    — only adequate for the small migration map we ship.
    """
    pattern = rf"const\s+{re.escape(var_name)}\s*=\s*\{{(.*?)\}};"
    match = re.search(pattern, source, re.DOTALL)
    if not match:
        raise AssertionError(f"could not find `const {var_name} = {{...}}` in App.js")
    body = match.group(1)

    pairs: dict[str, str] = {}
    # Quoted-string key followed by a quoted-string value.
    entry_pattern = re.compile(r'["\']([^"\']+)["\']\s*:\s*["\']([^"\']+)["\']')
    for key, value in entry_pattern.findall(body):
        pairs[key] = value
    return pairs


@pytest.fixture(scope="module")
def js_app_source() -> str:
    if not APP_JS.exists():
        pytest.skip(f"frontend not found at {APP_JS}")
    return APP_JS.read_text(encoding="utf-8")


def test_js_modelMigration_matches_python(js_app_source: str):
    js_map = _extract_js_object(js_app_source, "modelMigration")

    if js_map != LEGACY_MODEL_MIGRATION:
        diff = {
            "in_python_only": sorted(set(LEGACY_MODEL_MIGRATION) - set(js_map)),
            "in_js_only": sorted(set(js_map) - set(LEGACY_MODEL_MIGRATION)),
            "value_mismatch": {
                k: {"python": LEGACY_MODEL_MIGRATION[k], "js": js_map[k]}
                for k in set(js_map) & set(LEGACY_MODEL_MIGRATION)
                if js_map[k] != LEGACY_MODEL_MIGRATION[k]
            },
        }
        raise AssertionError(
            "JS `modelMigration` drifted from Python `LEGACY_MODEL_MIGRATION`:\n" + json.dumps(diff, indent=2)
        )


def test_js_default_model_matches_python_default(js_app_source: str):
    """The frontend hard-codes `claude-sonnet-4-6` as the fallback default."""
    fallback_match = re.search(r'return storedModel \|\| ["\']([^"\']+)["\']', js_app_source)
    assert fallback_match, "could not find default-model fallback in App.js"
    js_default = fallback_match.group(1)
    assert js_default == DEFAULT_MODEL_BY_PROVIDER["anthropic"], (
        f"JS default model fallback ({js_default}) drifted from "
        f"DEFAULT_MODEL_BY_PROVIDER['anthropic'] ({DEFAULT_MODEL_BY_PROVIDER['anthropic']})"
    )


def test_js_provider_models_lists_match_registry(js_app_source: str):
    """The dropdown lists in App.js show one canonical id per supported model."""
    from llm.model_registry import (
        ANTHROPIC_MODELS,
        GEMINI_MODELS,
        OPENAI_MODELS,
    )

    expected = {
        "openai": {m.id for m in OPENAI_MODELS},
        "anthropic": {m.id for m in ANTHROPIC_MODELS},
        "gemini": {m.id for m in GEMINI_MODELS},
    }

    # Each provider has its `<SelectItem value="...">` block. Pull the
    # values that fall inside the conditional — far less brittle than
    # parsing JSX.
    for provider, ids in expected.items():
        block = re.search(
            rf'selectedProvider === "{provider}".*?\)\s*\}}',
            js_app_source,
            re.DOTALL,
        )
        assert block, f"could not find dropdown block for provider={provider}"
        found = set(re.findall(r'<SelectItem value="([^"]+)">', block.group(0)))
        missing = ids - found
        assert not missing, (
            f"frontend dropdown for {provider} is missing model ids "
            f"present in the Python registry: {sorted(missing)}"
        )
