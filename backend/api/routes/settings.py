"""Settings routes — API keys, scanner toggles, AI scanner toggles.

Extracted from server.py during Phase 1.5. Two consolidations done in
the move:

1. **Duplicate `GET /settings/scanners`** (lines 1765 and 2064 of the
   original `server.py`) — FastAPI's behaviour with duplicate routes
   is undefined (first match wins, but ordering is fragile). The
   "installed binary" variant kept its public path (the frontend
   relies on it); the "persisted config" variant moved to
   `GET /settings/scanners/config`. The frontend currently does not
   call the latter.

2. **Inlined `_settings_response()` helper** so the API-keys POST
   handler does not call `get_all_settings()` twice.
"""

from __future__ import annotations

import logging
import os
import shutil
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from api import deps
from settings.models import (
    AIScannerSettings,
    ScannerSettings,
    SettingsResponse,
    UpdateAIScannerSettingsRequest,
    UpdateAPIKeysRequest,
    UpdateScannerSettingsRequest,
)

router = APIRouter(tags=["settings"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------- #
# Top-level settings
# ---------------------------------------------------------------- #


@router.get("/settings", response_model=SettingsResponse)
async def get_settings(settings_manager=Depends(deps.get_settings_manager)) -> SettingsResponse:
    try:
        return await settings_manager.get_all_settings()
    except Exception as exc:
        logger.exception("Error getting settings")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------- #
# API keys
# ---------------------------------------------------------------- #


@router.post("/settings/api-keys")
async def update_api_keys(
    request: UpdateAPIKeysRequest,
    settings_manager=Depends(deps.get_settings_manager),
) -> dict[str, Any]:
    """Encrypted store of LLM provider keys + scanner tokens.

    Pass an empty string to delete a single key.
    """
    try:
        from settings.models import APIKeySetting

        api_keys = APIKeySetting(
            openai_api_key=request.openai_api_key,
            anthropic_api_key=request.anthropic_api_key,
            gemini_api_key=request.gemini_api_key,
            github_token=request.github_token,
            snyk_token=request.snyk_token,
        )
        await settings_manager.update_api_keys(api_keys)
        settings_response = await settings_manager.get_all_settings()
        return {
            "message": "API keys updated successfully",
            "updated": settings_response.model_dump(),
        }

    except Exception as exc:
        logger.exception("Error updating API keys")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/settings/api-keys")
async def get_api_keys_values(
    settings_manager=Depends(deps.get_settings_manager),
) -> dict[str, Any]:
    """Return masked key values for the admin UI.

    WARNING: only the first 8 characters of each key are returned;
    full plaintext is never sent to the frontend.
    """
    try:
        keys = await settings_manager.get_api_keys()
        masked: dict[str, str | None] = {}
        for name, value in keys.items():
            if value:
                masked[name] = f"{value[:8]}…" if len(value) > 8 else value
            else:
                masked[name] = None
        return {"keys": masked}
    except Exception as exc:
        logger.exception("Error getting API key values")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------- #
# Scanner toggles (persisted)
# ---------------------------------------------------------------- #


@router.get("/settings/scanners")
async def get_installed_scanners() -> dict[str, dict[str, Any]]:
    """Which scanner binaries are reachable on PATH at this moment.

    Independent of the persisted enable/disable state — useful for
    the UI to show a red badge next to a scanner that is enabled in
    settings but missing from the host. Persisted config lives at
    ``GET /settings/scanners/config``.
    """
    return {
        "semgrep": {"name": "Semgrep (Enhanced)", "type": "SAST", "installed": bool(shutil.which("semgrep"))},
        "gitleaks": {"name": "Gitleaks", "type": "Secrets", "installed": bool(shutil.which("gitleaks"))},
        "trivy": {"name": "Trivy", "type": "Dependencies", "installed": bool(shutil.which("trivy"))},
        "checkov": {"name": "Checkov", "type": "IaC", "installed": bool(shutil.which("checkov"))},
        "bandit": {"name": "Bandit", "type": "Python Security", "installed": bool(shutil.which("bandit"))},
        "trufflehog": {
            "name": "TruffleHog",
            "type": "Secrets",
            "installed": bool(shutil.which("trufflehog")),
        },
        "grype": {"name": "Grype", "type": "Dependencies", "installed": bool(shutil.which("grype"))},
        "eslint": {"name": "ESLint", "type": "JS/TS Security", "installed": bool(shutil.which("eslint"))},
        "pylint": {"name": "Pylint", "type": "Python Quality", "installed": bool(shutil.which("pylint"))},
        "flake8": {"name": "Flake8", "type": "Python Style", "installed": bool(shutil.which("flake8"))},
        "radon": {"name": "Radon", "type": "Complexity", "installed": bool(shutil.which("radon"))},
        "shellcheck": {
            "name": "ShellCheck",
            "type": "Shell Scripts",
            "installed": bool(shutil.which("shellcheck")),
        },
        "hadolint": {"name": "Hadolint", "type": "Docker", "installed": bool(shutil.which("hadolint"))},
        "sqlfluff": {"name": "SQLFluff", "type": "SQL Security", "installed": bool(shutil.which("sqlfluff"))},
        "pydeps": {"name": "pydeps", "type": "Architecture", "installed": bool(shutil.which("pydeps"))},
        "pip_audit": {
            "name": "pip-audit",
            "type": "Python Deps",
            "installed": bool(shutil.which("pip-audit")),
        },
        "npm_audit": {"name": "npm-audit", "type": "JS/TS Deps", "installed": bool(shutil.which("npm"))},
        "syft": {"name": "Syft", "type": "SBOM/License", "installed": bool(shutil.which("syft"))},
        "nuclei": {
            "name": "Nuclei",
            "type": "Template/CVE Scanner",
            "installed": bool(shutil.which("nuclei"))
            or os.path.exists("/usr/local/bin/nuclei")
            or os.path.exists("/opt/homebrew/bin/nuclei"),
        },
        "snyk": {
            "name": "Snyk CLI",
            "type": "Modern Dependency Scanner",
            "installed": bool(shutil.which("snyk")),
        },
        "gosec": {"name": "Gosec", "type": "Go Security", "installed": bool(shutil.which("gosec"))},
        "spotbugs": {
            "name": "SpotBugs",
            "type": "Java Bytecode Analysis",
            "installed": bool(shutil.which("spotbugs")),
        },
        "pyre": {"name": "Pyre", "type": "Python Type Checker", "installed": bool(shutil.which("pyre"))},
        "zap": {"name": "OWASP ZAP (Static)", "type": "Web Security Patterns", "installed": True},
        "api_fuzzer": {"name": "API Fuzzer", "type": "API Security Testing", "installed": True},
        "zap_dast": {
            "name": "OWASP ZAP (DAST)",
            "type": "Dynamic Web Security",
            "installed": bool(shutil.which("docker")),
        },
        "horusec": {
            "name": "Horusec",
            "type": "Multi-Language SAST",
            "installed": bool(shutil.which("horusec")),
        },
        # Extended Coverage (added 2026-05) ────────────────────────
        "osv_scanner": {
            "name": "osv-scanner",
            "type": "Multi-Ecosystem CVE DB",
            "installed": bool(shutil.which("osv-scanner")),
        },
        "cyclonedx": {
            "name": "CycloneDX",
            "type": "SBOM (Compliance)",
            "installed": bool(shutil.which("cyclonedx-py")),
        },
        "license_scanner": {
            "name": "License Compliance",
            "type": "Copyleft Detection",
            "installed": bool(shutil.which("pip-licenses") or shutil.which("license-checker")),
        },
        "schemathesis": {
            "name": "Schemathesis",
            "type": "OpenAPI Fuzzing (DAST)",
            "installed": bool(shutil.which("schemathesis") or shutil.which("st")),
        },
        "garak": {
            "name": "garak (NVIDIA)",
            "type": "LLM Red-Team",
            "installed": bool(shutil.which("garak")),
        },
        "promptfoo": {
            "name": "promptfoo",
            "type": "LLM Prompt Eval",
            "installed": bool(shutil.which("promptfoo")),
        },
        "prowler": {
            "name": "Prowler",
            "type": "Cloud Security Audit",
            "installed": bool(shutil.which("prowler")),
        },
        "kube_bench": {
            "name": "kube-bench",
            "type": "K8s CIS Benchmark",
            "installed": bool(shutil.which("kube-bench")),
        },
        "kube_hunter": {
            "name": "kube-hunter",
            "type": "K8s Runtime Probe",
            "installed": bool(shutil.which("kube-hunter")),
        },
    }


@router.get("/settings/scanners/config", response_model=ScannerSettings)
async def get_scanner_config(
    settings_manager=Depends(deps.get_settings_manager),
) -> ScannerSettings:
    """Persisted enable/disable state for all scanners."""
    try:
        return await settings_manager.get_scanner_settings()
    except Exception as exc:
        logger.exception("Error getting scanner config")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.put("/settings/scanners")
async def update_scanner_config(
    request: UpdateScannerSettingsRequest,
    settings_manager=Depends(deps.get_settings_manager),
) -> dict[str, Any]:
    try:
        updated = await settings_manager.update_scanner_settings(request)
        settings_manager.clear_cache()
        return {
            "message": "Scanner settings updated successfully",
            "updated": updated.model_dump(),
        }
    except Exception as exc:
        logger.exception("Error updating scanner settings")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------- #
# AI scanner toggles (persisted)
# ---------------------------------------------------------------- #


@router.get("/settings/ai-scanners", response_model=AIScannerSettings)
async def get_ai_scanner_settings(
    settings_manager=Depends(deps.get_settings_manager),
) -> AIScannerSettings:
    try:
        settings = await settings_manager.get_ai_scanner_settings()
        return AIScannerSettings(**settings)
    except Exception as exc:
        logger.exception("Error getting AI scanner settings")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/settings/ai-scanners")
async def update_ai_scanner_settings(
    request: UpdateAIScannerSettingsRequest,
    settings_manager=Depends(deps.get_settings_manager),
) -> dict[str, Any]:
    try:
        current = await settings_manager.get_ai_scanner_settings()
        update_dict = request.model_dump(exclude_unset=True)
        current.update(update_dict)
        success = await settings_manager.update_ai_scanner_settings(current)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to update AI scanner settings")
        settings_manager.clear_cache()
        return {
            "message": "AI scanner settings updated successfully",
            "updated": current,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error updating AI scanner settings")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
