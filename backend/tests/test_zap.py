"""Unit tests for the ZAP DAST module — locks in AF YAML shape, auth
contexts, OpenAPI auto-discovery, SPA detection, and triage dedup
across DAST scanners."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from engines.triage import build_fingerprint
from scanners.zap import (
    AuthConfig,
    FormAuthConfig,
    JwtAuthConfig,
    OAuthClientCredentialsConfig,
    OpenApiConfig,
    SpiderConfig,
    ZapScanConfig,
)
from scanners.zap.automation import build_automation_plan, render_yaml


# --------------------------------------------------------------------------- AF YAML shape


def _baseline_config(**overrides) -> ZapScanConfig:
    overrides.setdefault("scan_type", "baseline")
    return ZapScanConfig(target_url="http://app.local", **overrides)


def test_plan_baseline_emits_passive_only():
    plan = build_automation_plan(_baseline_config())
    job_types = [j["type"] for j in plan["jobs"]]
    assert "spider" in job_types
    assert "activeScan" not in job_types
    assert "report" == job_types[-1]


def test_plan_full_includes_active_scan():
    plan = build_automation_plan(_baseline_config(scan_type="full"))
    assert "activeScan" in [j["type"] for j in plan["jobs"]]


def test_plan_ajax_spider_added_when_spa_detected():
    plan = build_automation_plan(_baseline_config(), spa_detected=True)
    assert "spiderAjax" in [j["type"] for j in plan["jobs"]]


def test_plan_ajax_spider_added_when_explicitly_enabled():
    spider = SpiderConfig(enable_ajax_spider=True)
    plan = build_automation_plan(_baseline_config(spider=spider))
    assert "spiderAjax" in [j["type"] for j in plan["jobs"]]


def test_plan_openapi_job_when_spec_url_provided():
    cfg = _baseline_config(scan_type="api", openapi=OpenApiConfig(spec_url="http://app/openapi.json"))
    plan = build_automation_plan(cfg)
    types = [j["type"] for j in plan["jobs"]]
    assert "openapi" in types
    # openapi runs before spider so spec-derived URLs seed the context.
    assert types.index("openapi") < types.index("activeScan")


def test_plan_openapi_uses_resolved_url_when_auto_discovered():
    cfg = _baseline_config(scan_type="api", openapi=OpenApiConfig())  # no spec set
    plan = build_automation_plan(cfg, resolved_openapi_url="http://app/v3/api-docs")
    openapi = next(j for j in plan["jobs"] if j["type"] == "openapi")
    assert openapi["parameters"]["apiUrl"] == "http://app/v3/api-docs"


def test_plan_session_dir_persists_state():
    cfg = _baseline_config(session_dir="/var/zap/sessions")
    plan = build_automation_plan(cfg)
    assert plan["env"]["parameters"].get("session", "").endswith(".session")


def test_plan_scope_controls_make_it_into_context():
    spider = SpiderConfig(scope_includes=["http://app/api/.*"], scope_excludes=[".*/logout"])
    plan = build_automation_plan(_baseline_config(spider=spider))
    ctx = plan["env"]["contexts"][0]
    assert "http://app/api/.*" in ctx["includePaths"]
    assert ".*/logout" in ctx["excludePaths"]


def test_plan_spider_depth_threads_and_duration_passed_through():
    spider = SpiderConfig(max_depth=11, threads=8, max_duration_minutes=15)
    plan = build_automation_plan(_baseline_config(spider=spider))
    spider_job = next(j for j in plan["jobs"] if j["type"] == "spider")
    p = spider_job["parameters"]
    assert p["maxDepth"] == 11
    assert p["threadCount"] == 8
    assert p["maxDuration"] == 15


# --------------------------------------------------------------------------- auth blocks


def test_form_auth_emits_form_method():
    auth = AuthConfig(form=FormAuthConfig(
        login_url="http://app/login",
        login_request_body="user={%username%}&pass={%password%}",
        username="alice", password="secret",
        logged_in_indicator_regex="welcome",
    ))
    plan = build_automation_plan(_baseline_config(auth=auth))
    ctx = plan["env"]["contexts"][0]
    assert ctx["authentication"]["method"] == "form"
    assert ctx["users"][0]["credentials"]["username"] == "alice"
    assert ctx["authentication"]["verification"]["loggedInRegex"] == "welcome"


def test_jwt_auth_emits_script_method_with_header_credentials():
    auth = AuthConfig(jwt=JwtAuthConfig(token="abc.def.ghi", header="X-Auth"))
    plan = build_automation_plan(_baseline_config(auth=auth))
    ctx = plan["env"]["contexts"][0]
    assert ctx["authentication"]["method"] == "script"
    creds = ctx["users"][0]["credentials"]
    assert creds["header"] == "X-Auth"
    assert creds["value"].endswith("abc.def.ghi")


def test_oauth_cc_emits_script_with_token_endpoint():
    auth = AuthConfig(oauth_client_credentials=OAuthClientCredentialsConfig(
        token_endpoint="http://idp/oauth/token",
        client_id="cid", client_secret="cs", scope="api:read",
    ))
    plan = build_automation_plan(_baseline_config(auth=auth))
    ctx = plan["env"]["contexts"][0]
    assert ctx["authentication"]["method"] == "script"
    creds = ctx["users"][0]["credentials"]
    assert creds["tokenEndpoint"] == "http://idp/oauth/token"
    assert creds["clientId"] == "cid"


# --------------------------------------------------------------------------- yaml emitter


def test_render_yaml_round_trips_through_pyyaml():
    plan = build_automation_plan(_baseline_config(scan_type="full"))
    rendered = render_yaml(plan)
    assert "jobs:" in rendered
    assert "type: spider" in rendered
    assert "type: activeScan" in rendered
    assert "fortknoxx" in rendered


# --------------------------------------------------------------------------- triage dedup


def test_zap_and_nuclei_findings_on_same_endpoint_share_fingerprint():
    """ZAP reports a full URL, Nuclei reports a path. Both should
    fingerprint to the same value once the path normaliser kicks in."""
    zap = {
        "file_path": "/api/users/123",
        "url": "http://app.local/api/users/123",
        "cwe": "CWE-89",
        "code": "id=123",
        "detected_by": "zap_dast",
        "line_start": 1,
    }
    nuclei = {
        "file_path": "/api/users/9999",  # numeric segment differs
        "cwe": "CWE-89",
        "code": "id=9999",
        "detected_by": "nuclei",
        "line_start": 1,
    }
    schemathesis = {
        "file_path": "http://app.local/api/users/{id}",  # parameterised form
        "cwe": "CWE-89",
        "code": "id={id}",
        "detected_by": "schemathesis",
        "line_start": 1,
    }
    fps = {build_fingerprint(f) for f in (zap, nuclei, schemathesis)}
    assert len(fps) == 1, f"expected one fingerprint across DAST scanners, got {fps}"


def test_zap_url_normalisation_strips_protocol_and_host():
    a = {"file_path": "http://app/api/orders", "cwe": "CWE-79", "code": "x", "line_start": 1}
    b = {"file_path": "/api/orders",          "cwe": "CWE-79", "code": "x", "line_start": 1}
    assert build_fingerprint(a) == build_fingerprint(b)


def test_zap_url_normalisation_collapses_uuid_segments():
    a = {"file_path": "/api/orders/123e4567-e89b-12d3-a456-426614174000", "cwe": "CWE-89", "code": "q", "line_start": 1}
    b = {"file_path": "/api/orders/00000000-0000-0000-0000-000000000000", "cwe": "CWE-89", "code": "q", "line_start": 1}
    assert build_fingerprint(a) == build_fingerprint(b)


def test_zap_url_normalisation_drops_query_string():
    a = {"file_path": "/api/users?id=42", "cwe": "CWE-89", "code": "q", "line_start": 1}
    b = {"file_path": "/api/users",       "cwe": "CWE-89", "code": "q", "line_start": 1}
    assert build_fingerprint(a) == build_fingerprint(b)


# --------------------------------------------------------------------------- openapi auto-discovery


def test_discover_openapi_returns_first_hit(monkeypatch):
    from scanners.zap import openapi_discovery as od

    class FakeResp:
        def __init__(self, status, body, ct="application/json"):
            self.status_code = status
            self.text = body
            self.headers = {"content-type": ct}
            self.url = "http://app/openapi.json"

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, **k):
            if url.endswith("/openapi.json"):
                return FakeResp(200, '{"openapi":"3.0.0","paths":{}}')
            return FakeResp(404, "")

    monkeypatch.setattr(od.httpx, "AsyncClient", FakeClient)
    result = asyncio.run(od.discover_openapi_spec_url("http://app"))
    assert result and result.endswith("/openapi.json")


def test_discover_openapi_returns_none_when_no_match(monkeypatch):
    from scanners.zap import openapi_discovery as od

    class FakeResp:
        status_code = 404
        text = ""
        headers = {"content-type": "text/plain"}
        url = "http://app"

    class FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def get(self, url, **k): return FakeResp()

    monkeypatch.setattr(od.httpx, "AsyncClient", FakeClient)
    assert asyncio.run(od.discover_openapi_spec_url("http://app")) is None
