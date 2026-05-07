"""ZAP Automation Framework YAML generator.

Why AF YAML and not the legacy ``zap-baseline.py`` / ``zap-full-scan.py``
shell wrappers:

  • One file, version-controllable per project (commit alongside code).
  • Native support for contexts (auth + scope) — the wrappers can't
    express form login or JWT injection without juggling extra args.
  • Native AJAX spider job — required for SPA crawl, missing from the
    baseline wrapper entirely.
  • Native OpenAPI job — pulls the spec by URL with one line.
  • Sessions persist between jobs in one run, so passive→spider→active
    don't re-discover the same URLs.

The plan emitted here is a single ``automation`` block with these jobs
in order:

  passiveScan-config → context-setup → openapi (optional) → spider →
  spiderAjax (optional) → activeScan → passiveScan-wait → report

Tests under ``tests/test_zap_automation.py`` lock in the YAML shape so
ZAP version bumps don't silently break it.
"""

from __future__ import annotations

import logging
from typing import Any

from .config import (
    AuthConfig,
    OpenApiConfig,
    SpiderConfig,
    ZapScanConfig,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- helpers


def _context_dict(target_url: str, auth: AuthConfig | None, spider: SpiderConfig) -> dict[str, Any]:
    """Build the AF ``contexts[0]`` block — scope + auth + users."""
    ctx: dict[str, Any] = {
        "name": "fortknoxx",
        "urls": [target_url],
        "includePaths": list(spider.scope_includes) or [f"{target_url}.*"],
        "excludePaths": list(spider.scope_excludes),
    }

    if not auth or not auth.is_set:
        return ctx

    if auth.form:
        ctx["authentication"] = {
            "method": "form",
            "parameters": {
                "loginPageUrl": auth.form.login_url,
                "loginRequestUrl": auth.form.login_url,
                "loginRequestBody": auth.form.login_request_body,
            },
            "verification": _verification_block(
                auth.form.logged_in_indicator_regex,
                auth.form.logged_out_indicator_regex,
            ),
        }
        ctx["users"] = [{
            "name": "primary",
            "credentials": {
                "username": auth.form.username,
                "password": auth.form.password,
            },
        }]
        return ctx

    if auth.jwt:
        # JWT is a "static" header; ZAP calls this script-based auth.
        # We use a built-in HTTP header script so the YAML stays portable.
        ctx["authentication"] = {
            "method": "script",
            "parameters": {
                "scriptName": "fortknoxx-jwt-header.js",
                "scriptEngine": "Oracle Nashorn",
            },
            "verification": _verification_block(None, None),
        }
        ctx["users"] = [{
            "name": "primary",
            "credentials": {
                "header": auth.jwt.header,
                "value": f"{auth.jwt.scheme} {auth.jwt.token}",
            },
        }]
        return ctx

    if auth.oauth_client_credentials:
        cc = auth.oauth_client_credentials
        ctx["authentication"] = {
            "method": "script",
            "parameters": {
                "scriptName": "fortknoxx-oauth-cc.js",
                "scriptEngine": "Oracle Nashorn",
            },
            "verification": _verification_block(None, None),
        }
        ctx["users"] = [{
            "name": "primary",
            "credentials": {
                "tokenEndpoint": cc.token_endpoint,
                "clientId": cc.client_id,
                "clientSecret": cc.client_secret,
                "scope": cc.scope,
            },
        }]
        return ctx

    return ctx


def _verification_block(logged_in_regex: str | None, logged_out_regex: str | None) -> dict:
    block = {"method": "poll", "pollFrequency": 60, "pollUnits": "requests"}
    if logged_in_regex:
        block["loggedInRegex"] = logged_in_regex
    if logged_out_regex:
        block["loggedOutRegex"] = logged_out_regex
    return block


def _spider_job(spider: SpiderConfig) -> dict[str, Any]:
    return {
        "type": "spider",
        "parameters": {
            "context": "fortknoxx",
            "user": "primary",
            "url": "",  # use context's urls
            "maxDuration": spider.max_duration_minutes,
            "maxDepth": spider.max_depth,
            "maxChildren": spider.max_children,
            "threadCount": spider.threads,
            "userAgent": spider.user_agent,
            "requestWaitTime": spider.request_wait_ms,
        },
    }


def _ajax_spider_job(spider: SpiderConfig) -> dict[str, Any]:
    return {
        "type": "spiderAjax",
        "parameters": {
            "context": "fortknoxx",
            "user": "primary",
            "browserId": spider.ajax_browser,
            "maxDuration": spider.ajax_max_duration_minutes,
            "maxCrawlDepth": spider.ajax_max_crawl_depth,
            "numberOfBrowsers": 1,
            "runOnlyIfModern": True,
        },
    }


def _openapi_job(openapi: OpenApiConfig, resolved_spec_url: str | None) -> dict[str, Any] | None:
    if openapi.spec_path:
        return {
            "type": "openapi",
            "parameters": {
                "apiFile": "/zap/wrk/openapi-spec",   # mounted into the container
                "context": "fortknoxx",
                "user": "primary",
            },
        }
    spec_url = openapi.spec_url or resolved_spec_url
    if spec_url:
        return {
            "type": "openapi",
            "parameters": {
                "apiUrl": spec_url,
                "context": "fortknoxx",
                "user": "primary",
            },
        }
    return None


def _active_scan_job() -> dict[str, Any]:
    return {
        "type": "activeScan",
        "parameters": {
            "context": "fortknoxx",
            "user": "primary",
            "policy": "Default Policy",
            "maxRuleDurationInMins": 5,
            "maxScanDurationInMins": 60,
        },
    }


def _passive_scan_config_job() -> dict[str, Any]:
    return {
        "type": "passiveScan-config",
        "parameters": {"maxAlertsPerRule": 10, "scanOnlyInScope": True},
    }


def _passive_scan_wait_job() -> dict[str, Any]:
    return {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}}


def _report_job(report_dir: str, name: str = "zap-report.json") -> dict[str, Any]:
    return {
        "type": "report",
        "parameters": {
            "template": "traditional-json-plus",
            "reportDir": report_dir,
            "reportFile": name,
        },
    }


# --------------------------------------------------------------------------- public


def build_automation_plan(
    config: ZapScanConfig,
    *,
    report_dir: str = "/zap/wrk",
    resolved_openapi_url: str | None = None,
    spa_detected: bool = False,
) -> dict[str, Any]:
    """Build the in-memory AF plan dict.

    The caller serialises it to YAML — kept as a pure function so tests
    can assert on the structure without parsing YAML.
    """
    jobs: list[dict] = [_passive_scan_config_job()]

    # OpenAPI runs *before* the spider so spec-derived URLs seed the
    # context, then the spider fans out from there.
    if (job := _openapi_job(config.openapi, resolved_openapi_url)):
        jobs.append(job)

    if config.scan_type in ("baseline", "full", "combined"):
        jobs.append(_spider_job(config.spider))
        if config.spider.enable_ajax_spider or spa_detected:
            jobs.append(_ajax_spider_job(config.spider))

    # Baseline = passive only; full/combined/api also actively probe.
    if config.scan_type in ("full", "combined", "api"):
        jobs.append(_active_scan_job())

    jobs.append(_passive_scan_wait_job())
    jobs.append(_report_job(report_dir))

    plan = {
        "env": {
            "contexts": [_context_dict(config.target_url, config.auth, config.spider)],
            "parameters": {
                "failOnError": False,
                "failOnWarning": False,
                "progressToStdout": True,
            },
        },
        "jobs": jobs,
    }

    if config.session_dir:
        # Persist + reuse session across runs. Halves runtime for
        # combined scans because the spider job picks up where it
        # left off.
        plan["env"]["parameters"]["session"] = "/zap/wrk/session/fortknoxx.session"

    return plan


def render_yaml(plan: dict[str, Any]) -> str:
    """Serialise the plan to YAML.

    Inlined to avoid a hard PyYAML dep in the scanner module — falls
    back to a hand-rolled emitter if PyYAML is missing. The dict shape
    we produce is small and predictable enough that the fallback is
    trustworthy.
    """
    try:
        import yaml
    except ImportError:
        return _hand_render(plan)
    return yaml.safe_dump(plan, sort_keys=False, default_flow_style=False)


def _hand_render(value: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(value, dict):
        out = []
        for k, v in value.items():
            if isinstance(v, (dict, list)):
                out.append(f"{pad}{k}:\n{_hand_render(v, indent + 1)}")
            else:
                out.append(f"{pad}{k}: {_scalar(v)}")
        return "\n".join(out)
    if isinstance(value, list):
        if not value:
            return f"{pad}[]"
        out = []
        for item in value:
            if isinstance(item, (dict, list)):
                rendered = _hand_render(item, indent + 1)
                # First key under "- " inline; rest indented.
                first_line, _, rest = rendered.partition("\n")
                out.append(f"{pad}- {first_line.lstrip()}")
                if rest:
                    out.append(rest)
            else:
                out.append(f"{pad}- {_scalar(item)}")
        return "\n".join(out)
    return f"{pad}{_scalar(value)}"


def _scalar(value: Any) -> str:
    if value is None:
        return '""'
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    if any(ch in s for ch in ":#\n") or s.strip() != s:
        return '"' + s.replace('"', '\\"') + '"'
    return s
