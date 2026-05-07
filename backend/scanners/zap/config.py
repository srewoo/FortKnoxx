"""Typed configuration for ZAP DAST scans.

These dataclasses are the single source of truth that the Settings UI
binds to, the API accepts as JSON, and the Automation Framework YAML
generator consumes. Keep them flat and JSON-serialisable — no
behaviour, no I/O.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SpiderConfig:
    """Crawl controls. Exposed in Settings UI."""

    # Traditional spider (link/form discovery).
    max_depth: int = 5
    max_children: int = 0           # 0 = unlimited per parent
    max_duration_minutes: int = 5
    request_wait_ms: int = 200
    threads: int = 2
    user_agent: str = ""

    # Scope controls — regexes evaluated against the full URL.
    scope_includes: list[str] = field(default_factory=list)
    scope_excludes: list[str] = field(default_factory=list)

    # AJAX spider (Selenium-driven; used to crawl SPAs).
    enable_ajax_spider: bool = False
    ajax_browser: str = "firefox-headless"
    ajax_max_duration_minutes: int = 5
    ajax_max_crawl_depth: int = 10


@dataclass
class FormAuthConfig:
    """Form-based login (the most common web auth flow)."""

    login_url: str
    login_request_body: str         # e.g. "username={%username%}&password={%password%}"
    username: str
    password: str
    logged_in_indicator_regex: str | None = None
    logged_out_indicator_regex: str | None = None


@dataclass
class JwtAuthConfig:
    """Static-token auth — JWT bearer header injected on every request."""

    token: str
    header: str = "Authorization"
    scheme: str = "Bearer"


@dataclass
class OAuthClientCredentialsConfig:
    """OAuth 2.0 client_credentials grant (machine-to-machine).

    The ZAP Automation script will request a token at scan-start and
    refresh it on 401s. We keep the secret in the in-memory dataclass
    only — never written into the AF YAML on disk.
    """

    token_endpoint: str
    client_id: str
    client_secret: str
    scope: str = ""


@dataclass
class AuthConfig:
    """Wrapper — exactly one of the three may be set."""

    form: FormAuthConfig | None = None
    jwt: JwtAuthConfig | None = None
    oauth_client_credentials: OAuthClientCredentialsConfig | None = None

    @property
    def is_set(self) -> bool:
        return any((self.form, self.jwt, self.oauth_client_credentials))


@dataclass
class OpenApiConfig:
    """Spec source for API scans.

    auto_discover: if True and neither ``spec_path`` nor ``spec_url`` is
    set, the runner probes ``/openapi.json``, ``/swagger.json``,
    ``/v3/api-docs``, ``/api-docs``, and ``/swagger.yaml`` on the
    target before scanning.
    """

    spec_path: str | None = None
    spec_url: str | None = None
    auto_discover: bool = True


@dataclass
class ZapScanConfig:
    """Top-level ZAP DAST scan request."""

    target_url: str
    scan_type: str = "baseline"      # baseline | full | api | combined

    spider: SpiderConfig = field(default_factory=SpiderConfig)
    auth: AuthConfig | None = None
    openapi: OpenApiConfig = field(default_factory=OpenApiConfig)

    # Persisted ZAP session directory. When set, baseline + active scans
    # share the same crawl + auth state — halves runtime for combined
    # scans because the spider doesn't re-discover URLs.
    session_dir: str | None = None

    timeout_seconds: int = 600
