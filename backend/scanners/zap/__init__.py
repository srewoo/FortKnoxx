"""ZAP DAST scanner package.

Public surface kept thin so the rest of the system imports
``ZAPDastScanner`` and the config dataclasses without caring how the
Automation Framework YAML is built.
"""

from .config import (
    AuthConfig,
    FormAuthConfig,
    JwtAuthConfig,
    OAuthClientCredentialsConfig,
    OpenApiConfig,
    SpiderConfig,
    ZapScanConfig,
)
from .openapi_discovery import discover_openapi_spec_url

__all__ = [
    "AuthConfig",
    "FormAuthConfig",
    "JwtAuthConfig",
    "OAuthClientCredentialsConfig",
    "OpenApiConfig",
    "SpiderConfig",
    "ZapScanConfig",
    "discover_openapi_spec_url",
]
