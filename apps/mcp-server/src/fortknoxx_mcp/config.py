"""Runtime configuration loaded from env at startup."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_base: str
    pat: str
    request_timeout_s: float
    log_level: str


def load_settings() -> Settings:
    api_base = os.environ.get("FORTKNOXX_API_BASE", "http://localhost:8000")
    pat = os.environ.get("FORTKNOXX_PAT", "")
    if not pat:
        # We don't fail hard here — the server still starts so the IDE
        # can introspect the tool list. Tool *invocation* will fail
        # with a clear "PAT required" error.
        pass

    return Settings(
        api_base=api_base.rstrip("/"),
        pat=pat,
        request_timeout_s=float(os.environ.get("FORTKNOXX_TIMEOUT", "30")),
        log_level=os.environ.get("FORTKNOXX_LOG_LEVEL", "INFO"),
    )
