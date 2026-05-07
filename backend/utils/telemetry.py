"""OpenTelemetry tracing setup.

Off by default — enabled when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set in
the environment. We deliberately do not require OTel as a hard dep; the
imports are lazy and any setup error logs a warning rather than crashing
the app.

What gets traced:
  • Every FastAPI request (via FastAPIInstrumentor).
  • Every scanner run (via the ``scanner_span`` context manager — see
    server.run_scanner_with_tracking).
  • Every LLM call (via ``llm_span``).
  • Every triage / autofix / scan-pipeline phase.

Why not Prometheus too: starts free, but adds another sidecar. OTel can
publish to Tempo/Jaeger or be tee'd to Prometheus by the collector, so
one instrumentation library covers both.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger(__name__)

_TRACER: Any | None = None
_INITIALISED = False


def init_telemetry(app=None, *, service_name: str = "fortknoxx-backend") -> None:
    """Idempotent setup. Safe to call multiple times."""
    global _TRACER, _INITIALISED
    if _INITIALISED:
        return
    _INITIALISED = True

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        logger.info("OTel disabled (set OTEL_EXPORTER_OTLP_ENDPOINT to enable).")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        logger.warning("OTel libs not installed (%s); tracing disabled.", exc)
        return

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    _TRACER = trace.get_tracer(service_name)

    if app is not None:
        try:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

            FastAPIInstrumentor.instrument_app(app)
        except ImportError as exc:
            logger.warning("FastAPI instrumentation unavailable: %s", exc)

    logger.info("OTel tracing enabled → %s", endpoint)


@contextmanager
def span(name: str, **attributes):
    """Convenience context manager. No-op when OTel is not initialised."""
    if _TRACER is None:
        yield None
        return
    with _TRACER.start_as_current_span(name) as s:
        for k, v in attributes.items():
            try:
                s.set_attribute(k, v)
            except Exception:  # pragma: no cover - attribute coercion errors
                pass
        yield s


@contextmanager
def scanner_span(scanner_name: str, repo_id: str | None = None):
    with span("scanner.run", scanner=scanner_name, repo_id=repo_id or "") as s:
        yield s


@contextmanager
def llm_span(provider: str, model: str | None = None, kind: str = "completion"):
    with span("llm.call", provider=provider, model=model or "", kind=kind) as s:
        yield s
