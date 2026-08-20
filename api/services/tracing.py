"""OpenTelemetry tracing for the API (ROADMAP P3 leftover).

Off unless ``OCTO_OTEL_EXPORTER_OTLP_ENDPOINT`` is set. An empty endpoint
must not start a TracerProvider that buffers spans nobody will read.

This is request tracing, not a scan fact: a span around ``GET /api/runs``
does not mean the scanner observed anything. Scanner wall-clock stays in
``stage_timings.json``.
"""

from __future__ import annotations

import logging
from typing import Any

from api.settings import Settings

LOG = logging.getLogger("shapoclyack.tracing")

_provider: Any = None


def configure(app: Any, settings: Settings, *, exporter: Any | None = None) -> bool:
    """Instrument FastAPI. Returns True when a provider was started."""
    global _provider
    endpoint = (settings.otel_exporter_otlp_endpoint or "").strip()
    if not endpoint and exporter is None:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor
    except ImportError:
        LOG.warning("OpenTelemetry packages missing; tracing not started")
        return False

    resource = Resource.create(
        {
            "service.name": settings.otel_service_name,
            "service.instance.id": settings.instance_id,
        }
    )
    provider = TracerProvider(resource=resource)
    if exporter is None:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter(endpoint=endpoint)
        provider.add_span_processor(BatchSpanProcessor(exporter))
    else:
        provider.add_span_processor(SimpleSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(
        app,
        excluded_urls="health,/metrics,/api/health",
    )
    _provider = provider
    LOG.info(
        "OpenTelemetry tracing on (service=%s exporter=%s)",
        settings.otel_service_name,
        "otlp" if endpoint else "injected",
    )
    return True


def shutdown() -> None:
    global _provider
    if _provider is not None:
        _provider.shutdown()
        _provider = None
