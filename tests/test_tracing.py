"""OpenTelemetry is off unless an exporter is configured (ROADMAP P3)."""

from __future__ import annotations

from pathlib import Path

from api.services import tracing
from tests.conftest import make_settings


def test_configure_is_noop_without_endpoint(tmp_path: Path):
    class _App:
        pass

    settings = make_settings(tmp_path)
    assert settings.otel_exporter_otlp_endpoint == ""
    assert tracing.configure(_App(), settings) is False
    tracing.shutdown()


def test_configure_with_injected_exporter_starts_provider(tmp_path: Path):
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    class _App:
        def add_middleware(self, *args, **kwargs):
            return None

    settings = make_settings(tmp_path)
    exporter = InMemorySpanExporter()
    try:
        assert tracing.configure(_App(), settings, exporter=exporter) is True
    finally:
        tracing.shutdown()
