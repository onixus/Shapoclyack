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


def test_sampler_ratio_defaults_to_keeping_everything(tmp_path: Path):
    assert make_settings(tmp_path).otel_traces_sampler_ratio == 1.0


def test_sampler_ratio_is_clamped_and_parent_based(tmp_path: Path, monkeypatch):
    """A ratio outside 0..1 has an obvious meaning at either end (#330).

    Clamped rather than refused: taking the API down over a typo in an
    observability knob is a worse outcome than sampling everything.
    """
    from api.settings import load_settings

    monkeypatch.setenv("OCTO_ENV", "dev")
    monkeypatch.setenv("OCTO_OTEL_TRACES_SAMPLER_RATIO", "7")
    assert load_settings().otel_traces_sampler_ratio == 1.0
    monkeypatch.setenv("OCTO_OTEL_TRACES_SAMPLER_RATIO", "-0.5")
    assert load_settings().otel_traces_sampler_ratio == 0.0
    monkeypatch.setenv("OCTO_OTEL_TRACES_SAMPLER_RATIO", "not-a-number")
    assert load_settings().otel_traces_sampler_ratio == 1.0
    monkeypatch.setenv("OCTO_OTEL_TRACES_SAMPLER_RATIO", "0.25")
    assert load_settings().otel_traces_sampler_ratio == 0.25


def test_configured_provider_uses_the_ratio(tmp_path: Path):
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.trace.sampling import ParentBased

    class _App:
        def add_middleware(self, *args, **kwargs):
            return None

    settings = make_settings(tmp_path, otel_traces_sampler_ratio=0.25)
    try:
        assert tracing.configure(_App(), settings, exporter=InMemorySpanExporter()) is True
        sampler = tracing._provider.sampler
        assert isinstance(sampler, ParentBased)
        assert "0.25" in sampler.get_description()
    finally:
        tracing.shutdown()
