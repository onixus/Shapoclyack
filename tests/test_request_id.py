"""``X-Request-Id`` in, out, and into every log line the request produces (#330).

Most of these run over a bare FastAPI app wrapped in the middleware itself:
the behaviour under test is the middleware's, and gating it on a reachable
Postgres (which ``create_app`` needs for the tenant store) would mean the
redaction and echo contract is only ever checked in CI. One test at the bottom
does go through ``create_app``, because "is it actually mounted, and outermost"
is a different claim from "does it work".
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import logging_setup
from api.middleware import RequestIdMiddleware
from api.request_context import (
    MAX_REQUEST_ID_LENGTH,
    current_request_id,
    sanitize_request_id,
)
from tests.conftest import configured_client, requires_postgres


def _probe_client() -> TestClient:
    """A one-route app behind the middleware, echoing the bound id."""
    app = FastAPI()

    @app.get("/probe")
    def probe() -> dict[str, str]:
        logging.getLogger("shapoclyack.request-id-probe").warning("probe")
        return {"request_id": current_request_id()}

    app.add_middleware(RequestIdMiddleware)
    return TestClient(app)


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("7f3c9a2b4d", "7f3c9a2b4d"),
        ("  padded-id  ", "padded-id"),
        ("00-4bf92f7f8ae-00f067aa0ba9-01", "00-4bf92f7f8ae-00f067aa0ba9-01"),  # traceparent
        (None, None),
        ("", None),
        ("x" * (MAX_REQUEST_ID_LENGTH + 1), None),
        ("has space", None),
        ("nl\r\ninjected", None),  # header splitting / log-line forgery
        ("quote\"and'brace{", None),
    ],
)
def test_sanitize_request_id(supplied, expected):
    assert sanitize_request_id(supplied) == expected


def test_current_request_id_is_empty_outside_a_request():
    assert current_request_id() == ""


def test_supplied_request_id_is_bound_and_echoed_back():
    response = _probe_client().get("/probe", headers={"X-Request-Id": "corr-12345"})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "corr-12345"
    assert response.json()["request_id"] == "corr-12345"


def test_request_without_an_id_gets_one():
    client = _probe_client()
    response = client.get("/probe")
    minted = response.headers["X-Request-Id"]
    assert sanitize_request_id(minted) == minted
    assert response.json()["request_id"] == minted
    # A second request is a second correlation, not the same one.
    assert client.get("/probe").headers["X-Request-Id"] != minted


def test_unsafe_supplied_id_is_replaced_not_echoed():
    """An id we had to reject must not reach the response header at all.

    ``\\r\\n`` in an echoed header is response splitting, and the reason the id
    is replaced rather than escaped is that then nothing downstream has to be
    trusted to escape it. httpx refuses to *send* a raw CRLF header, so the
    case exercised here is the other rejected shape — the assertion that
    matters is that the echoed value is one we minted.
    """
    response = _probe_client().get("/probe", headers={"X-Request-Id": "bad id with spaces"})
    assert response.headers["X-Request-Id"] != "bad id with spaces"
    assert sanitize_request_id(response.headers["X-Request-Id"])


def test_id_leaves_the_context_after_the_response():
    """The contextvar is reset, so the next request cannot inherit the last id."""
    _probe_client().get("/probe", headers={"X-Request-Id": "corr-12345"})
    assert current_request_id() == ""


def test_request_id_reaches_the_log_record():
    seen: list[str] = []

    class _Probe(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            logging_setup.RequestIdFilter().filter(record)
            seen.append(record.request_id)
            return True

    logger = logging.getLogger("shapoclyack.request-id-probe")
    probe = _Probe()
    logger.addFilter(probe)
    try:
        _probe_client().get("/probe", headers={"X-Request-Id": "probe-1"})
    finally:
        logger.removeFilter(probe)

    assert seen == ["probe-1"]


@requires_postgres
def test_the_api_app_carries_the_middleware(tmp_path: Path, monkeypatch):
    """Mounted in ``create_app``, and outermost enough to reach ``/livez``.

    ``/livez`` is deliberately dependency-free, so a response header on it is
    evidence about the middleware stack and nothing else.
    """
    client = configured_client(tmp_path, monkeypatch)
    response = client.get("/livez", headers={"X-Request-Id": "corr-12345"})
    assert response.status_code == 200
    assert response.headers["X-Request-Id"] == "corr-12345"


def test_request_id_lands_on_the_active_span():
    """The claim documentation makes about `shapoclyack.request_id` (#330).

    Exercised against a real (in-memory) provider rather than a mock: the
    attribute is only useful if it survives the span being exported.
    """
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from api.middleware import _annotate_span

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    try:
        with provider.get_tracer("test").start_as_current_span("GET /probe"):
            _annotate_span("corr-12345")
    finally:
        provider.shutdown()

    (span,) = exporter.get_finished_spans()
    assert span.attributes["shapoclyack.request_id"] == "corr-12345"
    # And outside a span it is a no-op, not an error: the API is allowed to run
    # with tracing off.
    assert trace.get_current_span().is_recording() is False
    _annotate_span("corr-12345")
