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
from opentelemetry.trace import SpanKind

from api import logging_setup
from api.middleware import install_request_id_middleware
from api.request_context import (
    MAX_REQUEST_ID_LENGTH,
    current_request_id,
    sanitize_request_id,
)
from tests.conftest import configured_client, requires_postgres


def _probe_app() -> FastAPI:
    """A one-route app, wired the way ``create_app`` wires the real one.

    ``install_request_id_middleware`` rather than ``add_middleware``: the
    difference between the two is the whole point of the layer (it has to sit
    outside ``ServerErrorMiddleware``), so a probe app that used the other one
    would be testing a stack the API does not have.
    """
    app = FastAPI()

    @app.get("/probe")
    def probe() -> dict[str, str]:
        logging.getLogger("shapoclyack.request-id-probe").warning("probe")
        return {"request_id": current_request_id()}

    @app.get("/boom")
    def boom() -> dict[str, str]:
        raise RuntimeError("probe blew up")

    install_request_id_middleware(app)
    return app


def _probe_client() -> TestClient:
    """A client over :func:`_probe_app`, echoing the bound id."""
    return TestClient(_probe_app())


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


def test_the_next_request_does_not_inherit_the_previous_id():
    """The contextvar is reset, so the next request cannot inherit the last id.

    Asserted from *inside* the route (the probe returns the bound id in its
    body) rather than from the test function: ``TestClient`` runs the app in
    its own thread with its own context, so ``current_request_id()`` here is
    ``""`` whether the middleware resets anything or not, and a test that
    checked it would pass over a middleware that leaked every id.
    """
    client = _probe_client()
    first = client.get("/probe", headers={"X-Request-Id": "corr-12345"})
    assert first.json()["request_id"] == "corr-12345"

    second = client.get("/probe")
    minted = second.json()["request_id"]
    assert minted != "corr-12345"
    assert minted == second.headers["X-Request-Id"]


def test_an_unhandled_exception_still_answers_with_the_id():
    """The 500 is the response that most needs the id, and used to lack it.

    ``ServerErrorMiddleware`` turns an unhandled exception into a 500 from
    *outside* everything ``add_middleware`` installs, so with the layer added
    that way the error response went out through uvicorn's own send — no
    ``X-Request-Id`` — while docs/api-and-rbac.md promised every response
    carries one.
    """
    response = _probe_client().get("/boom", headers={"X-Request-Id": "corr-boom"})
    assert response.status_code == 500
    assert response.headers["X-Request-Id"] == "corr-boom"


def test_the_unhandled_exception_is_logged_under_the_request_id():
    """And the record about that 500 is findable by the id it answered with.

    Logged by the middleware rather than left to uvicorn's "Exception in ASGI
    application": that one is emitted a frame above this contextvar, i.e. after
    it has been reset, so it carried ``request_id=""``.
    """
    seen: list[tuple[str, str]] = []

    class _Probe(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            logging_setup.RequestIdFilter().filter(record)
            seen.append((record.request_id, record.getMessage()))
            return True

    logger = logging.getLogger("shapoclyack.api")
    probe = _Probe()
    logger.addFilter(probe)
    try:
        _probe_client().get("/boom", headers={"X-Request-Id": "corr-boom"})
    finally:
        logger.removeFilter(probe)

    assert [request_id for request_id, _ in seen] == ["corr-boom"]
    assert "unhandled exception serving GET /boom" in seen[0][1]


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


@requires_postgres
def test_the_header_is_exposed_to_a_cross_origin_console(tmp_path: Path, monkeypatch):
    """A browser hides every response header the server does not name.

    So docs/operations.md telling an operator to grep for "the id the console
    reported" needed the console to be able to read it in the first place, and
    a console on another origin could not (#330).
    """
    client = configured_client(tmp_path, monkeypatch)
    response = client.get("/livez", headers={"Origin": "http://localhost:3000"})
    assert response.status_code == 200
    exposed = response.headers["access-control-expose-headers"]
    assert "X-Request-Id" in exposed


def test_request_id_lands_on_the_instrumented_server_span(tmp_path: Path):
    """The claim documentation makes about `shapoclyack.request_id` (#330).

    Over the real instrumentation, not over ``_annotate_span`` called by hand:
    the attribute is set from the ``http.response.start`` hook because the
    server span is created *inside* this middleware, and only a span that
    ``FastAPIInstrumentor`` actually made can show that the hook still runs
    inside it.
    """
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    from api.services import tracing as tracing_service
    from tests.conftest import make_settings

    exporter = InMemorySpanExporter()
    app = FastAPI()

    @app.get("/probe")
    def probe() -> dict[str, str]:
        return {"request_id": current_request_id()}

    # The order `create_app` uses: instrumentation first (it adds its own
    # middleware), the request-id wrap last.
    assert tracing_service.configure(app, make_settings(tmp_path), exporter=exporter) is True
    install_request_id_middleware(app)
    try:
        response = TestClient(app).get("/probe", headers={"X-Request-Id": "corr-span"})
        assert response.status_code == 200
    finally:
        tracing_service.shutdown()

    server_spans = [
        span for span in exporter.get_finished_spans() if span.kind is SpanKind.SERVER
    ]
    assert server_spans, "FastAPIInstrumentor produced no server span"
    assert server_spans[0].attributes["shapoclyack.request_id"] == "corr-span"


def test_annotating_a_span_is_a_no_op_with_tracing_off():
    """The API is allowed to run without an exporter; the hook must not raise."""
    from opentelemetry import trace

    from api.middleware import _annotate_span

    assert trace.get_current_span().is_recording() is False
    _annotate_span("corr-12345")
