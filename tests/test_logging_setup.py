"""Structured logging: format, level, and secret redaction (#330).

The redaction cases run against ``api.logging_setup`` **and**
``agent.logging_setup``: the agent package ships without ``api`` (see
``agent/logging_setup.py``), so the two copies exist on purpose and this is
what keeps them from drifting apart.
"""

from __future__ import annotations

import json
import logging

import pytest

from agent import logging_setup as agent_logging
from api import logging_setup as api_logging

REDACTORS = pytest.mark.parametrize(
    "module", [api_logging, agent_logging], ids=["api", "agent"]
)


def _record(module, msg: str, *args: object) -> logging.LogRecord:
    """A record pushed through the module's redaction filter, rendered."""
    record = logging.LogRecord("t", logging.INFO, __file__, 1, msg, args or None, None)
    assert module.SecretRedactingFilter().filter(record) is True
    return record


# --- Redaction masks -------------------------------------------------------


@REDACTORS
def test_redacts_keyed_password(module):
    record = _record(module, "connecting with password=hunter2 to db")
    assert "hunter2" not in record.getMessage()
    assert "password=***" in record.getMessage()


@REDACTORS
def test_redacts_keyed_token_and_secret(module):
    rendered = _record(module, 'token=abc123&secret: "s3kr3t" api_key=zzz').getMessage()
    assert "abc123" not in rendered
    assert "s3kr3t" not in rendered
    assert "zzz" not in rendered


@REDACTORS
def test_redacts_authorization_bearer(module):
    rendered = _record(module, "Authorization: Bearer abcDEF-123.456").getMessage()
    assert "abcDEF-123.456" not in rendered
    assert "***" in rendered


@REDACTORS
def test_redacts_password_in_url(module):
    rendered = _record(
        module, "postgresql://octo:sup3rs3cret@db.internal:5432/octo unreachable"
    ).getMessage()
    assert "sup3rs3cret" not in rendered
    # The user survives: it is what identifies which URL was wrong.
    assert "postgresql://octo:***@db.internal:5432/octo" in rendered


@REDACTORS
def test_redacts_jwt(module):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl"
    rendered = _record(module, "agent token %s expired", jwt).getMessage()
    assert "c2lnbmF0dXJl" not in rendered
    assert "eyJ***" in rendered


@REDACTORS
def test_redacts_percent_style_arguments(module):
    """The secret arrives as a ``%s`` argument, not in the format string.

    This is the case a formatter-based redaction cannot reach at all, and the
    way every call site in this repository actually logs.
    """
    record = _record(module, "claim failed for %s: %s", "agent-1", "token=abc123")
    assert "abc123" not in record.getMessage()
    assert record.args == ()


@REDACTORS
def test_leaves_ordinary_text_alone(module):
    """"token is invalid" is a message, not a secret.

    The separator is required by the mask precisely so that a sentence
    mentioning one of the keywords survives; without that the redaction eats
    the only line that says what went wrong.
    """
    rendered = _record(module, "the token is invalid, no secret here").getMessage()
    assert rendered == "the token is invalid, no secret here"


# --- Format and level ------------------------------------------------------


def test_json_formatter_emits_the_documented_fields():
    record = logging.LogRecord("octo.test", logging.WARNING, __file__, 1, "hello", None, None)
    record.request_id = "abc123"
    payload = json.loads(api_logging.JsonFormatter().format(record))
    assert set(payload) == {"ts", "level", "logger", "msg", "request_id"}
    assert payload["level"] == "WARNING"
    assert payload["logger"] == "octo.test"
    assert payload["msg"] == "hello"
    assert payload["request_id"] == "abc123"
    assert payload["ts"].endswith("Z")


def test_json_formatter_redacts_the_traceback():
    try:
        raise RuntimeError("connect to postgresql://octo:sup3rs3cret@db/octo failed")
    except RuntimeError:
        import sys

        record = logging.LogRecord(
            "octo.test", logging.ERROR, __file__, 1, "boom", None, sys.exc_info()
        )
    payload = json.loads(api_logging.JsonFormatter().format(record))
    assert "sup3rs3cret" not in payload["exc"]


def test_request_id_filter_defaults_to_empty_outside_a_request():
    record = logging.LogRecord("octo.test", logging.INFO, __file__, 1, "x", None, None)
    assert api_logging.RequestIdFilter().filter(record) is True
    # Empty rather than absent: TEXT_FORMAT names the field, and a background
    # worker's line must not raise a formatting error.
    assert record.request_id == ""


@pytest.mark.parametrize(
    "module", [api_logging, agent_logging], ids=["api", "agent"]
)
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", "text"),
        ("json", "json"),
        ("JSON", "json"),
        ("yaml", "text"),
    ],
)
def test_resolve_log_format(module, raw, expected):
    assert module.resolve_log_format(raw) == expected


@pytest.mark.parametrize(
    "module", [api_logging, agent_logging], ids=["api", "agent"]
)
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", logging.INFO),
        ("debug", logging.DEBUG),
        ("WARNING", logging.WARNING),
        ("chatty", logging.INFO),
    ],
)
def test_resolve_log_level(module, raw, expected):
    assert module.resolve_log_level(raw) == expected


@pytest.mark.parametrize(
    "module", [api_logging, agent_logging], ids=["api", "agent"]
)
def test_configure_logging_is_idempotent(module, monkeypatch, capsys):
    """Two calls leave one handler, not two — a reload must not double lines."""
    monkeypatch.setenv("OCTO_LOG_FORMAT", "json")
    monkeypatch.setenv("OCTO_LOG_LEVEL", "DEBUG")
    root = logging.getLogger()
    saved = list(root.handlers), root.level
    try:
        assert module.configure_logging() == ("json", logging.DEBUG)
        module.configure_logging()
        assert len(root.handlers) == 1
        logging.getLogger("octo.test").debug("db url %s", "postgresql://u:p@h/d")
        line = capsys.readouterr().out.strip()
        payload = json.loads(line)
        assert payload["level"] == "DEBUG"
        assert "postgresql://u:***@h/d" in payload["msg"]
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved[0]:
            root.addHandler(handler)
        root.setLevel(saved[1])


def test_uvicorn_log_config_routes_access_through_the_same_handler():
    config = api_logging.uvicorn_log_config(log_format="json", level=logging.INFO)
    assert config["formatters"]["octo"] == {"()": "api.logging_setup.JsonFormatter"}
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        assert config["loggers"][name]["handlers"] == ["octo"]
        # propagate=False, or every uvicorn line is emitted twice: once by its
        # own handler and once by root's.
        assert config["loggers"][name]["propagate"] is False
    assert config["handlers"]["octo"]["filters"] == ["request_id", "redact"]
    assert config["disable_existing_loggers"] is False


def test_uvicorn_access_line_is_redacted_by_the_shared_filter():
    """The access log's secret is in the request line, i.e. in ``record.args``."""
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1", "GET", "/api/runs?token=abc123", "1.1", 200),
        None,
    )
    api_logging.SecretRedactingFilter().filter(record)
    assert "abc123" not in record.getMessage()
