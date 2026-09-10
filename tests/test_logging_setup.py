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
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # The whole credential, scheme word included: `*** ***` is what the
        # keyed rule used to produce, having stopped at the first space.
        ("Authorization: Bearer abcDEF-123.456", "Authorization: ***"),
        # `Token` is the scheme api/services/tickets.py actually sends, and
        # `Basic` is what a proxy or a registry wants — neither is `Bearer`.
        ("Authorization: Token abcDEF-123.456", "Authorization: ***"),
        ("Authorization: Basic dXNlcjpwYXNz", "Authorization: ***"),
        # A header logged as a mapping, which is how a client library prints
        # the request it is about to make.
        ('{"Authorization": "Token abc123"}', '{"Authorization": "***"}'),
        ("{'Authorization': 'Bearer abc123'}", "{'Authorization': '***'}"),
        # And a sentence that happens to start with the word: one token
        # masked, not the rest of the line.
        ("authorization: required for this route", "authorization: *** for this route"),
    ],
)
def test_redacts_the_authorization_header_whole(module, line, expected):
    assert _record(module, line).getMessage() == expected


@REDACTORS
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # JSON: the key's closing quote sits between the name and the colon,
        # which is what the separator used to stop at.
        ('{"password": "hunter2"}', '{"password": "***"}'),
        ("{'api_key': 'zzz'}", "{'api_key': '***'}"),
        ("password=hunter2", "password=***"),
        # A secret with a space in it is masked whole, not up to the space.
        ('password="hunter 2"', 'password="***"'),
    ],
)
def test_redacts_keyed_secrets_exactly(module, line, expected):
    assert _record(module, line).getMessage() == expected


@REDACTORS
def test_redacts_a_url_password_with_no_user(module):
    """`redis://:pass@host` — the Redis spelling, and the one the mask missed."""
    rendered = _record(module, "redis://:justpass@cache.internal:6379/0 refused").getMessage()
    assert "justpass" not in rendered
    assert "redis://:***@cache.internal:6379/0" in rendered


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


@REDACTORS
def test_json_formatter_emits_the_documented_fields(module):
    """Both copies, because docs/configuration.md names one field list.

    ``request_id`` is always empty on the agent — it serves no requests — but
    it is present, so a shipper reading API and agent lines out of the same
    index has one schema rather than two.
    """
    record = logging.LogRecord("octo.test", logging.WARNING, __file__, 1, "hello", None, None)
    record.request_id = "abc123"
    payload = json.loads(module.JsonFormatter().format(record))
    assert set(payload) == {"ts", "level", "logger", "msg", "request_id"}
    assert payload["level"] == "WARNING"
    assert payload["logger"] == "octo.test"
    assert payload["msg"] == "hello"
    assert payload["ts"].endswith("Z")


def _exception_record(msg: str = "boom") -> logging.LogRecord:
    """A record carrying a traceback whose frame holds a connection URL."""
    import sys

    def connect(url: str) -> None:
        raise RuntimeError("connection refused")

    try:
        connect("postgresql://octo:sup3rs3cret@db/octo")
    except RuntimeError:
        return logging.LogRecord("octo.test", logging.ERROR, __file__, 1, msg, None, sys.exc_info())
    raise AssertionError("unreachable")


@REDACTORS
def test_json_formatter_redacts_the_traceback(module):
    payload = json.loads(module.JsonFormatter().format(_exception_record()))
    assert "sup3rs3cret" not in payload["exc"]


@REDACTORS
def test_text_formatter_redacts_the_traceback(module):
    """`text` is the default format, and it was the unredacted one.

    Redaction lived in the filter, which only ever sees the message; the
    traceback is rendered by the formatter, below every filter. So the format
    an operator gets by default printed the connection URL that
    ``LOG.exception`` was called about, while docs/operations.md said a
    formatted traceback is masked.
    """
    rendered = module.TextFormatter().format(_exception_record())
    assert "sup3rs3cret" not in rendered
    assert "postgresql://octo:***@db/octo" in rendered


@REDACTORS
def test_text_formatter_timestamps_in_utc(module):
    """`text` prints UTC under the `Z` the format string carries.

    The first cut used ``localtime`` with no zone in the line, so a text log
    could not be lined up against the JSON one — or against anything else in
    the cluster — without knowing the pod's ``/etc/localtime``.
    """
    import time as _time

    assert module.TextFormatter.converter is _time.gmtime
    assert module.TEXT_FORMAT.startswith("%(asctime)sZ ")

    record = logging.LogRecord("octo.test", logging.INFO, __file__, 1, "x", None, None)
    record.created = 1_700_000_000.0  # 2023-11-14T22:13:20Z
    record.request_id = ""
    assert module.TextFormatter().format(record).startswith("2023-11-14 22:13:20")


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
        # `NOTSET` is a level name, so it used to pass — and 0 on the root
        # logger is not "the default", it is "log absolutely everything",
        # including SQLAlchemy statements with their bound parameters.
        ("NOTSET", logging.INFO),
        ("notset", logging.INFO),
    ],
)
def test_resolve_log_level(module, raw, expected):
    assert module.resolve_log_level(raw) == expected


@REDACTORS
def test_quiet_loggers_are_the_same_in_both_copies(module):
    assert module.QUIET_LOGGERS == api_logging.QUIET_LOGGERS


@REDACTORS
def test_debug_does_not_reach_sqlalchemy_and_friends(module, monkeypatch):
    """`OCTO_LOG_LEVEL=DEBUG` must not turn on the statement log.

    ``sqlalchemy.engine`` at DEBUG prints every statement *with its bound
    parameters*, and on this schema those are bcrypt hashes, ``token_hash``
    values and session ids. An operator chasing a bug should not thereby write
    the credential store to stdout (#330).
    """
    monkeypatch.setenv("OCTO_LOG_LEVEL", "DEBUG")
    root = logging.getLogger()
    saved_root = list(root.handlers), root.level
    saved_quiet = {name: logging.getLogger(name).level for name in module.QUIET_LOGGERS}
    try:
        assert module.configure_logging(log_format="text")[1] == logging.DEBUG
        assert logging.getLogger("sqlalchemy.engine").getEffectiveLevel() == logging.WARNING
        assert logging.getLogger("httpx").getEffectiveLevel() == logging.INFO
        # The application's own loggers still get what was asked for.
        assert logging.getLogger("shapoclyack.api").getEffectiveLevel() == logging.DEBUG

        # A floor, not an override: a quieter process level still wins.
        module.configure_logging(log_format="text", level=logging.ERROR)
        assert logging.getLogger("sqlalchemy.engine").getEffectiveLevel() == logging.ERROR
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved_root[0]:
            root.addHandler(handler)
        root.setLevel(saved_root[1])
        for name, level in saved_quiet.items():
            logging.getLogger(name).setLevel(level)


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


def test_uvicorn_log_config_uses_the_text_formatter_class():
    """Not a bare format string: that gives ``logging.Formatter``, i.e. local
    time under a ``Z`` and a traceback that never meets :func:`redact`."""
    config = api_logging.uvicorn_log_config(log_format="text", level=logging.INFO)
    assert config["formatters"]["octo"] == {"()": "api.logging_setup.TextFormatter"}


def test_uvicorn_log_config_restates_the_quiet_floors():
    """uvicorn applies this dict itself, after ``configure_logging`` ran."""
    config = api_logging.uvicorn_log_config(log_format="json", level=logging.DEBUG)
    assert config["loggers"]["sqlalchemy.engine"] == {"level": "WARNING"}
    assert config["loggers"]["httpcore"] == {"level": "INFO"}


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
