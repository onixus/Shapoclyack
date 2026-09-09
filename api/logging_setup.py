"""One logging configuration for the API process, uvicorn included (#330).

Before this the API never configured logging at all: ``api/__main__.py`` called
``uvicorn.run`` bare, so application records went to the ``logging`` module's
last-resort handler (level WARNING, no timestamp) while ``uvicorn.access`` used
uvicorn's own colourised formatter. Two formats, no level control, no
correlation id, and nothing between a log call and stdout that could take a
password out of the line.

The configuration is read from the environment rather than from
:class:`api.settings.Settings` on purpose: it has to be in place *before*
``load_settings()`` runs, because a ``prod`` start on built-in credentials
refuses there and that refusal is the one line the operator will read.

Two variables:

``OCTO_LOG_FORMAT``
    ``text`` (default) or ``json``. ``json`` emits one object per line for a
    log shipper; ``text`` stays human-readable for a terminal.
``OCTO_LOG_LEVEL``
    Any level name (default ``INFO``). An unrecognised value falls back to
    ``INFO`` and says so, rather than silencing the process.

:func:`uvicorn_log_config` hands the same formatter and the same filters to
uvicorn, so ``uvicorn.access`` lands in the chosen format too — and goes
through the redaction filter, which is where a ``?token=`` in a request line
gets masked.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import UTC, datetime
from typing import Any

from api.request_context import current_request_id

LOG_FORMAT_TEXT = "text"
LOG_FORMAT_JSON = "json"
VALID_LOG_FORMATS = (LOG_FORMAT_TEXT, LOG_FORMAT_JSON)

DEFAULT_LOG_LEVEL = "INFO"

# The request id is part of the line, not an afterthought appended to the
# message: this is what makes "everything one request did" a grep for a single
# token across API and, once shipped, ingress logs.
TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s [%(request_id)s] %(message)s"

REDACTED = "***"

# --- Redaction masks -------------------------------------------------------
#
# Applied to the *rendered* message (``record.getMessage()``), so a secret that
# arrived as a ``%s`` argument is masked exactly like one written into the
# format string. The set is deliberately small and syntactic: these are the
# shapes a credential takes when it reaches a log line by accident — a keyed
# pair copied out of a config, an Authorization header echoed while debugging,
# a connection URL, a JWT.

# JWTs first: a compact-serialization token is recognisable on its own, wherever
# it sits, and masking it here means the Bearer rule below never has to.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?")

# `Authorization: Bearer <token>` and any bare `Bearer <token>`. Matched on the
# scheme rather than on the header name because the header is logged both ways
# (`Authorization: Bearer x`, `{"Authorization": "Bearer x"}`), and the token is
# the part that matters in either.
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")

# `scheme://user:pass@host` — Postgres, NATS and ClickHouse URLs all carry the
# password this way, and they are logged on connection failures. The user is
# left visible: it is what identifies *which* URL was wrong.
_URL_CREDENTIALS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^/\s:@]+):([^/\s@]+)@")

# `password=…`, `token=…`, `secret=…` and the near-spellings, with `=` or `:` as
# the separator so a query string, an env dump and a JSON fragment are all
# covered. The separator is required: without it "token is invalid" would be
# masked as a secret, which loses a message and protects nothing.
_KEYED_SECRET_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|authorization)"
    r"(\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}\]]+)"
)


def redact(text: str) -> str:
    """Mask the credential shapes above in ``text``.

    Order matters: the JWT and Bearer rules run before the keyed one so a
    ``Authorization: Bearer eyJ…`` line is masked as a token rather than being
    truncated at the first space.
    """
    text = _JWT_RE.sub("eyJ" + REDACTED, text)
    text = _BEARER_RE.sub("Bearer " + REDACTED, text)
    text = _URL_CREDENTIALS_RE.sub(r"\1\2:" + REDACTED + "@", text)
    return _KEYED_SECRET_RE.sub(r"\1\2" + REDACTED, text)


class SecretRedactingFilter(logging.Filter):
    """Rewrite a record's message with :func:`redact` before it is formatted.

    A ``Filter`` rather than a ``Formatter``: it has to apply to every handler
    whatever format that handler renders, and the same object is installed on
    the JSON and the text path.

    The record is rendered here (``getMessage()``) and ``args`` cleared, which
    is what makes ``LOG.info("connecting to %s", url)`` maskable at all — the
    secret is in the argument, and a formatter that only sees ``record.msg``
    never meets it.

    Boundary, stated plainly: this masks the *message*. A secret carried in a
    field of an exception that is re-rendered from ``exc_info``, or written to
    stdout by something that is not the logging module, is not covered.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            # A record whose args do not match its format string is a bug in
            # the caller, not a reason to drop the line (and not a reason to
            # let an unredacted repr through either): keep the raw format
            # string, which cannot contain the argument that carried a secret.
            return True
        masked = redact(rendered)
        if masked != rendered or record.args:
            record.msg = masked
            record.args = ()
        return True


class RequestIdFilter(logging.Filter):
    """Attach the current request id to every record as ``request_id``.

    Always sets the attribute, empty string included: :data:`TEXT_FORMAT` names
    it, and a record from a background worker must not raise a formatting error
    for having been emitted outside a request.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if not getattr(record, "request_id", ""):
            record.request_id = current_request_id()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ``ts``, ``level``, ``logger``, ``msg``, ``request_id``.

    Hand-rolled on ``json`` from the standard library rather than pulling in a
    logging dependency — the shape is five fields and an optional exception,
    and the API's requirement set is not the place to add a package for that.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            # Explicit UTC with a `Z`: log shippers parse this without being
            # told a timezone, and the API's other timestamps are UTC too.
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "") or "",
        }
        if record.exc_info:
            # Redacted like the message: a traceback prints the arguments the
            # frames were called with, and a connection URL is one of them.
            payload["exc"] = redact(self.formatException(record.exc_info))
        # `ensure_ascii=False` so a hostname or a finding title in Cyrillic
        # stays readable in the log rather than becoming \uXXXX escapes;
        # compact separators because this is a line in a log, not a document.
        return json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))


def resolve_log_format(raw: str | None = None) -> str:
    """``json`` or ``text``; an unrecognised value reads as ``text``."""
    value = (raw if raw is not None else os.environ.get("OCTO_LOG_FORMAT", "")).strip().lower()
    if not value:
        return LOG_FORMAT_TEXT
    if value not in VALID_LOG_FORMATS:
        # Printed rather than logged: logging is being configured right now.
        print(
            f"OCTO_LOG_FORMAT={value!r} is not one of {VALID_LOG_FORMATS}; using 'text'",
            file=sys.stderr,
        )
        return LOG_FORMAT_TEXT
    return value


def resolve_log_level(raw: str | None = None) -> int:
    """Numeric level for ``OCTO_LOG_LEVEL``; an unrecognised name reads as INFO."""
    value = (raw if raw is not None else os.environ.get("OCTO_LOG_LEVEL", "")).strip().upper()
    if not value:
        value = DEFAULT_LOG_LEVEL
    level = logging.getLevelName(value)
    if not isinstance(level, int):
        print(
            f"OCTO_LOG_LEVEL={value!r} is not a level name; using {DEFAULT_LOG_LEVEL}",
            file=sys.stderr,
        )
        return logging.INFO
    return level


def build_formatter(log_format: str) -> logging.Formatter:
    if log_format == LOG_FORMAT_JSON:
        return JsonFormatter()
    return logging.Formatter(TEXT_FORMAT)


def configure_logging(
    *, log_format: str | None = None, level: int | None = None
) -> tuple[str, int]:
    """Install the root handler for this process. Returns ``(format, level)``.

    Idempotent: the handlers it owns are replaced, not appended to, so calling
    it twice (a test, or a reload) does not double every line.
    """
    resolved_format = resolve_log_format(log_format)
    resolved_level = resolve_log_level() if level is None else level

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(build_formatter(resolved_format))
    handler.addFilter(RequestIdFilter())
    # After the request-id filter: the redaction filter rewrites the message,
    # and nothing downstream of it should be able to put a secret back.
    handler.addFilter(SecretRedactingFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(resolved_level)
    return resolved_format, resolved_level


def uvicorn_log_config(
    *, log_format: str | None = None, level: int | None = None
) -> dict[str, Any]:
    """``logging`` dictConfig for ``uvicorn.run(log_config=...)``.

    Uvicorn installs its own formatters and its own ``uvicorn.access`` handler
    unless it is given one of these, which is how the access log ended up in a
    different format from everything else. The dict below routes both uvicorn
    loggers through this module's formatter and filters instead.

    ``disable_existing_loggers`` is False: the application's own loggers exist
    by the time uvicorn applies this, and disabling them would silence the API.
    """
    resolved_format = resolve_log_format(log_format)
    resolved_level = resolve_log_level() if level is None else level
    level_name = logging.getLevelName(resolved_level)
    formatter: dict[str, Any] = (
        {"()": "api.logging_setup.JsonFormatter"}
        if resolved_format == LOG_FORMAT_JSON
        else {"format": TEXT_FORMAT}
    )
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"octo": formatter},
        "filters": {
            "request_id": {"()": "api.logging_setup.RequestIdFilter"},
            "redact": {"()": "api.logging_setup.SecretRedactingFilter"},
        },
        "handlers": {
            "octo": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
                "formatter": "octo",
                "filters": ["request_id", "redact"],
            }
        },
        "root": {"handlers": ["octo"], "level": level_name},
        "loggers": {
            "uvicorn": {"handlers": ["octo"], "level": level_name, "propagate": False},
            "uvicorn.error": {"handlers": ["octo"], "level": level_name, "propagate": False},
            "uvicorn.access": {"handlers": ["octo"], "level": level_name, "propagate": False},
        },
    }
