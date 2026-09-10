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
    ``INFO`` and says so, rather than silencing the process; so does
    ``NOTSET``, which on the root logger means "no level check at all".
    :data:`QUIET_LOGGERS` is the list of third-party loggers this level is not
    allowed to raise — ``sqlalchemy.engine`` at DEBUG prints statements with
    their bound parameters.

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
import time
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
#
# The `Z` is not decoration: :class:`TextFormatter` converts with ``gmtime``, so
# both formats print UTC and a text line can be compared with a JSON one without
# knowing what the pod's ``/etc/localtime`` says (#330).
TEXT_FORMAT = "%(asctime)sZ %(levelname)s %(name)s [%(request_id)s] %(message)s"

REDACTED = "***"

# Third-party loggers that are unusable at DEBUG, with the level below which
# they are not allowed to go. `sqlalchemy.engine` is the reason this exists:
# at DEBUG it prints every statement *with its bound parameters*, and on this
# schema those parameters are bcrypt hashes, `token_hash` values and session
# ids — an operator who sets OCTO_LOG_LEVEL=DEBUG to chase a bug should not
# thereby write the credential store into stdout. The rest are volume, not
# secrets: a DEBUG httpcore or paramiko buries the application's own lines.
#
# A floor, not an override: `max()` means OCTO_LOG_LEVEL=ERROR still quiets
# them further, and only the downward direction is refused.
QUIET_LOGGERS: dict[str, int] = {
    "sqlalchemy.engine": logging.WARNING,
    "sqlalchemy.pool": logging.WARNING,
    "paramiko": logging.INFO,
    "httpcore": logging.INFO,
    "httpx": logging.INFO,
    "nats": logging.INFO,
}

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

# An `Authorization` header, however it was logged: `Authorization: Bearer x`,
# `{"Authorization": "Token x"}`, `{'Authorization': 'Basic x'}`. The scheme
# word is swallowed together with the credential — the keyed rule below used to
# stop at the first space, which masked the word `Bearer` and left the token
# next to it. Any opening quote belongs to the separator group so the closing
# one survives and the line stays parseable.
#
# The known schemes are listed rather than "everything to end of value" so that
# `authorization: required` masks one word, not the rest of the line.
_AUTH_HEADER_RE = re.compile(
    r"(?i)(authorization)([\"']?\s*[=:]\s*[\"']?)"
    r"(?:(?:bearer|basic|token|apikey|api[_-]?key|digest|negotiate)\s+)?"
    r"[^\s,;\"'}\]]+"
)

# A bare `Bearer <token>` with no header name in the line. Only `Bearer`: it is
# the one scheme word that is never ordinary English next to a word, whereas a
# bare `Token`/`Basic` rule would turn "the token is invalid" and "Basic auth
# failed" into redactions. The other schemes are covered above, attached to the
# header name, which is where they actually occur.
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")

# `scheme://user:pass@host` — Postgres, NATS and ClickHouse URLs all carry the
# password this way, and they are logged on connection failures. The user is
# left visible: it is what identifies *which* URL was wrong. It may also be
# empty (`redis://:pass@host` is how Redis URLs are written), which is why the
# user group is `*`.
_URL_CREDENTIALS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^/\s:@]*):([^/\s@]+)@")

# `password=…`, `token=…`, `secret=…` and the near-spellings, with `=` or `:` as
# the separator so a query string, an env dump and a JSON fragment are all
# covered. The optional quote in the separator is what covers JSON: in
# `{"password": "x"}` the key's closing quote sits between the name and the
# colon. The separator itself is required: without it "token is invalid" would
# be masked as a secret, which loses a message and protects nothing.
_KEYED_SECRET_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)"
    r"([\"']?\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}\]]+)"
)


def _mask_keyed(match: re.Match[str]) -> str:
    """Replace the value, keeping the quotes that wrapped it.

    ``{"password": "hunter2"}`` becomes ``{"password": "***"}`` rather than
    ``{"password": ***}``: the quoted alternation is what lets a secret with a
    space in it be masked whole, and putting the quotes back is what keeps a
    JSON fragment in a log line readable as JSON afterwards.
    """
    value = match.group(3)
    quote = value[0] if value[:1] in ("\"", "'") else ""
    return f"{match.group(1)}{match.group(2)}{quote}{REDACTED}{quote}"


def redact(text: str) -> str:
    """Mask the credential shapes above in ``text``.

    Order matters: the JWT rule runs first (a compact token is recognisable
    wherever it sits), then the header rule, which swallows scheme and
    credential together so an ``Authorization`` line ends as ``***`` and not as
    ``*** ***``; the keyed rule last, on what is left.
    """
    text = _JWT_RE.sub("eyJ" + REDACTED, text)
    text = _AUTH_HEADER_RE.sub(r"\1\2" + REDACTED, text)
    text = _BEARER_RE.sub("Bearer " + REDACTED, text)
    text = _URL_CREDENTIALS_RE.sub(r"\1\2:" + REDACTED + "@", text)
    return _KEYED_SECRET_RE.sub(_mask_keyed, text)


class SecretRedactingFilter(logging.Filter):
    """Rewrite a record's message with :func:`redact` before it is formatted.

    A ``Filter`` rather than a ``Formatter``: it has to apply to every handler
    whatever format that handler renders, and the same object is installed on
    the JSON and the text path.

    The record is rendered here (``getMessage()``) and ``args`` cleared, which
    is what makes ``LOG.info("connecting to %s", url)`` maskable at all — the
    secret is in the argument, and a formatter that only sees ``record.msg``
    never meets it.

    Boundary, stated plainly: this masks the *message*. The traceback is
    rendered by the formatter, below every filter, and is masked there instead
    — see :class:`TextFormatter` and :class:`JsonFormatter`. Anything written
    to stdout by something that is not the logging module is not covered at
    all.
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


class TextFormatter(logging.Formatter):
    """:data:`TEXT_FORMAT`, in UTC, with the traceback redacted.

    Both halves are things the first cut of this module got wrong. The
    timestamp was local time with no zone printed, so a text line could not be
    lined up against a JSON one — or against anything else in the cluster —
    without knowing the pod's timezone. And redaction lived in the *filter*,
    which only reaches the message: ``LOG.exception("connect failed")`` on a
    driver error prints the connection URL out of the frame's arguments, and
    that is rendered here, below every filter.
    """

    converter = time.gmtime

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        # A default, because ``uvicorn_log_config`` instantiates this class by
        # name through ``dictConfig`` and passes no format string.
        super().__init__(fmt or TEXT_FORMAT, datefmt)

    def format(self, record: logging.LogRecord) -> str:
        # :data:`TEXT_FORMAT` names `request_id`, and a `%`-style formatter
        # raises on a record that has not got it — which drops the line. That
        # is normally :class:`RequestIdFilter`'s job, but it is installed per
        # *handler*, so a record reaching a handler somebody else added (a
        # sidecar, `pytest`'s caplog, `logging.basicConfig` in a script) would
        # otherwise be lost rather than merely uncorrelated.
        if not hasattr(record, "request_id"):
            record.request_id = ""
        return super().format(record)

    def formatException(self, ei: Any) -> str:
        return redact(super().formatException(ei))


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ``ts``, ``level``, ``logger``, ``msg``, ``request_id``.

    Hand-rolled on ``json`` from the standard library rather than pulling in a
    logging dependency — the shape is five fields and an optional exception,
    and the API's requirement set is not the place to add a package for that.
    """

    def formatException(self, ei: Any) -> str:
        # Redacted like the message: a traceback prints the arguments the
        # frames were called with, and a connection URL is one of them.
        return redact(super().formatException(ei))

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
            payload["exc"] = self.formatException(record.exc_info)
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
    if level == logging.NOTSET:
        # `NOTSET` is a level *name* and resolves to 0, so it passed the check
        # above and then meant something nobody asks for: on the root logger 0
        # disables the level check entirely, i.e. every DEBUG record in the
        # process — SQL statements with their bound parameters included — goes
        # to stdout, silently and without the operator having typed DEBUG.
        print(
            f"OCTO_LOG_LEVEL={value!r} would log everything; using {DEFAULT_LOG_LEVEL}",
            file=sys.stderr,
        )
        return logging.INFO
    return level


def build_formatter(log_format: str) -> logging.Formatter:
    if log_format == LOG_FORMAT_JSON:
        return JsonFormatter()
    return TextFormatter()


def apply_quiet_loggers(level: int) -> None:
    """Hold :data:`QUIET_LOGGERS` at their floor, whatever the process level is.

    Called from :func:`configure_logging`; :func:`uvicorn_log_config` states the
    same levels declaratively, because uvicorn applies its dict config after
    this module ran and a logger absent from that dict keeps whatever it had.
    """
    for name, floor in QUIET_LOGGERS.items():
        logging.getLogger(name).setLevel(max(level, floor))


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
    apply_quiet_loggers(resolved_level)
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
        else {"()": "api.logging_setup.TextFormatter"}
    )
    # By class name rather than by format string, for the text path too: a bare
    # `{"format": TEXT_FORMAT}` gives `logging.Formatter`, which prints local
    # time under a `Z` and renders a traceback without going through redaction.
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
            # Same floors as `apply_quiet_loggers`, restated here because
            # uvicorn applies this dict itself and would otherwise leave these
            # loggers at whatever `configure_logging` set — or, on a `--reload`
            # worker that never ran it, at root's level.
            **{
                name: {"level": logging.getLevelName(max(resolved_level, floor))}
                for name, floor in QUIET_LOGGERS.items()
            },
        },
    }
