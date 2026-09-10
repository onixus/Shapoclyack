"""Logging configuration for the remote agent (#330).

A copy of the core of ``api/logging_setup.py`` rather than an import of it, for
the same reason ``agent/__init__.py`` retypes the version literal: the scanner
image copies ``agent`` without ``api``, and a native install
(``scripts/install-agent.sh``) unpacks a tarball that contains the ``agent``
package and nothing else. An import across that line would work in the repo and
in the tests, and fail on every agent host.

``tests/test_logging_setup.py`` runs the same redaction cases against both
modules, which is what keeps the two copies from drifting.

What is deliberately *not* here: the request-id filter and the uvicorn dict
config. The agent serves no requests — its correlation key is the ``job_id``
it already logs.

``OCTO_LOG_FORMAT`` (``text``/``json``) and ``OCTO_LOG_LEVEL`` mean the same
here as they do for the API; ``--verbose`` still forces DEBUG, since that is
what the flag has always done.
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

LOG_FORMAT_TEXT = "text"
LOG_FORMAT_JSON = "json"
VALID_LOG_FORMATS = (LOG_FORMAT_TEXT, LOG_FORMAT_JSON)

DEFAULT_LOG_LEVEL = "INFO"

# The `Z` goes with `TextFormatter.converter = time.gmtime` below: the agent
# runs on a customer host in whatever timezone that host was installed with,
# and a line an operator has to line up against an API line has to say which.
TEXT_FORMAT = "%(asctime)sZ %(levelname)s %(name)s: %(message)s"

REDACTED = "***"

# Keep in sync with api/logging_setup.py — see the module docstring.
QUIET_LOGGERS: dict[str, int] = {
    "sqlalchemy.engine": logging.WARNING,
    "sqlalchemy.pool": logging.WARNING,
    "paramiko": logging.INFO,
    "httpcore": logging.INFO,
    "httpx": logging.INFO,
    "nats": logging.INFO,
}

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?")
_AUTH_HEADER_RE = re.compile(
    r"(?i)(authorization)([\"']?\s*[=:]\s*[\"']?)"
    r"(?:(?:bearer|basic|token|apikey|api[_-]?key|digest|negotiate)\s+)?"
    r"[^\s,;\"'}\]]+"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIALS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^/\s:@]*):([^/\s@]+)@")
_KEYED_SECRET_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key)"
    r"([\"']?\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}\]]+)"
)


def _mask_keyed(match: re.Match[str]) -> str:
    """Replace the value, keeping the quotes that wrapped it."""
    value = match.group(3)
    quote = value[0] if value[:1] in ("\"", "'") else ""
    return f"{match.group(1)}{match.group(2)}{quote}{REDACTED}{quote}"


def redact(text: str) -> str:
    """Mask credential shapes in ``text``; see ``api/logging_setup.redact``."""
    text = _JWT_RE.sub("eyJ" + REDACTED, text)
    text = _AUTH_HEADER_RE.sub(r"\1\2" + REDACTED, text)
    text = _BEARER_RE.sub("Bearer " + REDACTED, text)
    text = _URL_CREDENTIALS_RE.sub(r"\1\2:" + REDACTED + "@", text)
    return _KEYED_SECRET_RE.sub(_mask_keyed, text)


class SecretRedactingFilter(logging.Filter):
    """Rewrite a record's rendered message with :func:`redact`.

    The agent has the sharper version of the problem the API has: it holds a
    provisioning key and an agent JWT, dials the API with them, and logs its own
    HTTP failures — so an unmasked ``Authorization`` header in a debug line ends
    up in journald on a host the customer administers.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        masked = redact(rendered)
        if masked != rendered or record.args:
            record.msg = masked
            record.args = ()
        return True


class TextFormatter(logging.Formatter):
    """:data:`TEXT_FORMAT`, in UTC, with the traceback redacted.

    The API's :class:`api.logging_setup.TextFormatter` down to the format
    string; both halves matter here for the same reasons. ``gmtime`` because
    the agent's host timezone is the customer's business, not ours, and the
    traceback because ``LOG.exception`` on a failed claim renders the request
    the agent made — headers included — below every filter.
    """

    converter = time.gmtime

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt or TEXT_FORMAT, datefmt)

    def formatException(self, ei: Any) -> str:
        return redact(super().formatException(ei))


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ``ts``, ``level``, ``logger``, ``msg``, ``request_id``.

    ``request_id`` is always empty here — the agent serves no requests, and its
    own correlation key is the ``job_id`` it logs in the message. It is emitted
    anyway so that a shipper reading API and agent lines out of the same index
    has one schema rather than two, which is what docs/configuration.md
    promises for ``OCTO_LOG_FORMAT=json``.
    """

    def formatException(self, ei: Any) -> str:
        return redact(super().formatException(ei))

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": getattr(record, "request_id", "") or "",
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))


def resolve_log_format(raw: str | None = None) -> str:
    """``json`` or ``text``; an unrecognised value reads as ``text``."""
    value = (raw if raw is not None else os.environ.get("OCTO_LOG_FORMAT", "")).strip().lower()
    if not value:
        return LOG_FORMAT_TEXT
    if value not in VALID_LOG_FORMATS:
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
        # See api/logging_setup.resolve_log_level: 0 on the root logger is not
        # "the default", it is "log absolutely everything".
        print(
            f"OCTO_LOG_LEVEL={value!r} would log everything; using {DEFAULT_LOG_LEVEL}",
            file=sys.stderr,
        )
        return logging.INFO
    return level


def apply_quiet_loggers(level: int) -> None:
    """Hold :data:`QUIET_LOGGERS` at their floor; see the API's copy."""
    for name, floor in QUIET_LOGGERS.items():
        logging.getLogger(name).setLevel(max(level, floor))


def configure_logging(
    *, log_format: str | None = None, level: int | None = None
) -> tuple[str, int]:
    """Install the agent's root handler. Returns ``(format, level)``.

    Replaces ``logging.basicConfig``, which was a no-op on a second call and
    could not be given a filter at all.
    """
    resolved_format = resolve_log_format(log_format)
    resolved_level = resolve_log_level() if level is None else level

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        JsonFormatter() if resolved_format == LOG_FORMAT_JSON else TextFormatter()
    )
    handler.addFilter(SecretRedactingFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(resolved_level)
    apply_quiet_loggers(resolved_level)
    return resolved_format, resolved_level
