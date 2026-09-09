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
from datetime import UTC, datetime
from typing import Any

LOG_FORMAT_TEXT = "text"
LOG_FORMAT_JSON = "json"
VALID_LOG_FORMATS = (LOG_FORMAT_TEXT, LOG_FORMAT_JSON)

DEFAULT_LOG_LEVEL = "INFO"

TEXT_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

REDACTED = "***"

# Keep in sync with api/logging_setup.py — see the module docstring.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*)?")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_URL_CREDENTIALS_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)([^/\s:@]+):([^/\s@]+)@")
_KEYED_SECRET_RE = re.compile(
    r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|authorization)"
    r"(\s*[=:]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"'}\]]+)"
)


def redact(text: str) -> str:
    """Mask credential shapes in ``text``; see ``api/logging_setup.redact``."""
    text = _JWT_RE.sub("eyJ" + REDACTED, text)
    text = _BEARER_RE.sub("Bearer " + REDACTED, text)
    text = _URL_CREDENTIALS_RE.sub(r"\1\2:" + REDACTED + "@", text)
    return _KEYED_SECRET_RE.sub(r"\1\2" + REDACTED, text)


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


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ``ts``, ``level``, ``logger``, ``msg``."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat().replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
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
    return level


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
        JsonFormatter() if resolved_format == LOG_FORMAT_JSON else logging.Formatter(TEXT_FORMAT)
    )
    handler.addFilter(SecretRedactingFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(resolved_level)
    return resolved_format, resolved_level
