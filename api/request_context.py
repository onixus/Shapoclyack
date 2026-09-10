"""The correlation id of the request being served (#330).

A ``ContextVar`` rather than something hung on ``Request.state``: the id has to
reach code that never sees the request object — a ``logging.Filter`` formatting
a line from a service, an audit write, a span attribute — and all of it runs
inside the same asyncio task (or the threadpool worker Starlette copies the
context into) that :class:`api.middleware.RequestIdMiddleware` set it in.

``current_request_id()`` is the whole public surface for readers; outside a
request it answers ``""`` rather than raising, because a log line from a
background worker is not an error.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar, Token

REQUEST_ID_HEADER = "X-Request-Id"

# Long enough for a W3C traceparent or a ULID pair, short enough that the id
# cannot be used to push a kilobyte of attacker text into every log line the
# request produces.
MAX_REQUEST_ID_LENGTH = 128

# Deliberately narrow. The value is echoed into a response header and into
# every log record for the request, so the two things it must not contain are
# CR/LF (header splitting, log-line forgery) and anything a JSON or text log
# consumer would have to unescape. Everything a UUID, a ULID, a traceparent or
# an nginx ``$request_id`` can produce is inside this set.
_SAFE_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:@=+/-]+$")

_request_id: ContextVar[str] = ContextVar("octo_request_id", default="")


def current_request_id() -> str:
    """Correlation id of the request being served, or ``""`` outside one."""
    return _request_id.get()


def new_request_id() -> str:
    """Mint an id for a request that arrived without one."""
    return uuid.uuid4().hex


def sanitize_request_id(value: str | None) -> str | None:
    """Return a caller-supplied id that is safe to log and echo, else ``None``.

    Rejected rather than escaped: a client that sends an id we had to rewrite
    cannot correlate on it anyway, so a fresh one is more honest than a mangled
    one — and it keeps exactly one shape of id in the logs.
    """
    if value is None:
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > MAX_REQUEST_ID_LENGTH:
        return None
    if _SAFE_REQUEST_ID_RE.match(candidate) is None:
        return None
    return candidate


def set_request_id(value: str) -> Token[str]:
    """Bind ``value`` for this context; the token restores the previous one."""
    return _request_id.set(value)


def reset_request_id(token: Token[str]) -> None:
    _request_id.reset(token)
