"""Run identifier minting and validation."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def mint() -> str:
    """A run id for a scan this server starts: the clock, and enough to be unique.

    It was ``%Y%m%dT%H%M%SZ`` alone, and a second is not a lot: two jobs
    claimed inside the same one were handed the *same* run id, so their
    artifacts merged into one directory and one key prefix — across tenants,
    since the prefix carries no owner (#311) — and a publication of either
    that failed partway took the other's keys with it. The suffix goes after
    the timestamp so that the ordering a run listing depends on (ids sorted
    descending, which is the clock) is exactly as it was.
    """
    return f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"


def validate(value: str) -> str:
    """Refuse a run id that is not one safe path segment."""
    if not _RUN_ID_RE.fullmatch(value):
        raise ValueError("run_id must be 1-64 characters of [A-Za-z0-9_-]")
    return value


def confirm(expected: str | None, offered: str | None) -> str | None:
    """Resolve the run id an upload lands in.

    The server decided the run id at ``start_scan`` or at the claim, and the
    agent only echoes it back. The echo is accepted as confirmation, never as
    a choice: before this check an agent could name any directory — another
    tenant's run, or a path outside ``runs/`` — and have its archive extracted
    there and the run's ``tenant.json`` rewritten to its own tenant.
    """
    if expected and offered and offered != expected:
        raise ValueError("run_id does not match the job")
    resolved = expected or offered
    if resolved:
        validate(str(resolved))
    return resolved
