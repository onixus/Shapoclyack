"""Run identifier minting and validation."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def mint() -> str:
    """Mint a sortable run id with a collision-resistant suffix."""
    return (
        f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-"
        f"{uuid.uuid4().hex[:6]}"
    )


def validate(value: str) -> str:
    """Refuse a run id that is not one safe path segment."""
    if not _RUN_ID_RE.fullmatch(value):
        raise ValueError("run_id must be 1-64 characters of [A-Za-z0-9_-]")
    return value


def confirm(expected: str | None, offered: str | None) -> str | None:
    """Confirm an agent's echoed run id against the server-selected id."""
    if expected and offered and offered != expected:
        raise ValueError("run_id does not match the job")
    resolved = expected or offered
    if resolved:
        validate(str(resolved))
    return resolved
