"""Run identifier minting and validation, shared by the scanner CLI and the API.

Here rather than in ``api/``: the API already imports from ``scanner`` (and
ships it in its image), while the scanner image carries no ``api/`` at all. One
function, so a run the CLI starts and a run the server starts cannot disagree
about what a run id looks like -- which is what #427 was: the server grew a
suffix in #421 and the CLI kept minting the bare second.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

#: One safe path segment. Starts with an alphanumeric, so an id can never be a
#: hidden name (``.ingest-*`` staging, ``.sync``) or the reserved ``_tenants``
#: namespace under ``runs/`` (``api/services/artifact_store/keys.py``).
RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


def mint() -> str:
    """A run id for a new scan: the clock, and enough to be unique.

    It was ``%Y%m%dT%H%M%SZ`` alone, and a second is not a lot: two jobs
    claimed inside the same one were handed the *same* run id, so their
    artifacts merged into one directory and one key prefix -- across tenants,
    since the prefix carried no owner (#311) -- and a publication of either
    that failed partway took the other's keys with it. The suffix goes after
    the timestamp so that the ordering a run listing depends on (ids sorted
    descending, which is the clock) is exactly as it was.
    """
    return f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:6]}"


def validate(value: str) -> str:
    """Refuse a run id that is not one safe path segment."""
    if not RUN_ID_RE.fullmatch(value):
        raise ValueError("run_id must be 1-64 characters of [A-Za-z0-9_-]")
    return value
