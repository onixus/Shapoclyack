"""``Idempotency-Key`` for write endpoints that create no row of their own (#346).

``POST /api/jobs`` has been idempotent since P1.5 and needs none of this: a
scan start inserts a job, so the key lives in a unique index *on the thing the
request produced* (``jobs.tenant_id, jobs.idempotency_key``) and the replay is
that row. See :func:`api.services.jobs.find_by_idempotency_key` — this module
does not replace it and nothing here touches jobs.

A bulk action has no such row. ``POST /api/vulnerabilities/bulk`` edits
findings that already exist and answers with a per-id report, so there is
nowhere on the tenant's data to hang the key and no row to replay. It gets a
table (``idempotency_records``), and the same contract the scan start already
established, spelled the same way:

* a key seen before with the **same** request replays the stored answer, and
  the route answers 200 rather than the endpoint's own success code — nothing
  was applied by *this* request;
* a key seen before with a **different** request is :class:`IdempotencyMismatch`
  → 409. Replaying somebody else's answer would report a batch this caller
  never sent, and executing would break the promise the key was given for;
* a key whose first request is **still running** is :class:`IdempotencyInFlight`
  → 409. Two concurrent sends of one key must not both execute, and the honest
  answer to the loser is "the first one has not finished".

**The unique index is the mechanism, not an optimisation.** Look-then-insert is
something two API replicas can both pass; the second INSERT here fails, and
that is where the second request learns it lost. So :func:`reserve` inserts
*before* the work runs.

**A failed request does not burn its key.** :func:`release` drops the
reservation when the handler raised, so a caller whose batch died on a 500 can
retry with the same key. Only a reservation that never got an answer is
released — a completed record is the answer.

Rows are disposable: they are the memory of a retry window, not a record of
anything. :func:`purge_expired` drops them past :data:`RETENTION_SECONDS` and
is called opportunistically from :func:`reserve`, the same way the login trail
is pruned on the login path rather than by a worker of its own.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from api.db import models
from api.db.engine import get_session
from api.services import metrics as metrics_service
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.idempotency")

#: Longest a key is remembered. A retry window, not a history: a client that
#: comes back a day later with the same key is asking for the batch to be
#: applied again, and at that distance that is the likelier intent.
RETENTION_SECONDS = 24 * 3600

#: How often one process bothers to sweep. The purge is a single DELETE on an
#: indexed column, but it runs inside somebody's request, so it does not run
#: on every one of them.
_PURGE_INTERVAL_SECONDS = 300.0

#: Ceiling on the key a client may name. Same 200 characters the scan start
#: truncates to, so one client library can use one key everywhere.
MAX_KEY_LENGTH = 200

_purge_lock = threading.Lock()
_last_purge = 0.0


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def normalise_key(value: str | None) -> str:
    """The key as it will be stored: trimmed and length-capped, or ``""``.

    ``""`` means "the client named nothing", which is not an error — an
    endpoint that accepts a key does not require one.
    """
    return (value or "").strip()[:MAX_KEY_LENGTH]


def digest(payload: Any) -> str:
    """A fingerprint of the request a key was given to.

    Same construction as ``jobs._idempotency_digest``: canonical JSON, sorted
    keys, SHA-256. It is what lets a second call be answered with the first
    answer only when it is in fact the same request.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class IdempotencyMismatch(Exception):
    """A key an earlier request used, sent with a *different* request body.

    Not a ``ValueError``: the body is well-formed, and the routes map
    ``ValueError`` to 422. This is 409 — the key is taken.
    """

    def __init__(self, endpoint: str, key: str) -> None:
        super().__init__(
            f"Idempotency-Key {key!r} was already used on {endpoint} for a "
            "different request"
        )
        self.endpoint = endpoint
        self.key = key


class IdempotencyInFlight(Exception):
    """A key whose first request is still executing. 409, and retryable."""

    def __init__(self, endpoint: str, key: str) -> None:
        super().__init__(
            f"Idempotency-Key {key!r} is still being processed on {endpoint}"
        )
        self.endpoint = endpoint
        self.key = key


def reserve(
    settings: Settings,
    *,
    tenant_id: str,
    endpoint: str,
    key: str,
    request_digest: str,
) -> dict[str, Any] | None:
    """Claim ``key`` for this request, or hand back the answer it already has.

    Returns the stored response when this key has already been answered — the
    caller then answers 200 and does no work — and ``None`` when the key is now
    this request's to execute. Raises :class:`IdempotencyMismatch` for a key
    reused with a different body and :class:`IdempotencyInFlight` for one whose
    first request has not finished.
    """
    _maybe_purge(settings)
    with get_session(settings.postgres_url) as session:
        try:
            with session.begin_nested():
                session.add(
                    models.IdempotencyRecord(
                        tenant_id=tenant_id,
                        endpoint=endpoint,
                        key=key,
                        request_digest=request_digest,
                        response=None,
                        created_at=_now(),
                    )
                )
                session.flush()
            return None
        except IntegrityError:
            # Lost the race on (tenant_id, endpoint, key), or the key was used
            # in an earlier request altogether. Both are answered from the row
            # that won.
            pass
        row = session.execute(
            select(models.IdempotencyRecord).where(
                models.IdempotencyRecord.tenant_id == tenant_id,
                models.IdempotencyRecord.endpoint == endpoint,
                models.IdempotencyRecord.key == key,
            )
        ).scalars().first()
        if row is None:
            # The winner's row is gone — it was released as a failure between
            # our INSERT and this read. Nobody holds the key and nobody has an
            # answer, so this request executes.
            return None
        if row.request_digest and row.request_digest != request_digest:
            raise IdempotencyMismatch(endpoint, key)
        if row.response is None:
            raise IdempotencyInFlight(endpoint, key)
        stored = dict(row.response)
    metrics_service.IDEMPOTENT_REPLAYS_TOTAL.labels(endpoint=endpoint).inc()
    LOG.info("Idempotent replay on %s for key %r (tenant %s)", endpoint, key, tenant_id)
    return stored


def complete(
    settings: Settings,
    *,
    tenant_id: str,
    endpoint: str,
    key: str,
    response: dict[str, Any],
) -> None:
    """Store the answer this key's request produced, so a retry replays it."""
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.IdempotencyRecord).where(
                models.IdempotencyRecord.tenant_id == tenant_id,
                models.IdempotencyRecord.endpoint == endpoint,
                models.IdempotencyRecord.key == key,
            )
        ).scalars().first()
        if row is None:
            # Purged, or released by a concurrent failure path. The work is
            # done and the caller is about to be told so; losing the ability to
            # replay it is not worth failing the request over.
            LOG.warning(
                "Idempotency record for %s key %r vanished before completion", endpoint, key
            )
            return
        row.response = response


def release(settings: Settings, *, tenant_id: str, endpoint: str, key: str) -> None:
    """Drop an *unanswered* reservation, so a failed request may be retried.

    Deliberately conditional on ``response IS NULL``: a record that already
    carries an answer is that answer, and deleting it would let a retry apply
    the batch a second time.
    """
    with get_session(settings.postgres_url) as session:
        session.execute(
            delete(models.IdempotencyRecord).where(
                models.IdempotencyRecord.tenant_id == tenant_id,
                models.IdempotencyRecord.endpoint == endpoint,
                models.IdempotencyRecord.key == key,
                models.IdempotencyRecord.response.is_(None),
            )
        )


def purge_expired(settings: Settings, *, now: datetime | None = None) -> int:
    """Delete records past :data:`RETENTION_SECONDS`. Returns the row count."""
    cutoff = (now or _now()) - timedelta(seconds=RETENTION_SECONDS)
    with get_session(settings.postgres_url) as session:
        result = session.execute(
            delete(models.IdempotencyRecord).where(
                models.IdempotencyRecord.created_at < cutoff
            )
        )
    return int(result.rowcount or 0)


def _maybe_purge(settings: Settings) -> None:
    """Sweep at most once per :data:`_PURGE_INTERVAL_SECONDS` in this process.

    Fail-soft with a log: this runs inside a request that is about to do real
    work, and a failed sweep of a disposable table must not be why that work
    did not happen. The rows it missed are picked up by the next call.
    """
    global _last_purge
    now = time.monotonic()
    with _purge_lock:
        if now - _last_purge < _PURGE_INTERVAL_SECONDS:
            return
        _last_purge = now
    try:
        removed = purge_expired(settings)
    except Exception:  # pragma: no cover - defensive
        LOG.warning("Idempotency purge failed; retrying on a later request", exc_info=True)
        return
    if removed:
        LOG.info("Purged %d expired idempotency records", removed)


def reset_for_tests(settings: Settings) -> None:
    """Empty the table and forget when this process last swept.

    Called from ``tests/conftest.py`` alongside the other per-test resets. The
    table has no foreign key to ``tenants``, so unlike assets and findings it
    does **not** disappear when the tenant truncation cascades — a key one test
    used would otherwise 409 the next test that reached for the same name.
    """
    global _last_purge
    _last_purge = 0.0
    with get_session(settings.postgres_url) as session:
        session.execute(delete(models.IdempotencyRecord))
