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

**A key belongs to the caller, not to the tenant.** ``(tenant_id, endpoint,
actor, key)`` is what is unique, where ``actor`` is the principal string the
audit trail uses. The console mints a UUID per click and never noticed, but the
CI integrations in ``docs/wiki/scenarios-architect.md`` send meaningful,
guessable keys — ``nightly-triage`` — and under a tenant-wide namespace any
member could take one and either 409 somebody else's pipeline or, with a body
that happened to match, be handed its report as a replay without leaving an
audit row of their own. Two pipelines may now both call their batch
``nightly-triage``; one pipeline retrying still lands on its own key, because a
service token's actor string is the same on every retry.

* a key seen before with the **same** request replays the stored answer, and
  the route answers 200 rather than the endpoint's own success code — nothing
  was applied by *this* request;
* a key seen before with a **different** request is :class:`IdempotencyMismatch`
  → 409. Replaying somebody else's answer would report a batch this caller
  never sent, and executing would break the promise the key was given for;
* a key whose first request is **still running** is :class:`IdempotencyInFlight`
  → 409. Two concurrent sends of one key must not both execute, and the honest
  answer to the loser is "the first one has not finished". "Still running" is
  believed for :data:`RESERVATION_LEASE_SECONDS` and no longer: a process that
  died without releasing its key would otherwise make that 409 permanent for a
  day, which is not a retry window but an outage.

**The unique index is the mechanism, not an optimisation.** Look-then-insert is
something two API replicas can both pass; the second INSERT here fails, and
that is where the second request learns it lost. So :func:`reserve` inserts
*before* the work runs.

**A failed request does not burn its key.** :func:`release` drops the
reservation when the handler raised, so a caller whose batch died on a 500 can
retry with the same key. Only a reservation that never got an answer is
released — a completed record is the answer. A handler that never got to run
its own failure path (the pod was killed) leaves the reservation behind, and
the lease above is what still frees it. The one case that deliberately does
*not* release is a bulk request that died having applied part of itself: it
stores the partial report instead, so the retry is told which ids landed rather
than applying them again (``routes/vulnerabilities.py``).

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

from sqlalchemy import delete, select, update
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

#: How long a reservation with no answer stored against it is believed to be
#: running. Past this, a retry takes the key over and executes.
#:
#: Without a lease, "in flight" is forever: the reservation is dropped by
#: :func:`release` in the handler, so a replica the OOM killer took, a pod
#: Kubernetes evicted or a worker a sync timeout killed leaves ``response``
#: NULL for good — and every retry is answered "still being processed" for a
#: whole :data:`RETENTION_SECONDS`, for a key nobody holds.
#:
#: Generous on purpose. It has to exceed the longest a legitimate request can
#: take (200 ids, each its own transaction, each possibly one outbound tracker
#: call), because a lease that expires *under* a request still running would
#: let a retry apply the batch a second time — the one outcome the key exists
#: to prevent. Any proxy in front of the API gives up on the client long
#: before this.
RESERVATION_LEASE_SECONDS = 15 * 60

#: How often one process bothers to sweep. The purge is a single DELETE on an
#: indexed column, but it runs inside somebody's request, so it does not run
#: on every one of them.
_PURGE_INTERVAL_SECONDS = 300.0

#: How many times :func:`reserve` will look again after losing its INSERT.
#:
#: Two, and only because a rolling deploy has two generations of writer: a
#: replica of the previous release can take a key between this one's look-ahead
#: for a legacy row and its own INSERT, which the cross-generation trigger in
#: ``0055_idempotency_actor`` turns into an ``IntegrityError``. The second pass
#: reads that row and replays it. Goes away with the fallback below.
_RESERVE_ATTEMPTS = 2

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
    actor: str,
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

    ``actor`` is who the key belongs to, and it is part of the identity of the
    reservation: two members of one tenant may both call their nightly batch
    ``nightly-triage`` without taking it from each other.
    """
    _maybe_purge(settings)
    stored: dict[str, Any] | None = None
    for _ in range(_RESERVE_ATTEMPTS):
        with get_session(settings.postgres_url) as session:
            # Looked up *before* the INSERT, and only this one is: a row written
            # before keys had owners (``actor IS NULL``) lives in a different
            # index from the one below, so without this read a retry arriving
            # after the deploy would quietly execute its batch a second time. It
            # goes away with the last legacy row — see ``0055_idempotency_actor``.
            legacy = _row_for(
                session, tenant_id=tenant_id, endpoint=endpoint, key=key, actor=None
            )
            if legacy is not None:
                stored = _answer_from_legacy(
                    session, legacy, endpoint=endpoint, key=key, request_digest=request_digest
                )
            if stored is not None:
                break
            try:
                with session.begin_nested():
                    session.add(
                        models.IdempotencyRecord(
                            tenant_id=tenant_id,
                            actor=actor,
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
                # Lost the race on (tenant_id, endpoint, actor, key), or this
                # caller used the key in an earlier request altogether, or the
                # cross-generation trigger refused us because a replica of the
                # previous release took the key between the read above and this
                # INSERT. All three are answered from the row that won.
                pass
            row = _row_for(
                session, tenant_id=tenant_id, endpoint=endpoint, key=key, actor=actor
            )
            if row is None:
                if _row_for(
                    session, tenant_id=tenant_id, endpoint=endpoint, key=key, actor=None
                ) is None:
                    # The winner's row is gone — it was released as a failure
                    # between our INSERT and this read. Nobody holds the key and
                    # nobody has an answer, so this request executes.
                    return None
                # A pre-deploy replica took the key while we were reading. Its
                # row is the answer, and the pass below reads it with the
                # legacy semantics it was written under.
                continue
            if row.response is None:
                # Checked before the digest: an abandoned reservation holds a key
                # nobody is using, and answering a different body "that key is
                # taken" would keep it hostage for the lease as well.
                if (_now() - row.created_at).total_seconds() < RESERVATION_LEASE_SECONDS:
                    raise IdempotencyInFlight(endpoint, key)
                if not _claim_expired(session, row, request_digest=request_digest):
                    # Another retry took it over between the read and the write.
                    # It is the one executing now, so this one waits, exactly as it
                    # would have on the original request.
                    raise IdempotencyInFlight(endpoint, key)
                LOG.warning(
                    "Idempotency reservation on %s for key %r (tenant %s, actor %s) outlived "
                    "its %ds lease and was taken over; the request that made it never answered",
                    endpoint,
                    key,
                    tenant_id,
                    actor,
                    RESERVATION_LEASE_SECONDS,
                )
                return None
            if row.request_digest and row.request_digest != request_digest:
                raise IdempotencyMismatch(endpoint, key)
            stored = dict(row.response)
            break
    if stored is None:
        # Both passes lost the key to a writer of the other generation and
        # neither left an answer behind. Honest, and retryable: somebody else
        # is executing this key right now.
        raise IdempotencyInFlight(endpoint, key)
    metrics_service.IDEMPOTENT_REPLAYS_TOTAL.labels(endpoint=endpoint).inc()
    LOG.info("Idempotent replay on %s for key %r (tenant %s)", endpoint, key, tenant_id)
    return stored


def _row_for(
    session: Any, *, tenant_id: str, endpoint: str, key: str, actor: str | None
) -> models.IdempotencyRecord | None:
    """This key's record for one owner. ``actor=None`` asks for the legacy row."""
    owner = (
        models.IdempotencyRecord.actor.is_(None)
        if actor is None
        else models.IdempotencyRecord.actor == actor
    )
    return session.execute(
        select(models.IdempotencyRecord).where(
            models.IdempotencyRecord.tenant_id == tenant_id,
            models.IdempotencyRecord.endpoint == endpoint,
            models.IdempotencyRecord.key == key,
            owner,
        )
    ).scalars().first()


def _answer_from_legacy(
    session: Any,
    legacy: models.IdempotencyRecord,
    *,
    endpoint: str,
    key: str,
    request_digest: str,
) -> dict[str, Any] | None:
    """What a pre-``actor`` row says about this request, or ``None`` for "nothing".

    Rows written before ``0055_idempotency_actor`` carry no owner, and there is
    nothing to derive one from: the table never recorded who reserved a key. So
    for the day they survive they keep the semantics they were written under —
    tenant-wide — which is the only reading that does not lose a replay. The
    alternative, ignoring them, would let a retry arriving a second after the
    deploy apply its batch again, and that is the one outcome the key exists to
    prevent.

    TODO(contract step, #346): delete this function, the ``actor=None`` read in
    :func:`reserve`, the ``uq_idempotency_legacy_tenant_endpoint_key`` index and
    the ``idempotency_records_cross_generation`` trigger one release after
    ``0055`` ships. No row without an actor can exist :data:`RETENTION_SECONDS`
    after that deploy, and while these stay a legacy key is still read
    tenant-wide — the namespace this change exists to close. Tracked in
    ``ROADMAP.md`` (Track A) and ``docs/operations.md``.

    A legacy reservation whose lease is up is deleted rather than taken over:
    the caller is about to insert a row of its own, owned properly, and two
    rows for one key would then be two answers to one question.
    """
    if legacy.response is None:
        if (_now() - legacy.created_at).total_seconds() < RESERVATION_LEASE_SECONDS:
            raise IdempotencyInFlight(endpoint, key)
        session.execute(
            delete(models.IdempotencyRecord).where(
                models.IdempotencyRecord.id == legacy.id,
                models.IdempotencyRecord.response.is_(None),
            )
        )
        LOG.warning(
            "Dropped an unowned idempotency reservation on %s for key %r that outlived "
            "its %ds lease",
            endpoint,
            key,
            RESERVATION_LEASE_SECONDS,
        )
        return None
    if legacy.request_digest and legacy.request_digest != request_digest:
        raise IdempotencyMismatch(endpoint, key)
    return dict(legacy.response)


def _claim_expired(
    session: Any,
    row: models.IdempotencyRecord,
    *,
    request_digest: str,
) -> bool:
    """Take over a reservation whose lease is up. True when this call won it.

    A conditional UPDATE rather than a read-then-write, for the same reason the
    INSERT in :func:`reserve` is the mechanism and not an optimisation: two
    retries arriving together on a dead key must not both decide they may
    execute. The row's ``created_at`` moves, so the takeover gets a full lease
    of its own.
    """
    result = session.execute(
        update(models.IdempotencyRecord)
        .where(
            models.IdempotencyRecord.id == row.id,
            models.IdempotencyRecord.response.is_(None),
            models.IdempotencyRecord.created_at
            < _now() - timedelta(seconds=RESERVATION_LEASE_SECONDS),
        )
        .values(request_digest=request_digest, created_at=_now())
    )
    return bool(result.rowcount)


def complete(
    settings: Settings,
    *,
    tenant_id: str,
    actor: str,
    endpoint: str,
    key: str,
    response: dict[str, Any],
) -> None:
    """Store the answer this key's request produced, so a retry replays it."""
    with get_session(settings.postgres_url) as session:
        row = _row_for(
            session, tenant_id=tenant_id, endpoint=endpoint, key=key, actor=actor
        )
        if row is None:
            # Purged, or released by a concurrent failure path. The work is
            # done and the caller is about to be told so; losing the ability to
            # replay it is not worth failing the request over.
            LOG.warning(
                "Idempotency record for %s key %r vanished before completion", endpoint, key
            )
            return
        row.response = response


def release(
    settings: Settings, *, tenant_id: str, actor: str, endpoint: str, key: str
) -> None:
    """Drop an *unanswered* reservation, so a failed request may be retried.

    Deliberately conditional on ``response IS NULL``: a record that already
    carries an answer is that answer, and deleting it would let a retry apply
    the batch a second time. Conditional on ``actor`` for the same reason
    :func:`reserve` is: the only reservation a failed request may give back is
    its own.
    """
    with get_session(settings.postgres_url) as session:
        session.execute(
            delete(models.IdempotencyRecord).where(
                models.IdempotencyRecord.tenant_id == tenant_id,
                models.IdempotencyRecord.actor == actor,
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
