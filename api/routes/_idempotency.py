"""``Idempotency-Key`` as a route-level guard (#346).

The mechanism lives in :mod:`api.services.idempotency`; this is the four lines
of HTTP semantics around it that every write endpoint accepting a key would
otherwise re-type: read the header, translate the service's two refusals into
409, hand back a stored answer, and — the part that is easy to forget — give
the key back when the handler failed, so a caller whose batch died on a 500 can
retry with the same key.

``POST /api/jobs`` does **not** use this and is not being changed to: a scan
start hangs its key on the job row it creates
(:func:`api.services.jobs.find_by_idempotency_key`), which is strictly better
where the request produces a row, and it also has to answer 200-instead-of-202
and count its own replays. This guard is for the endpoints that produce no row
of their own — the bulk verbs.

Declared as a plain helper rather than a FastAPI dependency because the guard
has to bracket the work: a dependency runs before the handler and cannot be
told whether the handler succeeded.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Header, HTTPException, status

from api.services import idempotency as idempotency_service
from api.settings import Settings

#: The header, as a route parameter. 200 characters is the ceiling
#: ``idempotency.normalise_key`` truncates to — the same one the scan start
#: uses, so one client library can mint one shape of key for everything.
IdempotencyKeyHeader = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        description=(
            "Names this write so a retry after a timeout replays the first "
            "answer instead of applying it twice. Reusing a key with a "
            "different body is 409, as is a retry that arrives while the "
            "first request is still running."
        ),
    ),
]


class IdempotencyGuard:
    """One request's claim on a key. Built by :func:`begin`.

    ``replay`` is the answer an earlier identical request already produced, or
    ``None`` when this request is the one that has to do the work. With no key
    presented at all, the guard is inert: ``replay`` is ``None`` and both
    :meth:`store` and :meth:`release` do nothing.
    """

    def __init__(
        self,
        settings: Settings,
        *,
        tenant_id: str,
        endpoint: str,
        key: str,
        replay: dict[str, Any] | None,
    ) -> None:
        self._settings = settings
        self._tenant_id = tenant_id
        self._endpoint = endpoint
        self._key = key
        self.replay = replay

    def store(self, response: dict[str, Any]) -> None:
        """Remember what this request answered, so a retry replays it."""
        if not self._key:
            return
        idempotency_service.complete(
            self._settings,
            tenant_id=self._tenant_id,
            endpoint=self._endpoint,
            key=self._key,
            response=response,
        )

    def release(self) -> None:
        """Give the key back after a failure, so the caller may retry with it."""
        if not self._key:
            return
        idempotency_service.release(
            self._settings,
            tenant_id=self._tenant_id,
            endpoint=self._endpoint,
            key=self._key,
        )


def begin(
    settings: Settings,
    *,
    tenant_id: str,
    endpoint: str,
    key: str | None,
    payload: Any,
) -> IdempotencyGuard:
    """Claim ``key`` for this request, or return a guard carrying the replay.

    ``payload`` is what the key is a name *for* — its digest is what makes a
    replay checkable, so it must contain everything that decides what the
    request does and nothing that varies between honest retries.

    409 for both refusals, with different detail: a key reused for a different
    body is permanent and the caller must pick another key, while a key still
    in flight resolves by itself and the caller may retry.
    """
    normalised = idempotency_service.normalise_key(key)
    if not normalised:
        return IdempotencyGuard(
            settings, tenant_id=tenant_id, endpoint=endpoint, key="", replay=None
        )
    try:
        replay = idempotency_service.reserve(
            settings,
            tenant_id=tenant_id,
            endpoint=endpoint,
            key=normalised,
            request_digest=idempotency_service.digest(payload),
        )
    except (
        idempotency_service.IdempotencyMismatch,
        idempotency_service.IdempotencyInFlight,
    ) as exc:
        # 409, not 422: the body is well-formed, the *key* is taken.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return IdempotencyGuard(
        settings, tenant_id=tenant_id, endpoint=endpoint, key=normalised, replay=replay
    )
