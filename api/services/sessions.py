"""Console session state: is this token still the one we issued? (#314)

Everything a console JWT asserts used to be believed for its whole life. This
module is the one place that asks the database instead, and it is on the path
of every authenticated request, so it is deliberately two primary-key lookups
inside a single session and nothing else:

1. the account still exists and is not disabled, and its ``token_version``
   still matches the ``ver`` the token carries — this is what makes disable,
   delete, demote and a password change end a session;
2. the token's own ``jti`` is not on the logout denylist — this is what makes
   one session end without ending the others.

The role comes back from the same lookup rather than from the claim. It costs
nothing extra once the row has been read, and it is the difference between a
demotion taking effect now and taking effect in eight hours. The claim's role
is still parsed and validated by the caller, so a malformed token is refused
exactly as it was before.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.exc import SQLAlchemyError

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.settings import Settings

logger = logging.getLogger(__name__)


class SessionStoreUnavailable(RuntimeError):
    """The session store could not be reached, so the token is undecided.

    Distinct from :class:`PermissionError` on purpose: "the database is down"
    is not "your session was revoked". Before #314 an unreachable Postgres cost
    the console the endpoints that read it; now the check is on the path of
    every authenticated request, so mapping the failure to a 401 would sign the
    whole console out over an outage and mapping it to a 500 would report a bug
    the operator does not have. The caller answers 503 with ``Retry-After``.
    """


@dataclass(frozen=True)
class SessionState:
    """What the database says about the account behind a presented token."""

    username: str
    role: str
    token_version: int


def _now() -> datetime:
    # Naive UTC: every timestamp column in this schema is naive, and a mix of
    # aware and naive values compares as an error rather than as a date.
    return datetime.now(UTC).replace(tzinfo=None)


def check_session(
    settings: Settings, *, username: str, token_version: int, jti: str | None
) -> SessionState:
    """Resolve a presented console token to live account state.

    Raises :class:`PermissionError` — never an HTTP error — for every reason a
    token is no longer good: no such account, disabled, a stale ``ver``, or a
    ``jti`` that was logged out. The caller turns all of them into one 401 with
    one message, because which of the four applies is information only the
    presenter of a dead token is interested in.

    A database that cannot be reached is :class:`SessionStoreUnavailable`
    instead: the answer is unknown, not "no". Every authenticated request
    passes through here, so an outage that raised out of this function would
    turn into a 500 on the whole API rather than the 503 an operator can read
    and a client can retry.
    """
    try:
        with get_session(settings.postgres_url) as session:
            row = session.get(models.User, username)
            if row is None:
                raise PermissionError("no such account")
            if row.disabled_at is not None:
                raise PermissionError("account is disabled")
            if int(row.token_version or 0) != int(token_version):
                raise PermissionError("session was revoked")
            if jti is not None:
                revoked = session.get(models.RevokedToken, jti)
                if revoked is not None:
                    raise PermissionError("session was logged out")
            return SessionState(
                username=row.username, role=row.role, token_version=int(row.token_version or 0)
            )
    except SQLAlchemyError as exc:
        # Logged because this is the one refusal that is the platform's fault
        # and not the caller's; the message stays generic on the wire.
        logger.warning("session store unavailable: %s", exc)
        raise SessionStoreUnavailable("session store is unavailable") from exc


def current_version(settings: Settings, username: str) -> int:
    """The generation a token minted for this account right now belongs to.

    Read at issue time rather than carried from the login lookup so that a
    revocation racing a login loses: the token is stamped with whatever the
    column holds at the moment it is signed.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        return int(row.token_version or 0)


def revoke_token(
    settings: Settings, *, jti: str, username: str, expires_at: datetime
) -> None:
    """Put one token on the denylist until it expires on its own.

    Idempotent, and idempotent under a race: the ``jti`` is the primary key, so
    logging out twice writes the same row, and ``insert_if_absent`` scopes the
    conflict to a SAVEPOINT so two replicas answering the same logout do not
    turn the loser's request into a 500. Losing that race is a no-op — the row
    the winner wrote is this row.

    Expired rows are swept here rather than by a background job: the sweep's
    predicate is one index scan, this is not a hot path, and a table that only
    grows while somebody is logging out does not need a worker of its own.
    """
    expiry = expires_at.astimezone(UTC).replace(tzinfo=None) if expires_at.tzinfo else expires_at
    with get_session(settings.postgres_url) as session:
        session.execute(
            delete(models.RevokedToken).where(models.RevokedToken.expires_at < _now())
        )
        insert_if_absent(
            session,
            models.RevokedToken(
                jti=jti, username=username, revoked_at=_now(), expires_at=expiry
            ),
            jti,
        )


def revoke_all(settings: Settings, username: str) -> int:
    """End every session of one account, and return the new generation.

    Bumping ``token_version`` rather than listing the account's live tokens:
    the platform never held that list — a JWT is not stored anywhere when it is
    issued — so the only thing that can invalidate all of them at once is a
    value they all quote.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        row.token_version = int(row.token_version or 0) + 1
        row.updated_at = _now()
        session.flush()
        return int(row.token_version)


def count_revoked(settings: Settings, username: str | None = None) -> int:
    """Denylist size, for tests and for the operational "is the sweep working"."""
    with get_session(settings.postgres_url) as session:
        stmt = select(models.RevokedToken)
        if username is not None:
            stmt = stmt.where(models.RevokedToken.username == username)
        return len(session.execute(stmt).scalars().all())
