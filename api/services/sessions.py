"""Console session state: is this token still the one we issued? (#314)

Everything a console JWT asserts used to be believed for its whole life. This
module is the one place that asks the database instead, and it is on the path
of every authenticated request, so it is deliberately primary-key lookups
inside a single session and nothing else — three for a token with a ``sid``,
two for one minted before refresh tokens:

1. the account still exists and is not disabled, and its ``token_version``
   still matches the ``ver`` the token carries — this is what makes disable,
   delete, demote and a password change end a session;
2. the token's own ``jti`` is not on the logout denylist — this is what makes
   one session end without ending the others;
3. the session family the token was minted for (its ``sid``) has not ended —
   which is what makes logout, a detected refresh-token reuse and the idle
   timeout reach the short-lived access token as well as the refresh token.

It also owns the refresh-token half of a session: opening a family at sign-in
(:func:`open_session`) and rotating its refresh token (:func:`rotate`). See
``SessionFamily`` in ``api/db/models.py`` for the three clocks a family keeps.

The role comes back from the same lookup rather than from the claim. It costs
nothing extra once the row has been read, and it is the difference between a
demotion taking effect now and taking effect in eight hours. The claim's role
is still parsed and validated by the caller, so a malformed token is refused
exactly as it was before.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
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


#: Why a session family ended, as written to ``session_families.revoked_reason``.
END_LOGOUT = "logout"
END_REUSE = "reuse"
END_IDLE = "idle"
END_EXPIRED = "expired"
END_REVOKED = "revoked"
#: The only tenant the account could act in was suspended or deleted (#325).
END_TENANT_CLOSED = "tenant_closed"

# Bytes of randomness in a refresh token. 32 is the same width as the JWT
# signing key: the token is a bearer credential for hours, and it is looked up
# by an unsalted digest, so it has to be unguessable on its own.
_REFRESH_TOKEN_BYTES = 32


class RefreshTokenReused(PermissionError):
    """A refresh token was presented after it had already been exchanged.

    Either the browser it was issued to or somebody holding a copy has the
    successor — the server cannot tell which — so the whole family has been
    ended by the time this is raised. A subclass of :class:`PermissionError`
    so a caller that only wants "refused" needs no second ``except``; the
    route catches it separately to write the event to the auth trail.
    """

    def __init__(self, *, username: str, family_id: str) -> None:
        super().__init__("refresh token was already used")
        self.username = username
        self.family_id = family_id


@dataclass(frozen=True)
class OpenedSession:
    """A session family just opened or extended, with its new refresh token.

    ``refresh_token`` is the plaintext and exists only here, on its way into a
    cookie; the table holds its digest.
    """

    family_id: str
    refresh_token: str
    expires_at: datetime
    username: str
    role: str
    # The account's generation, read in the same transaction as everything
    # else here, so the access token can be signed without another query.
    token_version: int
    mfa_verified_at: datetime | None = None
    # The factor that proof was made with (#315), carried the same way.
    mfa_method: str | None = None


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
    settings: Settings,
    *,
    username: str,
    token_version: int,
    jti: str | None,
    session_id: str | None = None,
) -> SessionState:
    """Resolve a presented console token to live account state.

    Raises :class:`PermissionError` — never an HTTP error — for every reason a
    token is no longer good: no such account, disabled, a stale ``ver``, a
    ``jti`` that was logged out, or a session family (``sid``) that has ended.
    The caller turns all of them into one 401 with one message, because which
    of them applies is information only the presenter of a dead token is
    interested in.

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
            if session_id is not None:
                # A missing row is refused like an ended one: the sweep only
                # deletes families past their absolute end, which no access
                # token outlives, so a token naming one that is gone names a
                # session that is over.
                family = session.get(models.SessionFamily, session_id)
                if family is None or family.revoked_at is not None:
                    raise PermissionError("session has ended")
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

    The account's open session families are marked ended as well. Not needed
    for correctness — a refresh already compares the family's generation with
    the account's — but it keeps ``session_families`` telling the truth about
    which sessions are live.
    """
    with get_session(settings.postgres_url) as session:
        version = revoke_all_in_session(session, username, reason=END_REVOKED)
        if version is None:
            raise LookupError(f"user '{username}' not found")
        return version


def revoke_all_in_session(session, username: str, *, reason: str) -> int | None:
    """:func:`revoke_all` in the caller's transaction; None for an unknown account.

    For a change that ends somebody's sessions as a consequence of something
    else — suspending the tenant they belong to (#325) — and has to commit or
    roll back with it: a suspension that rolled back must not have signed its
    members out, and one that committed must not leave them signed in.
    """
    row = session.get(models.User, username)
    if row is None:
        return None
    row.token_version = int(row.token_version or 0) + 1
    row.updated_at = _now()
    session.execute(
        update(models.SessionFamily)
        .where(
            models.SessionFamily.username == username,
            models.SessionFamily.revoked_at.is_(None),
        )
        .values(revoked_at=_now(), revoked_reason=reason)
    )
    session.flush()
    return int(row.token_version)


def _digest(refresh_token: str) -> str:
    return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()


def _naive(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is None:
        return value
    return value.astimezone(UTC).replace(tzinfo=None)


def _aware(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None else None


def _end(family: models.SessionFamily, now: datetime, reason: str) -> None:
    family.revoked_at = now
    family.revoked_reason = reason


def open_session(
    settings: Settings,
    *,
    username: str,
    mfa_verified_at: datetime | None = None,
    mfa_method: str | None = None,
) -> OpenedSession:
    """Open a session family for a completed sign-in and issue its first refresh token.

    The family's generation is read from the account row in the same
    transaction, so a revocation racing the sign-in wins exactly as it does for
    the access token (:func:`current_version`). A missing account is a
    :class:`LookupError`, which every caller already maps to the refusal it
    gives a wrong password.

    Families past their absolute end are swept here, for the reason the
    denylist is swept on logout: it is one index scan, and a table that only
    grows while people are signing in needs no worker of its own. Their
    refresh tokens go with them (``ON DELETE CASCADE``).
    """
    now = _now()
    plaintext = secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)
    family_id = uuid.uuid4().hex
    expires_at = now + timedelta(minutes=settings.jwt_expire_minutes)
    with get_session(settings.postgres_url) as session:
        session.execute(
            delete(models.SessionFamily).where(models.SessionFamily.expires_at < now)
        )
        row = session.get(models.User, username)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        session.add(
            models.SessionFamily(
                family_id=family_id,
                username=username,
                token_version=int(row.token_version or 0),
                created_at=now,
                expires_at=expires_at,
                last_used_at=now,
                mfa_verified_at=_naive(mfa_verified_at),
                mfa_method=mfa_method if mfa_verified_at is not None else None,
            )
        )
        session.flush()
        session.add(
            models.RefreshToken(token_hash=_digest(plaintext), family_id=family_id, issued_at=now)
        )
        return OpenedSession(
            family_id=family_id,
            refresh_token=plaintext,
            expires_at=expires_at.replace(tzinfo=UTC),
            username=username,
            role=row.role,
            token_version=int(row.token_version or 0),
            mfa_verified_at=mfa_verified_at,
            mfa_method=mfa_method if mfa_verified_at is not None else None,
        )


def rotate(settings: Settings, refresh_token: str) -> OpenedSession:
    """Exchange a refresh token for its successor, or end the session trying.

    Everything that can refuse a refresh is decided under a row lock on the
    presented token and its family, so two presentations of the same token
    serialize: the first is exchanged, the second finds ``used_at`` set.

    Refusals are :class:`PermissionError`, in two kinds:

    * those that end the family and are **committed** before the error leaves
      this function — the token was already used (:class:`RefreshTokenReused`),
      the absolute lifetime is over, the idle timeout passed, or the account
      was disabled, deleted or had its sessions revoked since the sign-in;
    * those with nothing to write — an unknown token, or a family that had
      already ended.

    There is deliberately no grace window for a token presented twice in quick
    succession. Two tabs racing one cookie look exactly like a thief racing
    the browser, and a window wide enough for the first is wide enough for the
    second; the console serialises its own refreshes instead
    (``refreshAccessToken`` in ``web-next/src/lib/api.ts``).

    Everything the caller needs to sign the next access token — the role and
    the account's generation — comes back from this transaction, so nothing
    between the commit that spends the presented token and the response that
    carries its successor has to reach the database again.

    An unreachable database is :class:`SessionStoreUnavailable`, as on every
    other request: "try again", not "sign in again".
    """
    now = _now()
    refusal: PermissionError | None = None
    rotated: OpenedSession | None = None
    try:
        with get_session(settings.postgres_url) as session:
            token = session.get(models.RefreshToken, _digest(refresh_token), with_for_update=True)
            if token is None:
                raise PermissionError("unknown refresh token")
            family = session.get(models.SessionFamily, token.family_id, with_for_update=True)
            if family is None or family.revoked_at is not None:
                raise PermissionError("session has ended")
            account = session.get(models.User, family.username)
            idle = settings.session_idle_minutes
            if token.used_at is not None:
                _end(family, now, END_REUSE)
                refusal = RefreshTokenReused(username=family.username, family_id=family.family_id)
            elif now >= family.expires_at:
                _end(family, now, END_EXPIRED)
                refusal = PermissionError("session has expired")
            elif idle and now - family.last_used_at > timedelta(minutes=idle):
                _end(family, now, END_IDLE)
                refusal = PermissionError("session was idle for too long")
            elif (
                account is None
                or account.disabled_at is not None
                or int(account.token_version or 0) != int(family.token_version)
            ):
                _end(family, now, END_REVOKED)
                refusal = PermissionError("session was revoked")
            else:
                successor = secrets.token_urlsafe(_REFRESH_TOKEN_BYTES)
                token.used_at = now
                family.last_used_at = now
                session.add(
                    models.RefreshToken(
                        token_hash=_digest(successor), family_id=family.family_id, issued_at=now
                    )
                )
                rotated = OpenedSession(
                    family_id=family.family_id,
                    refresh_token=successor,
                    expires_at=family.expires_at.replace(tzinfo=UTC),
                    username=family.username,
                    role=account.role,
                    token_version=int(account.token_version or 0),
                    mfa_verified_at=_aware(family.mfa_verified_at),
                    mfa_method=family.mfa_method,
                )
    except SQLAlchemyError as exc:
        logger.warning("session store unavailable: %s", exc)
        raise SessionStoreUnavailable("session store is unavailable") from exc
    if refusal is not None:
        raise refusal
    assert rotated is not None
    return rotated


def end_session(settings: Settings, family_id: str, *, reason: str = END_LOGOUT) -> None:
    """Mark one session family ended. Idempotent: an ended one keeps its first reason."""
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.SessionFamily)
            .where(
                models.SessionFamily.family_id == family_id,
                models.SessionFamily.revoked_at.is_(None),
            )
            .values(revoked_at=_now(), revoked_reason=reason)
        )


def end_session_by_refresh_token(settings: Settings, refresh_token: str) -> None:
    """End the family a refresh token belongs to, whatever state the token is in.

    What logout does with the cookie it is sent: the refresh token is the half
    of a session that would otherwise outlive the sign-out by hours, and it
    need not belong to the family the access token names — a console that
    signed in twice holds the newer cookie. An unknown token is a no-op.
    """
    with get_session(settings.postgres_url) as session:
        token = session.get(models.RefreshToken, _digest(refresh_token))
        family_id = token.family_id if token is not None else None
    if family_id is not None:
        end_session(settings, family_id)


def record_step_up(
    settings: Settings, family_id: str, verified_at: datetime, *, method: str | None = None
) -> datetime:
    """Stamp a fresh second-factor proof on a live family; return its absolute end.

    So the access tokens refreshed from it afterwards carry the step-up rather
    than the proof from sign-in. A family that has ended is a
    :class:`PermissionError`: the step-up was made with a session that is over.

    ``method`` is written in the same statement as the time (#315), always —
    ``None`` included. A code-proved step-up after a key-proved sign-in must
    replace the label along with the time; keeping the old ``webauthn`` next
    to a newer code proof would let the next refresh pass a key-only step-up.
    One conditional ``UPDATE`` rather than read-then-write, so there is no
    window in which the two columns disagree.
    """
    with get_session(settings.postgres_url) as session:
        expires_at = session.execute(
            update(models.SessionFamily)
            .where(
                models.SessionFamily.family_id == family_id,
                models.SessionFamily.revoked_at.is_(None),
            )
            .values(mfa_verified_at=_naive(verified_at), mfa_method=method)
            .returning(models.SessionFamily.expires_at)
        ).scalar_one_or_none()
        if expires_at is None:
            raise PermissionError("session has ended")
        return expires_at.replace(tzinfo=UTC)


def get_family(settings: Settings, family_id: str) -> models.SessionFamily | None:
    """One family row, detached — for tests and for "why did this session end"."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.SessionFamily, family_id)
        if row is not None:
            session.expunge(row)
        return row


def count_revoked(settings: Settings, username: str | None = None) -> int:
    """Denylist size, for tests and for the operational "is the sweep working"."""
    with get_session(settings.postgres_url) as session:
        stmt = select(models.RevokedToken)
        if username is not None:
            stmt = stmt.where(models.RevokedToken.username == username)
        return len(session.execute(stmt).scalars().all())
