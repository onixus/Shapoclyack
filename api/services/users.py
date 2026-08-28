"""Console accounts, Postgres-backed (#156).

Replaces ``OCTO_API_USERS`` as the source of truth. The env var survives as a
*bootstrap* input only: it is imported once, into an empty table, and after
that the table wins — the same shape as the one-time import of the legacy
``state/api_{jobs,agents}.json`` files in ROADMAP P1.2.

Two rules carry most of the security value here:

1. **Only hashes are stored.** ``hash_password``/``verify_password`` come from
   ``api.auth``, which is the same passlib context ``ProvisioningKey`` uses.
   The pre-#156 store compared plaintext whenever the configured value did not
   start with ``$2``; nothing here reproduces that.
2. **The built-in demo accounts are never written to the table.** Their
   passwords are published in this repository, so importing them would re-open
   through the database exactly the hole #155 closed at the environment level.
   They exist only when ``OCTO_ENV=dev`` explicitly seeds them.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

from api.auth import hash_password, verify_password
from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.settings import ENV_PROD, InsecureConfigurationError, Settings

logger = logging.getLogger(__name__)

VALID_ROLES = ("viewer", "operator", "admin")

_settings: Settings | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "users_service.configure()/bootstrap() not called"
    return _settings


def _iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _to_dict(row: models.User) -> dict[str, Any]:
    """Public shape. There is no code path that returns password material."""
    return {
        "username": row.username,
        "role": row.role,
        "disabled": row.disabled_at is not None,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "disabled_at": _iso(row.disabled_at),
        "password_changed_at": _iso(row.password_changed_at),
        "created_by": row.created_by,
        # An account backfilled by migration 0013, or one whose password was
        # never set. Surfaced so an admin can tell "disabled by someone" from
        # "never had a password" without exposing the hash itself.
        "has_password": bool(row.password_hash),
    }


def _validate_role(role: str) -> str:
    if role not in VALID_ROLES:
        raise ValueError(f"role must be one of {', '.join(VALID_ROLES)}")
    return role


def _validate_username(username: str) -> str:
    cleaned = (username or "").strip()
    if not cleaned:
        raise ValueError("username must not be empty")
    if len(cleaned) > 128:
        raise ValueError("username must be at most 128 characters")
    return cleaned


def _validate_password(password: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    # A floor, not a policy: bcrypt silently truncates beyond 72 bytes, so a
    # longer value would make part of what the operator typed decorative.
    if len(password.encode("utf-8")) > 72:
        raise ValueError("password must be at most 72 bytes")
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return password


def authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Verify credentials against the table. Returns the user dict or None.

    Never distinguishes "no such user" from "wrong password" to the caller —
    that difference is the whole of a username-enumeration oracle, and #157
    will add the rate limit that makes the distinction expensive to probe.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        if row.disabled_at is not None:
            return None
        # Checked explicitly rather than trusting bcrypt to reject "": a
        # migration-backfilled placeholder must never authenticate, and that
        # should not depend on a library's behaviour with an empty digest.
        if not row.password_hash:
            return None
        try:
            if not verify_password(password, row.password_hash):
                return None
        except ValueError:
            # passlib raises (UnknownHashError, a ValueError) rather than
            # returning False when the stored value is not a recognisable
            # hash — which is exactly what a row left over from the pre-#156
            # plaintext era looks like. Uncaught, that surfaces as a 500 on the
            # login endpoint, so a malformed credential would be reported as a
            # server fault instead of a failed login. Refuse instead.
            logger.warning(
                "User %r has an unusable password hash and cannot authenticate; "
                "reset it with PUT /api/users/{username}/password.",
                username,
            )
            return None
        return _to_dict(row)


def list_users() -> list[dict[str, Any]]:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        rows = session.execute(select(models.User).order_by(models.User.username)).scalars().all()
        return [_to_dict(row) for row in rows]


def get_user(username: str) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        return _to_dict(row) if row else None


def create_user(
    *, username: str, password: str, role: str, created_by: str | None = None
) -> dict[str, Any]:
    username = _validate_username(username)
    role = _validate_role(role)
    password = _validate_password(password)

    settings = _require_settings()
    now = _now()
    with get_session(settings.postgres_url) as session:
        if session.get(models.User, username) is not None:
            raise ValueError(f"user '{username}' already exists")
        row = models.User(
            username=username,
            password_hash=hash_password(password),
            role=role,
            created_at=now,
            updated_at=now,
            password_changed_at=now,
            created_by=created_by,
        )
        session.add(row)
        session.flush()
        return _to_dict(row)


def set_password(username: str, password: str) -> dict[str, Any] | None:
    password = _validate_password(password)
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        row.password_hash = hash_password(password)
        row.password_changed_at = _now()
        row.updated_at = _now()
        session.flush()
        return _to_dict(row)


def change_own_password(username: str, *, current: str, new: str) -> dict[str, Any] | None:
    """Rotate one's own password, re-verifying the current one first.

    Separate from :func:`set_password` on purpose: an admin resetting someone
    else's password does not know the old one, while a user changing their own
    must prove they are still the one sitting at the session.
    """
    if authenticate(username, current) is None:
        return None
    return set_password(username, new)


def set_role(username: str, role: str) -> dict[str, Any] | None:
    role = _validate_role(role)
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        row.role = role
        row.updated_at = _now()
        session.flush()
        return _to_dict(row)


def set_disabled(username: str, disabled: bool) -> dict[str, Any] | None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return None
        row.disabled_at = _now() if disabled else None
        row.updated_at = _now()
        session.flush()
        return _to_dict(row)


def count_active_admins(exclude: str | None = None) -> int:
    """Enabled accounts with the admin role, optionally ignoring one username.

    Used to refuse the last-admin lockout: disabling or demoting the only
    remaining admin leaves an installation whose user management can only be
    recovered by editing the database by hand.
    """
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.User).where(
            models.User.role == "admin",
            models.User.disabled_at.is_(None),
            models.User.password_hash != "",
        )
        if exclude:
            stmt = stmt.where(models.User.username != exclude)
        return len(session.execute(stmt).scalars().all())


def delete_user(username: str) -> bool:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            return False
        # Memberships cascade (FK from migration 0013), so no orphan grant
        # survives to be silently re-attached if the name is recreated later.
        session.delete(row)
        return True


def reset_for_tests() -> None:
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        session.query(models.User).delete()


def _has_any_usable_account(session) -> bool:
    stmt = select(models.User).where(
        models.User.disabled_at.is_(None),
        models.User.password_hash != "",
    )
    return session.execute(stmt).scalars().first() is not None


def bootstrap(settings: Settings) -> None:
    """Configure the service, import legacy env users once, and check we can log in.

    Called from ``create_app()`` after the tenant store is up. Three outcomes:

    * ``OCTO_API_USERS`` is set and the table holds no usable account — the env
      users are imported (plaintext hashed on the way in) and the variable
      stops being consulted from then on. Import, not sync: a later edit to the
      variable is ignored, because two sources of truth is the state this
      change exists to leave.
    * ``OCTO_ENV=dev`` with nothing configured — the built-in demo accounts are
      seeded, so the kind overlay and the test suite keep working.
    * ``OCTO_ENV=prod`` with nothing configured — refuses to start, naming how
      to supply the first account. An install nobody can log into is a failure
      whether it is reported at startup or discovered at the login form, and
      the startup message is the one that says why.
    """
    configure(settings)

    with get_session(settings.postgres_url) as session:
        if _has_any_usable_account(session):
            return

    imported = _import_env_users(settings)
    if imported:
        logger.warning(
            "Imported %d account(s) from OCTO_API_USERS into the users table. "
            "The table is the source of truth from now on: later edits to the "
            "variable are ignored, and passwords rotate via POST /api/auth/password "
            "or PUT /api/users/{username}/password. Remove the variable once the "
            "import is confirmed.",
            imported,
        )
        return

    if settings.env != ENV_PROD:
        _seed_dev_users(settings)
        return

    raise InsecureConfigurationError(
        "Refusing to start: no console account exists and none was supplied.\n\n"
        "  Console users live in Postgres since #156. Seed the first account by\n"
        "  setting OCTO_API_USERS once (a JSON list of\n"
        '  {"username": ..., "password": ..., "role": "admin"}); it is imported\n'
        "  into the users table on the next start and then stops being consulted.\n\n"
        "  The built-in demo accounts are deliberately not seeded here: their\n"
        "  passwords are published in this repository. They exist only under\n"
        "  OCTO_ENV=dev."
    )


def _import_env_users(settings: Settings) -> int:
    """Import ``settings.users`` unless it is the built-in default list.

    Returns the number of accounts written. Passwords already stored as bcrypt
    (``$2``…) are carried across as-is; anything else is hashed here, which is
    the one and only place plaintext is still accepted — and it is accepted as
    *input to hashing*, never as a stored value.
    """
    from api.settings import DEFAULT_USERS

    configured = settings.users or []
    if not configured or configured == DEFAULT_USERS:
        return 0

    now = _now()
    written = 0
    with get_session(settings.postgres_url) as session:
        for entry in configured:
            username = str(entry.get("username", "")).strip()
            password = str(entry.get("password", ""))
            role = str(entry.get("role", "viewer"))
            if not username or not password:
                logger.warning(
                    "Skipping an OCTO_API_USERS entry with no username or no password."
                )
                continue
            if role not in VALID_ROLES:
                logger.warning(
                    "OCTO_API_USERS entry %r has an unknown role; importing as viewer.",
                    username,
                )
                role = "viewer"
            if session.get(models.User, username) is not None:
                continue
            session.add(
                models.User(
                    username=username,
                    password_hash=password if password.startswith("$2") else hash_password(password),
                    role=role,
                    created_at=now,
                    updated_at=now,
                    password_changed_at=now,
                    created_by="import:OCTO_API_USERS",
                )
            )
            written += 1
    return written


def _seed_dev_users(settings: Settings) -> None:
    """Seed the built-in demo accounts. Only reachable when OCTO_ENV != prod."""
    from api.settings import DEFAULT_USERS

    now = _now()
    with get_session(settings.postgres_url) as session:
        for entry in DEFAULT_USERS:
            username = str(entry["username"])
            # Not check-then-insert: nothing separates the lookup from the
            # insert, and this runs at startup in every replica at once (and,
            # in the suite, against a database a leftover worker thread is
            # still writing to). The row a racing writer inserted is the same
            # row, so losing the race is a no-op -- but only if the failure is
            # scoped to it, which is what insert_if_absent's SAVEPOINT buys.
            insert_if_absent(
                session,
                models.User(
                    username=username,
                    password_hash=hash_password(str(entry["password"])),
                    role=str(entry["role"]),
                    created_at=now,
                    updated_at=now,
                    password_changed_at=now,
                    created_by="seed:dev",
                ),
                username,
            )
    logger.warning(
        "OCTO_ENV=%s: seeded the built-in demo accounts, whose passwords are "
        "published in this repository. Never expose this installation.",
        settings.env,
    )
