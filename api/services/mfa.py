"""Enrolment, verification and revocation of the second factor (#315).

``api/core/totp.py`` owns the arithmetic; this module owns the state around it:
which account has enrolled, which time step it has already spent, which of its
recovery codes are gone, and who turned any of that off. Everything here is a
single short transaction on one ``users`` row, because every one of those facts
has to move together with the login it decides.

**The secret is stored encrypted.** ``users.mfa_secret`` goes through
``api/services/crypto`` under its own context (#310), so a database dump does
not hand over the seeds that generate every admin's codes. With no
``OCTO_MASTER_KEY`` configured the envelope layer stores plaintext exactly as it
does for webhook secrets — the behaviour is the same one an operator has
already been told about, not a second, quieter one.

**A code is spent, not merely correct.** ``users.mfa_last_step`` is written in
the same transaction that accepts the code, and a step at or before it is
refused. That is what stops an observed code being replayed inside the thirty
seconds it stays arithmetically valid, and it is why verification takes a row
lock rather than reading and writing in two statements.

**Recovery codes are passwords.** Ten of them, hashed with the same passlib
context as ``users.password_hash``, shown once at confirmation and never
recoverable afterwards. A spent code keeps its row with a ``used_at`` stamp:
"seven of your ten codes are left" is what the console shows, and deleting the
entry would lose the count as well as the trail.

Domain errors only — ``LookupError``, ``PermissionError``, ``ValueError``. The
routes in ``api/routes/mfa.py`` decide which status each becomes.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from api.auth import hash_password, verify_password
from api.core import totp
from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import metrics as metrics_service
from api.services.crypto import envelope as crypto
from api.settings import Settings

logger = logging.getLogger(__name__)

#: GCM additional data for the stored secret. A ciphertext lifted out of this
#: column therefore does not decrypt as a webhook secret, and vice versa.
SECRET_CONTEXT = "users.mfa_secret"

#: How many recovery codes one enrolment produces. Ten is the number every
#: comparable product settles on: enough that losing a phone is survivable
#: without a support call, few enough that people keep them somewhere deliberate.
RECOVERY_CODE_COUNT = 10
#: Characters a recovery code is drawn from — no 0/O, no 1/l, no i/u — so a code
#: read off paper into a form is unambiguous. Thirty symbols over ten
#: characters is a little under 50 bits, which is not a password anybody
#: brute-forces through a rate-limited login form.
_RECOVERY_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
_RECOVERY_HALF = 5

#: How long the pre-authentication token minted by a first login factor lives.
#: It covers a person reaching for their phone, and it is not a session: see
#: ``api.auth.create_pre_auth_token`` for what it is allowed to do.
PRE_AUTH_TTL_MINUTES = 5

#: What :func:`verify` reports it accepted, for the caller's audit trail.
FACTOR_TOTP = "totp"
FACTOR_RECOVERY = "recovery"


def _now() -> datetime:
    # Naive UTC, matching every timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _generate_recovery_code() -> str:
    """One human-transcribable code, grouped as ``xxxxx-xxxxx``."""
    raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_HALF * 2))
    return f"{raw[:_RECOVERY_HALF]}-{raw[_RECOVERY_HALF:]}"


def normalise_recovery_code(value: str) -> str:
    """The form a stored code was hashed in: lower case, no spaces, no dashes."""
    return (value or "").strip().lower().replace(" ", "").replace("-", "")


def _remaining(codes: Any) -> int:
    if not isinstance(codes, list):
        return 0
    return sum(1 for entry in codes if isinstance(entry, dict) and not entry.get("used_at"))


def required_for_role(settings: Settings, role: str) -> bool:
    """Whether this installation demands a second factor of ``role``."""
    return str(role or "").lower() in settings.mfa_required_roles


def _state(row: models.User, settings: Settings) -> dict[str, Any]:
    """Public shape. Never carries the secret, a code, or a hash of either."""
    enabled = row.mfa_enabled_at is not None
    return {
        "username": row.username,
        "enabled": enabled,
        "enabled_at": _iso(row.mfa_enabled_at),
        # A secret with no ``mfa_enabled_at`` is a setup somebody started and
        # never confirmed. Surfaced so the console can offer to resume it
        # rather than silently minting a third secret.
        "setup_pending": bool(row.mfa_secret) and not enabled,
        "recovery_codes_remaining": _remaining(row.mfa_recovery_codes),
        "required": required_for_role(settings, row.role),
        "stepup_minutes": settings.mfa_stepup_minutes,
    }


def status(settings: Settings, username: str) -> dict[str, Any]:
    """What the console shows on the account's security page."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        return _state(row, settings)


def is_enabled(settings: Settings, username: str) -> bool:
    """Whether this account must present a second factor. One primary-key read."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        return row is not None and row.mfa_enabled_at is not None


def begin_setup(settings: Settings, username: str, *, issuer: str) -> dict[str, Any]:
    """Mint an unconfirmed secret and return it with its ``otpauth://`` URI.

    Nothing is enabled here: the secret is written so the confirmation can
    check a code against it, and the account keeps authenticating exactly as it
    did until :func:`confirm_setup` succeeds. Calling this twice replaces the
    unconfirmed secret — an interrupted enrolment (wrong phone, wrong app)
    should be restartable without an admin.

    Refused for an account that already has MFA on: replacing a live second
    factor is a disable followed by an enrol, and folding the two together
    would let a stolen session swap the factor without proving anything.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        if row.mfa_enabled_at is not None:
            raise ValueError(
                "multi-factor authentication is already enabled for this account; "
                "disable it first"
            )
        secret = totp.generate_secret()
        row.mfa_secret = crypto.encrypt_secret(secret, context=SECRET_CONTEXT)
        # Cleared with the new secret: the steps a *previous* secret spent say
        # nothing about this one, and leaving a high-water mark behind would
        # refuse every code until the clock caught up with it.
        row.mfa_last_step = None
        row.updated_at = _now()
        session.flush()
        return {
            "secret": secret,
            "otpauth_uri": totp.provisioning_uri(secret, account=username, issuer=issuer),
            "digits": totp.DIGITS,
            "period": totp.STEP_SECONDS,
            "algorithm": "SHA1",
        }


def confirm_setup(
    settings: Settings,
    username: str,
    code: str,
    *,
    audit: "audit_service.AuditContext | None" = None,
) -> list[str]:
    """Turn MFA on once a code proves the authenticator holds the same secret.

    Returns the ten recovery codes **in plaintext, once**. Only their hashes
    are stored, so this return value is the single moment they exist; a caller
    that drops it has cost the user their recovery codes and must reset.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username, with_for_update=True)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        if row.mfa_enabled_at is not None:
            raise ValueError("multi-factor authentication is already enabled for this account")
        secret = crypto.decrypt_secret(row.mfa_secret, context=SECRET_CONTEXT)
        if not secret:
            raise ValueError(
                "no enrolment is in progress; start one with POST /api/auth/mfa/totp/setup"
            )
        step = totp.verify(secret, code, moment=now, last_step=row.mfa_last_step)
        if step is None:
            metrics_service.MFA_VERIFICATIONS_TOTAL.labels("setup_failure").inc()
            raise PermissionError("that code is not valid for this authenticator")

        plaintext = [_generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
        row.mfa_recovery_codes = [
            {"hash": hash_password(normalise_recovery_code(item)), "used_at": None}
            for item in plaintext
        ]
        row.mfa_enabled_at = now
        row.mfa_last_step = step
        row.updated_at = now
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_MFA_ENABLE,
            resource_type="user",
            resource_id=username,
            after={
                "mfa_enabled_at": _iso(now),
                "recovery_codes_issued": RECOVERY_CODE_COUNT,
            },
        )
        metrics_service.MFA_VERIFICATIONS_TOTAL.labels("setup_success").inc()
        return plaintext


def verify(
    settings: Settings,
    username: str,
    *,
    code: str | None = None,
    recovery_code: str | None = None,
) -> str:
    """Accept one second factor and spend it. Returns which kind was accepted.

    Both kinds are consumed in the same transaction that accepts them — the
    TOTP step by moving ``mfa_last_step``, the recovery code by stamping
    ``used_at`` — and the row is locked for the duration, so two requests
    presenting the same code cannot both win the race.

    Raises ``PermissionError`` for every refusal, with one message: which of
    "wrong code", "already used" and "no codes left" applies is of interest
    only to somebody who does not have the factor.
    """
    now = _now()
    refusal = PermissionError("that code is not valid")
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username, with_for_update=True)
        if row is None or row.mfa_enabled_at is None:
            # An account with no MFA has no second factor to accept. Not a
            # success: a caller that reaches here has been told a factor was
            # required, and answering "fine" would be the check disabling itself.
            metrics_service.MFA_VERIFICATIONS_TOTAL.labels("failure").inc()
            raise refusal

        supplied_recovery = normalise_recovery_code(recovery_code or "")
        if supplied_recovery:
            entries = row.mfa_recovery_codes if isinstance(row.mfa_recovery_codes, list) else []
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict) or entry.get("used_at"):
                    continue
                stored = str(entry.get("hash") or "")
                try:
                    matched = bool(stored) and verify_password(supplied_recovery, stored)
                except ValueError:
                    # An unreadable hash is a broken row, not a match. Logged
                    # without the username's codes: the operator's fix is a
                    # reset, and the trail already names who could not log in.
                    logger.warning(
                        "User %r has an unusable recovery-code hash at position %d; "
                        "reset MFA with POST /api/users/{username}/mfa/reset.",
                        username,
                        index,
                    )
                    continue
                if matched:
                    updated = [dict(item) for item in entries]
                    updated[index]["used_at"] = _iso(now)
                    # Reassigned rather than mutated in place: the column is
                    # JSON, and SQLAlchemy does not track a mutation inside it.
                    row.mfa_recovery_codes = updated
                    row.updated_at = now
                    session.flush()
                    metrics_service.MFA_VERIFICATIONS_TOTAL.labels("recovery").inc()
                    logger.warning(
                        "Account %r signed in with a recovery code; %d remain.",
                        username,
                        _remaining(updated),
                    )
                    return FACTOR_RECOVERY
            metrics_service.MFA_VERIFICATIONS_TOTAL.labels("failure").inc()
            raise refusal

        secret = crypto.decrypt_secret(row.mfa_secret, context=SECRET_CONTEXT)
        step = totp.verify(secret or "", code or "", moment=now, last_step=row.mfa_last_step)
        if step is None:
            metrics_service.MFA_VERIFICATIONS_TOTAL.labels("failure").inc()
            raise refusal
        row.mfa_last_step = step
        row.updated_at = now
        session.flush()
        metrics_service.MFA_VERIFICATIONS_TOTAL.labels("success").inc()
        return FACTOR_TOTP


def disable(
    settings: Settings,
    username: str,
    *,
    password: str,
    code: str | None = None,
    recovery_code: str | None = None,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Turn MFA off for one's own account: password **and** a live factor.

    Both, because either alone is exactly the thing the other protects against.
    A stolen session holds neither; a stolen password holds one; a shoulder-read
    code holds the other. The password is re-verified here rather than trusted
    from the session for the same reason ``POST /api/auth/password`` does it.
    """
    from api.services import users as users_service

    if users_service.authenticate(username, password) is None:
        raise PermissionError("password is incorrect")
    # Outside the transaction below, and deliberately before it: verify() takes
    # its own row lock, and nesting the two would hold a lock across a bcrypt
    # verification of up to ten recovery hashes.
    verify(settings, username, code=code, recovery_code=recovery_code)

    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username, with_for_update=True)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        before = _iso(row.mfa_enabled_at)
        _clear(row, now)
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_MFA_DISABLE,
            resource_type="user",
            resource_id=username,
            before={"mfa_enabled_at": before},
            after={"mfa_enabled_at": None},
        )
        return _state(row, settings)


def admin_reset(
    settings: Settings,
    username: str,
    *,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Clear an account's second factor and end its sessions (#314).

    The lost-phone path, and the only one that does not require the factor
    itself — which is why it is platform-admin only, why it is its own audit
    action, and why it bumps ``token_version``: a session that was opened
    *with* the factor being removed should not outlive it, and neither should
    one opened by whoever had the phone.
    """
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username, with_for_update=True)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        before = _iso(row.mfa_enabled_at)
        _clear(row, now)
        row.token_version = int(row.token_version or 0) + 1
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_MFA_RESET,
            resource_type="user",
            resource_id=username,
            before={"mfa_enabled_at": before},
            after={"mfa_enabled_at": None, "token_version": int(row.token_version)},
        )
        return _state(row, settings)


def _clear(row: models.User, now: datetime) -> None:
    """Return one row to "never enrolled". Every field, or none of them.

    Leaving the secret behind would keep a phone that still has the QR code
    able to produce codes the moment MFA is switched on again, and leaving the
    recovery codes would keep ten passwords alive for a factor that no longer
    exists.
    """
    row.mfa_secret = None
    row.mfa_enabled_at = None
    row.mfa_last_step = None
    row.mfa_recovery_codes = []
    row.updated_at = now


def stepup_deadline(verified_at: datetime | None, settings: Settings) -> datetime | None:
    """When a step-up proved at ``verified_at`` stops counting as recent."""
    if verified_at is None:
        return None
    return verified_at + timedelta(minutes=max(1, settings.mfa_stepup_minutes))
