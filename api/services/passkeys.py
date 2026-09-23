"""WebAuthn security keys and passkeys as a second factor (#315).

TOTP proves that whoever typed the code can read the phone; it says nothing
about *where* they typed it, so a convincing copy of the login page can relay
the password and the code in real time. A WebAuthn assertion is signed over
the origin the browser actually saw and the relying-party ID the credential
was created for, which is what makes it the phishing-resistant factor. This
module owns the state around that: which keys an account holds, which
challenges are in flight, and the counters that are checked on each use.

The cryptography is not here. Attestation parsing and assertion verification
are ``py_webauthn`` (``webauthn`` on PyPI); this module decides what to hand
it — the challenge that was issued, the RP ID and origins from configuration,
the public key and counter that were stored — and what to do with its answer.

**A key is added on top of an enrolled authenticator app, not instead of it.**
Recovery codes, "turn MFA off" and the admin reset all belong to the enrolment
``api/services/mfa.py`` already manages; a key extends it. That is also why
turning MFA off or resetting it removes every key (``mfa._clear``): a key left
behind would be a factor for an account that no longer has MFA.

**A challenge is spent before it is checked.** :func:`_consume_challenge`
deletes the row in its own transaction and only then is the response verified,
so a failed attempt burns the challenge as surely as a successful one. The row
is bound to the user, the ceremony (``register``/``authenticate``) and what
asked for it — the challenge token's ``jti`` on a login, the session family
(``sid``) on a signed-in session (:func:`session_binding`) — and it expires
after :data:`CHALLENGE_TTL_SECONDS`. Asking for one is limited per binding and
per (account, address), and never evicts somebody else's
(:func:`_store_challenge`).

**The counter is advanced under a row lock.** An assertion whose signature
counter does not move past the stored one is refused (the library's rule, with
the spec's exemption for authenticators that always report zero), and the new
value is written in the same transaction that accepted it.

Domain errors only — ``LookupError``, ``PermissionError``, ``ValueError``. The
routes in ``api/routes/passkeys.py`` and ``api/routes/mfa.py`` decide which
status each becomes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import webauthn
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import metrics as metrics_service
from api.settings import Settings

logger = logging.getLogger(__name__)

#: How long a ceremony may take between the options and the response. Five
#: minutes, like the pre-authentication token a login challenge rides on: long
#: enough to find the key on the keyring, short enough that an options response
#: somebody screenshotted is worthless by the time they act on it.
CHALLENGE_TTL_SECONDS = 300
#: Open challenges one binding — one login's challenge token, or one session —
#: may hold at once. Each options call writes a row. Ten is a person clicking
#: "use a security key" and cancelling the browser prompt, many times over.
MAX_OPEN_CHALLENGES = 10
#: Open challenges one account may hold from one client address, across all
#: its bindings: what bounds a script that signs in over and over.
MAX_CHALLENGES_PER_WINDOW = 30
#: Longest label a key may be given in the inventory.
MAX_NAME_LENGTH = 64

PURPOSE_REGISTER = "register"
PURPOSE_AUTHENTICATE = "authenticate"

#: What :func:`verify_assertion` reports it accepted, alongside
#: ``mfa.FACTOR_TOTP`` and ``mfa.FACTOR_RECOVERY``. It rides in the session
#: token as ``mfa_method`` and is what the phishing-resistant policy reads.
FACTOR_WEBAUTHN = "webauthn"

_UNAVAILABLE = (
    "WebAuthn is not configured on this installation: set OCTO_PUBLIC_BASE_URL, "
    "or OCTO_WEBAUTHN_RP_ID and OCTO_WEBAUTHN_ORIGINS"
)
#: What a response the library cannot verify raises. ``WebAuthnException`` is
#: its own family; ``ValueError``/``TypeError``/``KeyError`` are what a few of
#: its decoders (base64url of ``userHandle``, CBOR of a hand-made attestation)
#: raise on garbage before its own wrappers see it. All of them mean "this
#: response is not valid", and none of them is a server fault — a 500 here
#: would also skip the login limiter's failure count.
_MALFORMED = (WebAuthnException, ValueError, TypeError, KeyError)

_ENROL_FIRST = (
    "enrol an authenticator app first (POST /api/auth/mfa/totp/setup); "
    "a security key is added on top of it"
)


class TooManyChallenges(PermissionError):
    """An options call over the limit; the route answers 429 with ``Retry-After``.

    A :class:`PermissionError` so a caller that only wants "refused" needs no
    second ``except``, the same shape ``sessions.RefreshTokenReused`` has.
    """

    def __init__(self, *, retry_after_seconds: int) -> None:
        super().__init__("too many security key challenges; try again shortly")
        self.retry_after_seconds = retry_after_seconds


def _now() -> datetime:
    # Naive UTC, matching every timestamp column in this schema.
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def relying_party(settings: Settings) -> tuple[str, list[str]]:
    """``(rp_id, origins)``, or ``ValueError`` when WebAuthn is unavailable."""
    rp_id, origins = settings.webauthn_relying_party()
    if not rp_id or not origins:
        raise ValueError(_UNAVAILABLE)
    return rp_id, origins


def available(settings: Settings) -> bool:
    """Whether this installation can run a WebAuthn ceremony at all."""
    rp_id, origins = settings.webauthn_relying_party()
    return bool(rp_id and origins)


def _user_handle(username: str) -> bytes:
    """The WebAuthn ``user.id`` for an account: stable, and not the username.

    Stable so that a second key registered on the same platform authenticator
    replaces the first rather than sitting beside it under the same name. A
    hash rather than the name itself because the spec asks that the handle
    carry no personal information — ``user.name`` in the same options already
    carries the username, so this is about not *adding* a second copy, not
    about hiding the first.
    """
    return hashlib.sha256(f"shapoclyack:webauthn:{username}".encode()).digest()


def session_binding(session_id: str | None, jti: str | None) -> str | None:
    """What a challenge asked for on a signed-in session is bound to.

    The session family (``sid``, #314) when the token names one: the console
    refreshes its fifteen-minute access token on its own schedule, and a
    refresh between the options and the answer must not break the ceremony —
    the family is what "this sign-in" means now. A token minted before refresh
    tokens has no family and binds to its own ``jti``, as before. Prefixed so
    a family id can never equal a token id by accident.
    """
    if session_id:
        return f"sid:{session_id}"
    return jti or None


def phishing_resistant_required(settings: Settings, role: str) -> bool:
    """Whether ``OCTO_MFA_PHISHING_RESISTANT_ROLES`` names this role."""
    return str(role or "").lower() in settings.mfa_phishing_resistant_roles


def stepup_requires_webauthn(settings: Settings, role: str) -> bool:
    """Whether a step-up for this role must be a WebAuthn assertion."""
    return settings.mfa_stepup_phishing_resistant or phishing_resistant_required(settings, role)


def credential_count(session: Any, username: str) -> int:
    """How many keys an account holds, inside the caller's transaction."""
    rows = session.execute(
        select(models.WebAuthnCredential.id).where(models.WebAuthnCredential.username == username)
    ).all()
    return len(rows)


def has_credentials(settings: Settings, username: str) -> bool:
    with get_session(settings.postgres_url) as session:
        return credential_count(session, username) > 0


def delete_all(session: Any, username: str) -> int:
    """Remove every key and open challenge of an account. Returns the key count.

    Called by ``mfa._clear`` inside the transaction that turns MFA off or
    resets it, so the keys and the enrolment go together or not at all.
    """
    removed = session.execute(
        delete(models.WebAuthnCredential).where(models.WebAuthnCredential.username == username)
    ).rowcount
    session.execute(
        delete(models.WebAuthnChallenge).where(models.WebAuthnChallenge.username == username)
    )
    return int(removed or 0)


def _public(row: models.WebAuthnCredential) -> dict[str, Any]:
    """Inventory shape. The public key is not secret, but nobody needs it."""
    return {
        "id": row.id,
        "name": row.name,
        "credential_id": row.credential_id,
        "aaguid": row.aaguid,
        "transports": list(row.transports or []),
        "backed_up": bool(row.backed_up),
        "device_type": row.device_type,
        "created_at": _iso(row.created_at),
        "last_used_at": _iso(row.last_used_at),
    }


def list_credentials(settings: Settings, username: str) -> list[dict[str, Any]]:
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.WebAuthnCredential)
            .where(models.WebAuthnCredential.username == username)
            .order_by(models.WebAuthnCredential.created_at, models.WebAuthnCredential.id)
        ).scalars()
        return [_public(row) for row in rows]


def _descriptors(session: Any, username: str) -> list[PublicKeyCredentialDescriptor]:
    rows = session.execute(
        select(models.WebAuthnCredential).where(models.WebAuthnCredential.username == username)
    ).scalars()
    descriptors = []
    for row in rows:
        transports = []
        for value in row.transports or []:
            try:
                transports.append(AuthenticatorTransport(value))
            except ValueError:
                continue
        descriptors.append(
            PublicKeyCredentialDescriptor(
                id=webauthn.base64url_to_bytes(row.credential_id),
                transports=transports or None,
            )
        )
    return descriptors


def _store_challenge(
    session: Any,
    username: str,
    *,
    purpose: str,
    binding: str,
    challenge: bytes,
    client_ip: str,
    now: datetime,
) -> str:
    """Write one challenge row, or refuse with :class:`TooManyChallenges`.

    Nothing is ever evicted to make room. An account-wide cap that dropped the
    oldest row let anybody holding the password — their own sign-in, their own
    challenge token — push the owner's in-flight challenge out and fail the
    owner's key (#437 review). So the limits refuse the *asker* instead:

    * :data:`MAX_OPEN_CHALLENGES` open per binding — per login or per session,
      which only the holder of that token can spend;
    * :data:`MAX_CHALLENGES_PER_WINDOW` open per (account, client address), so
      a flood of sign-ins from one address cannot grow the table without bound
      and cannot touch the budget of an owner elsewhere.

    Both count rows still open, which is the same thing as "asked for within
    the last :data:`CHALLENGE_TTL_SECONDS`" less those already answered: a
    challenge a real ceremony spent frees its slot.
    """
    session.execute(delete(models.WebAuthnChallenge).where(models.WebAuthnChallenge.expires_at <= now))
    open_for_binding = session.execute(
        select(func.count())
        .select_from(models.WebAuthnChallenge)
        .where(
            models.WebAuthnChallenge.username == username,
            models.WebAuthnChallenge.binding == binding,
        )
    ).scalar_one()
    open_from_address = session.execute(
        select(func.count())
        .select_from(models.WebAuthnChallenge)
        .where(
            models.WebAuthnChallenge.username == username,
            models.WebAuthnChallenge.client_ip == client_ip,
        )
    ).scalar_one()
    if open_for_binding >= MAX_OPEN_CHALLENGES or open_from_address >= MAX_CHALLENGES_PER_WINDOW:
        oldest = session.execute(
            select(func.min(models.WebAuthnChallenge.expires_at)).where(
                models.WebAuthnChallenge.username == username,
                (models.WebAuthnChallenge.binding == binding)
                | (models.WebAuthnChallenge.client_ip == client_ip),
            )
        ).scalar_one()
        wait = int((oldest - now).total_seconds()) + 1 if oldest else CHALLENGE_TTL_SECONDS
        raise TooManyChallenges(retry_after_seconds=max(1, wait))
    challenge_id = uuid.uuid4().hex
    session.add(
        models.WebAuthnChallenge(
            id=challenge_id,
            username=username,
            purpose=purpose,
            binding=binding,
            challenge=challenge,
            client_ip=client_ip,
            created_at=now,
            expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        )
    )
    session.flush()
    return challenge_id


def _consume_challenge(
    settings: Settings, username: str, *, challenge_id: str, purpose: str, binding: str
) -> bytes:
    """Delete the challenge and return it — once. ``PermissionError`` otherwise.

    Its own transaction, committed before the response is verified: a
    verification that then fails has still spent the challenge, so a response
    can be tried against it exactly once whatever the outcome.
    """
    refusal = PermissionError("that security key response is not valid")
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.execute(
            delete(models.WebAuthnChallenge)
            .where(
                models.WebAuthnChallenge.id == str(challenge_id or ""),
                models.WebAuthnChallenge.username == username,
                models.WebAuthnChallenge.purpose == purpose,
                models.WebAuthnChallenge.binding == binding,
            )
            .returning(models.WebAuthnChallenge.challenge, models.WebAuthnChallenge.expires_at)
        ).first()
    if row is None or row.expires_at <= now:
        raise refusal
    return bytes(row.challenge)


def _options_json(options: Any) -> dict[str, Any]:
    return json.loads(webauthn.options_to_json(options))


# --------------------------------------------------------------------------- #
# Registration
# --------------------------------------------------------------------------- #


def check_registration_proof(
    settings: Settings,
    username: str,
    *,
    role: str,
    mfa_verified_at: datetime | None,
    mfa_method: str | None,
) -> None:
    """Whether this session may add a key. ``PermissionError`` if not.

    Adding a factor must cost at least a fresh proof of an existing one —
    otherwise a stolen session could plant its own key and keep it. The proof
    is the step-up window ``OCTO_MFA_STEPUP_MINUTES`` already defines.

    When the account already holds a key and a WebAuthn step-up is required of
    it (:func:`stepup_requires_webauthn`), the proof must be that key: a code
    relayed through a phishing page must not be enough to enrol the phisher's
    authenticator next to the owner's. The first key of such an account is
    necessarily bootstrapped by a code — there is no other factor to prove.
    """
    from api.services import mfa as mfa_service

    relying_party(settings)
    if not mfa_service.is_enabled(settings, username):
        raise ValueError(_ENROL_FIRST)
    deadline = mfa_service.stepup_deadline(mfa_verified_at, settings)
    if deadline is None or deadline <= mfa_service.now_utc():
        raise PermissionError(
            "adding a security key needs a recent multi-factor verification; "
            "re-verify with POST /api/auth/mfa/verify first"
        )
    if (
        mfa_method != FACTOR_WEBAUTHN
        and stepup_requires_webauthn(settings, role)
        and has_credentials(settings, username)
    ):
        raise PermissionError(
            "adding another security key needs a recent verification with one "
            "you already hold"
        )


def check_disable_proof(
    settings: Settings,
    username: str,
    *,
    role: str,
    mfa_verified_at: datetime | None,
    mfa_method: str | None,
) -> None:
    """Whether this session may turn MFA off. ``PermissionError`` if not.

    Turning MFA off removes every key (``mfa._clear``). Where policy wants a
    key of this account (:func:`stepup_requires_webauthn`) and the account
    holds one, the password and a code are not enough: a phishing kit relays
    exactly those two, and disable would then clear the owner's keys and leave
    an account whose *first* key — the attacker's — needs only a code. So the
    session must have been proved recently with a key. Accounts the policy
    does not cover, or that hold no key yet, are unchanged.
    """
    from api.services import mfa as mfa_service

    if not stepup_requires_webauthn(settings, role) or not has_credentials(settings, username):
        return
    deadline = mfa_service.stepup_deadline(mfa_verified_at, settings)
    if (
        mfa_method != FACTOR_WEBAUTHN
        or deadline is None
        or deadline <= mfa_service.now_utc()
    ):
        raise PermissionError(
            "turning multi-factor authentication off needs a recent multi-factor "
            "verification with a security key you hold; re-verify with "
            "POST /api/auth/mfa/verify using the key"
        )


def begin_registration(settings: Settings, username: str, *, binding: str, client_ip: str = "") -> dict[str, Any]:
    """Issue ``PublicKeyCredentialCreationOptions`` for a new key.

    Refused (``ValueError``) for an account with no authenticator app enrolled:
    a key is an addition to the enrolment, and the recovery codes and the
    "turn it off" path belong to that enrolment.
    """
    rp_id, _ = relying_party(settings)
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None:
            raise LookupError(f"user '{username}' not found")
        if row.mfa_enabled_at is None:
            raise ValueError(_ENROL_FIRST)
        options = webauthn.generate_registration_options(
            rp_id=rp_id,
            rp_name=settings.webauthn_rp_name,
            user_name=username,
            user_id=_user_handle(username),
            user_display_name=username,
            timeout=CHALLENGE_TTL_SECONDS * 1000,
            # No attestation: this installation keeps no trust store of
            # authenticator vendors, and asking for a statement it cannot
            # evaluate would only put a privacy prompt in front of the user.
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            exclude_credentials=_descriptors(session, username),
        )
        challenge_id = _store_challenge(
            session,
            username,
            purpose=PURPOSE_REGISTER,
            binding=binding,
            challenge=options.challenge,
            client_ip=client_ip,
            now=now,
        )
    return {"challenge_id": challenge_id, "public_key": _options_json(options)}


def finish_registration(
    settings: Settings,
    username: str,
    *,
    binding: str,
    challenge_id: str,
    credential: dict[str, Any],
    name: str,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Verify the authenticator's attestation and store the new key."""
    rp_id, origins = relying_party(settings)
    expected = _consume_challenge(
        settings, username, challenge_id=challenge_id, purpose=PURPOSE_REGISTER, binding=binding
    )
    try:
        verified = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=expected,
            expected_rp_id=rp_id,
            expected_origin=origins,
        )
    except _MALFORMED as exc:
        metrics_service.MFA_VERIFICATIONS_TOTAL.labels("webauthn_setup_failure").inc()
        logger.info("Rejected a security key registration for %r: %s", username, exc)
        raise PermissionError("that security key response is not valid") from exc

    transports = []
    response = credential.get("response") if isinstance(credential, dict) else None
    if isinstance(response, dict) and isinstance(response.get("transports"), list):
        transports = [str(item) for item in response["transports"] if isinstance(item, str)][:8]

    now = _now()
    label = (name or "").strip()[:MAX_NAME_LENGTH] or "Security key"
    credential_id = bytes_to_base64url(verified.credential_id)
    try:
        with get_session(settings.postgres_url) as session:
            user = session.get(models.User, username, with_for_update=True)
            if user is None:
                raise LookupError(f"user '{username}' not found")
            if user.mfa_enabled_at is None:
                # MFA was turned off or reset between the options and here.
                raise ValueError("multi-factor authentication is not enabled for this account")
            row = models.WebAuthnCredential(
                id=uuid.uuid4().hex,
                username=username,
                credential_id=credential_id,
                public_key=verified.credential_public_key,
                sign_count=int(verified.sign_count),
                name=label,
                aaguid=str(verified.aaguid or ""),
                transports=transports,
                backed_up=bool(verified.credential_backed_up),
                device_type=str(getattr(verified.credential_device_type, "value", "") or ""),
                created_at=now,
            )
            session.add(row)
            session.flush()
            audit_service.record(
                session,
                audit,
                action=audit_service.ACTION_USER_WEBAUTHN_REGISTER,
                resource_type="user",
                resource_id=username,
                after={
                    "credential": row.id,
                    "name": label,
                    "aaguid": row.aaguid,
                    "backed_up": row.backed_up,
                },
            )
            public = _public(row)
    except IntegrityError as exc:
        # ``credential_id`` is unique across the installation. The options
        # exclude this account's own keys, so a collision is another account's
        # key — a replayed registration, or a broken authenticator.
        raise ValueError("this security key is already registered") from exc
    metrics_service.MFA_VERIFICATIONS_TOTAL.labels("webauthn_setup_success").inc()
    return public


def revoke_credential(
    settings: Settings,
    username: str,
    credential_pk: str,
    *,
    audit: "audit_service.AuditContext | None" = None,
) -> None:
    """Remove one of the account's own keys. ``LookupError`` for anybody else's.

    Another account's key is answered exactly like a missing one: whether an
    id exists elsewhere is not the caller's business.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.WebAuthnCredential, credential_pk, with_for_update=True)
        if row is None or row.username != username:
            raise LookupError(f"security key '{credential_pk}' not found")
        before = {"credential": row.id, "name": row.name, "aaguid": row.aaguid}
        session.delete(row)
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_USER_WEBAUTHN_REVOKE,
            resource_type="user",
            resource_id=username,
            before=before,
            after={"remaining": credential_count(session, username)},
        )


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


def begin_authentication(settings: Settings, username: str, *, binding: str, client_ip: str = "") -> dict[str, Any]:
    """Issue ``PublicKeyCredentialRequestOptions`` naming the account's keys.

    ``ValueError`` when the account holds none: there is nothing for the
    browser to ask for, and saying so is safe — the caller has already passed
    the first factor, or holds a session.
    """
    rp_id, _ = relying_party(settings)
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, username)
        if row is None or row.mfa_enabled_at is None:
            raise ValueError("no security key is registered for this account")
        descriptors = _descriptors(session, username)
        if not descriptors:
            raise ValueError("no security key is registered for this account")
        options = webauthn.generate_authentication_options(
            rp_id=rp_id,
            timeout=CHALLENGE_TTL_SECONDS * 1000,
            allow_credentials=descriptors,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        challenge_id = _store_challenge(
            session,
            username,
            purpose=PURPOSE_AUTHENTICATE,
            binding=binding,
            challenge=options.challenge,
            client_ip=client_ip,
            now=now,
        )
    return {"challenge_id": challenge_id, "public_key": _options_json(options)}


def verify_assertion(
    settings: Settings,
    username: str,
    *,
    binding: str,
    challenge_id: str,
    credential: dict[str, Any],
) -> str:
    """Accept one assertion and advance its key's counter. Returns the factor.

    Raises ``PermissionError`` for every refusal with one message — which of
    "spent challenge", "wrong origin", "cloned key" and "bad signature" applies
    is of interest only to somebody without the key. The reason is logged.
    """
    refusal = PermissionError("that security key response is not valid")
    rp_id, origins = relying_party(settings)
    expected = _consume_challenge(
        settings,
        username,
        challenge_id=challenge_id,
        purpose=PURPOSE_AUTHENTICATE,
        binding=binding,
    )
    raw_id = credential.get("rawId") if isinstance(credential, dict) else None
    if not isinstance(raw_id, str) or not raw_id:
        metrics_service.MFA_VERIFICATIONS_TOTAL.labels("webauthn_failure").inc()
        raise refusal
    now = _now()
    with get_session(settings.postgres_url) as session:
        user = session.get(models.User, username)
        row = session.execute(
            select(models.WebAuthnCredential)
            .where(
                models.WebAuthnCredential.username == username,
                models.WebAuthnCredential.credential_id == raw_id.rstrip("="),
            )
            .with_for_update()
        ).scalar_one_or_none()
        if user is None or user.mfa_enabled_at is None or row is None:
            metrics_service.MFA_VERIFICATIONS_TOTAL.labels("webauthn_failure").inc()
            raise refusal
        try:
            verified = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=expected,
                expected_rp_id=rp_id,
                expected_origin=origins,
                credential_public_key=bytes(row.public_key),
                credential_current_sign_count=int(row.sign_count or 0),
            )
        except _MALFORMED as exc:
            metrics_service.MFA_VERIFICATIONS_TOTAL.labels("webauthn_failure").inc()
            logger.warning(
                "Rejected a security key assertion for %r (key %s): %s", username, row.id, exc
            )
            raise refusal from exc
        row.sign_count = int(verified.new_sign_count)
        row.backed_up = bool(verified.credential_backed_up)
        row.last_used_at = now
        session.flush()
    metrics_service.MFA_VERIFICATIONS_TOTAL.labels("webauthn_success").inc()
    return FACTOR_WEBAUTHN
