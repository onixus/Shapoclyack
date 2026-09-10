"""Multi-factor enrolment, verification and reset (#315).

Six routes, and the split between them is the whole design:

* the three under ``/auth/mfa`` that an account performs **on itself** — set
  up, confirm, disable — each of which costs the account something it already
  holds (the password, a live code, or both);
* ``POST /auth/mfa/verify``, which is two things wearing one name: the second
  leg of a login (it takes the challenge token from ``POST /auth/login``) and
  the step-up an already-signed-in admin does before minting a credential;
* ``POST /users/{username}/mfa/reset``, the only way a factor comes off an
  account without the factor — platform admin, audited, and it ends the
  account's sessions.

Everything these do lives in ``api/services/mfa.py``; this module is HTTP
semantics only, which here means translating the service's three domain
exceptions into 404, 409, 401 and 403 and never letting a secret into a place
it does not belong (there is exactly one response that carries recovery codes,
and exactly one that carries the shared secret).
"""

from __future__ import annotations

import urllib.parse
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials

from api.auth import (
    LoginResponse,
    Role,
    TokenUser,
    bearer_scheme,
    create_access_token,
    decode_pre_auth_token,
    decode_token,
    get_current_user,
    get_settings,
    require_role,
)
from api.core.client_ip import parse_trusted_proxies, resolve_client_ip
from api.routes._audit import AuditDep
from api.schemas import (
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaRecoveryCodesResponse,
    MfaSetupResponse,
    MfaStatus,
    MfaVerifyRequest,
)
from api.services import auth_audit
from api.services import local_login
from api.services import mfa as mfa_service
from api.services import users as users_service
from api.settings import Settings

router = APIRouter(tags=["auth"])

#: Fallback label for the ``otpauth://`` issuer when the installation has no
#: public URL configured. An authenticator lists accounts by it, so an operator
#: with two Shapoclyack installations wants the hostname — but a constant is
#: better than a blank line in the app.
DEFAULT_ISSUER = "Shapoclyack"


def _issuer(settings: Settings) -> str:
    """What an authenticator shows above the code.

    The public hostname when there is one: it is the one string that tells two
    installations of this platform apart in a phone full of six-digit codes.
    """
    host = urllib.parse.urlparse(settings.public_base_url.strip()).hostname
    return host or DEFAULT_ISSUER


def _client_ip(request: Request, settings: Settings) -> str:
    return resolve_client_ip(
        request.client.host if request.client else None,
        request.headers.get("x-forwarded-for"),
        parse_trusted_proxies(settings.trusted_proxies),
    )


def _not_found(username: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"user '{username}' not found"
    )


@router.get("/auth/mfa", response_model=MfaStatus)
def mfa_status(
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MfaStatus:
    """The caller's own second-factor state. Carries nothing secret."""
    try:
        return MfaStatus.model_validate(mfa_service.status(settings, user.username))
    except LookupError as exc:
        raise _not_found(user.username) from exc


@router.post("/auth/mfa/totp/setup", response_model=MfaSetupResponse)
def setup_totp(
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MfaSetupResponse:
    """Mint an authenticator secret for the caller's own account.

    The response is the only place the secret exists in readable form — it is
    stored encrypted and never returned again — and nothing is enabled until a
    code from it is confirmed. Reachable by a session carrying ``mfa_pending``,
    which is the point of that session existing at all.

    The console renders the QR itself from ``otpauth_uri``. No image is
    generated here and no external service is called: handing a third party
    every admin's TOTP seed to draw a square would defeat the feature.
    """
    try:
        created = mfa_service.begin_setup(settings, user.username, issuer=_issuer(settings))
    except LookupError as exc:
        raise _not_found(user.username) from exc
    except ValueError as exc:
        # Already enabled. 409 rather than 422: nothing about the request is
        # malformed, the account is simply in a state this operation is not for.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return MfaSetupResponse.model_validate(created)


@router.post("/auth/mfa/totp/confirm", response_model=MfaRecoveryCodesResponse)
def confirm_totp(
    body: MfaConfirmRequest,
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> MfaRecoveryCodesResponse:
    """Prove the authenticator holds the secret, and turn the factor on.

    Returns the ten recovery codes. They are stored as bcrypt hashes, so this
    response is the only moment they exist: a client that fails to show them
    has cost the user their recovery path, and the fix is an admin reset.
    """
    try:
        codes = mfa_service.confirm_setup(settings, user.username, body.code, audit=audit)
    except LookupError as exc:
        raise _not_found(user.username) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)
        ) from exc
    return MfaRecoveryCodesResponse(recovery_codes=codes)


@router.post("/auth/mfa/verify", response_model=LoginResponse)
def verify_mfa(
    body: MfaVerifyRequest,
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    """Present the second factor and receive a session that says so.

    Two callers, one endpoint, because it is one operation — "prove the factor
    now" — and the difference is only what proves the first one:

    * with ``mfa_token``: the second leg of a login. The challenge token is
      accepted by :func:`api.auth.decode_pre_auth_token` and by nothing else.
    * without it: an authenticated caller re-proving the factor for a step-up.
      The new token carries a fresh ``mfa_verified_at``; the console replaces
      the one it holds, and the previous token keeps working until it expires
      on its own, exactly as any other still-valid session does.

    Refusals go through the login rate limiter (#157) under the account's own
    key, so guessing six digits costs an attacker the same five attempts per
    window that guessing a password does — and lands in the same trail with
    ``reason=mfa_failed``.
    """
    if not (body.code or body.recovery_code):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="supply either 'code' or 'recovery_code'",
        )

    break_glass = False
    if body.mfa_token:
        challenge = decode_pre_auth_token(settings, body.mfa_token)
        username = challenge.username
        break_glass = challenge.break_glass
    elif credentials is not None and credentials.scheme.lower() == "bearer":
        # decode_token rather than the get_current_user dependency: a session
        # carrying ``mfa_pending`` must be able to reach this, and so must one
        # that is merely stepping up. The dependency's enrolment gate would
        # otherwise decide that for us before this route is entered.
        username = decode_token(settings, credentials.credentials).username
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="supply the challenge token from POST /api/auth/login, or sign in first",
        )

    client_ip = _client_ip(request, settings)

    def _check() -> str | None:
        try:
            mfa_service.verify(
                settings, username, code=body.code, recovery_code=body.recovery_code
            )
        except PermissionError:
            return None
        return username

    outcome = auth_audit.attempt_login(
        username=username,
        client_ip=client_ip,
        verify=_check,
        failure_reason=auth_audit.REASON_MFA_FAILED,
    )
    if outcome.lockout is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(outcome.lockout.retry_after_seconds)},
        )
    if outcome.user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="that code is not valid"
        )

    record = users_service.get_user(username)
    if record is None or record.get("disabled"):
        # The account went away between the two legs. Refused exactly like a
        # bad code: a race with a deletion is not the caller's business.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="that code is not valid"
        )
    principal = TokenUser(username=username, role=Role(str(record["role"])))
    verified_at = datetime.now(UTC)
    try:
        token = create_access_token(settings, principal, mfa_verified_at=verified_at)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="that code is not valid"
        ) from exc
    if break_glass:
        local_login.record_break_glass(settings, username=username, client_ip=client_ip)
    return LoginResponse(access_token=token, role=principal.role, username=username)



@router.post("/auth/mfa/disable", response_model=MfaStatus)
def disable_mfa(
    body: MfaDisableRequest,
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> MfaStatus:
    """Turn off one's own second factor. Password **and** a live code.

    Both, because a session alone is what the second factor exists to survive:
    somebody who has stolen a token holds neither of the two things this asks
    for. There is deliberately no admin route that does this *to* another
    account without recording it as a reset — see below.
    """
    if not (body.code or body.recovery_code):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="supply either 'code' or 'recovery_code'",
        )
    try:
        state = mfa_service.disable(
            settings,
            user.username,
            password=body.password,
            code=body.code,
            recovery_code=body.recovery_code,
            audit=audit,
        )
    except LookupError as exc:
        raise _not_found(user.username) from exc
    except PermissionError as exc:
        # One status for a wrong password and a wrong code alike: the caller is
        # already authenticated, so the distinction only helps whoever is
        # holding half of the credentials.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return MfaStatus.model_validate(state)


@router.post("/users/{username}/mfa/reset", response_model=MfaStatus)
def reset_user_mfa(
    username: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> MfaStatus:
    """Clear an account's second factor and end its sessions. Platform admin.

    The lost-phone path. It is the one operation in this module that removes a
    factor without presenting one, which is why it is admin-only, why it has
    its own audit action (``user.mfa_reset``), and why it bumps the account's
    token generation: whoever still has the phone must not keep a live session
    either.

    Deliberately not restricted to *other* accounts: an admin who has locked
    themselves out is not the caller here — they cannot be — and refusing the
    self-case would only complicate the honest one where an admin resets their
    own enrolment before setting it up again.
    """
    try:
        state = mfa_service.admin_reset(settings, username, audit=audit)
    except LookupError as exc:
        raise _not_found(username) from exc
    return MfaStatus.model_validate(state)
