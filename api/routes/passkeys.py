"""WebAuthn security keys and passkeys: ceremonies and inventory (#315).

Five routes under ``/auth/mfa/webauthn``, so a session confined by
``mfa_pending`` or by the phishing-resistant policy reaches every one of them —
registering a key is exactly what such a session exists to do.

* ``register/options`` and ``register/verify`` add a key to one's own account.
  Both cost a *recent* verification (``OCTO_MFA_STEPUP_MINUTES``): adding a
  factor must cost at least a fresh proof of an existing one, or a stolen
  session could plant a key of its own. The refusal carries the step-up
  sentence, so the console raises its re-verify prompt for it.
* ``authenticate/options`` issues the challenge a key signs. The signed
  answer goes to ``POST /api/auth/mfa/verify`` with the codes, because
  "prove the factor now" is one operation whichever factor proves it.
* ``GET credentials`` and ``DELETE credentials/{id}`` are the inventory. Removing
  a key is behind step-up like every other credential-destroying operation.

Every challenge is bound to what asked for it — the login's challenge token,
or the session family — and is spent by the verification that reads it. Asking
for one is limited per binding and per (account, address); over the limit is a
429 for the asker, never an eviction of somebody else's challenge. Everything else lives in
``api/services/passkeys.py``; this module is HTTP semantics only.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials

from api.auth import (
    StepUpDep,
    TokenUser,
    bearer_scheme,
    decode_pre_auth_token,
    decode_token,
    get_current_user,
    get_settings,
)
from api.core.client_ip import parse_trusted_proxies, resolve_client_ip
from api.routes._audit import AuditDep
from api.schemas import (
    WebAuthnCredentialInfo,
    WebAuthnOptionsRequest,
    WebAuthnOptionsResponse,
    WebAuthnRegisterRequest,
)
from api.services import passkeys as passkeys_service
from api.settings import Settings

router = APIRouter(tags=["auth"])


def _binding(user: TokenUser) -> str:
    """What a challenge asked for on this session is bound to.

    The session family (``sid``) when the token names one, so a refresh of the
    access token between the options and the answer does not break the
    ceremony; the token's own ``jti`` for a token minted before refresh tokens.
    A token with neither cannot bind, and is at least that old.
    """
    binding = passkeys_service.session_binding(user.session_id, user.jti)
    if not binding:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This session cannot run a security key ceremony; sign in again",
        )
    return binding


def _client_ip(request: Request, settings: Settings) -> str:
    # The same resolution the login limiter uses (``api/routes/mfa.py``), so
    # "one address" means the same thing to both limits.
    return resolve_client_ip(
        request.client.host if request.client else None,
        request.headers.get("x-forwarded-for"),
        parse_trusted_proxies(settings.trusted_proxies),
    )


def _too_many(exc: passkeys_service.TooManyChallenges) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=str(exc),
        headers={"Retry-After": str(exc.retry_after_seconds)},
    )


def _check_proof(settings: Settings, user: TokenUser) -> None:
    try:
        passkeys_service.check_registration_proof(
            settings,
            user.username,
            role=user.role.value,
            mfa_verified_at=user.mfa_verified_at,
            mfa_method=user.mfa_method,
        )
    except ValueError as exc:
        # Not configured, or no authenticator app to add a key on top of.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.post("/auth/mfa/webauthn/register/options", response_model=WebAuthnOptionsResponse)
def registration_options(
    request: Request,
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> WebAuthnOptionsResponse:
    """Creation options for a new key on the caller's own account.

    409 when this installation has no relying party configured, or when the
    account has no authenticator app enrolled yet — a key is added on top of
    one, because the recovery codes and the off switch belong to it. 429 over
    the challenge limit (:func:`api.services.passkeys._store_challenge`).
    """
    _check_proof(settings, user)
    try:
        options = passkeys_service.begin_registration(
            settings,
            user.username,
            binding=_binding(user),
            client_ip=_client_ip(request, settings),
        )
    except passkeys_service.TooManyChallenges as exc:
        raise _too_many(exc) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return WebAuthnOptionsResponse.model_validate(options)


@router.post(
    "/auth/mfa/webauthn/register/verify",
    response_model=WebAuthnCredentialInfo,
    status_code=status.HTTP_201_CREATED,
)
def register_key(
    body: WebAuthnRegisterRequest,
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> WebAuthnCredentialInfo:
    """Verify the authenticator's response and store the key.

    The proof is checked again rather than trusted from the options call: the
    step-up window may have closed in between, and the options call is not
    the one that changes anything.

    400 for a response that does not verify — wrong challenge, wrong origin,
    wrong RP ID, malformed. Not 401: the session is fine, and the console signs
    out on a 401.
    """
    _check_proof(settings, user)
    try:
        created = passkeys_service.finish_registration(
            settings,
            user.username,
            binding=_binding(user),
            challenge_id=body.challenge_id,
            credential=body.credential,
            name=body.name,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return WebAuthnCredentialInfo.model_validate(created)


@router.post("/auth/mfa/webauthn/authenticate/options", response_model=WebAuthnOptionsResponse)
def authentication_options(
    body: WebAuthnOptionsRequest,
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> WebAuthnOptionsResponse:
    """Request options naming the account's keys, for a login or a step-up.

    The same two callers ``POST /api/auth/mfa/verify`` has, told apart the same
    way: the login's challenge token in the body, or a session on the header
    (decoded directly, so a confined session reaches this too). The challenge
    is bound to whichever token that was.

    409 when the account holds no key, or the installation has no relying
    party. The caller has passed the first factor already, so saying which is
    no disclosure.
    """
    if body.mfa_token:
        challenge = decode_pre_auth_token(settings, body.mfa_token)
        username, binding = challenge.username, challenge.jti
    elif credentials is not None and credentials.scheme.lower() == "bearer":
        session = decode_token(settings, credentials.credentials)
        username = session.username
        binding = passkeys_service.session_binding(session.session_id, session.jti)
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="supply the challenge token from POST /api/auth/login, or sign in first",
        )
    if not binding:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This session cannot run a security key ceremony; sign in again",
        )
    try:
        options = passkeys_service.begin_authentication(
            settings, username, binding=binding, client_ip=_client_ip(request, settings)
        )
    except passkeys_service.TooManyChallenges as exc:
        raise _too_many(exc) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return WebAuthnOptionsResponse.model_validate(options)


@router.get("/auth/mfa/webauthn/credentials", response_model=list[WebAuthnCredentialInfo])
def list_keys(
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[WebAuthnCredentialInfo]:
    """The caller's own registered keys. Nothing here is secret."""
    return [
        WebAuthnCredentialInfo.model_validate(item)
        for item in passkeys_service.list_credentials(settings, user.username)
    ]


@router.delete(
    "/auth/mfa/webauthn/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_key(
    credential_id: str,
    user: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> Response:
    """Remove one of the caller's own keys. Step-up, audited.

    Another account's key id is answered 404, exactly like one that does not
    exist. Removing somebody else's keys is the admin MFA reset, which removes
    all of them and ends that account's sessions.
    """
    try:
        passkeys_service.revoke_credential(settings, user.username, credential_id, audit=audit)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
