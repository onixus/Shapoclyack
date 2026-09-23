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

Every challenge is bound to the ``jti`` of the token that asked for it, and is
spent by the verification that reads it. Everything else lives in
``api/services/passkeys.py``; this module is HTTP semantics only.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
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
    """The ``jti`` a challenge is bound to. A token without one cannot bind.

    Every session minted since #314 carries a ``jti``; one that does not is at
    least that old and has expired by now, so this refuses nothing real.
    """
    if not user.jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This session cannot run a security key ceremony; sign in again",
        )
    return user.jti


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
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> WebAuthnOptionsResponse:
    """Creation options for a new key on the caller's own account.

    409 when this installation has no relying party configured, or when the
    account has no authenticator app enrolled yet — a key is added on top of
    one, because the recovery codes and the off switch belong to it.
    """
    _check_proof(settings, user)
    try:
        options = passkeys_service.begin_registration(
            settings, user.username, binding=_binding(user)
        )
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
        username, binding = session.username, session.jti
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
        options = passkeys_service.begin_authentication(settings, username, binding=binding)
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
