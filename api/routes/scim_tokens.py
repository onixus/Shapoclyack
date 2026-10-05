"""SCIM token administration (#316).

Platform admin only, behind a recent second factor: a SCIM token creates
accounts and grants memberships, which is account administration — the same
gate as ``POST /api/users`` — and it outlives the session that minted it.
Under ``/auth`` so that a service token can never reach these routes
(``auth`` is one of its forbidden resources).

The plaintext is in the create response and nowhere else.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, StepUpDep, TokenUser, get_settings, require_role
from api.routes._audit import AuditDep
from api.schemas import CreateScimTokenRequest, ScimTokenInfo
from api.services import scim_tokens as scim_tokens_service
from api.settings import Settings

router = APIRouter(tags=["scim"])


@router.post("/auth/scim-tokens", response_model=ScimTokenInfo, status_code=status.HTTP_201_CREATED)
def create_scim_token(
    body: CreateScimTokenRequest,
    admin: Annotated[TokenUser, Depends(require_role(Role.admin))],
    _: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> ScimTokenInfo:
    """Issue one token. ``404`` for an unknown tenant, ``422`` for a binding
    that names no tenants, or both tenants and ``all_tenants``."""
    try:
        created = scim_tokens_service.create_token(
            settings,
            name=body.name,
            tenant_ids=body.tenant_ids,
            all_tenants=body.all_tenants,
            grant_platform_admin=body.grant_platform_admin,
            created_by=admin.username,
            expires_in_days=body.expires_in_days,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return ScimTokenInfo.model_validate(created)


@router.get("/auth/scim-tokens", response_model=list[ScimTokenInfo])
def list_scim_tokens(
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[ScimTokenInfo]:
    """Every SCIM token, newest first, without their secrets."""
    return [
        ScimTokenInfo.model_validate(token) for token in scim_tokens_service.list_tokens(settings)
    ]


@router.post("/auth/scim-tokens/{token_id}/revoke", response_model=ScimTokenInfo)
def revoke_scim_token(
    token_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    __: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> ScimTokenInfo:
    """Kill a token immediately. Idempotent."""
    revoked = scim_tokens_service.revoke_token(settings, token_id=token_id, audit=audit)
    if revoked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
    return ScimTokenInfo.model_validate(revoked)
