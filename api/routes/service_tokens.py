"""Service-token administration (ROADMAP Track E).

Platform admin only, and tenant-scoped in the path — the same shape as the
provisioning-key routes next door, and for the same reason (#231): deciding
that a non-human may act inside a tenant is an administrative act, and an
operator who could mint their own credential would be the control removing
itself.

The plaintext is in the create response and nowhere else. ``GET`` never
returns it, no log line carries it, and no error message quotes it — only a
bcrypt hash is stored, so there is nothing to return afterwards even by
mistake.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TokenUser, get_settings, require_role
from api.schemas import CreateServiceTokenRequest, ServiceTokenInfo
from api.services import service_tokens as service_tokens_service
from api.services import tenants as tenants_service
from api.settings import Settings

router = APIRouter(tags=["service-tokens"])


def _require_tenant(tenant_id: str) -> None:
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")


@router.post(
    "/tenants/{tenant_id}/service-tokens",
    response_model=ServiceTokenInfo,
    status_code=status.HTTP_201_CREATED,
)
def create_service_token(
    tenant_id: str,
    body: CreateServiceTokenRequest,
    admin: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ServiceTokenInfo:
    """Issue one token. The response is the only place its plaintext ever exists."""
    try:
        created = service_tokens_service.create_token(
            settings,
            tenant_id=tenant_id,
            name=body.name,
            scopes=body.scopes,
            role=body.role,
            created_by=admin.username,
            expires_in_days=body.expires_in_days,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return ServiceTokenInfo.model_validate(created)


@router.get("/tenants/{tenant_id}/service-tokens", response_model=list[ServiceTokenInfo])
def list_service_tokens(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[ServiceTokenInfo]:
    """Every token issued for this tenant, newest first, without their secrets.

    Revoked and expired ones stay listed: "which credential was this, and when
    did it stop working" is the question an incident asks, and deleting the row
    would delete the answer.
    """
    _require_tenant(tenant_id)
    return [
        ServiceTokenInfo.model_validate(token)
        for token in service_tokens_service.list_tokens(settings, tenant_id=tenant_id)
    ]


@router.post(
    "/tenants/{tenant_id}/service-tokens/{token_id}/revoke",
    response_model=ServiceTokenInfo,
)
def revoke_service_token(
    tenant_id: str,
    token_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> ServiceTokenInfo:
    """Kill a token immediately, without waiting for its expiry. Idempotent."""
    revoked = service_tokens_service.revoke_token(
        settings, token_id=token_id, tenant_id=tenant_id
    )
    if revoked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
    return ServiceTokenInfo.model_validate(revoked)
