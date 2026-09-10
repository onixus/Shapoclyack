"""Service-token administration (ROADMAP Track E).

``tenant.credential.manage`` on the tenant in the path — the same shape as the
provisioning-key routes next door, and for the same reason (#231): deciding
that a non-human may act inside a tenant is an administrative act, and an
operator who could mint their own credential would be the control removing
itself. Since #318 that permission is held by the tenant's own admin and by
the ``token-admin`` role as well as by the platform admin, so a customer
rotates its own integration credentials instead of asking the platform
operator to — but an ``operator`` still cannot, which is the part that matters.

The plaintext is in the create response and nowhere else. ``GET`` never
returns it, no log line carries it, and no error message quotes it — only a
bcrypt hash is stored, so there is nothing to return afterwards even by
mistake.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import (
    StepUpDep,
    TenantPrincipal,
    get_settings,
    require_path_tenant_permission,
)
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
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
    admin: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_CREDENTIAL_MANAGE)),
    ],
    # Minting a credential that outlives the session minting it is exactly the
    # act #315 puts behind a recent second factor. No effect on an admin who
    # has not enabled MFA, and none on a service token, which cannot reach
    # this route at all (``tenants`` is a forbidden scope resource).
    _: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
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
            audit=audit,
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
    _: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_CREDENTIAL_MANAGE)),
    ],
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
    _: Annotated[
        TenantPrincipal,
        Depends(require_path_tenant_permission(permission_catalog.TENANT_CREDENTIAL_MANAGE)),
    ],
    __: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> ServiceTokenInfo:
    """Kill a token immediately, without waiting for its expiry. Idempotent."""
    revoked = service_tokens_service.revoke_token(
        settings, token_id=token_id, tenant_id=tenant_id, audit=audit
    )
    if revoked is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="token not found")
    return ServiceTokenInfo.model_validate(revoked)
