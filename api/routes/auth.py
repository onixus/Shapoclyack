"""Tenant + provisioning-key admin routes and agent token exchange (Phase 2)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import (
    LoginRequest,
    MeResponse,
    Role,
    TokenResponse,
    TokenUser,
    authenticate_user,
    create_access_token,
    get_current_user,
    get_settings,
    require_role,
)
from api.schemas import (
    AgentTokenRequest,
    AgentTokenResponse,
    CreateProvisioningKeyRequest,
    CreateTenantRequest,
    ProvisioningKeyInfo,
    TenantInfo,
)
from api.services import auth as auth_service
from api.services import tenants as tenants_service
from api.settings import Settings

router = APIRouter(tags=["auth"])


@router.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, settings: Annotated[Settings, Depends(get_settings)]) -> TokenResponse:
    user = authenticate_user(settings, body.username, body.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(settings, user)
    return TokenResponse(access_token=token, role=user.role, username=user.username)


@router.get("/auth/me", response_model=MeResponse)
def me(user: Annotated[TokenUser, Depends(get_current_user)]) -> MeResponse:
    return MeResponse(username=user.username, role=user.role)


@router.post("/auth/agent/token", response_model=AgentTokenResponse)
def agent_token(
    body: AgentTokenRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentTokenResponse:
    """Exchange a provisioning key for a short-lived agent JWT (tenant_id in claims)."""
    try:
        result = auth_service.exchange_provisioning_key(settings, body.provisioning_key)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return AgentTokenResponse.model_validate(result)


@router.get("/tenants", response_model=list[TenantInfo])
def list_tenants(
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> list[TenantInfo]:
    return [TenantInfo.model_validate(t) for t in tenants_service.list_tenants()]


@router.post("/tenants", response_model=TenantInfo, status_code=status.HTTP_201_CREATED)
def create_tenant(
    body: CreateTenantRequest,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> TenantInfo:
    try:
        created = tenants_service.create_tenant(name=body.name, tenant_id=body.tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return TenantInfo.model_validate(created)


@router.post(
    "/tenants/{tenant_id}/provisioning-keys",
    response_model=ProvisioningKeyInfo,
    status_code=status.HTTP_201_CREATED,
)
def create_provisioning_key(
    tenant_id: str,
    body: CreateProvisioningKeyRequest,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> ProvisioningKeyInfo:
    try:
        created = tenants_service.create_provisioning_key(tenant_id=tenant_id, label=body.label)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ProvisioningKeyInfo.model_validate(created)


@router.get("/tenants/{tenant_id}/provisioning-keys", response_model=list[ProvisioningKeyInfo])
def list_provisioning_keys(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> list[ProvisioningKeyInfo]:
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    return [
        ProvisioningKeyInfo.model_validate(k)
        for k in tenants_service.list_provisioning_keys(tenant_id=tenant_id)
    ]


@router.post(
    "/tenants/{tenant_id}/provisioning-keys/{key_id}/revoke",
    response_model=ProvisioningKeyInfo,
)
def revoke_provisioning_key(
    tenant_id: str,
    key_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> ProvisioningKeyInfo:
    revoked = tenants_service.revoke_provisioning_key(key_id)
    if revoked is None or revoked.get("tenant_id") != tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="key not found")
    return ProvisioningKeyInfo.model_validate(revoked)
