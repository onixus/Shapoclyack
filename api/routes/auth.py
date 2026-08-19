"""Tenant + provisioning-key admin routes and agent token exchange (Phase 2)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

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
    AuthEventInfo,
    AuthExchangeRequest,
    AuthExchangeResponse,
    CreateProvisioningKeyRequest,
    CreateTenantRequest,
    GrantMembershipRequest,
    MembershipInfo,
    Page,
    ProvisioningKeyInfo,
    TenantInfo,
    TenantPosture,
)
from api.core.client_ip import parse_trusted_proxies, resolve_client_ip
from api.core.security import DEFAULT_EXCHANGE_TTL_MINUTES
from api.routes._pagination import PageParams, build_page
from api.services import auth as auth_service
from api.services import auth_audit
from api.services import memberships as memberships_service
from api.services import tenant_posture
from api.services import tenants as tenants_service
from api.settings import Settings

router = APIRouter(tags=["auth"])

# Deliberately the same text for "locked out" whichever limit tripped and
# whether or not the account exists: the response to a refused attempt is the
# last place worth leaking that an account is real (#157).
_LOCKED_DETAIL = "Too many failed login attempts. Try again later."


def _client_ip(request: Request, settings: Settings) -> str:
    return resolve_client_ip(
        request.client.host if request.client else None,
        request.headers.get("x-forwarded-for"),
        parse_trusted_proxies(settings.trusted_proxies),
    )


@router.post("/auth/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenResponse:
    """Exchange console credentials for a bearer token.

    Rate-limited per ``(username, client IP)`` with a Postgres-backed counter
    (#157), so the limit is shared by every API replica. A refusal is a 429
    with ``Retry-After``; it does not reveal whether the account exists, and
    the window decays on its own — no operator unlocks anything.

    Counting, verification and recording happen inside ``attempt_login`` as one
    serialized operation, so a batch of concurrent guesses cannot all pass a
    count taken before any of them has been recorded.
    """
    client_ip = _client_ip(request, settings)
    outcome = auth_audit.attempt_login(
        username=body.username,
        client_ip=client_ip,
        verify=lambda: authenticate_user(settings, body.username, body.password),
    )
    if outcome.lockout is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_LOCKED_DETAIL,
            headers={"Retry-After": str(outcome.lockout.retry_after_seconds)},
        )
    user = outcome.user
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(settings, user)
    return TokenResponse(access_token=token, role=user.role, username=user.username)


@router.get("/auth/events", response_model=Page[AuthEventInfo])
def list_auth_events(
    params: PageParams,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    outcome: Annotated[
        str | None, Query(pattern="^(success|failure|locked)$", description="Filter by outcome")
    ] = None,
) -> Page[AuthEventInfo]:
    """Recent login attempts, newest first (#157). Platform admin only.

    ``q`` matches username or client IP. Always newest-first: this is a log,
    and the ``sort``/``order`` parameters the other lists take would only offer
    orders nobody reads an audit trail in.
    """
    items, total = auth_audit.list_events(
        offset=params.offset, limit=params.limit, q=params.q, outcome=outcome
    )
    return build_page([AuthEventInfo.model_validate(item) for item in items], total, params)


@router.get("/auth/me", response_model=MeResponse)
def me(user: Annotated[TokenUser, Depends(get_current_user)]) -> MeResponse:
    is_platform_admin = user.role == Role.admin
    tenants = memberships_service.tenants_for_user(
        user.username, is_platform_admin=is_platform_admin
    )
    return MeResponse(
        username=user.username,
        role=user.role,
        tenants=tenants,
        default_tenant=memberships_service.default_tenant_for_user(
            user.username, is_platform_admin=is_platform_admin
        ),
        is_platform_admin=is_platform_admin,
    )


@router.post("/auth/agent/token", response_model=AgentTokenResponse)
def agent_token(
    body: AgentTokenRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentTokenResponse:
    """Exchange a provisioning key for a short-lived agent JWT (tenant_id in claims)."""
    try:
        result = auth_service.exchange_provisioning_key(
            settings,
            body.provisioning_key,
            agent_id=body.agent_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return AgentTokenResponse.model_validate(result)


@router.post("/v1/auth/exchange", response_model=AuthExchangeResponse)
def auth_exchange(
    body: AuthExchangeRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AuthExchangeResponse:
    """Provisioning key → short-lived JWT (2h) with ``tenant_id`` + ``agent_id``."""
    try:
        result = auth_service.exchange_provisioning_key(
            settings,
            body.provisioning_key,
            agent_id=body.agent_id,
            expires_minutes=DEFAULT_EXCHANGE_TTL_MINUTES,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return AuthExchangeResponse.model_validate(result)


@router.get("/tenants", response_model=list[TenantInfo])
def list_tenants(
    user: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> list[TenantInfo]:
    """Tenants the caller may act in — the whole list only for a platform admin.

    This is what the UI's tenant switcher reads, so returning every tenant to
    every operator would leak the customer list of an MSSP installation.
    """
    allowed = set(
        memberships_service.tenants_for_user(
            user.username, is_platform_admin=user.role == Role.admin
        )
    )
    return [
        TenantInfo.model_validate(t)
        for t in tenants_service.list_tenants()
        if t["tenant_id"] in allowed
    ]


@router.get("/tenants/posture", response_model=list[TenantPosture])
def list_tenant_posture(
    user: Annotated[TokenUser, Depends(require_role(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[TenantPosture]:
    """Per-tenant risk comparison for an MSSP (#139). Same tenant set as ``GET /tenants``."""
    allowed = memberships_service.tenants_for_user(
        user.username, is_platform_admin=user.role == Role.admin
    )
    return [
        TenantPosture.model_validate(row)
        for row in tenant_posture.list_posture(settings, tenant_ids=allowed)
    ]


@router.get("/tenants/{tenant_id}/members", response_model=list[MembershipInfo])
def list_members(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> list[MembershipInfo]:
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    return [
        MembershipInfo.model_validate(m)
        for m in memberships_service.list_memberships(tenant_id=tenant_id)
    ]


@router.put(
    "/tenants/{tenant_id}/members/{username}",
    response_model=MembershipInfo,
)
def grant_membership(
    tenant_id: str,
    username: str,
    body: GrantMembershipRequest,
    user: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> MembershipInfo:
    """Grant (or re-grant) one user access to one tenant. Idempotent."""
    try:
        granted = memberships_service.grant(
            username=username,
            tenant_id=tenant_id,
            role=body.role,
            created_by=user.username,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return MembershipInfo.model_validate(granted)


@router.delete("/tenants/{tenant_id}/members/{username}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_membership(
    tenant_id: str,
    username: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
) -> None:
    if not memberships_service.revoke(username=username, tenant_id=tenant_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="membership not found")


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
