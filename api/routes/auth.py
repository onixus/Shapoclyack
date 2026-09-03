"""Tenant + provisioning-key admin routes and agent token exchange (Phase 2)."""

from __future__ import annotations

import urllib.parse
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse

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
    OidcLoginResponse,
    Page,
    ProvisioningKeyInfo,
    ReplaceScanScopeRequest,
    ScanScopeEntryInfo,
    SsoStatus,
    TenantInfo,
    TenantPosture,
    TenantQuotaInfo,
    TenantQuotaRequest,
)
from api.core.client_ip import parse_trusted_proxies, resolve_client_ip
from api.core.security import DEFAULT_EXCHANGE_TTL_MINUTES
from api.routes._pagination import PageParams, build_page
from api.services import auth as auth_service
from api.services import auth_audit
from api.services import memberships as memberships_service
from api.services import oidc as oidc_service
from api.services import quotas
from api.services import scan_scopes
from api.services import tenant_posture
from api.services import tenants as tenants_service
from api.services import users as users_service
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
        str | None,
        Query(
            pattern="^(success|failure|locked|denied|trust_change)$",
            description="Filter by outcome",
        ),
    ] = None,
) -> Page[AuthEventInfo]:
    """Recent access decisions, newest first (#157). Platform admin only.

    Logins; since #226 the scans and (since #240) the deployment targets
    refused by a tenant's approved scanning scope (``outcome=denied``); and
    since #241 the SSH host-key pins an admin set or removed
    (``outcome=trust_change``) — one trail, because they are one question.

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


@router.get("/auth/sso", response_model=SsoStatus)
def sso_status(settings: Annotated[Settings, Depends(get_settings)]) -> SsoStatus:
    """Whether this installation offers SSO. Unauthenticated, by necessity.

    The login form has to render the button before anyone is signed in, so this
    cannot sit behind ``require_role``. It answers a boolean and a path and
    nothing else — in particular not the issuer, which would name the
    customer's identity provider to anyone who can reach the login page. The
    same object is embedded in ``GET /api/health`` so a client that already
    polls health needs no second call.
    """
    return SsoStatus.model_validate(oidc_service.public_config(settings))


@router.get("/auth/oidc/login", response_model=OidcLoginResponse)
def oidc_login(
    settings: Annotated[Settings, Depends(get_settings)],
    redirect: Annotated[bool, Query(description="Send a 307 instead of JSON")] = True,
    next_url: Annotated[
        str | None, Query(alias="next", max_length=512, description="Console path to land on")
    ] = None,
):
    """Begin an SSO login: mint state/nonce/PKCE and point the browser at the IdP.

    Answers a redirect by default, because that is what a link on the login
    form needs; ``?redirect=false`` returns the URL as JSON for a client that
    navigates itself.

    ``next`` is confined to a path on this console (it must start with a single
    ``/``). An open redirect on an *authentication* endpoint is the classic way
    to make a phishing link look legitimate, so anything else is dropped rather
    than refused — the login still works, it just lands on the dashboard.
    """
    try:
        request = oidc_service.build_authorization_request(
            settings, next_url=_safe_next(next_url)
        )
    except oidc_service.OidcDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except oidc_service.OidcError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    if redirect:
        return RedirectResponse(request.authorization_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    return OidcLoginResponse(
        authorization_url=request.authorization_url,
        state=request.state,
        expires_in=request.expires_in,
    )


def _safe_next(value: str | None) -> str:
    """Keep ``next`` only when it is a path on this console.

    ``//evil.example`` and ``/\\evil.example`` are both browser-relative
    protocol shorthands, so a leading slash alone is not enough.
    """
    candidate = (value or "").strip()
    if not candidate.startswith("/") or candidate.startswith(("//", "/\\")):
        return ""
    return candidate[:512]


@router.get("/auth/oidc/callback", response_model=TokenResponse)
def oidc_callback(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    code: Annotated[str | None, Query(max_length=4096)] = None,
    state: Annotated[str | None, Query(max_length=4096)] = None,
    error: Annotated[str | None, Query(max_length=256)] = None,
):
    """Finish an SSO login and issue the platform's ordinary session token.

    The session is exactly what password login issues — same JWT, same claims,
    same expiry — because everything downstream of authentication should not
    care how the user proved who they are.

    Every failure is one 401 with a short message: which check failed (state,
    signature, audience, nonce, provisioning policy) is information only the
    presenter of a bad callback wants. All of them are recorded in the auth
    trail, which is where an operator reads the difference.
    """
    client_ip = _client_ip(request, settings)
    if error:
        auth_audit.record_denied(
            username="", reason=auth_audit.REASON_SSO_DENIED, detail="provider returned an error"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Single sign-on was refused"
        )
    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Missing authorization code or state"
        )

    try:
        completed = oidc_service.complete_callback(settings, code=code, state=state)
    except oidc_service.OidcDisabledError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except oidc_service.OidcError as exc:
        auth_audit.record_denied(
            username="", reason=auth_audit.REASON_SSO_DENIED, detail=str(exc)
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Single sign-on failed"
        ) from exc

    claims = completed["claims"]
    username = oidc_service.username_from_claims(settings, claims)
    try:
        user_record, action = users_service.link_or_provision_sso_user(
            settings,
            issuer=settings.oidc_issuer.strip().rstrip("/"),
            subject=str(claims["sub"]),
            username=username,
            email=claims.get("email"),
            email_verified=oidc_service.email_verified_from_claims(claims),
            role=oidc_service.role_from_claims(settings, claims),
            tenant_id=oidc_service.tenant_from_claims(settings, claims),
            jit_enabled=settings.oidc_jit_provisioning,
        )
    except PermissionError as exc:
        auth_audit.record_denied(
            username=username, reason=auth_audit.REASON_SSO_NOT_PROVISIONED, detail=str(exc)
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This identity has no console account on this installation",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    token_user = TokenUser(
        username=str(user_record["username"]), role=Role(str(user_record["role"]))
    )
    auth_audit.record_sso_login(
        username=token_user.username, client_ip=client_ip, action=action
    )
    token = create_access_token(settings, token_user)

    destination = settings.oidc_post_login_redirect.strip()
    if destination:
        # The token rides in the URL *fragment*, which browsers never send to a
        # server and which is not written to access logs the way a query string
        # is. The console reads it, stores it, and clears the fragment.
        separator = "&" if "#" in destination else "#"
        landing = f"{destination}{separator}access_token={token}&token_type=bearer"
        next_url = str(completed.get("next_url") or "")
        if next_url:
            # Percent-encoded: the fragment already carries the session token as
            # ``&``-separated parameters, so an unescaped path could append
            # parameters of its own to the URL the console is about to parse.
            landing = f"{landing}&next={urllib.parse.quote(next_url, safe='/')}"
        return RedirectResponse(landing, status_code=status.HTTP_303_SEE_OTHER)
    return TokenResponse(access_token=token, role=token_user.role, username=token_user.username)


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


@router.get("/tenants/{tenant_id}/quota", response_model=TenantQuotaInfo)
def get_tenant_quota(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TenantQuotaInfo:
    """What this tenant was sold (Track E). Platform admin only.

    ``quota_source`` distinguishes a limit somebody wrote for this customer
    from the platform default they merely inherited — a distinction that
    matters when the answer is "unlimited", because only one of the two is a
    decision.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    quota = quotas.get_quota(settings, tenant_id)
    return TenantQuotaInfo(
        tenant_id=tenant_id,
        max_assets=quota.max_assets,
        max_scans_per_month=quota.max_scans_per_month,
        quota_source=quota.source,
        note=quota.note,
        updated_at=quota.updated_at,
        updated_by=quota.updated_by,
    )


@router.put("/tenants/{tenant_id}/quota", response_model=TenantQuotaInfo)
def set_tenant_quota(
    tenant_id: str,
    body: TenantQuotaRequest,
    user: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TenantQuotaInfo:
    """Set this tenant's limits, replacing whatever applied before.

    Platform admin, for the reason scan-scope approval is: a tenant operator
    who could raise their own quota is the control removing itself. The
    caller's username and the moment are stamped on the row, so "who sold them
    5,000 assets" has an answer that is not a memory.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    quota = quotas.set_quota(
        settings,
        tenant_id,
        max_assets=body.max_assets,
        max_scans_per_month=body.max_scans_per_month,
        note=body.note,
        updated_by=user.username,
    )
    return TenantQuotaInfo(
        tenant_id=tenant_id,
        max_assets=quota.max_assets,
        max_scans_per_month=quota.max_scans_per_month,
        quota_source=quota.source,
        note=quota.note,
        updated_at=quota.updated_at,
        updated_by=quota.updated_by,
    )


@router.delete("/tenants/{tenant_id}/quota", status_code=status.HTTP_204_NO_CONTENT)
def clear_tenant_quota(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Return this tenant to the platform default.

    Distinct from a PUT of nulls, which stores "unlimited **for this
    tenant**": that row survives a later change to the platform default,
    and deleting it is the only way to say the customer should follow
    whatever the platform is set to from now on.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    quotas.clear_quota(settings, tenant_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/tenants/{tenant_id}/scan-scope", response_model=list[ScanScopeEntryInfo])
def list_scan_scope(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[ScanScopeEntryInfo]:
    """What this tenant is allowed to scan (#226). Platform admin only.

    An empty list is a meaningful answer, not a missing one: the tenant scans
    nothing until a scope is approved.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    return [
        ScanScopeEntryInfo.model_validate(entry)
        for entry in scan_scopes.list_entries(settings, tenant_id)
    ]


@router.put("/tenants/{tenant_id}/scan-scope", response_model=list[ScanScopeEntryInfo])
def replace_scan_scope(
    tenant_id: str,
    body: ReplaceScanScopeRequest,
    user: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[ScanScopeEntryInfo]:
    """Approve the scope this tenant may scan, replacing whatever it had.

    Platform admin, like provisioning-key creation (#231): deciding that a
    tenant may point the platform at a network is an administrative act, and
    an operator who could widen their own scope would be the control removing
    itself. The caller's username is stamped on every resulting row.
    """
    try:
        entries = scan_scopes.replace_scope(
            settings,
            tenant_id=tenant_id,
            entries=[entry.model_dump() for entry in body.entries],
            approved_by=user.username,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return [ScanScopeEntryInfo.model_validate(entry) for entry in entries]
