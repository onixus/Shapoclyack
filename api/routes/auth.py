"""Tenant + provisioning-key admin routes and agent token exchange (Phase 2)."""

from __future__ import annotations

import urllib.parse
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse

from api.auth import (
    LoginRequest,
    LoginResponse,
    MeResponse,
    Role,
    StepUpDep,
    TokenUser,
    authenticate_user,
    create_access_token,
    create_pre_auth_token,
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
    PromotedDomainInfo,
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
from api.routes._audit import AuditDep
from api.routes._pagination import PageParams, build_page
from api.services import agents as agents_service
from api.services import auth as auth_service
from api.services import auth_audit
from api.services import local_login
from api.services import memberships as memberships_service
from api.services import mfa as mfa_service
from api.services import oidc as oidc_service
from api.services import promoted_domains
from api.services import quotas
from api.services import scan_scopes
from api.services import sessions as sessions_service
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


@router.post("/auth/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    """Exchange console credentials for a bearer token, or for a challenge.

    Rate-limited per ``(username, client IP)`` with a Postgres-backed counter
    (#157), so the limit is shared by every API replica. A refusal is a 429
    with ``Retry-After``; it does not reveal whether the account exists, and
    the window decays on its own — no operator unlocks anything.

    Counting, verification and recording happen inside ``attempt_login`` as one
    serialized operation, so a batch of concurrent guesses cannot all pass a
    count taken before any of them has been recorded.

    Three things can now happen to a correct password (#315):

    * the account has a second factor — no session is issued, only a five-minute
      pre-authentication token for ``POST /api/auth/mfa/verify``;
    * this installation requires a factor of the account's role and it has not
      enrolled — a session is issued carrying ``mfa_pending``, which reaches the
      enrolment routes and nothing else (:func:`api.auth.get_current_user`);
    * otherwise, exactly the session this endpoint has always returned.
    """
    client_ip = _client_ip(request, settings)
    try:
        break_glass = local_login.check_allowed(settings, body.username)
    except local_login.LocalLoginRefused as exc:
        # Refused by policy, answered as a wrong password. Naming the policy
        # here would tell an unauthenticated caller which usernames are *not*
        # break-glass accounts, i.e. hand over the shortlist worth attacking;
        # the installation-wide mode is public in ``GET /api/auth/sso``, which
        # names nobody. The reason is in the trail, where it belongs.
        auth_audit.record_denied(
            username=body.username, reason=exc.reason, detail=str(exc)
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        ) from exc

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

    if mfa_service.is_enabled(settings, user.username):
        # The password is right and that is all that has been established. The
        # success row above says the first factor passed; the session, and the
        # break-glass record that goes with it, wait for the second leg.
        try:
            challenge = create_pre_auth_token(
                settings,
                user.username,
                ttl_minutes=mfa_service.PRE_AUTH_TTL_MINUTES,
                break_glass=break_glass,
            )
        except LookupError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            ) from exc
        return LoginResponse(
            username=user.username,
            mfa_required=True,
            mfa_token=challenge,
            expires_in=mfa_service.PRE_AUTH_TTL_MINUTES * 60,
        )

    # Not enrolled — ``is_enabled`` said so above — so "policy names this role"
    # is the whole of "this session owes an enrolment". The session itself is
    # confined by ``get_current_user``, which re-decides it per request; this
    # is only what the console is told so it can route straight to the setup
    # page instead of discovering it as a 403 on the dashboard.
    pending = mfa_service.required_for_role(settings, user.role.value)
    try:
        token = create_access_token(settings, user)
    except LookupError as exc:
        # The account was deleted between the credential check and here. The
        # same refusal as a wrong password: a race with a deletion is not a
        # server fault, and the answer must not distinguish the two.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        ) from exc
    if break_glass:
        local_login.record_break_glass(settings, username=user.username, client_ip=client_ip)
    return LoginResponse(
        access_token=token,
        role=user.role,
        username=user.username,
        # Not an error and not a challenge: the session exists, and the console
        # reads this to send the user straight to the enrolment page instead of
        # letting them find out by way of a 403 on the dashboard.
        mfa_required=pending,
    )


@router.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """End *this* session and no other (#314).

    The presented token's ``jti`` goes on the denylist until its own ``exp``,
    so signing out on a laptop leaves the phone signed in. "Everywhere" is the
    next endpoint down.

    Refused rather than answered with a 204 that did nothing when the presented
    credential has no ``jti`` to deny. In practice that is a console token
    minted before #314: those hold their authority until they expire, and
    saying so is more use than pretending. A service token never reaches this
    branch at all — ``auth`` is a resource no service token may touch
    (``FORBIDDEN_RESOURCES``), so the scope layer answers 403 first, which is
    right: a service token is a credential, revoked with
    ``POST /api/tenants/{tenant_id}/service-tokens/{token_id}/revoke``, not a
    session.
    """
    if user.jti is None or user.expires_at is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "This session carries no token id and cannot be ended one at a "
                "time. End every session of the account with "
                "POST /api/auth/sessions/revoke-all."
            ),
        )
    sessions_service.revoke_token(
        settings, jti=user.jti, username=user.username, expires_at=user.expires_at
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/auth/sessions/revoke-all", status_code=status.HTTP_204_NO_CONTENT)
def revoke_own_sessions(
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Response:
    """Sign out of every session of the caller's own account, this one included.

    The "I left it logged in somewhere" button, and the only way to end a
    session whose token predates #314 and therefore carries no ``jti``: the
    account's token generation moves on and every token quoting the old one
    stops verifying at once.

    Unlike logout it accepts a token with no ``jti``, because the generation
    bump does not need one — which is what makes it the answer for a session
    that predates #314.
    """
    try:
        sessions_service.revoke_all(settings, user.username)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
def me(
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> MeResponse:
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
        # Reachable by a session that owes an enrolment: this route is on the
        # ``mfa_pending`` allowlist precisely so the console can render the
        # banner that sends the user to the setup page (#315).
        mfa_enabled=mfa_service.is_enabled(settings, user.username),
        mfa_required=mfa_service.required_for_role(settings, user.role.value),
        mfa_pending=user.mfa_pending,
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


@router.get("/auth/oidc/callback", response_model=LoginResponse)
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

    Which includes the second factor (#315): an account that has enrolled one
    is answered with the same five-minute challenge a password login gets, in
    the same place the session would have been (the fragment, as ``mfa_token``).
    Skipping it here would have made MFA opt-out by way of clicking the other
    button on the login form.

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
    # An account that has enrolled a second factor is challenged here too
    # (#315). The identity provider proved *an* identity; it did not prove
    # possession of the authenticator this installation holds a seed for, and
    # letting SSO skip the check would make the whole feature opt-out by way of
    # clicking a different button. An account that has *not* enrolled needs no
    # special case: ``get_current_user`` re-derives ``mfa_pending`` per request,
    # so an SSO session of a covered role is confined exactly like a password
    # one until it enrols.
    challenge: str | None = None
    try:
        if mfa_service.is_enabled(settings, token_user.username):
            challenge = create_pre_auth_token(
                settings,
                token_user.username,
                ttl_minutes=mfa_service.PRE_AUTH_TTL_MINUTES,
            )
            token = ""
        else:
            token = create_access_token(settings, token_user)
    except LookupError as exc:  # the account was deleted mid-callback
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Single sign-on failed"
        ) from exc

    destination = settings.oidc_post_login_redirect.strip()
    if destination:
        # The token rides in the URL *fragment*, which browsers never send to a
        # server and which is not written to access logs the way a query string
        # is. The console reads it, stores it, and clears the fragment.
        separator = "&" if "#" in destination else "#"
        landing = (
            f"{destination}{separator}mfa_token={challenge}"
            f"&expires_in={mfa_service.PRE_AUTH_TTL_MINUTES * 60}"
            if challenge
            else f"{destination}{separator}access_token={token}&token_type=bearer"
        )
        next_url = str(completed.get("next_url") or "")
        if next_url:
            # Percent-encoded: the fragment already carries the session token as
            # ``&``-separated parameters, so an unescaped path could append
            # parameters of its own to the URL the console is about to parse.
            landing = f"{landing}&next={urllib.parse.quote(next_url, safe='/')}"
        return RedirectResponse(landing, status_code=status.HTTP_303_SEE_OTHER)
    if challenge:
        return LoginResponse(
            username=token_user.username,
            mfa_required=True,
            mfa_token=challenge,
            expires_in=mfa_service.PRE_AUTH_TTL_MINUTES * 60,
        )
    return LoginResponse(
        access_token=token, role=token_user.role, username=token_user.username
    )


@router.post("/auth/agent/token", response_model=AgentTokenResponse)
def agent_token(
    body: AgentTokenRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentTokenResponse:
    """Exchange a provisioning key for a short-lived agent JWT (tenant_id in claims).

    A good key and a free ``agent_id`` are two different questions, and they
    get two different answers (#308): 401 when the key is not exchangeable,
    403 when it is but the id belongs to another tenant, to another live key,
    or to an agent an operator has disabled.
    """
    try:
        result = auth_service.exchange_provisioning_key(
            settings,
            body.provisioning_key,
            agent_id=body.agent_id,
        )
    except agents_service.AgentIdentityConflict as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
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
    except agents_service.AgentIdentityConflict as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
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
    audit: AuditDep,
) -> MembershipInfo:
    """Grant (or re-grant) one user access to one tenant. Idempotent."""
    try:
        granted = memberships_service.grant(
            username=username,
            tenant_id=tenant_id,
            role=body.role,
            created_by=user.username,
            audit=audit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return MembershipInfo.model_validate(granted)


@router.delete("/tenants/{tenant_id}/members/{username}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_membership(
    tenant_id: str,
    username: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    audit: AuditDep,
) -> None:
    if not memberships_service.revoke(username=username, tenant_id=tenant_id, audit=audit):
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
    # A provisioning key enrols agents into a tenant and outlives the session
    # that made it, so an account with a second factor must have proved it
    # recently to mint one (#315). No effect on an account without MFA.
    __: StepUpDep,
    audit: AuditDep,
) -> ProvisioningKeyInfo:
    try:
        created = tenants_service.create_provisioning_key(
            tenant_id=tenant_id, label=body.label, audit=audit
        )
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
    # Step-up on the revoke as well as the create (#315): cutting a tenant's
    # agents off the platform is as much a credential decision as issuing them.
    __: StepUpDep,
    audit: AuditDep,
) -> ProvisioningKeyInfo:
    revoked = tenants_service.revoke_provisioning_key(key_id, audit=audit)
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


@router.get("/tenants/{tenant_id}/promoted-domains", response_model=list[PromotedDomainInfo])
def list_promoted_domains(
    tenant_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[PromotedDomainInfo]:
    """Related domains this tenant's operators promoted into scope (org_profile M4).

    The admin's cross-check on the scope above: every scan the tenant starts
    carries these in addition to its own targets, so the admin approving the
    scope should be able to see what the operators have added underneath it.
    Withdrawal is the operator's ``DELETE /api/promoted-domains/{domain}``.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant not found")
    return [
        PromotedDomainInfo.model_validate(item)
        for item in promoted_domains.list_promoted(settings, tenant_id)
    ]


@router.put("/tenants/{tenant_id}/scan-scope", response_model=list[ScanScopeEntryInfo])
def replace_scan_scope(
    tenant_id: str,
    body: ReplaceScanScopeRequest,
    user: Annotated[TokenUser, Depends(require_role(Role.admin))],
    _: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> list[ScanScopeEntryInfo]:
    """Approve the scope this tenant may scan, replacing whatever it had.

    Platform admin, like provisioning-key creation (#231): deciding that a
    tenant may point the platform at a network is an administrative act, and
    an operator who could widen their own scope would be the control removing
    itself. The caller's username is stamped on every resulting row.

    Behind a step-up since #315, for the same reason the credential routes are:
    widening what the platform may scan is the one administrative act whose
    blast radius is somebody else's network, and an eight-hour-old session
    left open is not the evidence one should need to take it.
    """
    try:
        entries = scan_scopes.replace_scope(
            settings,
            tenant_id=tenant_id,
            entries=[entry.model_dump() for entry in body.entries],
            approved_by=user.username,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return [ScanScopeEntryInfo.model_validate(entry) for entry in entries]
