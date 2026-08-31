from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from api.settings import Settings, load_settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)

# Legacy shared-token agents map to this tenant until they migrate to provisioning keys.
LEGACY_AGENT_TENANT_ID = "default"
AGENT_TOKEN_TYP = "agent"


class Role(str, Enum):
    viewer = "viewer"
    operator = "operator"
    admin = "admin"


ROLE_RANK = {
    Role.viewer: 1,
    Role.operator: 2,
    Role.admin: 3,
}


class TokenUser(BaseModel):
    username: str
    role: Role


class TenantPrincipal(BaseModel):
    """Server-derived tenant context for one request (ROADMAP P0).

    ``tenant_id`` is resolved from the caller's memberships, never taken on
    trust from the query string, and ``role`` is the caller's role *inside*
    that tenant — which may differ from the global role in the JWT.
    """

    username: str
    tenant_id: str
    role: Role
    is_platform_admin: bool = False
    # True when the caller named a tenant explicitly. Lets the cross-tenant
    # lists (jobs, agents) keep showing a platform admin everything by default
    # while still honouring an explicit tenant filter.
    tenant_requested: bool = False


class AgentPrincipal(BaseModel):
    """Authenticated remote agent (JWT provisioning exchange or legacy shared token)."""

    tenant_id: str
    key_id: str | None = None
    agent_id: str | None = None
    subject: str = "agent"
    auth_mode: str = "jwt"  # jwt | legacy


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role
    username: str


class MeResponse(BaseModel):
    username: str
    role: Role
    # Tenants this user may act in, and the tenant used when a request omits
    # ``tenant_id`` (ROADMAP P0). Feeds the UI's tenant switcher.
    tenants: list[str] = Field(default_factory=list)
    default_tenant: str = "default"
    is_platform_admin: bool = False


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def authenticate_user(settings: Settings, username: str, password: str) -> TokenUser | None:
    """Verify console credentials against the Postgres users table (#156).

    Before #156 this walked ``settings.users`` and accepted a **plaintext**
    password whenever the configured value did not start with ``$2``. Both are
    gone: the store is a table, and it holds bcrypt hashes only.

    ``settings`` is still taken so the signature and the call sites are
    unchanged, and because the service resolves its session factory from it.
    """
    from api.services import users as users_service

    record = users_service.authenticate(username, password)
    if record is None:
        return None
    try:
        role = Role(str(record.get("role", "viewer")))
    except ValueError:
        # An unknown role is a broken row, not a viewer. Refusing the login is
        # the safe reading: granting the lowest role would silently turn a
        # typo'd "admn" into a working, quietly-downgraded account.
        return None
    return TokenUser(username=str(record["username"]), role=role)


def create_access_token(settings: Settings, user: TokenUser) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "typ": "user",
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(settings: Settings, token: str) -> TokenUser:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc
    if payload.get("typ") == AGENT_TOKEN_TYP:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent token cannot be used for operator APIs",
        )
    username = payload.get("sub")
    role_raw = payload.get("role")
    if not username or not role_raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    try:
        role = Role(str(role_raw))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid role") from exc
    return TokenUser(username=str(username), role=role)


def decode_agent_token(settings: Settings, token: str) -> AgentPrincipal:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired agent token",
        ) from exc
    if payload.get("typ") != AGENT_TOKEN_TYP:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not an agent token",
        )
    tenant_id = payload.get("tenant_id")
    if not tenant_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent token missing tenant_id",
        )
    return AgentPrincipal(
        tenant_id=str(tenant_id),
        key_id=str(payload["key_id"]) if payload.get("key_id") else None,
        agent_id=str(payload["agent_id"]) if payload.get("agent_id") else str(payload.get("sub") or ""),
        subject=str(payload.get("sub") or "agent"),
        auth_mode="jwt",
    )


def get_settings() -> Settings:
    return load_settings()


SERVICE_TOKEN_STATE_ATTR = "service_token"


def _authenticate_service_token(request: Request, settings: Settings, token: str) -> TokenUser:
    """Resolve a presented service token to a principal and enforce its scopes.

    The principal is stashed on ``request.state`` so :func:`require_tenant` can
    pin the request to the token's own tenant. It never becomes a platform
    admin and never consults a membership row: a service token's authority is
    exactly the role and the scopes it was issued with (ROADMAP Track E).
    """
    from api.services import service_tokens

    principal = service_tokens.verify_token(settings, token)
    if principal is None:
        # One message for unknown, revoked and expired alike — the presenter of
        # a guessed token learns nothing about which half was wrong.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired or revoked service token",
        )

    resource = service_tokens.resource_for_path(request.url.path)
    action = service_tokens.action_for_method(request.method)
    if not principal.allows(resource=resource, action=action):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Service token is not scoped for '{resource}:{action}'",
        )

    try:
        role = Role(principal.role)
    except ValueError as exc:  # pragma: no cover - defended at issue time
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid role"
        ) from exc
    setattr(request.state, SERVICE_TOKEN_STATE_ATTR, principal)
    return TokenUser(username=principal.username, role=role)


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenUser:
    """Authenticate a console JWT **or** a service token on the same header.

    Which one is decided by the credential's own shape (``octo_st_…``), never
    by anything the caller asserts: a value that is not a service token falls
    through to the JWT path and is verified there exactly as before, so nothing
    here weakens the existing check.
    """
    from api.services import service_tokens

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    if service_tokens.looks_like_service_token(token):
        return _authenticate_service_token(request, settings, token)
    return decode_token(settings, token)


def require_role(minimum: Role):
    def _checker(user: Annotated[TokenUser, Depends(get_current_user)]) -> TokenUser:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{minimum.value}' or higher required",
            )
        return user

    return _checker


def require_tenant(minimum: Role):
    """Authenticate, resolve the request's tenant, and enforce the role *in it*.

    Routes keep accepting a ``tenant_id`` query parameter, but it can now only
    select among the tenants the caller is entitled to; anything else is a 403
    rather than a silent cross-tenant read.
    """

    def _checker(
        request: Request,
        user: Annotated[TokenUser, Depends(get_current_user)],
        tenant_id: Annotated[str | None, Query(description="Tenant to act in")] = None,
    ) -> TenantPrincipal:
        from api.services import memberships as memberships_service

        service_principal = getattr(request.state, SERVICE_TOKEN_STATE_ATTR, None)
        if service_principal is not None:
            # A service token is issued *for* a tenant, so there is nothing to
            # resolve: naming another one is refused rather than ignored, and
            # no membership row can raise the role it was issued with.
            requested = (tenant_id or "").strip()
            if requested and requested != service_principal.tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"No access to tenant {requested}",
                )
            role = Role(service_principal.role)
            if ROLE_RANK[role] < ROLE_RANK[minimum]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Role '{minimum.value}' or higher required in tenant "
                        f"'{service_principal.tenant_id}'"
                    ),
                )
            return TenantPrincipal(
                username=user.username,
                tenant_id=service_principal.tenant_id,
                role=role,
                # Never: an admin-role token administers its own tenant, not
                # the fleet, so the cross-tenant listings stay closed to it.
                is_platform_admin=False,
                tenant_requested=True,
            )

        try:
            resolved, role_value = memberships_service.resolve_tenant(
                user.username, tenant_id, global_role=user.role.value
            )
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        try:
            role = Role(role_value)
        except ValueError:
            role = Role.viewer
        if ROLE_RANK[role] < ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{minimum.value}' or higher required in tenant '{resolved}'",
            )
        return TenantPrincipal(
            username=user.username,
            tenant_id=resolved,
            role=role,
            is_platform_admin=user.role == Role.admin,
            tenant_requested=bool((tenant_id or "").strip()),
        )

    return _checker


def require_agent(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentPrincipal:
    """Authenticate remote agent via agent JWT, or legacy OCTO_AGENT_TOKEN."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials

    # Prefer agent JWT (typ=agent). Fall back to shared static token for labs.
    try:
        # Routing peek only -- nothing here is trusted for authorization. A
        # forged typ=agent merely sends the request into decode_agent_token(),
        # which re-decodes against jwt_secret and re-checks typ; the legacy
        # branch compares with hmac.compare_digest.
        unverified = jwt.decode(
            token,
            # nosemgrep: python.jwt.security.unverified-jwt-decode.unverified-jwt-decode
            options={"verify_signature": False, "verify_exp": False},
            algorithms=[settings.jwt_algorithm],
        )
    except jwt.PyJWTError:
        unverified = {}

    if unverified.get("typ") == AGENT_TOKEN_TYP:
        return decode_agent_token(settings, token)

    if settings.agent_token:
        provided = token.encode("utf-8")
        expected = settings.agent_token.encode("utf-8")
        if hmac.compare_digest(provided, expected):
            return AgentPrincipal(
                tenant_id=LEGACY_AGENT_TENANT_ID,
                key_id=None,
                subject="agent",
                auth_mode="legacy",
            )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid agent token (use provisioning-key JWT or OCTO_AGENT_TOKEN)",
    )
