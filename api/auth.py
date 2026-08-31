from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Query, status
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
    scopes: list[str] = Field(default_factory=lambda: ["*"])
    tenant_id: str | None = None


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
    scopes: list[str] = Field(default_factory=list)
    token_id: str | None = None



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


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> TokenUser:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    if token.startswith("shk_"):
        from api.services import service_tokens as st_service

        principal = st_service.authenticate_token(token, settings=settings)
        if principal is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired service token",
            )
        try:
            role = Role(principal["role"])
        except ValueError:
            role = Role.viewer
        return TokenUser(
            username=f"token:{principal['token_id']}",
            role=role,
            scopes=principal.get("scopes", []),
            tenant_id=principal["tenant_id"],
        )
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
    rather than a silent cross-tenant read. Supports both user JWTs and scoped
    service tokens (``shk_...``).
    """

    def _checker(
        user: Annotated[TokenUser, Depends(get_current_user)],
        tenant_id: Annotated[str | None, Query(description="Tenant to act in")] = None,
    ) -> TenantPrincipal:
        if user.tenant_id:
            # Service token
            if tenant_id and tenant_id.strip() and tenant_id.strip() != user.tenant_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Service token is bound to tenant '{user.tenant_id}', cannot act in '{tenant_id}'",
                )
            if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Role '{minimum.value}' or higher required in tenant '{user.tenant_id}'",
                )
            token_id = user.username.split(":", 1)[1] if user.username.startswith("token:") else None
            return TenantPrincipal(
                username=user.username,
                tenant_id=user.tenant_id,
                role=user.role,
                is_platform_admin=False,
                tenant_requested=bool((tenant_id or "").strip()),
                scopes=user.scopes,
                token_id=token_id,
            )

        from api.services import memberships as memberships_service

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
            scopes=["*"],
            token_id=None,
        )

    return _checker


def require_scope(scope: str, minimum: Role = Role.viewer):
    """Enforce a fine-grained capability scope on service tokens (user JWTs pass by default)."""
    tenant_checker = require_tenant(minimum)

    def _checker(
        user: Annotated[TokenUser, Depends(get_current_user)],
        tenant_id: Annotated[str | None, Query(description="Tenant to act in")] = None,
    ) -> TenantPrincipal:
        principal = tenant_checker(user=user, tenant_id=tenant_id)
        if principal.token_id:
            # Service token: must have specific scope or wildcard '*'
            if "*" not in principal.scopes and scope not in principal.scopes:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Service token missing required scope '{scope}'",
                )
        return principal

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
