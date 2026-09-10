from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated, Any

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
    """The authenticated console principal for one request.

    ``jti`` and ``expires_at`` are carried so ``POST /api/auth/logout`` can put
    *this* token on the denylist without decoding the header a second time.
    Both are ``None`` for a service token, which is revoked as a credential
    rather than as a session
    (``POST /api/tenants/{tenant_id}/service-tokens/{token_id}/revoke``).
    """

    username: str
    role: Role
    jti: str | None = None
    expires_at: datetime | None = None


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
    """Mint a console session token (#314).

    Two claims beyond the pre-#314 set, and one header:

    * ``ver`` — the account's ``token_version`` *at this moment*, read from the
      table rather than carried from the login lookup, so a revocation racing a
      login wins. :func:`decode_token` refuses a token whose ``ver`` has since
      moved on, which is how a disable, a demotion or a password change reaches
      a token already in somebody's browser.
    * ``jti`` — a per-token identifier, so one session can be logged out
      without ending the others.
    * ``kid`` — which key signed this, so a rotation window verifies against
      the right one first instead of trying each in turn.

    An account that vanished between authentication and here is mint-refused
    rather than issued a version-0 token: a missing row is exactly what a
    concurrent delete looks like.
    """
    from api.core.security import jwt_kid
    from api.services import sessions as sessions_service

    expire = datetime.now(UTC) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "typ": "user",
        "ver": sessions_service.current_version(settings, user.username),
        "jti": uuid.uuid4().hex,
        "exp": expire,
        "iat": datetime.now(UTC),
    }
    return jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
        headers={"kid": jwt_kid(settings.jwt_secret)},
    )


def verify_signature(
    settings: Settings,
    token: str,
    secrets: list[str],
    *,
    leeway: float = 0,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify ``token`` against a rotation window, newest key first (#314).

    When the token names a ``kid`` this installation knows, that key is the
    only one tried: a token that says which key signed it and then does not
    verify under it is forged, and trying the rest would only make the refusal
    slower. An unknown or absent ``kid`` — every token issued before this
    change has none — falls back to trying the whole window in order.

    ``leeway`` and ``options`` are passed straight to ``jwt.decode``: the OIDC
    login state is signed with the same key and must verify against the same
    window (otherwise a rotation breaks SSO mid-rollout), but it asks for
    required claims and a clock skew allowance the console token does not.

    Raises ``jwt.PyJWTError`` like ``jwt.decode`` does, so the callers keep
    their existing single ``except``.
    """
    from api.core.security import jwt_kid

    candidates = secrets
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except jwt.PyJWTError:
        kid = None
    if kid:
        matched = [secret for secret in secrets if jwt_kid(secret) == kid]
        if matched:
            candidates = matched

    last_error: jwt.PyJWTError | None = None
    for secret in candidates:
        try:
            return jwt.decode(
                token,
                secret,
                algorithms=[settings.jwt_algorithm],
                leeway=leeway,
                options=options or {},
            )
        except jwt.ExpiredSignatureError:
            # Expiry is a property of the token, not of the key: another key in
            # the window cannot make an expired token fresh, and continuing
            # would report the last key's "signature mismatch" instead.
            raise
        except jwt.PyJWTError as exc:
            last_error = exc
    raise last_error if last_error is not None else jwt.InvalidTokenError("no signing key configured")


def decode_token(settings: Settings, token: str) -> TokenUser:
    """Verify a console JWT **and** confirm the session behind it still exists.

    Before #314 this function was the whole check: the role was read out of the
    claims and the database was never asked, so disabling, deleting or demoting
    an account left the token in that person's browser working for the rest of
    its eight-hour life. Every request now costs two primary-key lookups
    (:func:`api.services.sessions.check_session`) and revocation is immediate.

    The role that reaches the request is the one in the table, not the one in
    the claim — the row has already been read, so it is free, and it is the
    difference between a demotion applying now and applying at the next login.
    The claim is still parsed and rejected when it names a role that does not
    exist, so a malformed or invented token is refused exactly as before.
    """
    from api.services import sessions as sessions_service

    try:
        payload = verify_signature(settings, token, settings.jwt_verification_secrets())
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
        Role(str(role_raw))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid role") from exc

    # A token minted before #314 carries no ``ver``; migration 0038 backfills
    # every account at 0, so those sessions keep working until they expire
    # rather than the upgrade signing the console out. See the migration.
    try:
        state = sessions_service.check_session(
            settings,
            username=str(username),
            token_version=int(payload.get("ver") or 0),
            jti=str(payload["jti"]) if payload.get("jti") else None,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload"
        ) from exc
    except PermissionError as exc:
        # One message for all four reasons (gone, disabled, stale version,
        # logged out): which one applies is of interest only to whoever is
        # holding the dead token.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer valid",
        ) from exc
    except sessions_service.SessionStoreUnavailable as exc:
        # Not a 401: the session was not refused, it could not be checked. A
        # 401 here would sign every console in the fleet out over a Postgres
        # restart — and they would not be able to sign back in either.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Session store is unavailable, try again",
            headers={"Retry-After": "5"},
        ) from exc
    try:
        role = Role(state.role)
    except ValueError as exc:
        # A role the table cannot spell is a broken row, not a viewer — the
        # same reading authenticate_user() takes.
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid role") from exc

    expires_at = payload.get("exp")
    return TokenUser(
        username=state.username,
        role=role,
        jti=str(payload["jti"]) if payload.get("jti") else None,
        expires_at=datetime.fromtimestamp(int(expires_at), UTC) if expires_at else None,
    )


def decode_agent_token(settings: Settings, token: str) -> AgentPrincipal:
    """Verify an agent JWT against the *agent* signing key (#312).

    Not ``jwt_secret``: that key signs console sessions, and while the ``typ``
    checks above and below are what separate the two audiences, a shared
    signature meant every one of those checks was load-bearing on its own. With
    separate keys an operator token does not verify here at all, and an agent
    token does not verify in :func:`decode_token`.

    Verified against the same rotation window as a console token (#314): when
    the agent key is derived from ``jwt_secret`` a retired operator key derives
    a retired agent key, so one ``OCTO_JWT_SECRET_PREVIOUS`` covers both
    audiences and an agent fleet is not locked out mid-rotation. Nothing is
    ever *signed* with a retired key.
    """
    try:
        payload = verify_signature(settings, token, settings.agent_signing_secrets())
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
