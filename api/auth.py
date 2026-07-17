from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
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


class AgentPrincipal(BaseModel):
    """Authenticated remote agent (JWT provisioning exchange or legacy shared token)."""

    tenant_id: str
    key_id: str | None = None
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


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def _user_password_matches(stored: str, provided: str) -> bool:
    # Support bcrypt hashes ($2…) or plaintext bootstrap passwords from env/defaults.
    if stored.startswith("$2"):
        return verify_password(provided, stored)
    return stored == provided


def authenticate_user(settings: Settings, username: str, password: str) -> TokenUser | None:
    for user in settings.users:
        if user.get("username") != username:
            continue
        if not _user_password_matches(str(user.get("password", "")), password):
            return None
        try:
            role = Role(str(user.get("role", "viewer")))
        except ValueError:
            return None
        return TokenUser(username=username, role=role)
    return None


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
    return decode_token(settings, credentials.credentials)


def require_role(minimum: Role):
    def _checker(user: Annotated[TokenUser, Depends(get_current_user)]) -> TokenUser:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{minimum.value}' or higher required",
            )
        return user

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
        unverified = jwt.decode(
            token,
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
