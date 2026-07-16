from __future__ import annotations

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
    username = payload.get("sub")
    role_raw = payload.get("role")
    if not username or not role_raw:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    try:
        role = Role(str(role_raw))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid role") from exc
    return TokenUser(username=str(username), role=role)


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
