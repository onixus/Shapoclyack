from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import (
    LoginRequest,
    MeResponse,
    TokenResponse,
    TokenUser,
    authenticate_user,
    create_access_token,
    get_current_user,
    get_settings,
)
from api.settings import Settings

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, settings: Annotated[Settings, Depends(get_settings)]) -> TokenResponse:
    user = authenticate_user(settings, body.username, body.password)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(settings, user)
    return TokenResponse(access_token=token, role=user.role, username=user.username)


@router.get("/me", response_model=MeResponse)
def me(user: Annotated[TokenUser, Depends(get_current_user)]) -> MeResponse:
    return MeResponse(username=user.username, role=user.role)
