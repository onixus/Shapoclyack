"""OpenID Connect (OIDC) authentication endpoints (Sprint 1 IAM)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from api.auth import Role, TokenResponse, TokenUser, create_access_token, get_settings
from api.services import oidc as oidc_service
from api.settings import Settings

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])


class OIDCConfigResponse(BaseModel):
    enabled: bool
    issuer_url: str
    client_id: str


class OIDCLoginResponse(BaseModel):
    authorization_url: str
    state: str


@router.get("/config", response_model=OIDCConfigResponse)
def get_oidc_config(
    settings: Annotated[Settings, Depends(get_settings)],
) -> OIDCConfigResponse:
    """Return public OIDC configuration for the Web UI."""
    return OIDCConfigResponse(
        enabled=settings.oidc_enabled,
        issuer_url=settings.oidc_issuer_url,
        client_id=settings.oidc_client_id,
    )


@router.get("/login", response_model=OIDCLoginResponse)
def initiate_oidc_login(
    settings: Annotated[Settings, Depends(get_settings)],
    redirect_to: Annotated[str, Query(description="Target route after login")] = "/",
    direct_redirect: Annotated[bool, Query(description="If true, return 302 Redirect directly")] = False,
) -> Any:
    """Initiate OIDC login flow.

    Returns the authorization URL and state token, or redirects directly if requested.
    """
    if not settings.oidc_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC authentication is disabled on this server",
        )

    state = oidc_service.generate_state(settings, redirect_to=redirect_to)
    try:
        auth_url = oidc_service.build_authorization_url(settings, state=state)
        if direct_redirect:
            return RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
        return OIDCLoginResponse(authorization_url=auth_url, state=state)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to initialize OIDC flow: {exc}",
        ) from exc


@router.get("/callback", response_model=TokenResponse)
def handle_oidc_callback(
    settings: Annotated[Settings, Depends(get_settings)],
    code: Annotated[str, Query(description="Authorization code from IdP")],
    state: Annotated[str, Query(description="State parameter returned by IdP")],
) -> TokenResponse:
    """Process OIDC callback from IdP, provision user, and issue access token."""
    if not settings.oidc_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC authentication is disabled on this server",
        )

    state_data = oidc_service.verify_state(settings, state)
    if state_data is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OIDC state parameter (CSRF protection)",
        )

    try:
        claims = oidc_service.exchange_code(settings, code=code)
        user_info = oidc_service.provision_or_get_user(claims, settings)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OIDC authorization failed: {exc}",
        ) from exc

    try:
        role = Role(user_info["role"])
    except ValueError:
        role = Role.viewer

    token_user = TokenUser(username=user_info["username"], role=role)
    access_token = create_access_token(settings, token_user)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        role=token_user.role,
        username=token_user.username,
    )
