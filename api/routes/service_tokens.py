"""Service tokens REST API endpoints (Sprint 1 IAM)."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from api.auth import Role, TenantPrincipal, require_tenant
from api.services import service_tokens as st_service

router = APIRouter(prefix="/service-tokens", tags=["service-tokens"])


class CreateServiceTokenRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128, description="Human-readable token description")
    role: str = Field(default="viewer", description="Role granted to the token ('viewer' | 'operator' | 'admin')")
    scopes: list[str] = Field(default_factory=list, description="Capability scopes granted to token")
    expires_days: int | None = Field(default=90, ge=1, le=3650, description="Token validity in days (None for non-expiring)")


class CreateServiceTokenResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    tenant_id: str
    role: str
    scopes: list[str]
    created_at: str
    created_by: str | None = None
    expires_at: str | None = None
    token: str = Field(description="Plaintext token. Displayed only once upon creation.")


class ServiceTokenItem(BaseModel):
    id: str
    name: str
    key_prefix: str
    tenant_id: str
    role: str
    scopes: list[str]
    created_at: str | None = None
    created_by: str | None = None
    expires_at: str | None = None
    last_used_at: str | None = None
    revoked_at: str | None = None
    is_active: bool


class AvailableScopesResponse(BaseModel):
    scopes: list[str]


@router.get("/scopes", response_model=AvailableScopesResponse)
def get_available_scopes(
    _principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> AvailableScopesResponse:
    """Return available capability scopes for service tokens."""
    return AvailableScopesResponse(scopes=st_service.CANONICAL_SCOPES)


@router.get("", response_model=list[ServiceTokenItem])
def list_service_tokens(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> list[dict[str, Any]]:
    """List service tokens for the current tenant."""
    return st_service.list_tokens(principal.tenant_id)


@router.post("", response_model=CreateServiceTokenResponse, status_code=status.HTTP_201_CREATED)
def create_service_token(
    payload: CreateServiceTokenRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict[str, Any]:
    """Create a new scoped service token for the current tenant.

    The plaintext token string is returned in the response and will not be
    viewable again.
    """
    # Prevent an operator from minting an admin token unless they are admin
    if payload.role == "admin" and principal.role != Role.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin users can create admin service tokens",
        )

    try:
        metadata, raw_token = st_service.create_token(
            tenant_id=principal.tenant_id,
            name=payload.name,
            role=payload.role,
            scopes=payload.scopes,
            expires_days=payload.expires_days,
            created_by=principal.username,
        )
        metadata["token"] = raw_token
        return metadata
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.delete("/{token_id}", status_code=status.HTTP_200_OK)
def revoke_service_token(
    token_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict[str, Any]:
    """Revoke an existing service token."""
    revoked = st_service.revoke_token(principal.tenant_id, token_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found or already revoked",
        )
    return {"status": "revoked", "id": token_id}
