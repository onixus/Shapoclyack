from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TokenUser, get_settings, require_role
from api.schemas import AssetDetail, AssetSummary
from api.services import assets as assets_service
from api.services import tenants as tenants_service
from api.settings import Settings

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=list[AssetSummary])
def list_assets(
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    tenant_id: Annotated[str, Query()] = tenants_service.DEFAULT_TENANT_ID,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    q: Annotated[str | None, Query(description="Filter by identifier substring")] = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 500,
) -> list[AssetSummary]:
    items = assets_service.list_assets(settings, tenant_id, status=status_filter, q=q, limit=limit)
    return [AssetSummary.model_validate(item) for item in items]


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(
    asset_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    tenant_id: Annotated[str, Query()] = tenants_service.DEFAULT_TENANT_ID,
) -> AssetDetail:
    item = assets_service.get_asset(settings, tenant_id, asset_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return AssetDetail.model_validate(item)
