from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    AssetContextEventInfo,
    AssetDetail,
    AssetInventorySummary,
    AssetSummary,
    EndpointSoftwareItemInfo,
    Page,
    UpdateAssetRequest,
)
from api.services import assets as assets_service
from api.services import endpoint_inventory as endpoint_inventory_service
from api.settings import Settings

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("", response_model=Page[AssetSummary])
def list_assets(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    page: PageParams,
    status_filter: Annotated[str | None, Query(alias="status")] = None,
    unowned: Annotated[
        bool,
        Query(description="Active/stale assets with no owner_email — the dashboard's gap list"),
    ] = False,
) -> Page[AssetSummary]:
    items, total = assets_service.list_assets(
        settings,
        principal.tenant_id,
        status=status_filter,
        unowned=unowned,
        q=page.q,
        offset=page.offset,
        limit=page.limit,
        sort=page.sort,
        order=page.order,
    )
    return build_page([AssetSummary.model_validate(item) for item in items], total, page)


@router.get("/summary", response_model=AssetInventorySummary)
def get_asset_summary(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict:
    return assets_service.summary(settings, principal.tenant_id)


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(
    asset_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AssetDetail:
    item = assets_service.get_asset(settings, principal.tenant_id, asset_id)
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return AssetDetail.model_validate(item)


@router.get("/{asset_id}/events", response_model=Page[AssetContextEventInfo])
def list_asset_context_events(
    asset_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    page: PageParams,
) -> Page[AssetContextEventInfo]:
    if not assets_service.asset_exists(settings, principal.tenant_id, asset_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    items, total = assets_service.list_context_events(
        settings,
        principal.tenant_id,
        asset_id,
        offset=page.offset,
        limit=page.limit,
    )
    return build_page(items, total, page)


@router.get("/{asset_id}/software", response_model=list[EndpointSoftwareItemInfo])
def get_asset_software(
    asset_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[dict]:
    if assets_service.get_asset(settings, principal.tenant_id, asset_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return endpoint_inventory_service.list_software_for_asset(principal.tenant_id, asset_id)


@router.patch("/{asset_id}", response_model=AssetDetail)
def update_asset(
    asset_id: str,
    body: UpdateAssetRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AssetDetail:
    updates = body.model_dump(exclude_unset=True)
    try:
        item = assets_service.update_asset(
            settings, principal.tenant_id, asset_id, updates, actor=principal.username
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if item is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return AssetDetail.model_validate(item)
