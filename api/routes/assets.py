from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TenantPrincipal, get_settings, require_permission, require_tenant
from api.core import permissions as permission_catalog
from api.routes import _idempotency as idempotency
from api.routes._audit import AuditDep
from api.routes._idempotency import IdempotencyKeyHeader
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    AssetContextEventInfo,
    AssetDetail,
    AssetImportReport,
    AssetImportRequest,
    AssetInventorySummary,
    AssetServiceInfo,
    AssetSummary,
    BulkActionReport,
    BulkAssetRequest,
    EndpointSoftwareItemInfo,
    Page,
    UpdateAssetRequest,
)
from api.services import asset_import
from api.services import asset_services as asset_services_service
from api.services import assets as assets_service
from api.services import audit as audit_service
from api.services import bulk_actions
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
    exposure: Annotated[
        str | None,
        Query(description="Operator-set exposure_level: internet | partner | internal | unknown"),
    ] = None,
) -> Page[AssetSummary]:
    try:
        items, total = assets_service.list_assets(
            settings,
            principal.tenant_id,
            status=status_filter,
            unowned=unowned,
            exposure=exposure,
            q=page.q,
            offset=page.offset,
            limit=page.limit,
            sort=page.sort,
            order=page.order,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return build_page([AssetSummary.model_validate(item) for item in items], total, page)


@router.post("/bulk", response_model=BulkActionReport)
def bulk_action(
    body: BulkAssetRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
    idempotency_key: IdempotencyKeyHeader = None,
) -> dict:
    """Apply one context update to many assets, reporting on each id (#346).

    ``operator``, the same role ``PATCH /{asset_id}`` needs: this is that
    request applied to a selection, not a new power. 200 even with failures —
    an id that is not in this tenant comes back ``not_found`` and the rest are
    still applied; 422 only for a request that applies to nothing (no ids, too
    many, or an empty payload).

    Declared before ``/{asset_id}`` so "bulk" is not read as an asset id.
    """
    # ``exclude_unset`` carries PATCH's contract into the batch: an explicit
    # null clears the field on every selected asset, an omitted key leaves it.
    payload = body.payload.model_dump(exclude_unset=True)
    guard = idempotency.begin(
        settings,
        tenant_id=principal.tenant_id,
        # The key is this caller's name for their own request, not a tenant-wide
        # reservation: a guessable key like `nightly-triage` must not be takeable
        # from one integration by another member of the same tenant.
        actor=principal.username,
        endpoint="assets.bulk",
        key=idempotency_key,
        payload={"action": body.action, "ids": sorted(set(body.asset_ids)), "payload": payload},
    )
    if guard.replay is not None:
        return {**guard.replay, "replayed": True}
    def record(report: dict) -> None:
        # One row for the batch, listing the ids. The per-asset
        # ``asset_context_events`` rows that ``update_asset`` writes are still
        # there — this is the record that one operator changed all of them at
        # once, which those cannot express.
        audit_service.record_standalone(
            audit,
            action=audit_service.ACTION_ASSET_BULK,
            resource_type="asset",
            resource_id=f"bulk:{body.action}",
            tenant_id=principal.tenant_id,
            after=bulk_actions.audit_document(
                report, payload, write_scope=principal.tenant_id
            ),
        )

    try:
        report = bulk_actions.apply_asset_action(
            settings,
            tenant_id=principal.tenant_id,
            asset_ids=body.asset_ids,
            action=body.action,
            payload=payload,
            actor=principal.username,
        )
    except ValueError as exc:
        guard.release()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except bulk_actions.BulkActionAborted as exc:
        # Same contract as the findings batch: the assets before the failure
        # are committed, so the row is written before the 500 and the key is
        # kept when anything applied. See ``routes/vulnerabilities.py``.
        record(exc.report)
        if exc.report["succeeded"]:
            guard.store(exc.report)
        else:
            guard.release()
        raise
    except Exception:
        guard.release()
        raise
    record(report)
    if bulk_actions.changed_nothing(report):
        # Same contract as the findings batch: a batch that applied nothing
        # gives its key back rather than replaying the nothing it did.
        guard.release()
    else:
        guard.store(report)
    return report


@router.post("/import", response_model=AssetImportReport)
def import_assets(
    body: AssetImportRequest,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ASSET_IMPORT))
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
    idempotency_key: IdempotencyKeyHeader = None,
) -> dict:
    """Upsert a CMDB/AD export into this tenant's registry, row by row (#350).

    200 with a per-row report whatever the rows say — a conflicting or invalid
    row is the report's business, not the request's. 422 for a file that cannot
    be read at all, 413 past the size or row ceiling, 409 when a concurrent
    writer registered one of the file's identifiers mid-apply (nothing was
    applied). ``dry_run`` (the default) writes nothing and ignores
    ``Idempotency-Key``: there is nothing to apply twice.

    Declared before ``/{asset_id}`` so "import" is not read as an asset id.
    """
    guard = None
    if not body.dry_run:
        guard = idempotency.begin(
            settings,
            tenant_id=principal.tenant_id,
            actor=principal.username,
            endpoint="assets.import",
            key=idempotency_key,
            payload={
                "format": body.format,
                "sha256": asset_import.content_digest(body.content),
                "context_source": body.context_source,
                "overwrite_operator_edits": body.overwrite_operator_edits,
            },
        )
        if guard.replay is not None:
            return {**guard.replay, "replayed": True}
    try:
        report = asset_import.run_import(
            settings,
            tenant_id=principal.tenant_id,
            content=body.content,
            format=body.format,
            dry_run=body.dry_run,
            context_source=body.context_source,
            overwrite_operator_edits=body.overwrite_operator_edits,
            actor=principal.username,
            audit=audit,
        )
    except asset_import.ImportTooLarge as exc:
        if guard is not None:
            guard.release()
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        ) from exc
    except ValueError as exc:
        if guard is not None:
            guard.release()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except asset_import.ImportRace as exc:
        if guard is not None:
            guard.release()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except Exception:
        if guard is not None:
            guard.release()
        raise
    if guard is not None:
        if asset_import.changed_nothing(report):
            # Same contract as the bulk verbs: an apply that changed nothing
            # gives its key back rather than replaying the nothing it did.
            guard.release()
        else:
            guard.store(report)
    return report


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


@router.get("/{asset_id}/services", response_model=list[AssetServiceInfo])
def get_asset_services(
    asset_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[dict]:
    """Listeners scans fingerprinted on this asset, with the retro verdict on each."""
    if not assets_service.asset_exists(settings, principal.tenant_id, asset_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset_services_service.list_for_asset(
        settings, tenant_id=principal.tenant_id, asset_id=asset_id
    )


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
