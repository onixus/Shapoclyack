"""Lariska endpoint-inventory ingestion + read APIs (Agent_plan.md S1-S7)."""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from api.auth import (
    AgentPrincipal,
    Role,
    TenantPrincipal,
    get_settings,
    require_agent,
    require_tenant,
)
from api.schemas import (
    EndpointDeviceInfo,
    EndpointInventoryResponse,
    EndpointInventorySnapshotRequest,
    EndpointSnapshotSummary,
    EndpointSoftwareChangeFeedItem,
    EndpointSoftwareChangeInfo,
    SoftwareCveMatchInfo,
    SoftwareCveMatchRunSummary,
    SoftwareCveMatchSummary,
    SoftwareCveMatchTenantRunSummary,
)
from api.services import endpoint_inventory as endpoint_inventory_service
from api.services import metrics as metrics_service
from api.services import software_cve_match as cve_match_service
from api.settings import Settings

router = APIRouter(prefix="/endpoint", tags=["endpoint-inventory"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.post("/inventory", response_model=EndpointInventoryResponse)
def submit_inventory(
    body: EndpointInventorySnapshotRequest,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    response: Response,
) -> EndpointInventoryResponse:
    if principal.agent_id and principal.agent_id != body.agent_id:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("invalid").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="agent_id does not match the authenticated agent JWT",
        )
    started = time.perf_counter()
    try:
        result = endpoint_inventory_service.ingest_snapshot(
            tenant_id=principal.tenant_id,
            agent_id=body.agent_id,
            request=body,
        )
    except endpoint_inventory_service.RateLimitError as exc:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("rate_limited").inc()
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except endpoint_inventory_service.PayloadTooLargeError as exc:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("too_large").inc()
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)) from exc
    except endpoint_inventory_service.ConflictError as exc:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("conflict").inc()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("invalid").inc()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except Exception:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("error").inc()
        raise
    finally:
        metrics_service.ENDPOINT_INGEST_DURATION_SECONDS.observe(time.perf_counter() - started)
    is_replay = result.pop("_replay", False)
    metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("replay" if is_replay else "accepted").inc()
    response.status_code = status.HTTP_200_OK if is_replay else status.HTTP_201_CREATED
    return EndpointInventoryResponse.model_validate(result)


@router.get("/devices", response_model=list[EndpointDeviceInfo])
def list_devices(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    asset_id: Annotated[str | None, Query()] = None,
    device_status: Annotated[str | None, Query(pattern="^(active|stale)$")] = None,
) -> list[dict]:
    return endpoint_inventory_service.list_devices(
        principal.tenant_id, asset_id=asset_id, status=device_status
    )


@router.get("/devices/{device_id}", response_model=EndpointDeviceInfo)
def get_device(
    device_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> dict:
    device = endpoint_inventory_service.get_device(principal.tenant_id, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@router.get("/devices/{device_id}/snapshots", response_model=list[EndpointSnapshotSummary])
def list_snapshots(
    device_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> list[dict]:
    return endpoint_inventory_service.list_snapshots(principal.tenant_id, device_id)


@router.get("/devices/{device_id}/changes", response_model=list[EndpointSoftwareChangeInfo])
def list_changes(
    device_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> list[dict]:
    return endpoint_inventory_service.list_changes(principal.tenant_id, device_id)


@router.get("/changes", response_model=list[EndpointSoftwareChangeFeedItem])
def list_recent_changes(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    event_type: Annotated[str | None, Query()] = None,
) -> list[dict]:
    """Cross-device recent software-change feed (installed/removed/updated)."""
    return endpoint_inventory_service.list_recent_changes(
        principal.tenant_id, limit=limit, event_type=event_type
    )


# ---------------------------------------------------------------------------
# Software→CVE matching (ROADMAP Track E, M1)
#
# Reads need ``viewer`` like every other endpoint-inventory read. Re-running the
# matcher needs ``operator``: it is not a mutation an operator can regret — the
# rows are derived and get replaced wholesale — but it walks every package on
# every device in the tenant, so it is a workload rather than a query, and the
# neighbouring "do work now" routes (``POST /vulnerabilities/risk-history/
# snapshot``) draw the line in the same place.
# ---------------------------------------------------------------------------


@router.get("/cve-matches/summary", response_model=SoftwareCveMatchSummary)
def cve_match_summary(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict:
    """Tenant tallies, plus the provenance of the advisory data behind them."""
    return cve_match_service.summary(settings, tenant_id=principal.tenant_id)


@router.get("/cve-matches", response_model=list[SoftwareCveMatchInfo])
def list_cve_matches(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    match_status: Annotated[
        str | None, Query(pattern="^(vulnerable|fixed|not_applicable|unknown)$")
    ] = None,
    severity: Annotated[str | None, Query(max_length=32)] = None,
    cve: Annotated[str | None, Query(max_length=32)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[dict]:
    """Every match in the tenant, worst status first."""
    return cve_match_service.list_for_tenant(
        settings,
        tenant_id=principal.tenant_id,
        status=match_status,
        severity=severity,
        cve_id=cve,
        limit=limit,
    )


@router.post("/cve-matches/refresh", response_model=SoftwareCveMatchTenantRunSummary)
def refresh_tenant_cve_matches(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict:
    """Re-run the matcher over every device in the tenant."""
    return cve_match_service.run_for_tenant(settings, tenant_id=principal.tenant_id)


@router.get(
    "/devices/{device_id}/cve-matches", response_model=list[SoftwareCveMatchInfo]
)
def list_device_cve_matches(
    device_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    match_status: Annotated[
        str | None, Query(pattern="^(vulnerable|fixed|not_applicable|unknown)$")
    ] = None,
    severity: Annotated[str | None, Query(max_length=32)] = None,
) -> list[dict]:
    if endpoint_inventory_service.get_device(principal.tenant_id, device_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return cve_match_service.list_for_device(
        settings,
        tenant_id=principal.tenant_id,
        device_id=device_id,
        status=match_status,
        severity=severity,
    )


@router.post(
    "/devices/{device_id}/cve-matches/refresh", response_model=SoftwareCveMatchRunSummary
)
def refresh_device_cve_matches(
    device_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict:
    """Re-run the matcher for one device against the advisory data on disk."""
    result = cve_match_service.run_for_device(
        settings, tenant_id=principal.tenant_id, device_id=device_id
    )
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return result
