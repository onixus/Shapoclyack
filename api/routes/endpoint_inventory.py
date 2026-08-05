"""Lariska endpoint-inventory ingestion + read APIs (Agent_plan.md S1-S7)."""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from api.auth import AgentPrincipal, Role, TenantPrincipal, require_agent, require_tenant
from api.schemas import (
    EndpointDeviceInfo,
    EndpointInventoryResponse,
    EndpointInventorySnapshotRequest,
    EndpointSnapshotSummary,
    EndpointSoftwareChangeFeedItem,
    EndpointSoftwareChangeInfo,
)
from api.services import endpoint_inventory as endpoint_inventory_service
from api.services import metrics as metrics_service

router = APIRouter(prefix="/endpoint", tags=["endpoint-inventory"])


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
