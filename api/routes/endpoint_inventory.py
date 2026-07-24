"""Lariska endpoint-inventory ingestion + read APIs (Agent_plan.md S1-S7)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from api.auth import AgentPrincipal, Role, TokenUser, require_agent, require_role
from api.schemas import (
    EndpointDeviceInfo,
    EndpointInventoryResponse,
    EndpointInventorySnapshotRequest,
    EndpointSnapshotSummary,
    EndpointSoftwareChangeInfo,
)
from api.services import endpoint_inventory as endpoint_inventory_service
from api.services import tenants as tenants_service

router = APIRouter(prefix="/endpoint", tags=["endpoint-inventory"])


@router.post("/inventory", response_model=EndpointInventoryResponse)
def submit_inventory(
    body: EndpointInventorySnapshotRequest,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    response: Response,
) -> EndpointInventoryResponse:
    if principal.agent_id and principal.agent_id != body.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="agent_id does not match the authenticated agent JWT",
        )
    try:
        result = endpoint_inventory_service.ingest_snapshot(
            tenant_id=principal.tenant_id,
            agent_id=body.agent_id,
            request=body,
        )
    except endpoint_inventory_service.RateLimitError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    except endpoint_inventory_service.PayloadTooLargeError as exc:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)) from exc
    except endpoint_inventory_service.ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    is_replay = result.pop("_replay", False)
    response.status_code = status.HTTP_200_OK if is_replay else status.HTTP_201_CREATED
    return EndpointInventoryResponse.model_validate(result)


@router.get("/devices", response_model=list[EndpointDeviceInfo])
def list_devices(
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    tenant_id: Annotated[str, Query()] = tenants_service.DEFAULT_TENANT_ID,
    asset_id: Annotated[str | None, Query()] = None,
) -> list[dict]:
    return endpoint_inventory_service.list_devices(tenant_id, asset_id=asset_id)


@router.get("/devices/{device_id}", response_model=EndpointDeviceInfo)
def get_device(
    device_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    tenant_id: Annotated[str, Query()] = tenants_service.DEFAULT_TENANT_ID,
) -> dict:
    device = endpoint_inventory_service.get_device(tenant_id, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@router.get("/devices/{device_id}/snapshots", response_model=list[EndpointSnapshotSummary])
def list_snapshots(
    device_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    tenant_id: Annotated[str, Query()] = tenants_service.DEFAULT_TENANT_ID,
) -> list[dict]:
    return endpoint_inventory_service.list_snapshots(tenant_id, device_id)


@router.get("/devices/{device_id}/changes", response_model=list[EndpointSoftwareChangeInfo])
def list_changes(
    device_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    tenant_id: Annotated[str, Query()] = tenants_service.DEFAULT_TENANT_ID,
) -> list[dict]:
    return endpoint_inventory_service.list_changes(tenant_id, device_id)
