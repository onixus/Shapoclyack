"""Lariska endpoint-inventory ingestion + read APIs (Agent_plan.md S1-S7)."""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)

from api.auth import (
    AgentPrincipal,
    Role,
    cached_agent_info,
    TenantPrincipal,
    get_settings,
    require_agent,
    require_permission,
    require_tenant,
)
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.schemas import (
    EndpointAgentPolicyInfo,
    EndpointAgentPolicyRequest,
    EndpointAgentReleaseInfo,
    EndpointDeviceInfo,
    EndpointInventoryResponse,
    EndpointInventorySnapshotRequest,
    EndpointSnapshotSummary,
    EndpointSoftwareChangeFeedItem,
    EndpointSoftwareChangeInfo,
    DevicePatchGap,
    SoftwareCveMatchInfo,
    SoftwareCveMatchRunSummary,
    SoftwareCveMatchSummary,
    SoftwareCveMatchTenantRunSummary,
    TenantPatchGap,
)
from api.services import agents as agents_service
from api.services import audit as audit_service
from api.services import endpoint_agent_mgmt
from api.services import endpoint_inventory as endpoint_inventory_service
from api.services import metrics as metrics_service
from api.services import patch_gap as patch_gap_service
from api.services import software_cve_match as cve_match_service
from api.services import software_findings
from api.settings import Settings

router = APIRouter(prefix="/endpoint", tags=["endpoint-inventory"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.post("/inventory", response_model=EndpointInventoryResponse)
def submit_inventory(
    body: EndpointInventorySnapshotRequest,
    request: Request,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    response: Response,
) -> EndpointInventoryResponse:
    if principal.agent_id and principal.agent_id != body.agent_id:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("invalid").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="agent_id does not match the authenticated agent JWT",
        )
    # A disabled or quarantined agent must not keep feeding the inventory
    # either (#308). It is the same refusal the job routes give, on purpose:
    # an operator who quarantines a host expects it to stop writing, not to
    # stop only the half of its traffic that carries a job id.
    hit, agent = cached_agent_info(request, principal, body.agent_id)
    if not hit:
        agent = agents_service.get_agent(body.agent_id)
    try:
        agents_service.require_active_info(agent)
    except PermissionError as exc:
        metrics_service.ENDPOINT_SUBMISSIONS_TOTAL.labels("invalid").inc()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
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
    """Re-run the matcher over every device in the tenant, then fold the result
    into the vulnerability lifecycle.

    Synchronous on purpose, unlike the background worker: an operator who
    pressed this wants the tracked findings to reflect it when the response
    comes back, not at the end of the worker's interval. The matcher has
    already been re-run, so the fold reads the rows rather than re-matching.
    """
    result = cve_match_service.run_for_tenant(settings, tenant_id=principal.tenant_id)
    stats = software_findings.ingest_tenant(
        settings, tenant_id=principal.tenant_id, run_matcher=False
    )
    return {**result, "lifecycle": stats.as_dict()}


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
    """Re-run the matcher for one device, then fold the result into the
    vulnerability lifecycle (see the tenant-wide route for why synchronously)."""
    result = cve_match_service.run_for_device(
        settings, tenant_id=principal.tenant_id, device_id=device_id
    )
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    stats = software_findings.ingest_device(
        settings, tenant_id=principal.tenant_id, device_id=device_id, run_matcher=False
    )
    return {**result, "lifecycle": stats.as_dict()}


@router.get("/patch-gaps", response_model=TenantPatchGap)
def tenant_patch_gap(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    limit: Annotated[int, Query(ge=1, le=500)] = 50,
) -> dict:
    """Estate-wide patch gap: what is outstanding, worst devices first.

    Derived from the matcher's ``vulnerable`` rows on read, so it cannot
    disagree with the findings it is built from. The totals cover the tenant
    even when ``devices`` is capped.
    """
    return patch_gap_service.for_tenant(
        settings, tenant_id=principal.tenant_id, limit=limit
    )


@router.get("/devices/{device_id}/patch-gap", response_model=DevicePatchGap)
def device_patch_gap(
    device_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict:
    """One endpoint's outstanding upgrades and the command that applies them.

    A device with nothing outstanding answers with an empty gap list; only an
    unknown device is a 404, because "clean" and "not here" are different
    answers.
    """
    result = patch_gap_service.for_device(
        settings, tenant_id=principal.tenant_id, device_id=device_id
    )
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return result


# ---------------------------------------------------------------------------
# Remote management of the endpoint agents (#358)
#
# An operator could previously change an agent's configuration or its build
# only by visiting the machine. These routes decide both centrally; the
# heartbeat response in ``api/routes/agents.py`` is what carries the decision
# to a running agent.
# ---------------------------------------------------------------------------


@router.get("/agent/policies", response_model=list[EndpointAgentPolicyInfo])
def list_agent_policies(
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
) -> list[EndpointAgentPolicyInfo]:
    """Every policy this tenant has set: the default first, then the overrides."""
    return [
        EndpointAgentPolicyInfo(**row)
        for row in endpoint_agent_mgmt.list_policies(principal.tenant_id)
    ]


@router.put("/agent/policy", response_model=EndpointAgentPolicyInfo)
def set_default_agent_policy(
    body: EndpointAgentPolicyRequest,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
    audit: AuditDep,
) -> EndpointAgentPolicyInfo:
    """Set the tenant-wide default every endpoint agent inherits."""
    return _write_agent_policy(body, principal, audit, agent_id=None)


@router.put("/agent/policy/{agent_id}", response_model=EndpointAgentPolicyInfo)
def set_agent_policy(
    agent_id: str,
    body: EndpointAgentPolicyRequest,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
    audit: AuditDep,
) -> EndpointAgentPolicyInfo:
    """Override the default for one agent, field by field."""
    agent = agents_service.get_agent(agent_id)
    if agent is None or agent.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown agent")
    return _write_agent_policy(body, principal, audit, agent_id=agent_id)


def _write_agent_policy(
    body: EndpointAgentPolicyRequest,
    principal: TenantPrincipal,
    audit: AuditDep,
    *,
    agent_id: str | None,
) -> EndpointAgentPolicyInfo:
    try:
        row = endpoint_agent_mgmt.set_policy(
            tenant_id=principal.tenant_id,
            agent_id=agent_id,
            settings=body.settings,
            desired_version=body.desired_version,
            updated_by=principal.username,
        )
    except endpoint_agent_mgmt.PolicyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    # Audited because naming a version here is the authority to replace a
    # binary on every endpoint in the tenant -- the record of who asked for
    # that, and when, is the point.
    audit_service.record_standalone(
        audit,
        action="endpoint_agent.policy.set",
        resource_type="endpoint_agent_policy",
        resource_id=agent_id or "(tenant default)",
        tenant_id=principal.tenant_id,
        after={"settings": row["settings"], "desired_version": row["desired_version"]},
    )
    return EndpointAgentPolicyInfo(**row)


@router.delete("/agent/policy", status_code=status.HTTP_204_NO_CONTENT)
def delete_default_agent_policy(
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
) -> Response:
    endpoint_agent_mgmt.delete_policy(tenant_id=principal.tenant_id, agent_id=None)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/agent/policy/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_agent_policy(
    agent_id: str,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
) -> Response:
    endpoint_agent_mgmt.delete_policy(tenant_id=principal.tenant_id, agent_id=agent_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/agent/releases", response_model=list[EndpointAgentReleaseInfo])
def list_agent_releases(
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
) -> list[EndpointAgentReleaseInfo]:
    """Builds this installation can hand out.

    Installation-wide rather than per tenant: it is the same program, and a
    build stored twice is a build that can be two different binaries.
    """
    return [EndpointAgentReleaseInfo(**row) for row in endpoint_agent_mgmt.list_releases()]


@router.post(
    "/agent/releases",
    response_model=EndpointAgentReleaseInfo,
    status_code=status.HTTP_201_CREATED,
)
async def upload_agent_release(
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
    audit: AuditDep,
    version: Annotated[str, Form()],
    platform: Annotated[str, Form()],
    binary: Annotated[UploadFile, File()],
    notes: Annotated[str | None, Form()] = None,
) -> EndpointAgentReleaseInfo:
    """Store one build of the endpoint agent.

    The sha256 in the response is computed here, from the stored bytes. It is
    not accepted from the uploader: it is what an endpoint checks a download
    against before executing it, and a digest travelling beside the bytes it
    describes attests to nothing.
    """
    content = await binary.read()
    try:
        row = endpoint_agent_mgmt.store_release(
            version=version,
            platform=platform,
            content=content,
            notes=notes,
            uploaded_by=principal.username,
        )
    except endpoint_agent_mgmt.ReleaseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    audit_service.record_standalone(
        audit,
        action="endpoint_agent.release.upload",
        resource_type="endpoint_agent_release",
        resource_id=f"{row['version']}/{row['platform']}",
        tenant_id=principal.tenant_id,
        after={"sha256": row["sha256"], "size_bytes": row["size_bytes"]},
    )
    return EndpointAgentReleaseInfo(**row)


@router.delete(
    "/agent/releases/{version}/{platform}", status_code=status.HTTP_204_NO_CONTENT
)
def delete_agent_release(
    version: str,
    platform: str,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.ENDPOINT_AGENT_MANAGE))
    ],
) -> Response:
    endpoint_agent_mgmt.delete_release(version=version, platform=platform)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/agent/releases/{version}/{platform}/download")
def download_agent_release(
    version: str,
    platform: str,
    request: Request,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
) -> Response:
    """Hand the build to an agent that has been told to move to it.

    Authenticated as the agent, with the same token it heartbeats with, so the
    digest and the bytes come from one channel rather than two: an attacker who
    could substitute the download would have had to substitute the heartbeat
    that named its digest.
    """
    hit, agent = cached_agent_info(request, principal, principal.agent_id)
    if not hit and principal.agent_id:
        agent = agents_service.get_agent(principal.agent_id)
    agents_service.require_active_info(agent)
    found = endpoint_agent_mgmt.get_release_bytes(version=version, platform=platform)
    if found is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown build")
    content, digest = found
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            # Repeated in the response so a download saved out of band can be
            # checked against the same value the heartbeat carried.
            "X-Content-SHA256": digest,
            "Content-Disposition": f'attachment; filename="lariska-{version}-{platform}"',
        },
    )
