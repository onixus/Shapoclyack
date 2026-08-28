"""Remote agent endpoints + operator agent listing."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import PlainTextResponse

from api.auth import AgentPrincipal, Role, TenantPrincipal, get_settings, require_agent, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    AgentClaimResponse,
    AgentDeploymentSnippetResponse,
    AgentDeploySSHRequest,
    AgentDeployStatusResponse,
    AgentFleetSummary,
    AgentHeartbeatRequest,
    AgentInfo,
    AgentRegisterRequest,
    AgentSSHHostKeyInfo,
    AgentSSHHostKeyProbeRequest,
    CreateAgentDeploymentKeyRequest,
    JobInfo,
    Page,
)
from api.services import agent_deployer
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.settings import Settings

router = APIRouter(tags=["agents"])


def _server_url(settings: Settings, request: Request) -> str:
    """The URL this installation is reached at, for embedding in install snippets.

    ``OCTO_PUBLIC_BASE_URL`` and nothing else in ``prod`` — the value used to
    come from ``request.base_url``, i.e. from the caller's own ``Host`` /
    ``X-Forwarded-Host`` header, which decided where the next agent would fetch
    its installer from and report to. ``_validate_production`` refuses to start
    without it, so the request fallback below is reachable only under
    ``OCTO_ENV=dev``, where a laptop's address is not a security decision.
    """
    if settings.public_base_url:
        return settings.public_base_url.rstrip("/")
    return str(request.base_url).rstrip("/")


@router.post("/agent/register", response_model=AgentInfo)
def register_agent(
    body: AgentRegisterRequest,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
) -> AgentInfo:
    try:
        return agents_service.register_agent(
            agent_id=body.agent_id,
            hostname=body.hostname,
            version=body.version,
            labels=body.labels,
            tenant_id=principal.tenant_id,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.post("/agent/heartbeat", response_model=AgentInfo)
def heartbeat(
    body: AgentHeartbeatRequest,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentInfo:
    info = agents_service.heartbeat(
        body.agent_id,
        status=body.status,
        current_job_id=body.current_job_id,
        detail=body.detail,
        metrics=body.metrics,
        capabilities=body.capabilities,
    )
    if info is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    if info.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant agent access denied")
    # The agent naming a job it holds is the only evidence the API gets that
    # the scan actually started, so it is what promotes claimed → running
    # (ROADMAP P1.3). Any other state is left alone by mark_running.
    if body.current_job_id:
        jobs_service.mark_running(settings, body.current_job_id, agent_id=body.agent_id)
    return info


@router.post(
    "/agent/jobs/claim",
    response_model=AgentClaimResponse,
    responses={204: {"description": "No queued agent jobs"}},
)
def claim_job(
    agent_id: str,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
    job_id: str | None = None,
) -> AgentClaimResponse | Response:
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown agent_id; register first")
    if agent.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant agent access denied")
    try:
        claimed = jobs_service.claim_job(
            settings,
            agent_id,
            job_id=job_id,
            tenant_id=principal.tenant_id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if claimed is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return claimed


@router.post("/agent/jobs/{job_id}/results", response_model=JobInfo)
async def upload_results(
    job_id: str,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
    agent_id: Annotated[str, Form()],
    exit_code: Annotated[int, Form()] = 0,
    error: Annotated[str | None, Form()] = None,
    run_id: Annotated[str | None, Form()] = None,
    archive: UploadFile | None = File(None),
    # Optional (ROADMAP P1.5): identifies *this completion*, so a retry after a
    # network timeout is answered with the stored outcome instead of an error.
    # Sent as a form field rather than a header because the agent already
    # builds this request as multipart.
    idempotency_key: Annotated[str | None, Form()] = None,
    # Fencing token from the claim response (ROADMAP P1.4/P1.5). Optional, so
    # pre-P1.5 agents keep working — unfenced, as they were.
    attempt: Annotated[int | None, Form()] = None,
) -> JobInfo:
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown agent_id")
    if agent.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant agent access denied")
    archive_bytes: bytes | None = None
    if archive is not None:
        archive_bytes = await archive.read()
        if not archive_bytes:
            archive_bytes = None
    try:
        return jobs_service.complete_job(
            settings,
            job_id,
            agent_id=agent_id,
            exit_code=exit_code,
            error=error,
            run_id=run_id,
            archive_bytes=archive_bytes,
            tenant_id=principal.tenant_id,
            idempotency_key=(idempotency_key or "").strip()[:200] or None,
            attempt=attempt,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except jobs_service.StaleAttempt as exc:
        # The lease for that attempt expired and the job was handed out again;
        # this result belongs to a scan that has since been replaced.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except jobs_service.ResultsConflict as exc:
        # Same job, different completion — or the same one still being ingested.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/agents/summary", response_model=AgentFleetSummary)
def get_fleet_summary(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> AgentFleetSummary:
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    return agents_service.get_fleet_summary(tenant_id=tenant_id)


@router.get("/agents/{agent_id}", response_model=AgentInfo)
def get_agent_detail(
    agent_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
) -> AgentInfo:
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    # An agent in another tenant reads as absent, not forbidden — the service
    # returns None for both, so the id says nothing about other tenants (#223).
    agent = agents_service.get_agent(agent_id, tenant_id=tenant_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent


@router.delete("/agents/{agent_id}")
def delete_agent(
    agent_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict[str, Any]:
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    deleted = agents_service.delete_agent(agent_id, tenant_id=tenant_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return {"status": "deleted", "agent_id": agent_id}


@router.post("/agents/{agent_id}/upgrade")
def trigger_agent_upgrade(
    agent_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> dict[str, Any]:
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    try:
        return agents_service.request_upgrade(agent_id, tenant_id=tenant_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/agent/deploy/ssh/host-key", response_model=AgentSSHHostKeyInfo)
def probe_ssh_host_key(
    body: AgentSSHHostKeyProbeRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
) -> AgentSSHHostKeyInfo:
    """Report the SSH host key of a deployment target, without deploying to it.

    Authenticates to nothing — this is how an operator gets a fingerprint to
    compare against the target's own ``ssh-keygen -lf`` output before allowing
    credentials anywhere near it. Reading a key here does not trust it: that is
    the ``expected_host_key`` on the deployment request.

    It is still a connection this API opens to an address the caller chose, so
    the target has to pass the deployment policy first (#240): `403` for a
    host or port this tenant may not point at.
    """
    try:
        return agent_deployer.describe_host_key(
            tenant_id=principal.tenant_id,
            host=body.host,
            port=body.port,
            actor=principal.username,
        )
    except agent_deployer.DeployTargetDenied as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except agent_deployer.HostKeyUnavailable as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)
        ) from exc


@router.delete("/agent/deploy/ssh/host-key", response_model=AgentSSHHostKeyInfo)
def unpin_ssh_host_key(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    host: Annotated[str, Query(min_length=1, max_length=255, description="Pinned target host")],
    port: Annotated[int, Query(ge=1, le=65535, description="Pinned target port")] = 22,
) -> AgentSSHHostKeyInfo:
    """Remove this tenant's pinned SSH host key for a target (#241).

    **admin**, the same bar as deploying — deciding that the platform should
    stop trusting a key is not a smaller act than deciding it should start.
    Answers with the pin that was removed, so the fingerprint being dropped is
    in front of the operator, and `404` when there was nothing pinned.

    The next deployment to that host needs `expected_host_key` again, which is
    the point: a rebuilt machine is re-verified against the target rather than
    silently re-trusted. Both events are in the audit trail
    (`GET /api/auth/events?outcome=trust_change`).
    """
    try:
        return agent_deployer.unpin_host_key(
            tenant_id=principal.tenant_id,
            host=host,
            port=port,
            actor=principal.username,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/agent/deploy/ssh", response_model=AgentDeployStatusResponse)
def deploy_agent_ssh(
    body: AgentDeploySSHRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    request: Request,
) -> AgentDeployStatusResponse:
    # Ensure tenant alignment
    tenant_id = principal.tenant_id if not principal.is_platform_admin else (body.tenant_id or principal.tenant_id)
    body.tenant_id = tenant_id

    server_url = _server_url(settings, request)
    try:
        deploy_id = agent_deployer.start_ssh_deployment(
            body, server_url=server_url, actor=principal.username
        )
    except agent_deployer.DeployTargetDenied as exc:
        # 403, not 422: the request is well-formed, this tenant is simply not
        # entitled to that target (#240). The refusal is already journalled.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except agent_deployer.HostKeyUnavailable as exc:
        # The target could not be reached at all, so there is nothing to refuse
        # or to trust — an upstream problem, not a malformed request.
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except (agent_deployer.HostKeyUnverified, agent_deployer.HostKeyMismatch) as exc:
        # 409: the request is well-formed, the target's identity is what is in
        # conflict. The message carries the fingerprint the operator has to
        # confirm, so it is the whole of the remediation.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    deploy_status = agent_deployer.get_deployment_status(deploy_id, tenant_id=tenant_id)
    if not deploy_status:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to initialize deployment")
    return deploy_status


@router.get("/agent/deploy/{deploy_id}/status", response_model=AgentDeployStatusResponse)
def get_deploy_status(
    deploy_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
) -> AgentDeployStatusResponse:
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    deploy_status = agent_deployer.get_deployment_status(deploy_id, tenant_id=tenant_id)
    if not deploy_status:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment run not found")
    return deploy_status


@router.get("/agent/install.sh", response_class=PlainTextResponse)
def get_install_script() -> PlainTextResponse:
    script_path = Path("scripts/install-agent.sh")
    if not script_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Installer script not found")
    content = script_path.read_text(encoding="utf-8")
    return PlainTextResponse(content, media_type="text/x-sh")


@router.get("/agent/deployment-command", response_model=AgentDeploymentSnippetResponse)
def get_deployment_command(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: Annotated[Settings, Depends(get_settings)],
    request: Request,
) -> AgentDeploymentSnippetResponse:
    """Render the install snippets with a placeholder key.

    Read-only: registering an agent is an operator act, and the key that lets
    someone do it is minted by the POST below, never by loading this page.
    """
    snippets = agents_service.get_deployment_snippets(
        tenant_id=principal.tenant_id,
        server_url=_server_url(settings, request),
    )
    return AgentDeploymentSnippetResponse(**snippets)


@router.post(
    "/agent/deployment-command",
    response_model=AgentDeploymentSnippetResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_deployment_command(
    body: CreateAgentDeploymentKeyRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    request: Request,
) -> AgentDeploymentSnippetResponse:
    """Mint one provisioning key for this tenant and return the snippets.

    Tenant ``admin``, the same bar as
    ``POST /api/tenants/{id}/provisioning-keys``, because it mints the same
    credential: a key that registers agents into this tenant (#231). The
    plaintext is in this response only.
    """
    try:
        snippets = agents_service.mint_deployment_snippets(
            tenant_id=principal.tenant_id,
            server_url=_server_url(settings, request),
            label=body.label,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return AgentDeploymentSnippetResponse(**snippets)


@router.get("/agents", response_model=Page[AgentInfo])
def list_agents(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    page: PageParams,
) -> Page[AgentInfo]:
    items, total = agents_service.list_agents(
        offset=page.offset,
        limit=page.limit,
        q=page.q,
        sort=page.sort,
        order=page.order,
        # Same rule as /jobs: fleet-wide for an unscoped platform admin.
        tenant_id=None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id,
    )
    return build_page(items, total, page)
