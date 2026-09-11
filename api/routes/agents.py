"""Remote agent endpoints + operator agent listing."""

from __future__ import annotations

import os

from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import PlainTextResponse

from api.auth import (
    AgentPrincipal,
    Role,
    StepUpDep,
    TenantPrincipal,
    get_settings,
    require_agent,
    require_permission,
    require_tenant,
)
from api.core import permissions as permission_catalog
from api.routes._audit import AuditDep
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    AgentClaimResponse,
    AgentDeploymentSnippetResponse,
    AgentDeploySSHRequest,
    AgentDeployStatusResponse,
    AgentFleetSummary,
    AgentGroupInfo,
    AgentHeartbeatRequest,
    AgentInfo,
    AgentRegisterRequest,
    AgentSSHHostKeyInfo,
    AgentSSHHostKeyProbeRequest,
    CreateAgentGroupRequest,
    CreateAgentDeploymentKeyRequest,
    JobInfo,
    Page,
    SetAgentGroupRequest,
    UpdateAgentStatusRequest,
)
from api.services import agent_deployer
from api.services import agent_groups as agent_groups_service
from api.services import agents as agents_service
from api.services import audit as audit_service
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


def _bind_identity(principal: AgentPrincipal, requested_agent_id: str | None) -> None:
    """403 unless the request acts as the agent its token was minted for (#308).

    The rule and its one exemption (a legacy shared token carries no identity)
    live in the service; this is the HTTP half of it, applied on every route
    that takes an ``agent_id`` from the caller — body, form or query string.
    """
    try:
        agents_service.require_identity_match(principal.agent_id, requested_agent_id)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


def _require_active(agent_id: str) -> None:
    """403 when an operator has disabled or quarantined this agent (#308).

    Applied to the two things a non-active agent must not do — claim work and
    upload results — but deliberately not to the heartbeat, which is answered
    normally so the agent learns *why* it is being refused instead of polling
    into a wall.
    """
    try:
        agents_service.require_active(agent_id)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.post("/agent/register", response_model=AgentInfo)
def register_agent(
    body: AgentRegisterRequest,
    request: Request,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentInfo:
    """Register (or re-register) the agent this token was minted for.

    The body may still name an ``agent_id``, but it can now only be the
    token's own (#308). Omitting it no longer mints a random id either: the
    exchange already put one in the token, and using it is what makes a
    restarted agent come back as itself rather than as a second row.
    """
    _bind_identity(principal, body.agent_id)
    # The actor is the agent, not a console account, so the context is built
    # here rather than through ``AuditDep``, which authenticates a user (#327).
    audit = audit_service.context_from_request(
        request,
        settings,
        actor=(body.agent_id or principal.agent_id or principal.subject),
        actor_type=audit_service.ACTOR_AGENT,
    )
    try:
        return agents_service.register_agent(
            agent_id=body.agent_id or principal.agent_id,
            hostname=body.hostname,
            version=body.version,
            labels=body.labels,
            tenant_id=principal.tenant_id,
            provisioning_key_id=principal.key_id,
            audit=audit,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc


@router.post("/agent/heartbeat", response_model=AgentInfo)
def heartbeat(
    body: AgentHeartbeatRequest,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentInfo:
    """Accepted even from a disabled or quarantined agent, on purpose (#308).

    The response carries ``lifecycle_status`` and ``lifecycle_message``, which
    is the only channel that reaches a running agent: refusing the heartbeat
    too would take an agent out of the fleet view at exactly the moment an
    operator is watching it, and leave the agent retrying a bare 403 with
    nothing to log. What a non-active agent *cannot* do is claim work or upload
    results, and those are refused below.
    """
    _bind_identity(principal, body.agent_id)
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
    responses={
        204: {"description": "No queued agent jobs"},
        426: {"description": "Agent version is below OCTO_AGENT_MIN_VERSION"},
    },
)
def claim_job(
    agent_id: str,
    principal: Annotated[AgentPrincipal, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
    job_id: str | None = None,
) -> AgentClaimResponse | Response:
    _bind_identity(principal, agent_id)
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown agent_id; register first")
    if agent.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant agent access denied")
    _require_active(agent_id)
    # The version floor is checked here rather than in require_agent: an agent
    # below it must still register and heartbeat, or the fleet view would lose
    # the very agents an operator needs to find and upgrade (#363).
    try:
        agents_service.require_min_version(agent.version)
    except agents_service.AgentVersionTooOld as exc:
        raise HTTPException(
            status_code=status.HTTP_426_UPGRADE_REQUIRED, detail=str(exc)
        ) from exc
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
    _bind_identity(principal, agent_id)
    agent = agents_service.get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown agent_id")
    if agent.tenant_id != principal.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cross-tenant agent access denied")
    _require_active(agent_id)
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


@router.get("/agent-groups", response_model=list[AgentGroupInfo])
def list_agent_groups(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[dict[str, Any]]:
    """The tenant's agent groups — what a scan may be addressed to (#361).

    Readable at viewer rank because it is the vocabulary of the scan form and
    of the approved scope; *changing* it needs ``agent.group.manage``.
    """
    return agent_groups_service.list_groups(settings, principal.tenant_id)


@router.post(
    "/agent-groups", response_model=AgentGroupInfo, status_code=status.HTTP_201_CREATED
)
def create_agent_group(
    body: CreateAgentGroupRequest,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.AGENT_GROUP_MANAGE))
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> dict[str, Any]:
    try:
        return agent_groups_service.create_group(
            settings,
            tenant_id=principal.tenant_id,
            name=body.name,
            description=body.description,
            created_by=principal.username,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.delete("/agent-groups/{name}")
def delete_agent_group(
    name: str,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.AGENT_GROUP_MANAGE))
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> dict[str, str]:
    """Delete one group, or 409 while an agent, a live job or a scope entry
    still names it — see api/services/agent_groups.py for why that is not a
    cascade."""
    try:
        agent_groups_service.delete_group(
            settings, tenant_id=principal.tenant_id, name=name, audit=audit
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return {"status": "deleted", "name": name}


@router.put("/agents/{agent_id}/group", response_model=AgentInfo)
def set_agent_group(
    agent_id: str,
    body: SetAgentGroupRequest,
    principal: Annotated[
        TenantPrincipal, Depends(require_permission(permission_catalog.AGENT_GROUP_MANAGE))
    ],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> AgentInfo:
    """Put one agent into a group, or take it out of every group with ``null``.

    The agent is not consulted: which group a worker is in decides which of the
    tenant's jobs it may claim, so it is an operator's grant rather than
    something a host can report about itself (#361).
    """
    try:
        agent_groups_service.set_agent_group(
            settings,
            tenant_id=principal.tenant_id,
            agent_id=agent_id,
            name=body.group,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        # An agent in another tenant reads as absent, not forbidden — the id
        # must not be confirmed to somebody with no right to know it (#223).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found"
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    agent = agents_service.get_agent(agent_id, tenant_id=principal.tenant_id)
    if agent is None:  # pragma: no cover - deleted between the write and the read
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent


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


@router.patch("/agents/{agent_id}", response_model=AgentInfo)
def update_agent_status(
    agent_id: str,
    body: UpdateAgentStatusRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    audit: AuditDep,
) -> AgentInfo:
    """Disable, quarantine, or re-activate one agent (#308).

    Tenant ``admin`` — a rung above the ``operator`` who deletes an agent, and
    for the reason the two differ in effect: delete is undone by the agent
    itself on its next poll, while this state survives re-registration and is
    the only thing that stops a compromised host from claiming work.

    Answers the agent as it now stands, so the console renders the new state
    from the response rather than from what it asked for.
    """
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    try:
        return agents_service.set_lifecycle_status(
            agent_id,
            lifecycle_status=body.status,
            reason=body.reason,
            tenant_id=tenant_id,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.delete("/agents/{agent_id}")
def delete_agent(
    agent_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    audit: AuditDep,
    revoke_key: Annotated[
        bool,
        Query(description="Also revoke the provisioning key this agent registered with"),
    ] = False,
) -> dict[str, Any]:
    """Deregister an agent, optionally revoking the key it registered with.

    Off by default, because one key commonly provisions a whole fleet and
    revoking it on a single deregistration would strand the rest. `true` is
    what makes a delete permanent: without it the host still holds the key and
    a live JWT, and re-registers on its next poll (#308). The response reports
    which of the two happened — ``key_revoked: false`` with no
    ``provisioning_key_id`` means there was no key on record to revoke (an
    agent registered before this was tracked, or a legacy shared-token one).
    """
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    deleted = agents_service.delete_agent(
        agent_id,
        tenant_id=tenant_id,
        revoke_key=revoke_key,
        audit=audit,
    )
    if deleted is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return {"status": "deleted", **deleted}


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


# Resolved from the package, not from the working directory: the API is
# started from wherever the operator (or the image's WORKDIR) happens to be,
# and a relative path there answered 404 to the very installer the SSH push
# deployment had just told the target to fetch. OCTO_AGENT_INSTALLER overrides
# it for an installation that ships its own script.
_INSTALLER_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "install-agent.sh"


@router.get("/agent/install.sh", response_class=PlainTextResponse)
def get_install_script() -> PlainTextResponse:
    script_path = Path(os.environ.get("OCTO_AGENT_INSTALLER") or _INSTALLER_SCRIPT)
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
    # Same credential, therefore same step-up (#315). This is the route the
    # console actually uses to mint a provisioning key — the one under
    # /api/tenants is the API-first path — so gating only that one would have
    # put the check on the door nobody walks through.
    _: StepUpDep,
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
