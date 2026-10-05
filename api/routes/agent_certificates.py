"""Client certificates of sensors and endpoint agents (#309).

``POST /agent/certificate`` is the agent's own: it trades a CSR for a
certificate naming the token's agent. The rest are the operator's view of one
agent's certificates — list, pin, revoke, and reset the enrolment a
revocation locked. The rules live in
``api/services/agent_certs.py``; the certificate a request presented is
read and bound in ``api.auth`` before any of these run.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from api.auth import (
    AgentPrincipal,
    Role,
    StepUpDep,
    TenantPrincipal,
    get_settings,
    require_agent_enrolment,
    require_tenant,
)
from api.routes._audit import AuditDep
from api.schemas import (
    AgentCertificateRequest,
    AgentCertificateResponse,
    AgentClientCertInfo,
    AgentInfo,
    PinAgentCertificateRequest,
    ResetAgentCertEnrolmentRequest,
    RevokeAgentCertificatesRequest,
)
from api.services import agent_certs
from api.services import agents as agents_service
from api.services import audit as audit_service
from api.settings import Settings

router = APIRouter(tags=["agents"])


@router.post("/agent/certificate", response_model=AgentCertificateResponse)
def enrol_certificate(
    body: AgentCertificateRequest,
    request: Request,
    principal: Annotated[AgentPrincipal, Depends(require_agent_enrolment)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentCertificateResponse:
    """Sign the agent's CSR with ``OCTO_AGENT_MTLS_ISSUER_*`` (#309).

    The certificate names the token's agent
    (``spiffe://<domain>/tenant/<t>/sensor/<id>``), whatever the CSR asks for.
    A renewal must present the agent's current certificate; a first enrolment
    may not have one (``require_agent_enrolment``). 404 when this installation
    does not issue certificates, 422 for an unusable CSR, 403 for the legacy
    shared token and for an agent an operator disabled or quarantined.
    """
    if not principal.agent_id or principal.auth_mode != "jwt":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a per-agent token can enrol a client certificate",
        )
    agent = agents_service.get_agent(principal.agent_id, tenant_id=principal.tenant_id)
    try:
        agents_service.require_active_info(agent)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    audit = audit_service.context_from_request(
        request,
        settings,
        actor=principal.agent_id,
        actor_type=audit_service.ACTOR_AGENT,
    )
    try:
        issued = agent_certs.issue(
            settings,
            tenant_id=principal.tenant_id,
            agent_id=principal.agent_id,
            # An agent that has not registered yet — under ``required`` it
            # cannot, without a certificate — says what it is; once on
            # record, the record says (docs/api-and-rbac.md).
            agent_kind=agent.agent_kind if agent is not None else (body.agent_kind or "scanner"),
            csr_pem=body.csr,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return AgentCertificateResponse(
        certificate=issued.certificate_pem,
        ca_certificate=issued.ca_certificate_pem,
        fingerprint_sha256=issued.fingerprint_sha256,
        serial=issued.serial_hex,
        spiffe_id=issued.spiffe_id,
        not_before=agent_certs.iso(issued.not_before),
        not_after=agent_certs.iso(issued.not_after),
        renew_after=agent_certs.iso(issued.renew_after),
    )


def _agent_in_scope(principal: TenantPrincipal, agent_id: str) -> AgentInfo:
    """The agent, in the caller's tenant (any tenant for an unscoped platform admin)."""
    tenant_id = (
        None
        if principal.is_platform_admin and not principal.tenant_requested
        else principal.tenant_id
    )
    agent = agents_service.get_agent(agent_id, tenant_id=tenant_id)
    if agent is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent


@router.get("/agents/{agent_id}/certificates", response_model=list[AgentClientCertInfo])
def list_agent_certificates(
    agent_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[AgentClientCertInfo]:
    """Every client certificate on record for one agent, revoked ones included."""
    agent = _agent_in_scope(principal, agent_id)
    return [
        AgentClientCertInfo.model_validate(row)
        for row in agent_certs.list_certs(
            settings, tenant_id=agent.tenant_id, agent_id=agent.agent_id
        )
    ]


@router.post(
    "/agents/{agent_id}/certificates",
    response_model=AgentClientCertInfo,
    status_code=status.HTTP_201_CREATED,
)
def pin_agent_certificate(
    agent_id: str,
    body: PinAgentCertificateRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> AgentClientCertInfo:
    """Bind a certificate to this agent by its fingerprint (tenant ``admin``).

    For certificates whose SAN does not name the sensor. Tenant admin, like the
    lifecycle change: it decides which key material speaks for a sensor.
    """
    agent = _agent_in_scope(principal, agent_id)
    try:
        row = agent_certs.pin(
            settings,
            tenant_id=agent.tenant_id,
            agent_id=agent.agent_id,
            certificate_pem=body.certificate,
            audit=audit,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return AgentClientCertInfo.model_validate(row)


@router.post(
    "/agents/{agent_id}/certificates/revoke",
    response_model=list[AgentClientCertInfo],
)
def revoke_agent_certificates(
    agent_id: str,
    body: RevokeAgentCertificatesRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> list[AgentClientCertInfo]:
    """Revoke by fingerprint, by serial, or all of them; effective on the next request.

    Also locks the agent out of enrolling or calling without a certificate
    until ``reset-enrolment`` — otherwise the host holding the revoked one
    would enrol itself a new one by its token on the next poll.
    """
    agent = _agent_in_scope(principal, agent_id)
    try:
        rows = agent_certs.revoke(
            settings,
            tenant_id=agent.tenant_id,
            agent_id=agent.agent_id,
            fingerprint=body.fingerprint,
            serial=body.serial,
            revoke_all=body.all,
            reason=body.reason,
            audit=audit,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return [AgentClientCertInfo.model_validate(row) for row in rows]


@router.post(
    "/agents/{agent_id}/certificates/reset-enrolment",
    response_model=list[AgentClientCertInfo],
)
def reset_agent_certificate_enrolment(
    agent_id: str,
    body: ResetAgentCertEnrolmentRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    # Same step-up as minting a provisioning key (#315): what this hands out
    # is the next certificate to whoever holds the agent's token first.
    _: StepUpDep,
    settings: Annotated[Settings, Depends(get_settings)],
    audit: AuditDep,
) -> list[AgentClientCertInfo]:
    """Let this agent enrol from scratch by its token (tenant ``admin``, step-up).

    Revokes whatever of its certificates is still live and lifts the lock a
    revocation set. Every certificate on record is returned, as by revoke.
    """
    agent = _agent_in_scope(principal, agent_id)
    rows = agent_certs.reset_enrolment(
        settings,
        tenant_id=agent.tenant_id,
        agent_id=agent.agent_id,
        reason=body.reason,
        audit=audit,
    )
    return [AgentClientCertInfo.model_validate(row) for row in rows]
