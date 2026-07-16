"""Remote agent endpoints + operator agent listing."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status

from api.auth import Role, TokenUser, get_settings, require_agent, require_role
from api.schemas import (
    AgentClaimResponse,
    AgentHeartbeatRequest,
    AgentInfo,
    AgentRegisterRequest,
    JobInfo,
)
from api.services import agents as agents_service
from api.services import jobs as jobs_service
from api.settings import Settings

router = APIRouter(tags=["agents"])


@router.post("/agent/register", response_model=AgentInfo)
def register_agent(
    body: AgentRegisterRequest,
    _: Annotated[str, Depends(require_agent)],
) -> AgentInfo:
    return agents_service.register_agent(
        agent_id=body.agent_id,
        hostname=body.hostname,
        version=body.version,
        labels=body.labels,
    )


@router.post("/agent/heartbeat", response_model=AgentInfo)
def heartbeat(
    body: AgentHeartbeatRequest,
    _: Annotated[str, Depends(require_agent)],
) -> AgentInfo:
    info = agents_service.heartbeat(
        body.agent_id,
        status=body.status,
        current_job_id=body.current_job_id,
        detail=body.detail,
    )
    if info is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return info


@router.post(
    "/agent/jobs/claim",
    response_model=AgentClaimResponse,
    responses={204: {"description": "No queued agent jobs"}},
)
def claim_job(
    agent_id: str,
    _: Annotated[str, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AgentClaimResponse | Response:
    try:
        claimed = jobs_service.claim_job(settings, agent_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if claimed is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return claimed


@router.post("/agent/jobs/{job_id}/results", response_model=JobInfo)
async def upload_results(
    job_id: str,
    _: Annotated[str, Depends(require_agent)],
    settings: Annotated[Settings, Depends(get_settings)],
    agent_id: Annotated[str, Form()],
    exit_code: Annotated[int, Form()] = 0,
    error: Annotated[str | None, Form()] = None,
    run_id: Annotated[str | None, Form()] = None,
    archive: UploadFile | None = File(None),
) -> JobInfo:
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
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc


@router.get("/agents", response_model=list[AgentInfo])
def list_agents(
    _: Annotated[TokenUser, Depends(require_role(Role.operator))],
) -> list[AgentInfo]:
    return agents_service.list_agents()
