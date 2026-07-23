from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, PlainTextResponse

from api.auth import Role, TokenUser, get_settings, require_role
from api.schemas import AliveHostItem, PortAggregateItem, RunDetail, RunSummary, VulnerabilityItem
from api.services import runs as runs_service
from api.settings import Settings

router = APIRouter(prefix="/runs", tags=["runs"])


@router.get("", response_model=list[RunSummary])
def list_runs(
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> list[RunSummary]:
    return runs_service.list_runs(settings)


@router.get("/{run_id}", response_model=RunDetail)
def get_run(
    run_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> RunDetail:
    detail = runs_service.get_run_detail(settings, run_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return detail


@router.get("/{run_id}/hosts", response_model=list[AliveHostItem])
def get_hosts(
    run_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=20000)] = 10000,
) -> list[AliveHostItem]:
    items = runs_service.get_hosts(settings, run_id, limit=limit)
    if items is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return items


@router.get("/{run_id}/ports", response_model=list[PortAggregateItem])
def get_ports(
    run_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=20000)] = 10000,
) -> list[PortAggregateItem]:
    items = runs_service.get_ports(settings, run_id, limit=limit)
    if items is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return items


@router.get("/{run_id}/vulnerabilities", response_model=list[VulnerabilityItem])
def get_vulnerabilities(
    run_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
    limit: Annotated[int, Query(ge=1, le=10000)] = 5000,
    host: Annotated[str | None, Query(description="Filter findings by target host/IP")] = None,
    port: Annotated[str | None, Query(description="Filter findings by port")] = None,
) -> list[VulnerabilityItem]:
    items = runs_service.get_vulnerabilities(settings, run_id, limit=limit, host=host, port=port)
    if items is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    return items


@router.get("/{run_id}/diff")
def get_diff(
    run_id: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> dict[str, Any]:
    detail = runs_service.get_run_detail(settings, run_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
    if detail.diff is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Diff not available for this run")
    return detail.diff


@router.get("/{run_id}/artifacts/{artifact_path:path}", response_class=PlainTextResponse)
def get_artifact(
    run_id: str,
    artifact_path: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    text = runs_service.read_artifact_text(settings, run_id, artifact_path)
    if text is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    return text


# Media types for the download endpoint below. Anything not listed (or with no
# extension) falls back to application/octet-stream so the browser downloads it
# as a binary blob rather than trying to render it.
_ARTIFACT_MEDIA_TYPES = {
    ".pdf": "application/pdf",
    ".json": "application/json",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".xml": "application/xml",
    ".html": "text/html",
    ".log": "text/plain",
}


@router.get("/{run_id}/download/{artifact_path:path}")
def download_artifact(
    run_id: str,
    artifact_path: str,
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> FileResponse:
    """Binary-safe artifact download. Unlike the text endpoint above (which
    UTF-8-decodes and truncates to 1 MB — fine for previewing JSON/TXT but
    corrupts binaries like ``summary.pdf``), this streams the raw file with an
    attachment disposition and a content-type derived from its extension."""
    target = runs_service.resolve_artifact(settings, run_id, artifact_path)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
    media_type = _ARTIFACT_MEDIA_TYPES.get(target.suffix.lower(), "application/octet-stream")
    return FileResponse(target, media_type=media_type, filename=target.name)
