from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from api.auth import Role, TokenUser, get_settings, require_role
from api.schemas import SystemStatus
from api.services import system_status as system_service
from api.settings import Settings

router = APIRouter(prefix="/system", tags=["system"])


@router.get("", response_model=SystemStatus)
def get_system_status(
    _: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SystemStatus:
    """Read-only installation status: app/tool versions, enrichment-DB
    freshness, enabled pipeline stages, runtime flags, and tenant/agent
    counts. Exposes no secrets (see api.services.system_status)."""
    return SystemStatus.model_validate(system_service.build_status(settings))
