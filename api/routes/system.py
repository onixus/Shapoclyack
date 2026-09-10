from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from api.auth import Role, TokenUser, get_settings, platform_permissions, require_role
from api.core import permissions as permission_catalog
from api.schemas import SystemStatus
from api.services import system_status as system_service
from api.settings import Settings

router = APIRouter(prefix="/system", tags=["system"])


@router.get("", response_model=SystemStatus)
def get_system_status(
    request: Request,
    user: Annotated[TokenUser, Depends(require_role(Role.viewer))],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SystemStatus:
    """Read-only installation status: app/tool versions, enrichment-DB
    freshness, enabled pipeline stages, runtime flags, and tenant/agent
    counts. Exposes no secrets (see api.services.system_status).

    The last of those is not everyone's (#318): ``inventory`` counts tenants
    and agents across the whole installation, so on an MSSP deployment it told
    one customer's viewer how many other customers there are. It needs
    ``platform.fleet.read`` and comes back as nulls without it — the same shape
    the panel already renders when Postgres cannot be reached, so no client
    needs changing and nothing else on this page moves.
    """
    return SystemStatus.model_validate(
        system_service.build_status(
            settings,
            include_fleet_counts=(
                permission_catalog.PLATFORM_FLEET_READ
                in platform_permissions(request, user)
            ),
        )
    )
