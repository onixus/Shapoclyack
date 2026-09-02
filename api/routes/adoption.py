"""Adoption metrics for one tenant (ROADMAP Track E, "What to measure").

Read-only and ``viewer``-gated: the page exists so the people doing the work
can see whether it is turning into outcomes, and a number an analyst cannot
open is a number that gets estimated in a slide instead.

One tenant, always — like compliance, a cross-tenant MTTR would be true of
nobody.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.schemas import AdoptionMetrics
from api.services import adoption as adoption_service
from api.settings import Settings

router = APIRouter(prefix="/adoption", tags=["adoption"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("", response_model=AdoptionMetrics)
def get_adoption(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    window_days: Annotated[
        int,
        Query(
            ge=adoption_service.MIN_WINDOW_DAYS,
            le=adoption_service.MAX_WINDOW_DAYS,
            description="Closures, MTTR and SLA adherence are counted over this many days.",
        ),
    ] = adoption_service.DEFAULT_WINDOW_DAYS,
) -> dict:
    return adoption_service.metrics(
        settings, tenant_id=principal.tenant_id, window_days=window_days
    )
