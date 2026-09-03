"""Usage metering and quotas (ROADMAP Track E, enterprise operations & MSSP).

Two audiences, which is why the read is split in two routes rather than
filtered by role inside one.

``GET /api/usage`` is the **customer's** view of their own consumption: how
many assets and scans against what was sold, and twelve months of scan volume
so a renewal conversation starts from the same number both sides can see. It
is ``viewer``-gated and single-tenant, like every other tenant-scoped read
here — a number the person doing the work cannot open is a number that gets
estimated in a slide.

``GET /api/usage/tenants`` is the **provider's** view across every tenant, so
an MSSP operator can answer "who is near their limit" without opening each
customer in turn. Platform admin only.

Writing a quota is an administrative act on the same footing as approving a
scan scope, so it lives with the other per-tenant administration in
``api/routes/auth.py`` (``GET/PUT /api/tenants/{id}/quota``) rather than here:
this module stays the meter, not the contract.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from api.auth import Role, TenantPrincipal, TokenUser, get_settings, require_role, require_tenant
from api.schemas import TenantUsage, TenantUsageSummary
from api.services import quotas
from api.settings import Settings

router = APIRouter(prefix="/usage", tags=["usage"])

SettingsDep = Annotated[Settings, Depends(get_settings)]

MIN_HISTORY_MONTHS = 1
DEFAULT_HISTORY_MONTHS = 12
MAX_HISTORY_MONTHS = 36


@router.get("", response_model=TenantUsage)
def get_usage(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    history_months: Annotated[
        int,
        Query(
            ge=MIN_HISTORY_MONTHS,
            le=MAX_HISTORY_MONTHS,
            description="How many calendar months of scan volume to return.",
        ),
    ] = DEFAULT_HISTORY_MONTHS,
) -> dict:
    return quotas.usage(settings, principal.tenant_id, history_months=history_months)


@router.get("/tenants", response_model=TenantUsageSummary)
def get_usage_across_tenants(
    _: Annotated[TokenUser, Depends(require_role(Role.admin))],
    settings: SettingsDep,
) -> dict:
    """Consumption for every tenant in the current period. Platform admin only."""
    return quotas.tenant_summaries(settings)
