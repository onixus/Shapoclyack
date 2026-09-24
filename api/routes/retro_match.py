"""Retro CVE matching: status and the operator's "check again now".

See docs/retro-cve-matching.md. Reads need ``viewer``, like every other
vulnerability read. Queuing a re-match needs ``operator`` — the same line the
software matcher's ``POST /endpoint/cve-matches/refresh`` draws: nothing an
operator can regret (the queue is derived), but a tenant-wide re-match is a
workload rather than a query. Unlike that route this one does not match in the
request; it marks the tenant's listeners due and wakes the worker, which drains
them within its budget.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.schemas import RetroMatchRefreshResult, RetroMatchStatus
from api.services import retro_match_worker
from api.settings import Settings

router = APIRouter(prefix="/retro-match", tags=["vulnerabilities"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("/status", response_model=RetroMatchStatus)
def retro_match_status(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict:
    """Dataset version, the tenant's queue, and what the last sweep did."""
    return retro_match_worker.status(settings, tenant_id=principal.tenant_id)


@router.post("/refresh", response_model=RetroMatchRefreshResult)
def refresh_retro_match(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict:
    """Put every stored listener of the tenant back on the retro queue."""
    return retro_match_worker.request_refresh(
        settings, tenant_id=principal.tenant_id, actor=principal.username
    )
