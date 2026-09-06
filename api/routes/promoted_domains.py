"""A tenant's promoted related domains, as the tenant sees them (org_profile M4).

The run's Org Profile tab is where a domain gets *promoted* — the evidence
is there. It is not where the promotion *lives*: it is a property of the
tenant, carried by every scan the tenant starts, and it outlives the run
(retention, #187) and the candidate list (a promoted domain is a seed on the
next run and is never proposed again). So the list and the undo are keyed on
the tenant alone and gated like every other tenant-scoped resource: ``viewer``
reads what widens their scans, ``operator`` withdraws — the same role that
promotes. The admin's cross-tenant view is ``GET /api/tenants/{id}/promoted-domains``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.schemas import PromoteDomainResponse, PromotedDomainInfo
from api.services import promoted_domains
from api.settings import Settings

router = APIRouter(prefix="/promoted-domains", tags=["promoted-domains"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.get("", response_model=list[PromotedDomainInfo])
def list_promoted_domains(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> list[PromotedDomainInfo]:
    """Every domain this tenant's operators promoted — what every scan carries."""
    return [
        PromotedDomainInfo.model_validate(item)
        for item in promoted_domains.list_promoted(settings, principal.tenant_id)
    ]


@router.delete("/{domain}", response_model=PromoteDomainResponse)
def withdraw_promoted_domain(
    domain: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> PromoteDomainResponse:
    """Withdraw a promotion: the tenant's next scan no longer carries the domain.

    Needs no run — the run that proposed the domain may be gone, and the
    plan's own risk table says an attribution error is a scan of somebody
    else's infrastructure, so the undo cannot depend on anything that expires.
    """
    name = promoted_domains.normalize_domain(domain)
    removed = promoted_domains.withdraw(
        settings, tenant_id=principal.tenant_id, domain=name, withdrawn_by=principal.username
    )
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"'{name}' is not a promoted domain of tenant {principal.tenant_id}",
        )
    return PromoteDomainResponse(
        domain=name,
        promoted=False,
        message=f"Domain '{name}' withdrawn from scope of tenant {principal.tenant_id}",
    )
