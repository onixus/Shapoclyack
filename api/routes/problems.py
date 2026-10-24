"""Aggregated problem list over tracked findings (#579, stage 1).

Read-only and ``viewer``: a problem is a grouping of findings the caller can
already list, so the gate is the findings list's. The scope is always the
caller's own tenant — never the platform-admin cross-tenant view the findings
list offers — because an aggregate that summed two tenants' findings under one
key would leak one tenant's counts into another's.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes._pagination import PageParams, build_page
from api.services import problems as problems_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.settings import Settings

router = APIRouter(prefix="/problems", tags=["problems"])

SettingsDep = Annotated[Settings, Depends(get_settings)]
Reader = Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))]


def finding_filter_query(
    state: Annotated[
        str | None, Query(description="OPEN | ACKNOWLEDGED | PLANNED | FIXING | VERIFYING | CLOSED")
    ] = None,
    open_only: Annotated[bool, Query(description="Everything not CLOSED")] = False,
    severity: str | None = None,
    asset_id: str | None = None,
    finding_type: vulns_service.FindingType | None = None,
    detector_source: vulns_service.DetectorSource | None = None,
    source: str | None = None,
    network_exposure: vulns_service.NetworkExposure | None = None,
    assignee: str | None = None,
    unassigned: bool = False,
    sla: str | None = None,
    exception_state: str | None = None,
    stale_days: Annotated[int | None, Query(ge=1)] = None,
    in_kev: bool = False,
) -> dict[str, Any]:
    """The findings list's filters, with the same names and meaning, as one
    dict. The problem list and its drill-down take these verbatim so the
    console can carry one filter state across both views."""
    return {
        "state": state,
        "states": sorted(vuln_states.ACTIVE) if open_only else None,
        "severity": severity,
        "asset_id": asset_id,
        "finding_type": finding_type,
        "detector_source": detector_source,
        "source": source,
        "network_exposure": network_exposure,
        "assignee": assignee,
        "unassigned": unassigned,
        "sla": sla,
        "exception_state": exception_state,
        "stale_days": stale_days,
        "in_kev": True if in_kev else None,
    }


FilterDep = Annotated[dict[str, Any], Depends(finding_filter_query)]


@router.get("")
def list_problems(
    principal: Reader,
    settings: SettingsDep,
    page: PageParams,
    filters: FilterDep,
) -> dict[str, Any]:
    """Problems for the filtered selection, with whole-selection aggregates.

    ``sort`` is one of risk (default) | severity | instances | assets |
    breached | kev | last_seen | due; ``q`` is the findings list's search.
    """
    try:
        result = problems_service.list_problems(
            settings,
            tenant_id=principal.tenant_id,
            filters={**filters, "q": page.q},
            offset=page.offset,
            limit=page.limit,
            sort=page.sort,
            order=page.order,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    built = build_page(result["items"], result["total"], page)
    return {
        **built.model_dump(),
        "aggregates": result["aggregates"],
        "as_of": result["as_of"],
        "semantics": result["semantics"],
    }


@router.get("/instances")
def problem_instances(
    principal: Reader,
    settings: SettingsDep,
    page: PageParams,
    filters: FilterDep,
    problem_key: Annotated[str, Query(min_length=1, max_length=400)],
    as_of: Annotated[str | None, Query(description="`as_of` of the list the row came from")] = None,
    expected_instances: Annotated[int | None, Query(ge=0)] = None,
) -> dict[str, Any]:
    """The findings behind one problem under the same filters as the list.

    Pass the row's ``as_of`` and ``instances`` back as ``as_of`` /
    ``expected_instances`` and the answer carries ``drift``: whether the count
    changed since the list was loaded and how many findings changed after it.
    """
    try:
        result = problems_service.problem_instances(
            settings,
            tenant_id=principal.tenant_id,
            problem_key=problem_key,
            filters={**filters, "q": page.q},
            as_of=as_of,
            expected_instances=expected_instances,
            offset=page.offset,
            limit=page.limit,
            sort=page.sort,
            order=page.order,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    built = build_page(result["items"], result["total"], page)
    return {**built.model_dump(), "drift": result["drift"], "problem_key": problem_key}
