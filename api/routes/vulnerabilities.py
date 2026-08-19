"""Tracked vulnerabilities: lifecycle, ownership, SLA (#145, Track C).

Reads need ``viewer``; moving a finding through the lifecycle or reassigning it
needs ``operator``. Two things need tenant ``admin``:

* **accepting risk** (``POST /{id}/exception``) — it suspends an SLA the
  organisation set, which is a decision about what this tenant is willing to
  live with rather than a step in someone's remediation work;
* **editing SLA policy** — it changes every future deadline in the tenant.

Same reasoning as ``webhooks.py`` requiring ``admin`` to create a subscription:
the role follows what the action can commit the tenant to, not how hard it is.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    Page,
    SlaPolicyInfo,
    SlaPolicyRequest,
    VulnerabilityAssignRequest,
    VulnerabilityCommentRequest,
    VulnerabilityEventInfo,
    VulnerabilityExceptionRequest,
    VulnerabilityInfo,
    VulnerabilitySummary,
    VulnerabilityTicketRequest,
    VulnerabilityTransitionRequest,
)
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.settings import Settings

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

SettingsDep = Annotated[Settings, Depends(get_settings)]


def _scope(principal: TenantPrincipal) -> str | None:
    """Unscoped platform admin keeps the cross-tenant view (as for webhooks)."""
    if principal.is_platform_admin and not principal.tenant_requested:
        return None
    return principal.tenant_id


def _write_scope(principal: TenantPrincipal) -> str | None:
    """Tenant a *write* is confined to. ``None`` only for a platform admin, who
    may act on any tenant's finding; everyone else is pinned to their own, so a
    guessed ``vuln_id`` from another tenant 404s instead of being mutated."""
    return None if principal.is_platform_admin else principal.tenant_id


def _found(row: dict[str, Any] | None) -> dict[str, Any]:
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found"
        )
    return row


# Declared before /{vuln_id} so these paths are not read as ids.
@router.get("/summary", response_model=VulnerabilitySummary)
def get_summary(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict[str, Any]:
    return vulns_service.summary(settings, tenant_id=_scope(principal))


@router.get("/sla-policies", response_model=list[SlaPolicyInfo])
def list_sla_policies(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> list[dict[str, Any]]:
    return vulns_service.list_sla_policies(settings, tenant_id=_scope(principal))


@router.put("/sla-policies", response_model=SlaPolicyInfo)
def upsert_sla_policy(
    body: SlaPolicyRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Upsert the deadline for one (criticality, severity) scope.

    ``PUT`` rather than ``POST``: the scope is the identity, so sending it twice
    has to mean "this is the policy", not "make a second one".
    """
    try:
        return vulns_service.upsert_sla_policy(
            settings,
            tenant_id=principal.tenant_id,
            severity=body.severity,
            remediation_days=body.remediation_days,
            asset_criticality=body.asset_criticality,
            created_by=principal.username,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.delete("/sla-policies/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_sla_policy(
    policy_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> None:
    if not vulns_service.delete_sla_policy(
        settings, tenant_id=principal.tenant_id, policy_id=policy_id
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SLA policy not found")


@router.get("/events", response_model=Page[VulnerabilityEventInfo])
def list_all_events(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    page: PageParams,
) -> Page[VulnerabilityEventInfo]:
    """The tenant-wide remediation activity feed (#138)."""
    items, total = vulns_service.list_events(
        settings, tenant_id=_scope(principal), offset=page.offset, limit=page.limit
    )
    return build_page(items, total, page)


@router.get("", response_model=Page[VulnerabilityInfo])
def list_vulnerabilities(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    page: PageParams,
    state: Annotated[
        str | None, Query(description="OPEN | ACKNOWLEDGED | PLANNED | FIXING | VERIFYING | CLOSED")
    ] = None,
    open_only: Annotated[
        bool, Query(description="Everything not CLOSED — the default working set")
    ] = False,
    severity: Annotated[str | None, Query(description="critical | high | medium | low | unknown")] = None,
    asset_id: str | None = None,
    assignee: str | None = None,
    unassigned: Annotated[
        bool, Query(description="Open findings with no assignee — the dashboard's unowned work")
    ] = False,
    sla: Annotated[
        str | None, Query(description="on_track | due_soon | breached | accepted | none")
    ] = None,
    stale_days: Annotated[
        int | None,
        Query(
            ge=1,
            description="Not re-observed for this many days. Absence is never "
            "auto-closed, so this is how a stale finding gets looked at.",
        ),
    ] = None,
) -> Page[VulnerabilityInfo]:
    try:
        items, total = vulns_service.list_vulnerabilities(
            settings,
            tenant_id=_scope(principal),
            state=state,
            states=sorted(vuln_states.ACTIVE) if open_only else None,
            severity=severity,
            asset_id=asset_id,
            assignee=assignee,
            unassigned=unassigned,
            sla=sla,
            stale_days=stale_days,
            offset=page.offset,
            limit=page.limit,
            q=page.q,
            sort=page.sort,
            order=page.order,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return build_page(items, total, page)


@router.get("/{vuln_id}", response_model=VulnerabilityInfo)
def get_vulnerability(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict[str, Any]:
    return _found(
        vulns_service.get_vulnerability(settings, tenant_id=_scope(principal), vuln_id=vuln_id)
    )


@router.get("/{vuln_id}/events", response_model=Page[VulnerabilityEventInfo])
def list_vulnerability_events(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    page: PageParams,
) -> Page[VulnerabilityEventInfo]:
    # 404 first: an empty timeline and "no such finding in your tenant" must not
    # look the same to a caller probing ids.
    _found(vulns_service.get_vulnerability(settings, tenant_id=_scope(principal), vuln_id=vuln_id))
    items, total = vulns_service.list_events(
        settings,
        tenant_id=_scope(principal),
        vuln_id=vuln_id,
        offset=page.offset,
        limit=page.limit,
    )
    return build_page(items, total, page)


@router.post("/{vuln_id}/transition", response_model=VulnerabilityInfo)
def transition(
    vuln_id: str,
    body: VulnerabilityTransitionRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Move the finding to ``state``. 409 when the move is not legal.

    409 rather than 422 for the same reason ``POST /jobs/{id}/cancel`` uses it:
    the request is well-formed and the refusal is about the finding's current
    state, which the caller can re-read and act on.
    """
    try:
        return _found(
            vulns_service.transition(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                to_state=body.state,
                actor=principal.username,
                note=body.note,
            )
        )
    except vuln_states.InvalidVulnTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/{vuln_id}/assign", response_model=VulnerabilityInfo)
def assign(
    vuln_id: str,
    body: VulnerabilityAssignRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    return _found(
        vulns_service.assign(
            settings,
            tenant_id=_write_scope(principal),
            vuln_id=vuln_id,
            assignee=body.assignee,
            owner_team=body.owner_team,
            actor=principal.username,
            note=body.note,
            # Only the keys the client actually sent, so `{"assignee": null}`
            # unassigns while `{"owner_team": "x"}` leaves the assignee alone.
            fields=set(body.model_dump(exclude_unset=True)) & {"assignee", "owner_team"},
        )
    )


@router.post("/{vuln_id}/exception", response_model=VulnerabilityInfo)
def set_exception(
    vuln_id: str,
    body: VulnerabilityExceptionRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Accept the risk until ``until``, suspending the SLA clock until then."""
    try:
        return _found(
            vulns_service.set_exception(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                until=body.until,
                reason=body.reason,
                actor=principal.username,
            )
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.delete("/{vuln_id}/exception", response_model=VulnerabilityInfo)
def clear_exception(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Withdraw an acceptance. The deadline is recomputed from when the SLA
    clock started, not from now — the risk was accepted, not restarted."""
    return _found(
        vulns_service.clear_exception(
            settings,
            tenant_id=_write_scope(principal),
            vuln_id=vuln_id,
            actor=principal.username,
        )
    )


@router.post("/{vuln_id}/comment", response_model=VulnerabilityInfo)
def add_comment(
    vuln_id: str,
    body: VulnerabilityCommentRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Leave a comment on the audit trail. Does not change lifecycle state."""
    try:
        return _found(
            vulns_service.add_comment(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                note=body.note,
                actor=principal.username,
            )
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.post("/{vuln_id}/ticket", response_model=VulnerabilityInfo)
def set_ticket(
    vuln_id: str,
    body: VulnerabilityTicketRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Link an external ticket. The platform does not open the ticket."""
    try:
        return _found(
            vulns_service.set_ticket(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                system=body.system,
                key=body.key,
                url=body.url,
                actor=principal.username,
                note=body.note,
            )
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.delete("/{vuln_id}/ticket", response_model=VulnerabilityInfo)
def clear_ticket(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    return _found(
        vulns_service.clear_ticket(
            settings,
            tenant_id=_write_scope(principal),
            vuln_id=vuln_id,
            actor=principal.username,
        )
    )
