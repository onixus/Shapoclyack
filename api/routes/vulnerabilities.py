"""Tracked vulnerabilities: lifecycle, ownership, SLA (#145, Track C).

Reads need ``viewer``; moving a finding through the lifecycle or reassigning it
needs ``operator``. Two things need tenant ``admin``:

* **asking for risk to be accepted** (``POST /{id}/exception``) — it proposes
  living past an SLA the organisation set, which is a decision about what this
  tenant is willing to tolerate rather than a step in someone's remediation
  work. Since #348 it only *asks*: the acceptance itself is
  ``POST /{id}/exception/approve``, gated on the named permission
  ``vulnerability.exception.approve`` (the ``risk-approver`` role) and refused
  to whoever filed the request. Two roles, two people, and the SLA clock keeps
  running until the second one signs. Undoing splits the same way: the
  requester takes back their own ask at ``DELETE /{id}/exception/request``,
  while revoking an acceptance that was signed (``DELETE /{id}/exception``)
  needs the permission that could have signed it;
* **editing SLA policy** — it changes every future deadline in the tenant, and
  the escalation policy next to it (#349) decides what the platform does to a
  finding whose deadline passed and whose asset owner is mailed about it;
* **marking a false positive** (``POST /{id}/false-positive``) — it closes the
  finding *and* stops the scanner re-opening it, which is strictly stronger
  than accepting the risk. Withdrawing one is ``operator``: it only ever puts
  work back on the queue.

Same reasoning as ``webhooks.py`` requiring ``admin`` to create a subscription:
the role follows what the action can commit the tenant to, not how hard it is.

``POST /bulk`` (#346) applies one of those verbs to many findings and inherits
that table exactly — see ``_BULK_ROLES``. A batch is a partial success by
design and answers 200 with a per-id report; the only 422s are the ones that
apply to no id at all.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse

from api.auth import (
    ROLE_RANK,
    Role,
    TenantPrincipal,
    get_settings,
    require_permission,
    require_tenant,
)
from api.core import permissions as permission_catalog
from api.routes import _idempotency as idempotency
from api.routes._audit import AuditDep
from api.routes._idempotency import IdempotencyKeyHeader
from api.routes._pagination import PageParams, build_page
from api.schemas import (
    BulkActionReport,
    BulkVulnerabilityRequest,
    Page,
    RiskAcceptanceInfo,
    RiskScoreSnapshotInfo,
    SlaEscalationPolicyInfo,
    SlaEscalationPolicyRequest,
    SlaPolicyInfo,
    SlaPolicyRequest,
    VulnerabilityAssignRequest,
    VulnerabilityCommentRequest,
    VulnerabilityEventInfo,
    VulnerabilityExceptionDecision,
    VulnerabilityExceptionRequest,
    VulnerabilityFalsePositiveRequest,
    VulnerabilityInfo,
    VulnerabilitySummary,
    VulnerabilityTicketRequest,
    VulnerabilityTransitionRequest,
)
from api.services import audit as audit_service
from api.services import bulk_actions
from api.services import risk_snapshots
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


@router.get("/risk-history", response_model=list[RiskScoreSnapshotInfo])
def get_risk_history(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    since: datetime | None = Query(default=None, description="Filter snapshots recorded on or after this timestamp"),
    until: datetime | None = Query(default=None, description="Filter snapshots recorded on or before this timestamp"),
    limit: int = Query(default=90, ge=1, le=500, description="Max snapshots to return"),
) -> list[dict[str, Any]]:
    """Time-series risk posture snapshots for trend charts (#144, Track C).

    Always one tenant, unlike ``/summary``: a chart is a line, and merging two
    tenants' snapshots into one chronological series draws the difference
    between them as a change over time (#228). A platform admin picks the
    tenant with the ``tenant_id`` query parameter every route already takes;
    without one they get their own, which is what the console asks for.
    """
    return risk_snapshots.list_snapshots(
        settings,
        tenant_id=principal.tenant_id,
        since=since,
        until=until,
        limit=limit,
    )


@router.post(
    "/risk-history/snapshot",
    response_model=RiskScoreSnapshotInfo,
    status_code=status.HTTP_201_CREATED,
)
def create_risk_snapshot(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Capture and persist an immediate risk snapshot for the tenant."""
    return risk_snapshots.take_snapshot(
        settings,
        tenant_id=principal.tenant_id,
        source="manual",
    )


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


@router.get("/sla-escalation", response_model=SlaEscalationPolicyInfo)
def get_sla_escalation(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """The tenant's escalation policy, or the all-off defaults if it has none.

    Always one tenant, unlike ``/sla-policies``: there is one row per tenant,
    so a platform admin's cross-tenant view would be a list of unrelated
    policies with no way to say which is being edited.
    """
    return vulns_service.get_escalation_policy(settings, tenant_id=principal.tenant_id)


@router.put("/sla-escalation", response_model=SlaEscalationPolicyInfo)
def upsert_sla_escalation(
    body: SlaEscalationPolicyRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Replace it. ``admin`` for the same reason editing SLA policy is: this
    decides what the platform does to the tenant's findings and who is mailed
    about them, which is a decision about the tenant rather than a step in
    somebody's remediation work."""
    try:
        return vulns_service.upsert_escalation_policy(
            settings,
            tenant_id=principal.tenant_id,
            enabled=body.enabled,
            escalate_after_days=body.escalate_after_days,
            escalate_to=body.escalate_to,
            escalate_owner_team=body.escalate_owner_team,
            bump_severity=body.bump_severity,
            digest_enabled=body.digest_enabled,
            updated_by=principal.username,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


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


# Leading characters a spreadsheet evaluates rather than displays. Same list
# and same reason as ``api/routes/audit.py``: the register's cells carry a
# finding's title and somebody's free-text justification, and the file exists
# to be opened in Excel by whoever is reviewing the acceptances.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

#: Columns of the CSV, in the order an auditor reads them: what was accepted,
#: on whose word, until when, and who owns it now.
_REGISTER_CSV_COLUMNS = (
    "vuln_id",
    "status",
    "severity",
    "title",
    "cve",
    "asset_id",
    "asset_owner",
    "business_service",
    "assignee",
    "owner_team",
    "state",
    "reason",
    "requested_by",
    "requested_at",
    "approved_by",
    "approved_at",
    "decision_note",
    "until",
    "days_remaining",
    "self_approved",
)


def _register_csv(entries: list[dict[str, Any]]) -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_REGISTER_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    yield _drain(buffer)
    for entry in entries:
        writer.writerow(
            {
                key: ("'" + value if isinstance(value, str) and value.startswith(
                    _FORMULA_PREFIXES
                ) else value)
                for key, value in entry.items()
            }
        )
        yield _drain(buffer)


def _drain(buffer: io.StringIO) -> str:
    value = buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    return value


@router.get("/risk-register", response_model=None)
def risk_register(
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))],
    settings: SettingsDep,
    since: Annotated[
        datetime | None,
        Query(description="Include acceptances that lapsed at or after this UTC time"),
    ] = None,
    export_format: Annotated[
        str | None, Query(alias="format", pattern="^csv$", description="Stream a CSV instead")
    ] = None,
) -> list[RiskAcceptanceInfo] | StreamingResponse:
    """The register of accepted risk: in force now, and lapsed since ``since``.

    ``viewer``, like every other read here — this is the document a team is
    asked about in a review, and making it admin-only would mean the people who
    have to answer for an acceptance cannot see the list of them.

    Always one tenant, like ``/risk-history`` and for the same reason: a
    register that merged two customers' acceptances is not a register of
    either. The default window is
    ``vulnerabilities.RISK_REGISTER_DAYS`` days back.
    """
    entries = vulns_service.risk_acceptance_register(
        settings, tenant_id=principal.tenant_id, since=since
    )
    if export_format == "csv":
        return StreamingResponse(
            _register_csv(entries),
            media_type="text/csv",
            headers={
                "Content-Disposition": 'attachment; filename="risk-acceptance-register.csv"'
            },
        )
    return entries


# The role each bulk verb needs, which is exactly the role its single-finding
# route needs: ``operator`` to move work along, ``admin`` to commit the tenant
# to accepting a risk or to suppressing a finding. Doing two hundred of a thing
# must never be cheaper than doing one of it — a bulk endpoint that took the
# lowest role of its members would be a way around the admin gate on
# ``/exception`` and ``/false-positive``.
_BULK_ROLES: dict[str, Role] = {
    "assign": Role.operator,
    "transition": Role.operator,
    "ticket": Role.operator,
    "exception": Role.admin,
    "false_positive": Role.admin,
}


def _record_bulk_audit(
    audit: Any,
    principal: TenantPrincipal,
    report: dict[str, Any],
    payload: dict[str, Any],
    *,
    action: str,
) -> None:
    """The batch's audit row, filed in the tenant whose findings it changed.

    Which is not always the caller's: a platform admin writes with no scope
    (``_write_scope``), so ``?tenant_id=acme`` reads to a human like a boundary
    and is not one. Filing that batch's only row under the admin's own tenant
    left the affected customer's trail — and the SIEM forward, which filters by
    tenant — with no record of their finding being edited. So a batch that
    crossed tenants is one row per tenant it touched; see
    ``bulk_actions.audit_rows``.
    """
    for tenant_id, document in bulk_actions.audit_rows(
        report,
        payload,
        write_scope=_write_scope(principal),
        caller_tenant=principal.tenant_id,
    ):
        audit_service.record_standalone(
            audit,
            action=audit_service.ACTION_VULN_BULK,
            resource_type="vulnerability",
            resource_id=f"bulk:{action}",
            tenant_id=tenant_id,
            after=document,
        )


@router.post("/bulk", response_model=BulkActionReport)
def bulk_action(
    body: BulkVulnerabilityRequest,
    # ``operator`` is the floor; the per-action check below raises it to
    # ``admin`` where the verb needs one. The dependency cannot express it —
    # it runs before the body is parsed, so it does not know the verb yet.
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
    audit: AuditDep,
    idempotency_key: IdempotencyKeyHeader = None,
) -> dict[str, Any]:
    """Apply one lifecycle verb to many findings, reporting on each id (#346).

    200 even when some ids failed: a batch is a partial success by design. One
    finding that has since closed, or one id belonging to a tenant this caller
    cannot write in, must not refuse the other hundred and ninety-nine — see
    ``BulkActionReport``, and :mod:`api.services.bulk_actions` for what each
    outcome means. 422 is reserved for a request that could not be applied to
    *anything*: an empty or oversized id list.

    Recorded as **one** ``audit_events`` row listing the ids, not one row per
    id: this was one decision, and two hundred rows that each look like a hand
    edit would bury that.
    """
    required = _BULK_ROLES[body.action]
    if ROLE_RANK[principal.role] < ROLE_RANK[required]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Role '{required.value}' or higher required in tenant "
                f"'{principal.tenant_id}' for bulk '{body.action}'"
            ),
        )
    # ``exclude_unset`` for the same reason the single ``/assign`` route uses
    # it: `{"assignee": null}` unassigns, an omitted key leaves the field alone.
    payload = body.payload.model_dump(exclude_unset=True)
    guard = idempotency.begin(
        settings,
        tenant_id=principal.tenant_id,
        endpoint="vulnerabilities.bulk",
        key=idempotency_key,
        # Sorted ids: a retry that reshuffles its selection is the same batch,
        # and calling it a different one would 409 an honest retry.
        payload={"action": body.action, "ids": sorted(set(body.vuln_ids)), "payload": payload},
    )
    if guard.replay is not None:
        return {**guard.replay, "replayed": True}
    try:
        report = bulk_actions.apply_vulnerability_action(
            settings,
            tenant_id=_write_scope(principal),
            vuln_ids=body.vuln_ids,
            action=body.action,
            payload=payload,
            actor=principal.username,
        )
    except ValueError as exc:
        # Request-level, not per-id: nothing was applied, so there is no
        # partial report to hand back and the key must not be burned.
        guard.release()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except bulk_actions.BulkActionAborted as exc:
        # The batch died part-way and every id before that is committed. The
        # row goes in *before* the 500 leaves: findings changed with nothing in
        # `audit_events` is the silent change the trail exists to make
        # impossible, and a partial report is still a report.
        _record_bulk_audit(audit, principal, exc.report, payload, action=body.action)
        if exc.report["succeeded"]:
            # The key is deliberately *not* given back. A retry with it would
            # be a second pass over the ids that did apply — for `transition`
            # a hundred conflicts, for `false_positive` a second suppression
            # window — so what the retry gets is this partial report, which
            # tells it exactly which ids are left to send.
            guard.store(exc.report)
        else:
            guard.release()
        raise
    except Exception:
        guard.release()
        raise
    _record_bulk_audit(audit, principal, report, payload, action=body.action)
    guard.store(report)
    return report


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
    source: Annotated[
        str | None,
        Query(
            description="scan | endpoint_software — which observer found it. "
            "Software findings come from the endpoint inventory and are "
            "verified by the next snapshot, not by a re-scan."
        ),
    ] = None,
    network_exposure: Annotated[
        Literal["external", "internal", "unknown"] | None,
        Query(
            description="external | internal | unknown — where the finding sits "
            "relative to the perimeter. 'unknown' also matches findings scored "
            "before the signal existed."
        ),
    ] = None,
    assignee: str | None = None,
    unassigned: Annotated[
        bool, Query(description="Open findings with no assignee — the dashboard's unowned work")
    ] = False,
    sla: Annotated[
        str | None, Query(description="on_track | due_soon | breached | accepted | none")
    ] = None,
    exception_state: Annotated[
        str | None,
        Query(
            description="none | exception_requested | exception_approved | "
            "exception_rejected | exception_expired. "
            "``exception_requested`` is the approval queue (#348): the requests "
            "waiting for somebody holding vulnerability.exception.approve."
        ),
    ] = None,
    stale_days: Annotated[
        int | None,
        Query(
            ge=1,
            description="Not re-observed for this many days. Absence is never "
            "auto-closed, so this is how a stale finding gets looked at.",
        ),
    ] = None,
    in_kev: Annotated[
        bool,
        Query(description="Open or any-state findings currently on CISA KEV"),
    ] = False,
) -> Page[VulnerabilityInfo]:
    try:
        items, total = vulns_service.list_vulnerabilities(
            settings,
            tenant_id=_scope(principal),
            state=state,
            states=sorted(vuln_states.ACTIVE) if open_only else None,
            severity=severity,
            asset_id=asset_id,
            source=source,
            network_exposure=network_exposure,
            assignee=assignee,
            unassigned=unassigned,
            sla=sla,
            exception_state=exception_state,
            stale_days=stale_days,
            in_kev=True if in_kev else None,
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
def request_exception(
    vuln_id: str,
    body: VulnerabilityExceptionRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    """Ask for the risk to be accepted until ``until``. Suspends nothing (#348).

    Still ``admin`` — proposing that the tenant live past its own deadline is
    the same decision it always was — but it is now a *request*: the clock
    keeps running until somebody holding ``vulnerability.exception.approve``
    answers it at ``POST /{id}/exception/approve``. A tenant admin does not
    carry that permission, which is what makes the two roles two people.
    """
    try:
        return _found(
            vulns_service.request_exception(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                until=body.until,
                reason=body.reason,
                actor=principal.username,
                audit=audit,
            )
        )
    except vuln_states.InvalidVulnTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.post("/{vuln_id}/exception/approve", response_model=VulnerabilityInfo)
def approve_exception(
    vuln_id: str,
    body: VulnerabilityExceptionDecision,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_permission(permission_catalog.VULNERABILITY_EXCEPTION_APPROVE)),
    ],
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    """Grant a pending request. The permission, and never the rank (#318/#348).

    ``risk-approver`` is a rank-1 role on purpose — it approves and runs
    nothing — so this route cannot be written as ``require_tenant(Role.admin)``
    plus a check: the gate *is* the named permission. The 403 that matters most
    is not the one for a missing permission, though, but the one below it: the
    requester is refused by name even when they hold it, which is the only
    thing that separates duties for a platform admin.
    """
    try:
        return _found(
            vulns_service.approve_exception(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                actor=principal.username,
                note=body.note,
                audit=audit,
            )
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except vuln_states.InvalidVulnTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.post("/{vuln_id}/exception/reject", response_model=VulnerabilityInfo)
def reject_exception(
    vuln_id: str,
    body: VulnerabilityExceptionDecision,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_permission(permission_catalog.VULNERABILITY_EXCEPTION_APPROVE)),
    ],
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    """Refuse a pending request. Same permission, same self-decision bar.

    Rejecting is gated as highly as approving, unlike withdrawing: an operator
    who could reject would be able to close somebody else's request without
    holding the authority to answer it, and "refused" is an answer.
    """
    try:
        return _found(
            vulns_service.reject_exception(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                actor=principal.username,
                note=body.note,
                audit=audit,
            )
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except vuln_states.InvalidVulnTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.delete("/{vuln_id}/exception/request", response_model=VulnerabilityInfo)
def withdraw_exception_request(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    """Take back your own pending request. The granted acceptance is untouched.

    Same rank as filing one, because it is the same person doing it — the
    service refuses a request somebody else filed by name. Nothing about the
    SLA moves: a request never suspended the clock.

    Separate from ``DELETE /{id}/exception`` next door, which revokes what a
    second person signed. One route for both is what let an admin correcting a
    date in their own extension request destroy the acceptance in force under
    it (#348 debt).
    """
    try:
        return _found(
            vulns_service.withdraw_exception_request(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                actor=principal.username,
                audit=audit,
            )
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except vuln_states.InvalidVulnTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.delete("/{vuln_id}/exception", response_model=VulnerabilityInfo)
def clear_exception(
    vuln_id: str,
    principal: Annotated[
        TenantPrincipal,
        Depends(require_permission(permission_catalog.VULNERABILITY_EXCEPTION_APPROVE)),
    ],
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    """Revoke a granted acceptance. The finding is back under its deadline.

    The permission that could have granted it, not the rank that asked for it
    (#348 debt): an acceptance carries a second person's signature, and taking
    it away the day before an audit is a decision of the same weight as
    signing it. The tenant ``admin`` who filed the request does not hold
    ``vulnerability.exception.approve`` — which is the whole point of the two
    roles — so it can no longer undo somebody else's approval. The platform
    admin holds every permission and remains the way out for an installation
    with nobody in the ``risk-approver`` role.

    The deadline is recomputed from when the SLA clock started, not from now:
    the risk was accepted, not restarted. A request still waiting on a decision
    is left waiting — that one belongs to its requester.
    """
    return _found(
        vulns_service.clear_exception(
            settings,
            tenant_id=_write_scope(principal),
            vuln_id=vuln_id,
            actor=principal.username,
            audit=audit,
        )
    )


@router.post("/{vuln_id}/false-positive", response_model=VulnerabilityInfo)
def mark_false_positive(
    vuln_id: str,
    body: VulnerabilityFalsePositiveRequest,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.admin))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Close a finding as never having been real, suppressing its re-opening.

    ``admin``, one notch above closing a finding by hand and the same as
    accepting risk. Suppression is strictly the stronger of the two: an
    acceptance leaves the finding open with a visible deadline, while this
    closes it and keeps the scanner from bringing it back, so the bar cannot be
    lower.
    """
    try:
        return _found(
            vulns_service.mark_false_positive(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                reason=body.reason,
                suppress_days=body.suppress_days,
                evidence=body.evidence,
                actor=principal.username,
            )
        )
    except vuln_states.InvalidVulnTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.delete("/{vuln_id}/false-positive", response_model=VulnerabilityInfo)
def clear_false_positive(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Withdraw the verdict and put the finding back on the queue as ``OPEN``.

    ``operator``, deliberately cheaper than setting it: releasing a suppression
    can only add work back, and a control that is harder to undo than to apply
    is one people stop applying.

    A finding with no verdict on it is a 409, not a 200: answering "withdrawn"
    to a request that withdrew nothing is what made the console's button report
    a success it had not had.
    """
    try:
        return _found(
            vulns_service.clear_false_positive(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                actor=principal.username,
            )
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


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


@router.post("/{vuln_id}/verify", response_model=VulnerabilityInfo)
def verify(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Dispatch a targeted re-scan and move the finding to ``VERIFYING``.

    409 when the move is not legal from the finding's current state, and also
    when the scan could not be dispatched: a finding parked in ``VERIFYING``
    with no scan behind it would later be closed as machine-verified by a run
    that never looked at it, so the request fails instead. A finding from the
    endpoint software inventory is 409 for the same reason — a port scan does
    not observe an installed package — and is verified by its device's next
    accepted snapshot.
    """
    try:
        return _found(
            vulns_service.trigger_verification(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                actor=principal.username,
            )
        )
    except vuln_states.InvalidVulnTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except vulns_service.VerificationDispatchError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/{vuln_id}/ticket/sync", response_model=VulnerabilityInfo)
def sync_ticket(
    vuln_id: str,
    principal: Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))],
    settings: SettingsDep,
) -> dict[str, Any]:
    """Read the linked ticket's status and reconcile the finding's state.

    A tracker can report that the work is done; it cannot report that the
    finding is verified gone, so a closure from here is recorded as
    ``ticket_resolved`` and is never counted as machine-verified.
    """
    try:
        return _found(
            vulns_service.sync_ticket_status(
                settings,
                tenant_id=_write_scope(principal),
                vuln_id=vuln_id,
                actor=principal.username,
            )
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
