"""Remediation campaigns over a snapshot of tracked findings (#579, stage 2).

Reads need ``viewer``; everything that creates or changes a campaign, or asks
for verification, needs ``operator`` — the same floor as moving a finding
through its lifecycle. A campaign changes no finding by itself: lifecycle,
owners, SLA and exceptions stay on the findings and are edited through the
findings' own routes (``/vulnerabilities``). The one cross-over is
``POST /{id}/verify``, which calls the existing per-finding verification.

Scope is always the caller's own tenant. A finding id from another tenant is
reported as not found, exactly like a missing one, in previews, creation and
membership changes alike.

``POST ""`` and ``POST /{id}/verify`` take ``Idempotency-Key``: a retry
replays the first answer (200) instead of creating a second campaign or
dispatching verification twice.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field

from api.auth import Role, TenantPrincipal, get_settings, require_tenant
from api.routes import _idempotency as idempotency
from api.routes._audit import AuditDep
from api.routes._idempotency import IdempotencyKeyHeader
from api.routes._pagination import PageParams, build_page
from api.services import remediation_campaigns as service
from api.settings import Settings

router = APIRouter(prefix="/remediation-campaigns", tags=["remediation-campaigns"])

SettingsDep = Annotated[Settings, Depends(get_settings)]
Reader = Annotated[TenantPrincipal, Depends(require_tenant(Role.viewer))]
Writer = Annotated[TenantPrincipal, Depends(require_tenant(Role.operator))]


class Selection(BaseModel):
    """What to put in a campaign: whole problems (under optional filters), and/or
    explicit findings. Resolved on the server every time it is used."""

    model_config = ConfigDict(extra="forbid")
    problem_keys: list[str] = Field(default_factory=list, max_length=service.MAX_PROBLEM_KEYS)
    vuln_ids: list[str] = Field(default_factory=list, max_length=service.MAX_MEMBERS)
    filters: service.SelectionFilters = Field(default_factory=service.SelectionFilters)


class CampaignCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=service.MAX_NAME)
    description: str = Field(default="", max_length=service.MAX_DESCRIPTION)
    owner: str | None = Field(default=None, max_length=service.MAX_OWNER)
    due_at: datetime | None = None
    selection: Selection
    composition_hash: str | None = Field(
        default=None,
        max_length=128,
        description="`composition_hash` of the preview the operator reviewed; "
        "creation fails with 409 if the selection no longer resolves to it.",
    )


class CampaignPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=service.MAX_NAME)
    description: str | None = Field(default=None, max_length=service.MAX_DESCRIPTION)
    owner: str | None = Field(default=None, max_length=service.MAX_OWNER)
    due_at: datetime | None = None


class MembersAdd(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selection: Selection
    reason: str = Field(min_length=service.MIN_REASON, max_length=service.MAX_REASON)


class MembersExclude(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vuln_ids: list[str] = Field(min_length=1, max_length=service.MAX_MEMBERS)
    reason: str = Field(min_length=service.MIN_REASON, max_length=service.MAX_REASON)


class VerifyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vuln_ids: list[str] | None = Field(
        default=None,
        max_length=service.MAX_MEMBERS,
        description="Members to re-check. Omitted: every included member that is "
        "in FIXING (the only state the lifecycle lets move to VERIFYING).",
    )


class StatusBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=service.MIN_REASON, max_length=service.MAX_REASON)


def _call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except service.CampaignConflict as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.post("/preview")
def preview(body: Selection, principal: Writer, settings: SettingsDep) -> dict[str, Any]:
    """The exact findings this selection would freeze right now (read-only)."""
    return _call(
        service.preview,
        settings,
        tenant_id=principal.tenant_id,
        selection=body.model_dump(),
    )


@router.post("", status_code=status.HTTP_201_CREATED)
def create_campaign(
    body: CampaignCreate,
    principal: Writer,
    settings: SettingsDep,
    audit: AuditDep,
    response: Response,
    idempotency_key: IdempotencyKeyHeader = None,
) -> dict[str, Any]:
    guard = idempotency.begin(
        settings,
        tenant_id=principal.tenant_id,
        actor=principal.username,
        endpoint="remediation_campaigns.create",
        key=idempotency_key,
        payload=body.model_dump(mode="json"),
    )
    if guard.replay is not None:
        response.status_code = status.HTTP_200_OK
        return {**guard.replay, "replayed": True}
    try:
        created = _call(
            service.create_campaign,
            settings,
            tenant_id=principal.tenant_id,
            actor=principal.username,
            audit=audit,
            name=body.name,
            description=body.description,
            owner=body.owner,
            due_at=body.due_at,
            selection=body.selection.model_dump(),
            expected_hash=body.composition_hash,
        )
    except BaseException:
        guard.release()
        raise
    guard.store(created)
    return created


@router.get("")
def list_campaigns(
    principal: Reader,
    settings: SettingsDep,
    page: PageParams,
    campaign_status: Annotated[str | None, Query(alias="status")] = None,
    owner: str | None = None,
) -> Any:
    items, total = _call(
        service.list_campaigns,
        settings,
        tenant_id=principal.tenant_id,
        status=campaign_status,
        owner=owner,
        offset=page.offset,
        limit=page.limit,
        q=page.q,
    )
    return build_page(items, total, page)


@router.get("/{campaign_id}")
def get_campaign(campaign_id: str, principal: Reader, settings: SettingsDep) -> dict[str, Any]:
    return _call(
        service.get_campaign, settings, tenant_id=principal.tenant_id, campaign_id=campaign_id
    )


@router.patch("/{campaign_id}")
def update_campaign(
    campaign_id: str,
    body: CampaignPatch,
    principal: Writer,
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    # ``exclude_unset``: `{"owner": null}` clears the owner, an omitted key
    # leaves it alone.
    return _call(
        service.update_campaign,
        settings,
        tenant_id=principal.tenant_id,
        campaign_id=campaign_id,
        actor=principal.username,
        audit=audit,
        changes=body.model_dump(exclude_unset=True),
    )


@router.get("/{campaign_id}/members")
def list_members(
    campaign_id: str,
    principal: Reader,
    settings: SettingsDep,
    page: PageParams,
    member_status: Annotated[str, Query(alias="status", pattern="^(included|excluded)$")] = "included",
    category: str | None = None,
    problem_key: str | None = None,
) -> Any:
    items, total = _call(
        service.list_members,
        settings,
        tenant_id=principal.tenant_id,
        campaign_id=campaign_id,
        member_status=member_status,
        category=category,
        problem_key=problem_key,
        offset=page.offset,
        limit=page.limit,
        sort=page.sort,
        order=page.order,
    )
    return build_page(items, total, page)


@router.post("/{campaign_id}/members")
def add_members(
    campaign_id: str,
    body: MembersAdd,
    principal: Writer,
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    """Add findings, each with the author and reason on record. 200 with a
    per-id report: ids that are missing or closed do not refuse the rest."""
    return _call(
        service.add_members,
        settings,
        tenant_id=principal.tenant_id,
        campaign_id=campaign_id,
        actor=principal.username,
        audit=audit,
        selection=body.selection.model_dump(),
        reason=body.reason,
    )


@router.post("/{campaign_id}/members/exclude")
def exclude_members(
    campaign_id: str,
    body: MembersExclude,
    principal: Writer,
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    return _call(
        service.exclude_members,
        settings,
        tenant_id=principal.tenant_id,
        campaign_id=campaign_id,
        actor=principal.username,
        audit=audit,
        vuln_ids=body.vuln_ids,
        reason=body.reason,
    )


@router.get("/{campaign_id}/events")
def list_events(
    campaign_id: str, principal: Reader, settings: SettingsDep, page: PageParams
) -> Any:
    items, total = _call(
        service.list_events,
        settings,
        tenant_id=principal.tenant_id,
        campaign_id=campaign_id,
        offset=page.offset,
        limit=page.limit,
    )
    return build_page(items, total, page)


@router.post("/{campaign_id}/verify")
def verify(
    campaign_id: str,
    body: VerifyBody,
    principal: Writer,
    settings: SettingsDep,
    audit: AuditDep,
    response: Response,
    idempotency_key: IdempotencyKeyHeader = None,
) -> dict[str, Any]:
    """Run the existing verification for members; a per-finding report.

    200 even when some findings are refused: the report says which were
    dispatched and which were not, and why (not in FIXING, unsupported source,
    scope/maintenance/sensor refusal, per-request cap).
    """
    guard = idempotency.begin(
        settings,
        tenant_id=principal.tenant_id,
        actor=principal.username,
        endpoint=f"remediation_campaigns.verify:{campaign_id}",
        key=idempotency_key,
        payload={"vuln_ids": sorted(set(body.vuln_ids)) if body.vuln_ids is not None else None},
    )
    if guard.replay is not None:
        return {**guard.replay, "replayed": True}
    try:
        report = _call(
            service.verify_members,
            settings,
            tenant_id=principal.tenant_id,
            campaign_id=campaign_id,
            actor=principal.username,
            audit=audit,
            vuln_ids=body.vuln_ids,
        )
    except HTTPException:
        # Refused before anything was dispatched (unknown campaign, cancelled,
        # bad body): the key goes back.
        guard.release()
        raise
    # Any other failure may come after some jobs were dispatched. The key is
    # deliberately kept: a retry with it would dispatch those findings a second
    # time. The reservation lapses by itself (idempotency lease), and the
    # campaign's own history records what went out.
    guard.store(report)
    return report


@router.post("/{campaign_id}/cancel")
def cancel(
    campaign_id: str,
    body: StatusBody,
    principal: Writer,
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    return _call(
        service.set_status,
        settings,
        tenant_id=principal.tenant_id,
        campaign_id=campaign_id,
        actor=principal.username,
        audit=audit,
        action="cancel",
        reason=body.reason,
    )


@router.post("/{campaign_id}/resume")
def resume(
    campaign_id: str,
    body: StatusBody,
    principal: Writer,
    settings: SettingsDep,
    audit: AuditDep,
) -> dict[str, Any]:
    return _call(
        service.set_status,
        settings,
        tenant_id=principal.tenant_id,
        campaign_id=campaign_id,
        actor=principal.username,
        audit=audit,
        action="resume",
        reason=body.reason,
    )
