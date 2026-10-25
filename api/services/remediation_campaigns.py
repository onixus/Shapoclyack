"""Remediation campaigns over a snapshot of tracked findings (#579, stage 2).

A campaign is a durable *effort* ("upgrade openssl on the fleet"), not a second
state machine. It stores who is accountable, the target date, the description
of the shared action and **which findings were chosen when it was created**.
Everything a finding *is* — its state, owner, SLA, exception, ticket,
verification — stays on ``vulnerabilities`` and moves only through the existing
operations; a campaign only reads those and verifies through
:func:`vulnerabilities.trigger_verification`, the same path as the per-finding
button, so scope, policy, maintenance and sensor-capability checks are not
re-implemented here.

**Snapshot.** Creation resolves a selection (problem keys under filters and/or
explicit finding ids) to exact finding ids, freezes them, and stores a hash of
the set. A finding that matches the same filters later is *not* added; the
only ways in and out are :func:`add_members` and :func:`exclude_members`, each
with an author, a time and a reason, in the campaign's append-only history and
the audit trail. A (campaign, finding) pair is one row for life, so excluding
and re-including never counts a finding twice.

**Progress** is a set of mutually exclusive categories computed in SQL from the
live findings (one grouped query per page of campaigns, no per-member reads):

``open``                 OPEN / ACKNOWLEDGED
``fixing``               PLANNED / FIXING
``awaiting_verification`` VERIFYING — a check was dispatched, no verdict yet
``verified``             CLOSED with ``machine_verified`` — a verification run
                         re-checked it
``accepted_risk``        an approved, unexpired exception
``false_positive``       CLOSED as a false positive
``closed_unverified``    CLOSED without a machine verdict (manually, or because
                         a ticket was resolved)
``unavailable``          could not be verified: closed as unreachable, the last
                         campaign dispatch was refused/unsupported, or the last
                         verification came back inconclusive

They are never summed into "fixed". A ticket resolution, a manual close and the
campaign being finished do not make anything ``verified``.

**Completion and recurrence policy.** A campaign is ``completed`` only when it
has included members and every one is ``verified``, ``accepted_risk`` or
``false_positive`` — unverified closures keep it open on purpose. The state is
derived and recorded (:func:`_reconcile`) whenever the campaign is read or
written. If a member of a completed campaign comes back (the scanner re-opens
it) or unresolved members are added, the campaign returns to ``active``,
``reopen_count`` increments and a ``reopened`` event names the cause.
``cancelled`` is only set and lifted by a person and is never changed by data.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import and_, case, func, or_, select, update

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import pagination
from api.services import problem_identity
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.campaigns")

V = models.Vulnerability
M = models.RemediationCampaignMember
C = models.RemediationCampaign
E = models.RemediationCampaignEvent

MAX_MEMBERS = 2000
MAX_PROBLEM_KEYS = 100
MAX_NAME = 160
MAX_DESCRIPTION = 4000
MAX_OWNER = 200
MIN_REASON = 3
MAX_REASON = 1000
#: Verification dispatches per request. Each is a scan job; the remainder is
#: reported as ``deferred`` so the caller sends the rest, instead of one
#: request fanning out hundreds of jobs.
MAX_VERIFY_PER_REQUEST = 25
PREVIEW_ITEMS = 200
EVENT_ID_CAP = 200

STATUS_ACTIVE = "active"
STATUS_COMPLETED = "completed"
STATUS_CANCELLED = "cancelled"
STATUSES = (STATUS_ACTIVE, STATUS_COMPLETED, STATUS_CANCELLED)

INCLUDED = "included"
EXCLUDED = "excluded"

CATEGORIES = (
    "open",
    "fixing",
    "awaiting_verification",
    "verified",
    "accepted_risk",
    "false_positive",
    "closed_unverified",
    "unavailable",
)
RESOLVED = ("verified", "accepted_risk", "false_positive")

_INCONCLUSIVE_KINDS = ("verification_inconclusive", "verification_unreachable")


class CampaignConflict(RuntimeError):
    """The request is valid but contradicts the campaign's current state (409)."""


class CompositionChanged(CampaignConflict):
    """The previewed composition no longer matches what the selection resolves to."""


def _now() -> datetime:
    return vulns._now()


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------


def _text(value: Any, field: str, *, limit: int, required: bool = False) -> str | None:
    text = str(value).strip() if value is not None else ""
    if not text:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if len(text) > limit:
        raise ValueError(f"{field} is longer than {limit} characters")
    return text


def _reason(value: Any) -> str:
    text = _text(value, "reason", limit=MAX_REASON, required=True)
    assert text is not None
    if len(text) < MIN_REASON:
        raise ValueError(f"reason must be at least {MIN_REASON} characters")
    return text


def _due(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise ValueError("due_at must be an ISO 8601 timestamp")
    return vulns._naive(value)


class SelectionFilters(BaseModel):
    """The filters a selection may narrow problem keys with: the findings list's
    own, each with its closed vocabulary or numeric bounds. Strict types, so
    ``"false"`` is not a bool and ``"abc"`` is not a number; anything else is a
    422 instead of a 500 or a silently different selection."""

    model_config = ConfigDict(extra="forbid", strict=True)

    state: Literal["OPEN", "ACKNOWLEDGED", "PLANNED", "FIXING", "VERIFYING", "CLOSED"] | None = None
    states: list[Literal["OPEN", "ACKNOWLEDGED", "PLANNED", "FIXING", "VERIFYING", "CLOSED"]] | None = Field(
        default=None, max_length=6
    )
    severity: Literal["critical", "high", "medium", "low", "unknown"] | None = None
    asset_id: str | None = Field(default=None, min_length=1, max_length=256)
    source: Literal["scan", "endpoint_software", "retro_match"] | None = None
    finding_type: vulns.FindingType | None = None
    detector_source: vulns.DetectorSource | None = None
    network_exposure: vulns.NetworkExposure | None = None
    assignee: str | None = Field(default=None, min_length=1, max_length=256)
    unassigned: bool | None = None
    sla: Literal["on_track", "due_soon", "breached", "accepted", "none"] | None = None
    exception_state: Literal[
        "none", "exception_requested", "exception_approved", "exception_rejected", "exception_expired"
    ] | None = None
    stale_days: int | None = Field(default=None, ge=1, le=3650)
    in_kev: bool | None = None
    q: str | None = Field(default=None, max_length=200)


def normalise_selection(selection: Any) -> dict[str, Any]:
    """Validate the shape of a selection; never trusts what a preview returned."""
    if not isinstance(selection, dict):
        raise ValueError("selection must be an object")
    unknown = set(selection) - {"problem_keys", "vuln_ids", "filters"}
    if unknown:
        raise ValueError(f"unknown selection field(s): {', '.join(sorted(unknown))}")
    keys = [problem_identity.validate_key(k) for k in selection.get("problem_keys") or []]
    keys = sorted(set(keys))
    if len(keys) > MAX_PROBLEM_KEYS:
        raise ValueError(f"at most {MAX_PROBLEM_KEYS} problems per selection")
    ids = sorted({str(i).strip() for i in selection.get("vuln_ids") or [] if str(i).strip()})
    if any(len(i) > 64 for i in ids):
        raise ValueError("invalid finding id")
    if len(ids) > MAX_MEMBERS:
        raise ValueError(f"at most {MAX_MEMBERS} findings per selection")
    raw_filters = selection.get("filters") or {}
    if not isinstance(raw_filters, dict):
        raise ValueError("filters must be an object")
    try:
        filters = SelectionFilters.model_validate(raw_filters).model_dump(exclude_none=True)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
        )
        raise ValueError(f"invalid filters: {problems}") from exc
    if not keys and not ids:
        raise ValueError("select at least one problem or finding")
    return {"problem_keys": keys, "vuln_ids": ids, "filters": filters}


def _filter_args(filters: dict[str, Any]) -> dict[str, Any]:
    args = dict(filters)
    # A campaign is for work that is still open: unless the caller chose
    # states, closed findings are not eligible.
    if not args.get("state") and not args.get("states"):
        args["states"] = sorted(vuln_states.ACTIVE)
    return args


# --------------------------------------------------------------------------
# Selection -> exact finding ids
# --------------------------------------------------------------------------


def _resolve(session: Any, tenant_id: str, selection: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Resolve to ``({vuln_id: row}, skipped)`` inside the caller's tenant.

    Every id is looked up under ``tenant_id``: an id from another tenant is
    reported exactly as a missing one, so the answer cannot be used to probe
    for foreign findings.
    """
    resolved: dict[str, Any] = {}
    skipped: list[dict[str, Any]] = []
    key = problem_identity.problem_key_expr()

    if selection["problem_keys"]:
        predicates = vulns.finding_filters(
            **_filter_args(selection["filters"]), tenant_id=tenant_id
        )
        rows = session.execute(
            select(V).where(*predicates, key.in_(selection["problem_keys"]))
            .order_by(V.vuln_id)
            .limit(MAX_MEMBERS + 1)
        ).scalars().all()
        for row in rows:
            resolved[row.vuln_id] = row
    if selection["vuln_ids"]:
        rows = session.execute(
            select(V).where(V.tenant_id == tenant_id, V.vuln_id.in_(selection["vuln_ids"]))
        ).scalars().all()
        found = {row.vuln_id: row for row in rows}
        for vuln_id in selection["vuln_ids"]:
            row = found.get(vuln_id)
            if row is None:
                skipped.append({"id": vuln_id, "reason": "not_found"})
            elif row.state == vuln_states.CLOSED:
                skipped.append({"id": vuln_id, "reason": "closed"})
            else:
                resolved[vuln_id] = row
    if len(resolved) > MAX_MEMBERS:
        raise ValueError(
            f"the selection resolves to more than {MAX_MEMBERS} findings; narrow the filters"
        )
    return resolved, skipped


def composition_hash(vuln_ids: Any) -> str:
    return hashlib.sha256("\n".join(sorted(vuln_ids)).encode("utf-8")).hexdigest()


def _brief(row: Any) -> dict[str, Any]:
    return {
        "vuln_id": row.vuln_id,
        "asset_id": row.asset_id,
        "problem_key": problem_identity.problem_key_of(row),
        "cve": row.cve,
        "title": row.title,
        "severity": row.severity,
        "state": row.state,
    }


def preview(settings: Settings, *, tenant_id: str, selection: Any) -> dict[str, Any]:
    """Exact composition the same selection would freeze right now. Read-only."""
    selection = normalise_selection(selection)
    with get_session(settings.postgres_url) as session:
        resolved, skipped = _resolve(session, tenant_id, selection)
        ids = sorted(resolved)
        elsewhere = 0
        if ids:
            elsewhere = session.execute(
                select(func.count(func.distinct(M.vuln_id)))
                .select_from(M)
                .join(C, C.campaign_id == M.campaign_id)
                .where(
                    M.tenant_id == tenant_id,
                    M.vuln_id.in_(ids),
                    M.status == INCLUDED,
                    C.status != STATUS_CANCELLED,
                )
            ).scalar_one()
        by_problem: dict[str, dict[str, Any]] = {}
        for row in resolved.values():
            pk = problem_identity.problem_key_of(row)
            bucket = by_problem.setdefault(
                pk, {"problem_key": pk, "title": row.title, "instances": 0, "assets": set()}
            )
            bucket["instances"] += 1
            bucket["assets"].add(row.asset_id)
        return {
            "total": len(ids),
            "assets": len({row.asset_id for row in resolved.values()}),
            "problems": sorted(
                (
                    {**{k: v for k, v in b.items() if k != "assets"}, "assets": len(b["assets"])}
                    for b in by_problem.values()
                ),
                key=lambda b: (-b["instances"], b["problem_key"]),
            ),
            "composition_hash": composition_hash(ids),
            "already_in_other_campaigns": elsewhere,
            "skipped": skipped,
            "items": [_brief(resolved[i]) for i in ids[:PREVIEW_ITEMS]],
            "truncated": len(ids) > PREVIEW_ITEMS,
            "as_of": vulns._iso(_now()),
        }


# --------------------------------------------------------------------------
# Events and audit
# --------------------------------------------------------------------------


def _event(
    session: Any,
    campaign: Any,
    *,
    kind: str,
    actor: str | None,
    now: datetime,
    reason: str | None = None,
    detail: dict[str, Any] | None = None,
) -> None:
    session.add(
        E(
            tenant_id=campaign.tenant_id,
            campaign_id=campaign.campaign_id,
            occurred_at=now,
            kind=kind,
            actor=actor,
            reason=reason,
            detail=detail or {},
        )
    )


def _audit(
    session: Any,
    audit: Any,
    campaign: Any,
    *,
    action: str,
    after: dict[str, Any],
) -> None:
    audit_service.record(
        session,
        audit,
        action=action,
        resource_type="remediation_campaign",
        resource_id=campaign.campaign_id,
        tenant_id=campaign.tenant_id,
        after=after,
    )


def _capped(ids: list[str]) -> dict[str, Any]:
    return {"count": len(ids), "ids": ids[:EVENT_ID_CAP], "truncated": len(ids) > EVENT_ID_CAP}


# --------------------------------------------------------------------------
# Progress
# --------------------------------------------------------------------------


def _category_expr(now: datetime) -> Any:
    active = V.state.in_(sorted(vuln_states.ACTIVE))
    closed = V.state == vuln_states.CLOSED
    inconclusive = (
        select(models.VulnerabilityEvent.id)
        .where(
            models.VulnerabilityEvent.vuln_id == V.vuln_id,
            models.VulnerabilityEvent.kind.in_(_INCONCLUSIVE_KINDS),
            models.VulnerabilityEvent.occurred_at >= V.state_changed_at,
        )
        .exists()
    )
    refused = and_(
        M.last_verify_outcome.in_(("unsupported", "failed")),
        M.last_verify_at.is_not(None),
        M.last_verify_at >= V.state_changed_at,
    )
    return case(
        (and_(closed, V.closure_reason == vulns.FALSE_POSITIVE), "false_positive"),
        (and_(closed, V.machine_verified.is_(True)), "verified"),
        (and_(closed, V.closure_reason == vulns.ENDPOINT_UNREACHABLE), "unavailable"),
        (closed, "closed_unverified"),
        (and_(active, V.exception_until.is_not(None), V.exception_until > now), "accepted_risk"),
        (V.state == vuln_states.VERIFYING, "awaiting_verification"),
        (or_(refused, inconclusive), "unavailable"),
        (V.state.in_((vuln_states.PLANNED, vuln_states.FIXING)), "fixing"),
        else_="open",
    )


def _progress(session: Any, campaign_ids: list[str], now: datetime) -> dict[str, dict[str, Any]]:
    """Progress for several campaigns in three queries, whatever their size."""
    out = {
        cid: {
            "total": 0,
            "excluded": 0,
            "categories": {c: 0 for c in CATEGORIES},
            "recurred": 0,
            "vanished": 0,
            "assets": 0,
            "tickets": {"linked_findings": 0, "distinct_tickets": 0},
        }
        for cid in campaign_ids
    }
    if not campaign_ids:
        return out
    category = _category_expr(now)
    for cid, name, count in session.execute(
        select(M.campaign_id, category, func.count())
        .select_from(M)
        .join(V, and_(V.vuln_id == M.vuln_id, V.tenant_id == M.tenant_id))
        .where(M.campaign_id.in_(campaign_ids), M.status == INCLUDED)
        .group_by(M.campaign_id, category)
    ):
        out[cid]["categories"][name] = count
        out[cid]["total"] += count
    for cid, count in session.execute(
        select(M.campaign_id, func.count())
        .where(M.campaign_id.in_(campaign_ids), M.status == EXCLUDED)
        .group_by(M.campaign_id)
    ):
        out[cid]["excluded"] = count
    for cid, recurred, assets, linked in session.execute(
        select(
            M.campaign_id,
            func.coalesce(func.sum(case((V.reopen_count > M.reopen_baseline, 1), else_=0)), 0),
            func.count(func.distinct(V.asset_id)),
            func.coalesce(func.sum(case((V.ticket_key.is_not(None), 1), else_=0)), 0),
        )
        .select_from(M)
        .join(V, and_(V.vuln_id == M.vuln_id, V.tenant_id == M.tenant_id))
        .where(M.campaign_id.in_(campaign_ids), M.status == INCLUDED)
        .group_by(M.campaign_id)
    ):
        out[cid]["recurred"] = recurred
        out[cid]["assets"] = assets
        out[cid]["tickets"]["linked_findings"] = linked
    for cid, count in session.execute(
        select(M.campaign_id, func.count(func.distinct(V.ticket_system + ":" + V.ticket_key)))
        .select_from(M)
        .join(V, and_(V.vuln_id == M.vuln_id, V.tenant_id == M.tenant_id))
        .where(
            M.campaign_id.in_(campaign_ids),
            M.status == INCLUDED,
            V.ticket_key.is_not(None),
            V.ticket_system.is_not(None),
        )
        .group_by(M.campaign_id)
    ):
        out[cid]["tickets"]["distinct_tickets"] = count
    for cid, tracked in session.execute(
        select(C.campaign_id, C.tracked_members).where(C.campaign_id.in_(campaign_ids))
    ):
        # Membership rows that no longer exist because their finding was deleted.
        out[cid]["vanished"] = max(0, (tracked or 0) - out[cid]["total"] - out[cid]["excluded"])
    for value in out.values():
        cats = value["categories"]
        value["unresolved"] = value["total"] - sum(cats[c] for c in RESOLVED)
    return out


def _reconcile(
    session: Any,
    campaign: Any,
    progress: dict[str, Any],
    *,
    now: datetime,
    cause: str,
    actor: str | None = None,
) -> None:
    """Record completion or recurrence. Compare-and-set, so two concurrent
    readers write one event, not two.

    This runs on reads as well as writes (a GET may be the first thing to see
    that the last member was verified). That write is the platform's own, not
    the viewer's: it is attributed to the system in ``audit_events``
    (``campaign.status`` with ``derived: true``) and in the campaign history
    (``actor`` null), and it is idempotent. Computing the status on the fly and
    persisting it only in write paths was rejected: completion and recurrence
    would then go unrecorded for a campaign nobody writes to.
    """
    if campaign.status == STATUS_CANCELLED:
        return
    total, unresolved = progress["total"], progress["unresolved"]
    if (
        campaign.status == STATUS_ACTIVE
        and total > 0
        and unresolved == 0
        # Members whose finding was deleted are unaccounted for, not done.
        and not progress.get("vanished")
    ):
        claimed = session.execute(
            update(C)
            .where(C.campaign_id == campaign.campaign_id, C.status == STATUS_ACTIVE)
            .values(status=STATUS_COMPLETED, status_changed_at=now, completed_at=now, updated_at=now)
        ).rowcount
        if claimed:
            _event(
                session,
                campaign,
                kind="completed",
                actor=None,
                now=now,
                detail={"members": total, "cause": cause, "categories": progress["categories"]},
            )
            _audit(session, None, campaign, action=audit_service.ACTION_CAMPAIGN_STATUS,
                   after={"status": STATUS_COMPLETED, "derived": True, "cause": cause})
    elif campaign.status == STATUS_COMPLETED and unresolved > 0:
        claimed = session.execute(
            update(C)
            .where(C.campaign_id == campaign.campaign_id, C.status == STATUS_COMPLETED)
            .values(
                status=STATUS_ACTIVE,
                status_changed_at=now,
                completed_at=None,
                reopen_count=C.reopen_count + 1,
                updated_at=now,
            )
        ).rowcount
        if claimed:
            # No manual attribute writes: the ORM-enabled UPDATE above already
            # synchronised the loaded row, including ``reopen_count + 1``.
            _event(
                session,
                campaign,
                kind="reopened",
                actor=actor,
                now=now,
                detail={
                    "cause": cause,
                    "unresolved": unresolved,
                    "recurred": progress["recurred"],
                    "categories": progress["categories"],
                },
            )
            _audit(session, None, campaign, action=audit_service.ACTION_CAMPAIGN_STATUS,
                   after={"status": STATUS_ACTIVE, "derived": True, "cause": cause,
                          "unresolved": progress["unresolved"]})


def _campaign_dict(campaign: Any, progress: dict[str, Any], now: datetime) -> dict[str, Any]:
    due = campaign.due_at
    return {
        "campaign_id": campaign.campaign_id,
        "tenant_id": campaign.tenant_id,
        "name": campaign.name,
        "description": campaign.description or "",
        "owner": campaign.owner,
        "due_at": vulns._iso(due),
        "status": campaign.status,
        "status_changed_at": vulns._iso(campaign.status_changed_at),
        "completed_at": vulns._iso(campaign.completed_at),
        "reopen_count": campaign.reopen_count,
        # The campaign's own date. Informational: it never changes a
        # finding's SLA (``due_at`` of each finding), nor is derived from it.
        "past_due": bool(due and campaign.status == STATUS_ACTIVE and vulns._naive(due) <= now),
        "composition_hash": campaign.composition_hash,
        "snapshot_size": campaign.snapshot_size,
        "selection": campaign.selection or {},
        "created_by": campaign.created_by,
        "created_at": vulns._iso(campaign.created_at),
        "updated_at": vulns._iso(campaign.updated_at),
        "progress": progress,
    }


def _load(session: Any, tenant_id: str, campaign_id: str, *, lock: bool = False) -> Any:
    """The tenant's campaign. ``lock`` takes the row ``FOR UPDATE``: membership
    changes serialise per campaign, so two concurrent adds of one finding cannot
    both insert it (the second waits, then sees the first's row)."""
    query = select(C).where(C.campaign_id == campaign_id, C.tenant_id == tenant_id)
    if lock:
        query = query.with_for_update()
    row = session.execute(query).scalar_one_or_none()
    if row is None:
        raise LookupError("Campaign not found")
    return row


def _detail(session: Any, campaign: Any, *, cause: str, actor: str | None = None) -> dict[str, Any]:
    now = _now()
    progress = _progress(session, [campaign.campaign_id], now)[campaign.campaign_id]
    _reconcile(session, campaign, progress, now=now, cause=cause, actor=actor)
    return _campaign_dict(campaign, progress, now)


# --------------------------------------------------------------------------
# Create / read / update
# --------------------------------------------------------------------------


def create_campaign(
    settings: Settings,
    *,
    tenant_id: str,
    actor: str | None,
    audit: Any,
    name: Any,
    description: Any = None,
    owner: Any = None,
    due_at: Any = None,
    selection: Any,
    expected_hash: str | None = None,
) -> dict[str, Any]:
    """Freeze the selection's current composition into a new campaign.

    The selection is resolved again here, under the caller's tenant — nothing
    from an earlier preview is trusted. With ``expected_hash`` the request
    fails (:class:`CompositionChanged`) if the composition is no longer the one
    the operator reviewed.
    """
    name_text = _text(name, "name", limit=MAX_NAME, required=True)
    description_text = _text(description, "description", limit=MAX_DESCRIPTION) or ""
    owner_text = _text(owner, "owner", limit=MAX_OWNER)
    due = _due(due_at)
    selection = normalise_selection(selection)
    now = _now()
    with get_session(settings.postgres_url) as session:
        resolved, skipped = _resolve(session, tenant_id, selection)
        if not resolved:
            raise ValueError("the selection resolves to no eligible findings")
        digest = composition_hash(resolved)
        if expected_hash and expected_hash != digest:
            raise CompositionChanged(
                "the selection no longer resolves to the previewed composition; preview again"
            )
        campaign = C(
            campaign_id=f"cmp_{uuid.uuid4().hex[:16]}",
            tenant_id=tenant_id,
            name=name_text,
            description=description_text,
            owner=owner_text,
            due_at=due,
            status=STATUS_ACTIVE,
            status_changed_at=now,
            composition_hash=digest,
            snapshot_size=len(resolved),
            tracked_members=len(resolved),
            selection=selection,
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        session.add(campaign)
        session.flush()
        for vuln_id in sorted(resolved):
            session.add(_member(tenant_id, campaign.campaign_id, resolved[vuln_id], actor, now, None))
        _event(
            session,
            campaign,
            kind="created",
            actor=actor,
            now=now,
            detail={
                "members": len(resolved),
                "composition_hash": digest,
                "skipped": len(skipped),
                "problem_keys": selection["problem_keys"],
            },
        )
        _audit(
            session,
            audit,
            campaign,
            action=audit_service.ACTION_CAMPAIGN_CREATE,
            after={
                "name": name_text,
                "members": len(resolved),
                "composition_hash": digest,
                "due_at": vulns._iso(due),
            },
        )
        session.flush()
        return _detail(session, campaign, cause="created")


def _member(
    tenant_id: str, campaign_id: str, row: Any, actor: str | None, now: datetime, reason: str | None
) -> Any:
    return M(
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        vuln_id=row.vuln_id,
        status=INCLUDED,
        problem_key=problem_identity.problem_key_of(row),
        reopen_baseline=row.reopen_count or 0,
        snapshot={
            "finding_key": row.finding_key,
            "asset_id": row.asset_id,
            "state": row.state,
            "severity": row.severity,
            "cve": row.cve,
            "reopen_count": row.reopen_count or 0,
        },
        added_by=actor,
        added_at=now,
        add_reason=reason,
    )


def get_campaign(settings: Settings, *, tenant_id: str, campaign_id: str) -> dict[str, Any]:
    with get_session(settings.postgres_url) as session:
        return _detail(session, _load(session, tenant_id, campaign_id), cause="read")


def list_campaigns(
    settings: Settings,
    *,
    tenant_id: str,
    status: str | None = None,
    owner: str | None = None,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    q: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    if status and status not in STATUSES:
        raise ValueError(f"unknown status {status!r}; expected one of {', '.join(STATUSES)}")
    filters = [C.tenant_id == tenant_id]
    if status:
        filters.append(C.status == status)
    if owner:
        filters.append(C.owner == owner)
    if q and q.strip():
        filters.append(func.lower(C.name).like(f"%{q.strip().lower()}%"))
    now = _now()
    with get_session(settings.postgres_url) as session:
        total = session.execute(select(func.count()).select_from(C).where(*filters)).scalar_one()
        rows = session.execute(
            select(C).where(*filters).order_by(C.created_at.desc(), C.campaign_id).offset(offset).limit(limit)
        ).scalars().all()
        progress = _progress(session, [r.campaign_id for r in rows], now)
        items = []
        for row in rows:
            _reconcile(session, row, progress[row.campaign_id], now=now, cause="read")
            items.append(_campaign_dict(row, progress[row.campaign_id], now))
    return items, total


_UNSET = object()


def update_campaign(
    settings: Settings,
    *,
    tenant_id: str,
    campaign_id: str,
    actor: str | None,
    audit: Any,
    changes: dict[str, Any],
) -> dict[str, Any]:
    """Edit the campaign's own fields. Never touches a finding."""
    allowed = {"name", "description", "owner", "due_at"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError(f"cannot change: {', '.join(sorted(unknown))}")
    if not changes:
        raise ValueError("nothing to change")
    now = _now()
    with get_session(settings.postgres_url) as session:
        campaign = _load(session, tenant_id, campaign_id)
        if campaign.status == STATUS_CANCELLED:
            raise CampaignConflict("a cancelled campaign cannot be edited; resume it first")
        changed: dict[str, Any] = {}
        if "name" in changes:
            campaign.name = _text(changes["name"], "name", limit=MAX_NAME, required=True)
            changed["name"] = True
        if "description" in changes:
            campaign.description = _text(changes["description"], "description", limit=MAX_DESCRIPTION) or ""
            changed["description"] = True
        if "owner" in changes:
            campaign.owner = _text(changes["owner"], "owner", limit=MAX_OWNER)
            changed["owner"] = True
        if "due_at" in changes:
            before = vulns._iso(campaign.due_at)
            campaign.due_at = _due(changes["due_at"])
            changed["due_at"] = {"from": before, "to": vulns._iso(campaign.due_at)}
        campaign.updated_at = now
        _event(session, campaign, kind="updated", actor=actor, now=now, detail={"fields": changed})
        _audit(
            session,
            audit,
            campaign,
            action=audit_service.ACTION_CAMPAIGN_UPDATE,
            after={"fields": sorted(changed)},
        )
        session.flush()
        return _detail(session, campaign, cause="updated", actor=actor)


def set_status(
    settings: Settings,
    *,
    tenant_id: str,
    campaign_id: str,
    actor: str | None,
    audit: Any,
    action: str,
    reason: Any,
) -> dict[str, Any]:
    """``cancel`` (active|completed -> cancelled) or ``resume`` (cancelled -> active)."""
    if action not in {"cancel", "resume"}:
        raise ValueError("action must be cancel or resume")
    reason_text = _reason(reason)
    now = _now()
    with get_session(settings.postgres_url) as session:
        campaign = _load(session, tenant_id, campaign_id)
        if action == "cancel":
            if campaign.status == STATUS_CANCELLED:
                raise CampaignConflict("the campaign is already cancelled")
            campaign.status, campaign.completed_at = STATUS_CANCELLED, None
            kind = "cancelled"
        else:
            if campaign.status != STATUS_CANCELLED:
                raise CampaignConflict("only a cancelled campaign can be resumed")
            campaign.status = STATUS_ACTIVE
            kind = "resumed"
        campaign.status_changed_at = campaign.updated_at = now
        _event(session, campaign, kind=kind, actor=actor, now=now, reason=reason_text)
        _audit(
            session,
            audit,
            campaign,
            action=audit_service.ACTION_CAMPAIGN_STATUS,
            after={"status": campaign.status, "reason": reason_text},
        )
        session.flush()
        return _detail(session, campaign, cause=kind, actor=actor)


# --------------------------------------------------------------------------
# Membership
# --------------------------------------------------------------------------


def add_members(
    settings: Settings,
    *,
    tenant_id: str,
    campaign_id: str,
    actor: str | None,
    audit: Any,
    selection: Any,
    reason: Any,
) -> dict[str, Any]:
    """Explicitly add findings (or re-include excluded ones). Per-id report.

    A finding already included is reported ``already_member`` and changes
    nothing, which is what keeps progress from counting it twice.
    """
    reason_text = _reason(reason)
    selection = normalise_selection(selection)
    now = _now()
    with get_session(settings.postgres_url) as session:
        campaign = _load(session, tenant_id, campaign_id, lock=True)
        if campaign.status == STATUS_CANCELLED:
            raise CampaignConflict("a cancelled campaign takes no new members; resume it first")
        resolved, skipped = _resolve(session, tenant_id, selection)
        existing = {
            m.vuln_id: m
            for m in session.execute(
                select(M).where(M.campaign_id == campaign_id, M.vuln_id.in_(list(resolved) or [""]))
            ).scalars()
        }
        included_now = session.execute(
            select(func.count()).select_from(M).where(M.campaign_id == campaign_id, M.status == INCLUDED)
        ).scalar_one()
        results: list[dict[str, Any]] = [
            {"id": s["id"], "outcome": "not_found" if s["reason"] == "not_found" else "ineligible",
             "detail": s["reason"]}
            for s in skipped
        ]
        added: list[str] = []
        readded: list[str] = []
        for vuln_id in sorted(resolved):
            member = existing.get(vuln_id)
            if member is not None and member.status == INCLUDED:
                results.append({"id": vuln_id, "outcome": "already_member"})
                continue
            if included_now + len(added) + len(readded) >= MAX_MEMBERS:
                results.append({"id": vuln_id, "outcome": "limit", "detail": f"campaign holds at most {MAX_MEMBERS}"})
                continue
            row = resolved[vuln_id]
            if member is None:
                session.add(_member(tenant_id, campaign_id, row, actor, now, reason_text))
                added.append(vuln_id)
                results.append({"id": vuln_id, "outcome": "added"})
            else:
                member.status = INCLUDED
                member.added_by, member.added_at, member.add_reason = actor, now, reason_text
                member.excluded_by = member.excluded_at = member.exclude_reason = None
                member.reopen_baseline = row.reopen_count or 0
                readded.append(vuln_id)
                results.append({"id": vuln_id, "outcome": "readded"})
        if added or readded:
            campaign.tracked_members = (campaign.tracked_members or 0) + len(added)
            campaign.updated_at = now
            _event(
                session,
                campaign,
                kind="members_added",
                actor=actor,
                now=now,
                reason=reason_text,
                detail={"added": _capped(added), "readded": _capped(readded)},
            )
            _audit(
                session,
                audit,
                campaign,
                action=audit_service.ACTION_CAMPAIGN_MEMBERS,
                after={"op": "add", "added": len(added), "readded": len(readded), "reason": reason_text},
            )
        session.flush()
        detail = _detail(session, campaign, cause="members_added", actor=actor)
    return {"results": results, "added": len(added), "readded": len(readded), "campaign": detail}


def exclude_members(
    settings: Settings,
    *,
    tenant_id: str,
    campaign_id: str,
    actor: str | None,
    audit: Any,
    vuln_ids: list[str],
    reason: Any,
) -> dict[str, Any]:
    """Take findings out of the campaign (kept as ``excluded``, with a reason)."""
    reason_text = _reason(reason)
    ids = sorted({str(i).strip() for i in vuln_ids if str(i).strip()})
    if not ids:
        raise ValueError("vuln_ids is empty")
    if len(ids) > MAX_MEMBERS:
        raise ValueError(f"at most {MAX_MEMBERS} findings per request")
    now = _now()
    with get_session(settings.postgres_url) as session:
        campaign = _load(session, tenant_id, campaign_id, lock=True)
        if campaign.status == STATUS_CANCELLED:
            raise CampaignConflict("a cancelled campaign cannot change members; resume it first")
        members = {
            m.vuln_id: m
            for m in session.execute(
                select(M).where(M.campaign_id == campaign_id, M.tenant_id == tenant_id, M.vuln_id.in_(ids))
            ).scalars()
        }
        results: list[dict[str, Any]] = []
        excluded: list[str] = []
        for vuln_id in ids:
            member = members.get(vuln_id)
            if member is None:
                results.append({"id": vuln_id, "outcome": "not_member"})
            elif member.status == EXCLUDED:
                results.append({"id": vuln_id, "outcome": "already_excluded"})
            else:
                member.status = EXCLUDED
                member.excluded_by, member.excluded_at, member.exclude_reason = actor, now, reason_text
                excluded.append(vuln_id)
                results.append({"id": vuln_id, "outcome": "excluded"})
        if excluded:
            campaign.updated_at = now
            _event(
                session,
                campaign,
                kind="members_excluded",
                actor=actor,
                now=now,
                reason=reason_text,
                detail={"excluded": _capped(excluded)},
            )
            _audit(
                session,
                audit,
                campaign,
                action=audit_service.ACTION_CAMPAIGN_MEMBERS,
                after={"op": "exclude", "excluded": len(excluded), "reason": reason_text},
            )
        session.flush()
        detail = _detail(session, campaign, cause="members_excluded", actor=actor)
    return {"results": results, "excluded": len(excluded), "campaign": detail}


MEMBER_SORTS = {"severity", "state", "added_at", "asset_id"}


def list_members(
    settings: Settings,
    *,
    tenant_id: str,
    campaign_id: str,
    member_status: str = INCLUDED,
    category: str | None = None,
    problem_key: str | None = None,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
    sort: str | None = None,
    order: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    if member_status not in (INCLUDED, EXCLUDED):
        raise ValueError("status must be included or excluded")
    if category and category not in CATEGORIES:
        raise ValueError(f"unknown category {category!r}; expected one of {', '.join(CATEGORIES)}")
    now = _now()
    cat = _category_expr(now).label("category")
    with get_session(settings.postgres_url) as session:
        _load(session, tenant_id, campaign_id)
        base = (
            select(M, V, cat)
            .join(V, and_(V.vuln_id == M.vuln_id, V.tenant_id == M.tenant_id))
            .where(M.campaign_id == campaign_id, M.tenant_id == tenant_id, M.status == member_status)
        )
        if problem_key:
            base = base.where(M.problem_key == problem_identity.validate_key(problem_key))
        if category:
            base = base.where(_category_expr(now) == category)
        total = session.execute(select(func.count()).select_from(base.subquery())).scalar_one()
        sort_col = {
            "severity": case(
                (V.severity == "critical", 4), (V.severity == "high", 3),
                (V.severity == "medium", 2), (V.severity == "low", 1), else_=0,
            ),
            "state": V.state,
            "added_at": M.added_at,
            "asset_id": V.asset_id,
        }.get(sort or "", None)
        if sort_col is None:
            sort_col = case(
                (V.severity == "critical", 4), (V.severity == "high", 3),
                (V.severity == "medium", 2), (V.severity == "low", 1), else_=0,
            )
        ordering = sort_col.asc() if (order or "").lower() == "asc" else sort_col.desc()
        rows = session.execute(base.order_by(ordering, M.id).offset(offset).limit(limit)).all()
        latest = _latest_verification(session, [r[1].vuln_id for r in rows])
        items = [_member_dict(m, v, c, latest.get(v.vuln_id), now) for m, v, c in rows]
    return items, total


def _latest_verification(session: Any, vuln_ids: list[str]) -> dict[str, Any]:
    """Newest verification event per finding, in one query for the page."""
    if not vuln_ids:
        return {}
    ev = models.VulnerabilityEvent
    out: dict[str, Any] = {}
    for event in session.execute(
        select(ev)
        .where(ev.vuln_id.in_(vuln_ids), ev.kind.like("verification_%"))
        .order_by(ev.occurred_at, ev.id)
    ).scalars():
        out[event.vuln_id] = event
    return out


def _member_dict(m: Any, v: Any, category: str, event: Any, now: datetime) -> dict[str, Any]:
    detail = (event.detail or {}) if event is not None else {}
    return {
        "vuln_id": v.vuln_id,
        "status": m.status,
        "category": category,
        "problem_key": m.problem_key,
        "asset_id": v.asset_id,
        "cve": v.cve,
        "title": v.title,
        "severity": v.severity,
        "state": v.state,
        "assignee": v.assignee,
        "due_at": vulns._iso(v.due_at),
        "sla_state": vulns.sla_state(v, now=now),
        "machine_verified": bool(v.machine_verified),
        "closure_reason": v.closure_reason,
        "reopen_count": v.reopen_count,
        "recurred": (v.reopen_count or 0) > (m.reopen_baseline or 0),
        "ticket_system": v.ticket_system,
        "ticket_key": v.ticket_key,
        "ticket_url": v.ticket_url,
        "added_by": m.added_by,
        "added_at": vulns._iso(m.added_at),
        "add_reason": m.add_reason,
        "excluded_by": m.excluded_by,
        "excluded_at": vulns._iso(m.excluded_at),
        "exclude_reason": m.exclude_reason,
        "last_verify": {
            "requested_at": vulns._iso(m.last_verify_at),
            "outcome": m.last_verify_outcome,
            "detail": m.last_verify_detail,
        },
        # The newest verification event the finding itself recorded: its
        # verdict (passed / failed / inconclusive / unreachable) and, for
        # partial coverage, what was not covered.
        "verification": (
            {
                "kind": event.kind,
                "at": vulns._iso(event.occurred_at),
                "note": event.note,
                "gaps": detail.get("gaps"),
            }
            if event is not None
            else None
        ),
    }


def list_events(
    settings: Settings,
    *,
    tenant_id: str,
    campaign_id: str,
    offset: int = 0,
    limit: int = pagination.DEFAULT_LIMIT,
) -> tuple[list[dict[str, Any]], int]:
    with get_session(settings.postgres_url) as session:
        _load(session, tenant_id, campaign_id)
        total = session.execute(
            select(func.count()).select_from(E).where(E.campaign_id == campaign_id)
        ).scalar_one()
        rows = session.execute(
            select(E).where(E.campaign_id == campaign_id)
            .order_by(E.occurred_at.desc(), E.id.desc()).offset(offset).limit(limit)
        ).scalars().all()
        return [
            {
                "id": r.id,
                "occurred_at": vulns._iso(r.occurred_at),
                "kind": r.kind,
                "actor": r.actor,
                "reason": r.reason,
                "detail": r.detail or {},
            }
            for r in rows
        ], total


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------


def verify_members(
    settings: Settings,
    *,
    tenant_id: str,
    campaign_id: str,
    actor: str | None,
    audit: Any,
    vuln_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Ask the existing verify workflow to re-check members, one by one.

    Each finding goes through :func:`vulnerabilities.trigger_verification`, so
    the lifecycle rule (only ``FIXING`` may move to ``VERIFYING``), the
    approved scan scope, scan policy, maintenance windows, admission limits and
    sensor capability are exactly the per-finding button's. A refusal for one
    finding is that finding's result; it never stops the others, and every
    dispatched job stays dispatched.

    Outcomes: ``dispatched`` | ``conflict`` (not in FIXING) | ``unsupported``
    (the source cannot be re-scanned) | ``failed`` (dispatch refused: scope,
    sensors, disabled) | ``not_member`` | ``deferred`` (over the per-request
    cap). A dispatch is not a verdict: the member becomes ``verified`` only
    when the run closes the finding as machine-verified.
    """
    with get_session(settings.postgres_url) as session:
        campaign = _load(session, tenant_id, campaign_id)
        if campaign.status == STATUS_CANCELLED:
            raise CampaignConflict("a cancelled campaign cannot request verification")
        included = {
            vuln_id: (source, state)
            for vuln_id, source, state in session.execute(
                select(M.vuln_id, V.source, V.state)
                .select_from(M)
                .join(V, and_(V.vuln_id == M.vuln_id, V.tenant_id == M.tenant_id))
                .where(M.campaign_id == campaign_id, M.tenant_id == tenant_id, M.status == INCLUDED)
            )
        }
    explicit = vuln_ids is not None
    if explicit:
        targets = sorted({str(i).strip() for i in vuln_ids if str(i).strip()})
        if not targets:
            raise ValueError("vuln_ids is empty")
        if len(targets) > MAX_MEMBERS:
            raise ValueError(f"at most {MAX_MEMBERS} findings per request")
    else:
        # Default: everything that is legally ready (the only state that may
        # move to VERIFYING is FIXING).
        targets = sorted(i for i, (_, state) in included.items() if state == vuln_states.FIXING)

    results: list[dict[str, Any]] = []
    attempted = 0
    try:
        for vuln_id in targets:
            if vuln_id not in included:
                results.append({"id": vuln_id, "outcome": "not_member"})
                continue
            source, _state = included[vuln_id]
            if attempted >= MAX_VERIFY_PER_REQUEST:
                results.append({"id": vuln_id, "outcome": "deferred",
                                "detail": f"at most {MAX_VERIFY_PER_REQUEST} verifications per request"})
                continue
            outcome, detail, job_id = _verify_one(settings, tenant_id, vuln_id, source, actor)
            if outcome != "unsupported":
                attempted += 1
            _remember_verify(settings, campaign_id, vuln_id, outcome, detail)
            result = {"id": vuln_id, "outcome": outcome}
            if detail:
                result["detail"] = detail
            if job_id:
                result["job_id"] = job_id
            results.append(result)
    finally:
        # Recorded whatever happened above: jobs already dispatched must be on
        # the campaign's history even if a later finding raised unexpectedly.
        _record_verify(settings, tenant_id, campaign_id, actor, audit, results, explicit)
    summary: dict[str, int] = {}
    for item in results:
        summary[item["outcome"]] = summary.get(item["outcome"], 0) + 1
    detail_now = get_campaign(settings, tenant_id=tenant_id, campaign_id=campaign_id)
    return {"results": results, "summary": summary, "campaign": detail_now}


def _verify_one(
    settings: Settings, tenant_id: str, vuln_id: str, source: str, actor: str | None
) -> tuple[str, str | None, str | None]:
    if source != "scan":
        return (
            "unsupported",
            f"a {source} finding is not verified by a network re-scan; "
            "it is closed by its own source (next inventory snapshot / a scan that observes it)",
            None,
        )
    try:
        result = vulns.trigger_verification(
            settings, tenant_id=tenant_id, vuln_id=vuln_id, actor=actor
        )
    except vuln_states.InvalidVulnTransition as exc:
        return "conflict", str(exc), None
    except vulns.VerificationDispatchError as exc:
        return "failed", str(exc)[:500], None
    except Exception as exc:  # noqa: BLE001 - one finding must not abort the batch
        LOG.warning("Campaign verification of %s failed", vuln_id, exc_info=True)
        return "failed", f"{type(exc).__name__}: {exc}"[:500], None
    if result is None:
        return "failed", "finding no longer exists", None
    return "dispatched", None, result.get("verification_job_id")


def _remember_verify(settings: Settings, campaign_id: str, vuln_id: str, outcome: str, detail: str | None) -> None:
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(M)
            .where(M.campaign_id == campaign_id, M.vuln_id == vuln_id)
            .values(last_verify_at=_now(), last_verify_outcome=outcome, last_verify_detail=detail)
        )


def _record_verify(
    settings: Settings,
    tenant_id: str,
    campaign_id: str,
    actor: str | None,
    audit: Any,
    results: list[dict[str, Any]],
    explicit: bool,
) -> None:
    if not results:
        return
    summary: dict[str, int] = {}
    for item in results:
        summary[item["outcome"]] = summary.get(item["outcome"], 0) + 1
    now = _now()
    with get_session(settings.postgres_url) as session:
        campaign = _load(session, tenant_id, campaign_id)
        dispatched = [r["id"] for r in results if r["outcome"] == "dispatched"]
        _event(
            session,
            campaign,
            kind="verification_requested",
            actor=actor,
            now=now,
            detail={"summary": summary, "dispatched": _capped(dispatched), "explicit": explicit},
        )
        _audit(
            session,
            audit,
            campaign,
            action=audit_service.ACTION_CAMPAIGN_VERIFY,
            after={"summary": summary},
        )
