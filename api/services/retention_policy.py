"""Per-tenant retention windows, and the plan every reaper sweeps by (#332).

Until this module every reaper read one number from ``Settings`` —
``run_retention_days``, ``audit_event_retention_days`` and seven more — and
applied it to every tenant on the installation. Two customers with two DPAs
could not both be honoured, and a tenant in litigation lost its data on the
same schedule as everybody else.

Three layers, each owned by somebody different:

* **The platform default** is the existing ``OCTO_*_RETENTION_DAYS`` setting.
  Unchanged, and still what every tenant without a policy gets.
* **The bounds** are platform configuration: :data:`CATEGORIES` carries a
  compiled ``[min, max]`` per category and ``OCTO_RETENTION_BOUNDS`` overrides
  it. They constrain what a tenant may *choose*, never what it inherits. The
  audit floor is the point of them: a tenant admin can lengthen the trail, not
  shorten it below what the platform's own compliance needs.
* **The tenant's override** is a row in ``tenant_retention_policies``, written
  by whoever holds ``tenant.retention.manage`` in that tenant — its own admin —
  and audited with the document before and after.

On top of all three sits the legal hold (:mod:`api.services.legal_hold`): a
held tenant's window is "keep", whatever its policy says.

**How the reapers use it.** A sweep calls :func:`load_plan` once and gets a
:class:`RetentionPlan`: the default, the overrides, and the held tenants. The
SQL-table reapers turn it into one ``WHERE`` with :func:`expired_clause`; the
artifact reapers, whose rows are files, ask :func:`run_owner` whose run each is.
A plan that cannot be loaded raises, and the sweep deletes nothing that tick —
a reaper that cannot see the hold table must not guess that it is empty.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from api.db import models
from api.db.engine import get_session
from api.services import artifact_store
from api.services import audit as audit_service
from api.services import legal_hold
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.retention-policy")

#: Ten years. A bound above this is a typo for "forever", and forever is not a
#: retention window — it is the absence of one, which the platform default
#: (``0``) already expresses for the installation as a whole.
MAX_BOUND_DAYS = 3650


@dataclass(frozen=True)
class Category:
    """One kind of data with a window of its own.

    ``setting`` is the ``Settings`` attribute holding the platform default and
    ``column`` the ``tenant_retention_policies`` column holding the tenant's
    override. ``min_days``/``max_days`` are the compiled bounds, which
    ``OCTO_RETENTION_BOUNDS`` may replace.
    """

    key: str
    column: str
    setting: str
    min_days: int
    max_days: int
    description: str


#: Every retention category, in the order the console lists them. The bounds
#: are argued in docs/data-retention.md; the two floors above one day are the
#: two categories that are *records* rather than working data — the audit trail
#: (a year: PCI DSS 10.5.1 and most ISMS policies ask for twelve months) and the
#: endpoint change history — plus the workflow markers, whose window is also how
#: often an unresolved breach is announced again.
CATEGORIES: tuple[Category, ...] = (
    Category(
        "runs",
        "run_days",
        "run_retention_days",
        1,
        365,
        "Scan run artifacts, and the inputs of scans that never finished",
    ),
    Category(
        "screenshots",
        "screenshot_days",
        "screenshot_retention_days",
        1,
        90,
        "Screenshot images captured during scans",
    ),
    Category(
        "reports",
        "report_days",
        "report_retention_days",
        1,
        MAX_BOUND_DAYS,
        "Generated reports and their files",
    ),
    Category(
        "endpoint_snapshots",
        "endpoint_snapshot_days",
        "endpoint_snapshot_retention_days",
        1,
        730,
        "Software lists of superseded endpoint inventory snapshots",
    ),
    Category(
        "endpoint_changes",
        "endpoint_change_days",
        "endpoint_change_retention_days",
        30,
        MAX_BOUND_DAYS,
        "Endpoint software change history",
    ),
    Category(
        "risk_snapshots",
        "risk_snapshot_days",
        "risk_snapshot_retention_days",
        1,
        MAX_BOUND_DAYS,
        "Risk posture history behind the trend charts",
    ),
    Category(
        "webhook_deliveries",
        "webhook_delivery_days",
        "webhook_delivery_retention_days",
        1,
        365,
        "Delivered and dead webhook deliveries, payloads included",
    ),
    Category(
        "workflow_markers",
        "workflow_marker_days",
        "workflow_marker_retention_days",
        30,
        MAX_BOUND_DAYS,
        "Workflow event markers; expiring one re-announces its event",
    ),
    Category(
        "audit_events",
        "audit_event_days",
        "audit_event_retention_days",
        365,
        MAX_BOUND_DAYS,
        "Administrative audit trail",
    ),
)

CATEGORY_BY_KEY: dict[str, Category] = {category.key: category for category in CATEGORIES}

RUNS = "runs"
SCREENSHOTS = "screenshots"
REPORTS = "reports"
ENDPOINT_SNAPSHOTS = "endpoint_snapshots"
ENDPOINT_CHANGES = "endpoint_changes"
RISK_SNAPSHOTS = "risk_snapshots"
WEBHOOK_DELIVERIES = "webhook_deliveries"
WORKFLOW_MARKERS = "workflow_markers"
AUDIT_EVENTS = "audit_events"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() + "Z" if value else None


def _category(key: str) -> Category:
    try:
        return CATEGORY_BY_KEY[key]
    except KeyError:
        raise ValueError(
            f"unknown retention category {key!r}: one of {sorted(CATEGORY_BY_KEY)}"
        ) from None


def default_days(settings: Settings, category: str) -> int:
    """The platform window for ``category``; 0 keeps the data until deleted by hand."""
    return max(0, int(getattr(settings, _category(category).setting) or 0))


def bounds(settings: Settings) -> dict[str, tuple[int, int]]:
    """``{category: (min_days, max_days)}`` after ``OCTO_RETENTION_BOUNDS``.

    Raises ValueError for a category that does not exist or for bounds that
    cannot hold a value. Called once at startup (:func:`validate_configuration`)
    so a bad value stops the API there instead of at the first PUT.
    """
    configured = settings.retention_bounds or {}
    unknown = sorted(set(configured) - set(CATEGORY_BY_KEY))
    if unknown:
        raise ValueError(
            f"OCTO_RETENTION_BOUNDS names unknown categories {unknown}; "
            f"known: {sorted(CATEGORY_BY_KEY)}"
        )
    result: dict[str, tuple[int, int]] = {}
    for category in CATEGORIES:
        entry = configured.get(category.key) or {}
        low = int(entry.get("min", category.min_days))
        high = int(entry.get("max", category.max_days))
        # A floor of zero would let a tenant ask for "delete on sight", which
        # is not a window: the next sweep would take everything it has.
        if low < 1:
            raise ValueError(f"OCTO_RETENTION_BOUNDS[{category.key!r}].min must be at least 1")
        if high < low:
            raise ValueError(
                f"OCTO_RETENTION_BOUNDS[{category.key!r}]: max {high} is below min {low}"
            )
        if high > MAX_BOUND_DAYS:
            raise ValueError(
                f"OCTO_RETENTION_BOUNDS[{category.key!r}].max must be at most {MAX_BOUND_DAYS}"
            )
        result[category.key] = (low, high)
    return result


def validate_configuration(settings: Settings) -> None:
    """Refuse to start on bounds that cannot be applied."""
    bounds(settings)


# -- the plan the reapers sweep by -------------------------------------------


@dataclass(frozen=True)
class RetentionPlan:
    """What one sweep of one category does, for every tenant at once.

    ``overrides`` never names a held tenant: the hold wins, and keeping the two
    sets disjoint is what lets the default pass exclude both with one clause.
    """

    category: str
    default_days: int
    overrides: Mapping[str, int] = field(default_factory=dict)
    held: frozenset[str] = frozenset()

    def days_for(self, tenant_id: str | None) -> int:
        """The window for ``tenant_id``; 0 means nothing of it is deleted."""
        if tenant_id is not None and tenant_id in self.held:
            return 0
        if tenant_id is not None and tenant_id in self.overrides:
            return self.overrides[tenant_id]
        return self.default_days

    @property
    def active(self) -> bool:
        """Whether this sweep can delete anything at all."""
        return self.default_days > 0 or any(days > 0 for days in self.overrides.values())

    @property
    def tenant_specific(self) -> bool:
        """Whether a row's owner changes its window.

        False on an installation with no policies and no holds — every one on
        the day this shipped — where the artifact reapers can skip reading
        each run's owner entirely.
        """
        return bool(self.overrides or self.held)

    @property
    def excluded(self) -> frozenset[str]:
        """Tenants the default pass must not touch."""
        return frozenset(self.overrides) | self.held


def load_plan(
    settings: Settings, category: str, *, session: Session | None = None
) -> RetentionPlan:
    """The plan for ``category``, read from the policy and hold tables.

    No database configured (a tool, a file-only test) means there is nowhere a
    policy or a hold could have been written, so the plan is the platform
    default alone. A database that is configured and fails **raises**: the
    caller's sweep then deletes nothing, which is the only safe reading of
    "could not tell whether this tenant is on hold".
    """
    spec = _category(category)
    base = default_days(settings, category)
    if not settings.postgres_url:
        return RetentionPlan(category=category, default_days=base)
    if session is None:
        with get_session(settings.postgres_url) as own:
            return load_plan(settings, category, session=own)
    held = legal_hold.held_tenants(session)
    column = getattr(models.TenantRetentionPolicy, spec.column)
    overrides = {
        tenant_id: int(days)
        for tenant_id, days in session.execute(
            select(models.TenantRetentionPolicy.tenant_id, column).where(column.is_not(None))
        ).all()
        if tenant_id not in held
    }
    return RetentionPlan(
        category=category, default_days=base, overrides=overrides, held=held
    )


def expired_clause(plan: RetentionPlan, *, tenant_column, time_column, now: datetime):
    """One SQL condition: rows past their tenant's window. ``None`` when none can be.

    ``now`` must be in the flavour ``time_column`` stores (naive or aware
    UTC); each reaper already knows which, and the cutoffs are computed from
    it unchanged. The default pass excludes every tenant with an override or a
    hold — ``NOT IN`` alone would also drop rows whose tenant is NULL, hence
    the explicit ``IS NULL``.
    """
    clauses = []
    if plan.default_days > 0:
        default_cut = time_column < now - timedelta(days=plan.default_days)
        if plan.excluded:
            default_cut = and_(
                default_cut,
                or_(tenant_column.is_(None), tenant_column.not_in(sorted(plan.excluded))),
            )
        clauses.append(default_cut)
    for tenant_id, days in sorted(plan.overrides.items()):
        if days > 0:
            clauses.append(
                and_(tenant_column == tenant_id, time_column < now - timedelta(days=days))
            )
    if not clauses:
        return None
    return or_(*clauses) if len(clauses) > 1 else clauses[0]


def effective_days(
    settings: Settings, tenant_id: str, category: str, *, session: Session | None = None
) -> int:
    """The window that applies to one tenant right now; 0 when nothing is deleted."""
    return load_plan(settings, category, session=session).days_for(tenant_id)


def run_owner(
    store: artifact_store.ArtifactStore,
    ref: artifact_store.keys.RunRef,
    segments: Mapping[str, str],
) -> str | None:
    """The tenant whose window applies to the run at ``ref``; None when unknown.

    ``segments`` maps a tenant's path segment back to its id, for the tenants
    the plan singles out; any other segment is a tenant on the default window,
    and the segment is as good a key as its id for that.

    A flat run's owner is its ``tenant.json``, and a run with none is the
    default tenant's — the rule ``runs.read_run_tenant`` applies to readers.
    But an *unreadable* marker is not a missing one: ``workspace.read_run_marker``
    treats the two alike, which is right for a listing and wrong here, where
    guessing "default" could delete a held tenant's run. None tells the reaper
    to leave the run for the next tick.
    """
    from api.services.tenants import DEFAULT_TENANT_ID

    if ref.tenant is not None:
        return segments.get(ref.tenant, ref.tenant)
    marker = artifact_store.keys.run_artifact(ref, "tenant.json")
    try:
        payload = json.loads(store.get_bytes(marker).decode("utf-8"))
    except artifact_store.ArtifactNotFound:
        return DEFAULT_TENANT_ID
    except (artifact_store.ArtifactStoreError, UnicodeDecodeError, ValueError):
        return None
    owner = str(payload.get("tenant_id") or "").strip() if isinstance(payload, dict) else ""
    return owner or DEFAULT_TENANT_ID


def segment_map(plan: RetentionPlan) -> dict[str, str]:
    """``{path segment: tenant id}`` for the tenants whose window is not the default."""
    return {
        artifact_store.keys.tenant_segment(tenant_id): tenant_id
        for tenant_id in plan.excluded
    }


# -- the policy API -----------------------------------------------------------


def _overrides_of(row: models.TenantRetentionPolicy | None) -> dict[str, int | None]:
    return {
        category.key: (getattr(row, category.column) if row is not None else None)
        for category in CATEGORIES
    }


def _document(row: models.TenantRetentionPolicy | None) -> dict[str, Any] | None:
    """What the audit trail records of a stored policy."""
    if row is None:
        return None
    return {"overrides": _overrides_of(row), "note": row.note or ""}


def describe(settings: Settings, tenant_id: str) -> dict[str, Any]:
    """One tenant's windows: default, override, effective, bounds — and its hold.

    Every category is listed whether or not the tenant overrides it, because
    the question a DPO asks is "how long is *each* kind of data kept", and a
    category missing from the answer reads as "not kept at all".
    """
    limits = bounds(settings)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantRetentionPolicy, tenant_id)
        hold = session.get(models.TenantLegalHold, tenant_id)
        overrides = _overrides_of(row)
        categories = []
        for category in CATEGORIES:
            platform = default_days(settings, category.key)
            override = overrides[category.key]
            low, high = limits[category.key]
            categories.append(
                {
                    "category": category.key,
                    "description": category.description,
                    "default_days": platform,
                    "override_days": override,
                    "effective_days": override if override is not None else platform,
                    "min_days": low,
                    "max_days": high,
                    "source": "tenant" if override is not None else "default",
                }
            )
        return {
            "tenant_id": tenant_id,
            "categories": categories,
            "note": (row.note or "") if row is not None else "",
            "updated_at": _iso(row.updated_at) if row is not None else None,
            "updated_by": (row.updated_by or "") if row is not None else "",
            "legal_hold": (
                {
                    "tenant_id": hold.tenant_id,
                    "reason": hold.reason,
                    "set_by": hold.set_by,
                    "set_at": _iso(hold.set_at),
                }
                if hold is not None
                else None
            ),
        }


def _validated(settings: Settings, overrides: Mapping[str, Any]) -> dict[str, int | None]:
    """Every category's stored value, or ValueError naming the first bad one."""
    unknown = sorted(set(overrides) - set(CATEGORY_BY_KEY))
    if unknown:
        raise ValueError(
            f"unknown retention categories {unknown}; known: {sorted(CATEGORY_BY_KEY)}"
        )
    limits = bounds(settings)
    values: dict[str, int | None] = {}
    for category in CATEGORIES:
        given = overrides.get(category.key)
        if given is None:
            values[category.key] = None
            continue
        if isinstance(given, bool) or not isinstance(given, int):
            raise ValueError(f"{category.key}: days must be a whole number")
        low, high = limits[category.key]
        if not low <= given <= high:
            raise ValueError(
                f"{category.key}: {given} days is outside the platform bounds "
                f"[{low}, {high}]"
            )
        values[category.key] = given
    return values


def replace_policy(
    settings: Settings,
    tenant_id: str,
    *,
    overrides: Mapping[str, Any],
    note: str = "",
    updated_by: str,
    audit: audit_service.AuditContext | None = None,
) -> dict[str, Any]:
    """Store the tenant's overrides, replacing whatever it had.

    Whole-document, like the scan policy: a category the request leaves out
    goes back to the platform default, so what is stored is always exactly
    what the caller last sent — a partial update applied over a policy the
    caller had not seen is how a tenant ends up keeping something nobody chose.

    Raises LookupError for an unknown tenant and ValueError for a category that
    does not exist or a value outside the platform bounds. Out of bounds is
    refused, never clamped: an admin who asked for 30 days of audit trail and
    silently got 365 would believe the shorter window is in force.
    """
    values = _validated(settings, overrides)
    with get_session(settings.postgres_url) as session:
        if session.get(models.Tenant, tenant_id) is None:
            raise LookupError(f"tenant not found: {tenant_id}")
        row = session.get(models.TenantRetentionPolicy, tenant_id)
        before = _document(row)
        if row is None:
            row = models.TenantRetentionPolicy(tenant_id=tenant_id, updated_at=_now())
            session.add(row)
        for category in CATEGORIES:
            setattr(row, category.column, values[category.key])
        row.note = str(note or "")[:500]
        row.updated_at = _now()
        row.updated_by = (updated_by or "")[:200]
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_RETENTION_POLICY_UPDATE,
            resource_type="retention_policy",
            resource_id=tenant_id,
            tenant_id=tenant_id,
            before=before,
            after=_document(row),
        )
    return describe(settings, tenant_id)


def clear_policy(
    settings: Settings,
    tenant_id: str,
    *,
    audit: audit_service.AuditContext | None = None,
) -> bool:
    """Put every category back on the platform default. False when there was no policy."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantRetentionPolicy, tenant_id)
        if row is None:
            return False
        before = _document(row)
        session.delete(row)
        session.flush()
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_RETENTION_POLICY_UPDATE,
            resource_type="retention_policy",
            resource_id=tenant_id,
            tenant_id=tenant_id,
            before=before,
            after=None,
        )
        return True
