"""Per-tenant usage metering and quotas (ROADMAP Track E, MSSP operations).

An MSSP sells capacity — "up to 2,000 assets, 40 scans a month" — and until
this module existed the platform could express none of it. A tenant could
register assets until the disk filled and start scans until the queue was the
only limit, and neither the provider nor the customer could answer *how much
of what we sold is being used*. That question is asked at renewal, and being
unable to answer it is how a platform gets replaced by a spreadsheet.

Two decisions shape everything here.

**Usage is counted, never accumulated.** There is no ``used`` column. Assets
come from ``assets`` and scans from ``jobs`` at the moment of the read, so the
meter cannot drift away from the lists the same customer is looking at. A
counter row would eventually disagree with the asset inventory, and the
customer would be right and the invoice wrong.

**Quotas fail open; the approved scan scope does not.** Migration 0025
grandfathered every tenant into an explicit allow-all because an absent scope
must never mean "scan anything". Here the opposite is correct: a tenant with
no ``tenant_quotas`` row inherits the platform default, which ships as
*unlimited*. An upgrade that started refusing customers' scans because nobody
had yet typed a number would be an outage caused by billing.

The two limits are also enforced differently, on purpose:

* **Scans** are refused at admission — :func:`assert_scan_quota` runs inside
  ``jobs_service.start_scan``, so the operator gets a 429 naming the limit and
  the date it resets, and no work is started. Verification re-scans (#183) are
  exempt: refusing the machine check that closes a finding would leave it stuck
  in ``VERIFYING`` and make the quota a correctness bug.
* **Assets** are capped at ingest — :func:`asset_capacity` tells the ingest
  path how many *new* assets it may create. It never fails the scan, and it
  never touches assets that already exist: a customer at their limit keeps
  getting fresh data about the estate they paid for, and only the discovery of
  further hosts stops. Refusing the whole result set would throw away the
  findings for the assets inside the quota as well, which is a punishment for
  the wrong thing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import metrics as metrics_service
from api.settings import Settings

_log = logging.getLogger(__name__)

#: Resource names, used in the API, the metric label and the refusal message.
RESOURCE_ASSETS = "assets"
RESOURCE_SCANS = "scans"

#: Callers whose scans are never counted against a quota, because refusing
#: them would break the platform rather than the customer's budget. The
#: verification re-scan (#183) is the mechanical half of a finding closure:
#: quota-refusing it would strand findings in ``VERIFYING`` for a reason that
#: has nothing to do with the finding.
EXEMPT_USERNAMES = frozenset({"system:verification"})

#: Asset statuses that consume quota. A decommissioned asset is inventory
#: history, not capacity in use — billing for it would make deleting an asset
#: the customer's only way to stop paying for a machine they already retired.
BILLED_ASSET_STATUSES = ("active", "stale")


class QuotaExceeded(PermissionError):
    """An action refused because it would exceed the tenant's purchased limit.

    A ``PermissionError`` for the same reason ``ScanScopeDenied`` is one: the
    request is well-formed and the principal is authenticated, they are simply
    not entitled to it right now. The routes answer **429**, not 403 — unlike a
    scope refusal, this one stops being true on its own, and ``Retry-After``
    can say exactly when.
    """

    def __init__(
        self,
        message: str,
        *,
        tenant_id: str,
        resource: str,
        limit: int,
        used: int,
        retry_after_seconds: int | None = None,
    ) -> None:
        super().__init__(message)
        self.tenant_id = tenant_id
        self.resource = resource
        self.limit = limit
        self.used = used
        self.retry_after_seconds = retry_after_seconds


@dataclass(frozen=True)
class Quota:
    """One tenant's effective limits.

    ``None`` means unlimited, and ``source`` says where the number came from:
    ``"tenant"`` for a row somebody wrote for this customer, ``"default"`` for
    the platform-wide setting they inherited. The console shows the difference
    because "unlimited because we sold it" and "unlimited because nobody has
    configured this yet" are not the same answer at renewal.
    """

    tenant_id: str
    max_assets: int | None
    max_scans_per_month: int | None
    source: str
    note: str = ""
    updated_at: datetime | None = None
    updated_by: str = ""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def period_bounds(now: datetime | None = None) -> tuple[datetime, datetime]:
    """The current billing period: one UTC calendar month, [start, end).

    A calendar month rather than a rolling 30-day window because that is what
    contracts say and what an invoice covers. A rolling window would make "how
    many scans do I have left this month" unanswerable without a chart.
    """
    moment = now or _now()
    start = moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    return start, end


def _shift_months(moment: datetime, delta: int) -> datetime:
    """Move a first-of-month timestamp ``delta`` months, without a date library."""
    index = moment.year * 12 + (moment.month - 1) + delta
    return moment.replace(year=index // 12, month=index % 12 + 1, day=1)


def _normalise_limit(value: int | None) -> int | None:
    """0 and negatives mean unlimited; anything else is the number itself."""
    if value is None or value <= 0:
        return None
    return int(value)


def get_quota(settings: Settings, tenant_id: str) -> Quota:
    """The limits that apply to ``tenant_id`` right now.

    A stored row wins over the platform default *including when its columns
    are NULL*: that is how one customer is exempted from a default everyone
    else is metered against, rather than by turning metering off globally.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantQuota, tenant_id)
        if row is not None:
            return Quota(
                tenant_id=tenant_id,
                max_assets=_normalise_limit(row.max_assets),
                max_scans_per_month=_normalise_limit(row.max_scans_per_month),
                source="tenant",
                note=row.note or "",
                updated_at=row.updated_at,
                updated_by=row.updated_by or "",
            )
    return Quota(
        tenant_id=tenant_id,
        max_assets=_normalise_limit(settings.quota_default_max_assets),
        max_scans_per_month=_normalise_limit(settings.quota_default_max_scans_per_month),
        source="default",
    )


def set_quota(
    settings: Settings,
    tenant_id: str,
    *,
    max_assets: int | None,
    max_scans_per_month: int | None,
    note: str = "",
    updated_by: str = "",
) -> Quota:
    """Write (or overwrite) one tenant's limits. ``None`` stores unlimited."""
    stored_assets = _normalise_limit(max_assets)
    stored_scans = _normalise_limit(max_scans_per_month)
    now = _now()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantQuota, tenant_id)
        if row is None:
            row = models.TenantQuota(tenant_id=tenant_id, updated_at=now)
            session.add(row)
        row.max_assets = stored_assets
        row.max_scans_per_month = stored_scans
        row.note = (note or "")[:500]
        row.updated_at = now
        row.updated_by = (updated_by or "")[:200]
    return Quota(
        tenant_id=tenant_id,
        max_assets=stored_assets,
        max_scans_per_month=stored_scans,
        source="tenant",
        note=(note or "")[:500],
        updated_at=now,
        updated_by=(updated_by or "")[:200],
    )


def clear_quota(settings: Settings, tenant_id: str) -> None:
    """Drop the tenant's row, returning it to the platform default."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.TenantQuota, tenant_id)
        if row is not None:
            session.delete(row)


def assets_used(settings: Settings, tenant_id: str) -> int:
    with get_session(settings.postgres_url) as session:
        return int(
            session.execute(
                select(func.count())
                .select_from(models.Asset)
                .where(
                    models.Asset.tenant_id == tenant_id,
                    models.Asset.status.in_(BILLED_ASSET_STATUSES),
                )
            ).scalar_one()
        )


def scans_used(settings: Settings, tenant_id: str, *, since: datetime | None = None) -> int:
    """Scans this tenant started in the current period.

    Counted from ``jobs.queued_at``, so a job that is still queued counts: the
    customer has consumed the entitlement by asking for the work, and a limit
    that only counted finished scans could be bypassed by starting a thousand.
    """
    start = since if since is not None else period_bounds()[0]
    with get_session(settings.postgres_url) as session:
        return int(
            session.execute(
                select(func.count())
                .select_from(models.Job)
                .where(models.Job.tenant_id == tenant_id, models.Job.queued_at >= start)
            ).scalar_one()
        )


def assert_scan_quota(settings: Settings, *, tenant_id: str, username: str) -> None:
    """Refuse a scan that would exceed this month's entitlement.

    Called from ``jobs_service.start_scan``, which is the single choke point
    every path reaches — the API route, the recurring-scan dispatcher and the
    verification re-scan alike — so a quota cannot be walked around by
    scheduling the scan instead of starting it.
    """
    if not settings.quota_enforcement_enabled:
        return
    if username in EXEMPT_USERNAMES:
        return
    quota = get_quota(settings, tenant_id)
    limit = quota.max_scans_per_month
    if limit is None:
        return
    start, end = period_bounds()
    used = scans_used(settings, tenant_id, since=start)
    if used < limit:
        return
    retry_after = max(1, int((end - _now()).total_seconds()))
    metrics_service.QUOTA_DENIED_TOTAL.labels(RESOURCE_SCANS).inc()
    raise QuotaExceeded(
        f"Scan quota reached for tenant {tenant_id}: {used}/{limit} scans this month; "
        f"resets {end.strftime('%Y-%m-%d')}",
        tenant_id=tenant_id,
        resource=RESOURCE_SCANS,
        limit=limit,
        used=used,
        retry_after_seconds=retry_after,
    )


def asset_capacity(settings: Settings, tenant_id: str) -> int | None:
    """How many *new* assets this tenant may still register. ``None`` = unlimited.

    The ingest paths call this instead of a raising assertion because they run
    inside a completed scan: raising there would discard results for assets
    that are inside the quota, so the answer has to be a number they can honour
    partially. A tenant already over its limit gets 0, never a negative.
    """
    if not settings.quota_enforcement_enabled:
        return None
    quota = get_quota(settings, tenant_id)
    if quota.max_assets is None:
        return None
    return max(0, quota.max_assets - assets_used(settings, tenant_id))


def record_asset_refusal(tenant_id: str, skipped: int) -> None:
    """Note that ``skipped`` new assets were not created for a quota reason.

    Loud in the log and counted in Prometheus, because this is the one refusal
    in this module that the person triggering it never sees: the scan they
    started succeeded, and some hosts it discovered are simply not in the
    inventory. Silence would look like a discovery bug.
    """
    if skipped <= 0:
        return
    metrics_service.QUOTA_DENIED_TOTAL.labels(RESOURCE_ASSETS).inc()
    _log.warning(
        "Asset quota reached for tenant %s: %d newly discovered asset(s) were not "
        "registered. Existing assets keep being updated.",
        tenant_id,
        skipped,
    )


def _shape(used: int, limit: int | None) -> dict[str, Any]:
    """One metered resource, with the shares the console shows.

    ``remaining`` and ``used_ratio`` are ``None`` when the resource is
    unlimited — the same rule the Adoption page follows: a share with nothing
    to divide by is ``null``, never 0% or 100%, because a progress bar at 0%
    against no limit reads as "plenty left" and one at 100% reads as an
    outage.
    """
    return {
        "used": used,
        "limit": limit,
        "remaining": None if limit is None else max(0, limit - used),
        "used_ratio": None if limit is None or limit <= 0 else round(used / limit, 4),
        "over_limit": limit is not None and used > limit,
    }


def usage(settings: Settings, tenant_id: str, *, history_months: int = 12) -> dict[str, Any]:
    """Everything the Usage page shows for one tenant."""
    quota = get_quota(settings, tenant_id)
    start, end = period_bounds()
    return {
        "tenant_id": tenant_id,
        "period_start": start,
        "period_end": end,
        "quota_source": quota.source,
        "enforced": settings.quota_enforcement_enabled,
        "note": quota.note,
        "updated_at": quota.updated_at,
        "updated_by": quota.updated_by,
        "assets": _shape(assets_used(settings, tenant_id), quota.max_assets),
        "scans": _shape(scans_used(settings, tenant_id, since=start), quota.max_scans_per_month),
        "scan_history": scan_history(settings, tenant_id, months=history_months),
    }


def scan_history(settings: Settings, tenant_id: str, *, months: int = 12) -> list[dict[str, Any]]:
    """Scans per calendar month, oldest first, with empty months present.

    Months with no scans are returned as zeroes rather than omitted: a gap a
    chart has to guess at is how a customer's quiet quarter turns into a
    missing bar somebody reads as missing data.
    """
    months = max(1, min(int(months), 36))
    start, _ = period_bounds()
    first = _shift_months(start, -(months - 1))
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.Job.queued_at).where(
                models.Job.tenant_id == tenant_id, models.Job.queued_at >= first
            )
        ).all()
    counts: dict[str, int] = {}
    for (queued_at,) in rows:
        if queued_at is None:
            continue
        counts[queued_at.strftime("%Y-%m")] = counts.get(queued_at.strftime("%Y-%m"), 0) + 1
    out: list[dict[str, Any]] = []
    cursor = first
    while cursor <= start:
        key = cursor.strftime("%Y-%m")
        out.append({"month": key, "scans": counts.get(key, 0)})
        cursor = _shift_months(cursor, 1)
    return out


def tenant_summaries(settings: Settings) -> dict[str, Any]:
    """Consumption across every tenant — the provider's side of the meter.

    Platform-admin only, and the one place in this module that reads more than
    one tenant: an MSSP operator asking "who is near their limit" should not
    have to open twelve tenants to find out. Counted in two grouped queries
    rather than per tenant, so the answer does not get slower with the customer
    list.
    """
    start, end = period_bounds()
    with get_session(settings.postgres_url) as session:
        tenants = session.execute(select(models.Tenant)).scalars().all()
        asset_rows = session.execute(
            select(models.Asset.tenant_id, func.count())
            .where(models.Asset.status.in_(BILLED_ASSET_STATUSES))
            .group_by(models.Asset.tenant_id)
        ).all()
        scan_rows = session.execute(
            select(models.Job.tenant_id, func.count())
            .where(models.Job.queued_at >= start)
            .group_by(models.Job.tenant_id)
        ).all()
        quota_rows = {
            row.tenant_id: row
            for row in session.execute(select(models.TenantQuota)).scalars().all()
        }
        tenant_info = [(t.tenant_id, t.name, t.status) for t in tenants]

    asset_counts = {tid: int(count) for tid, count in asset_rows}
    scan_counts = {tid: int(count) for tid, count in scan_rows}

    default_assets = _normalise_limit(settings.quota_default_max_assets)
    default_scans = _normalise_limit(settings.quota_default_max_scans_per_month)

    out: list[dict[str, Any]] = []
    for tenant_id, name, status in tenant_info:
        row = quota_rows.get(tenant_id)
        if row is None:
            max_assets, max_scans, source = default_assets, default_scans, "default"
        else:
            max_assets = _normalise_limit(row.max_assets)
            max_scans = _normalise_limit(row.max_scans_per_month)
            source = "tenant"
        out.append(
            {
                "tenant_id": tenant_id,
                "name": name,
                "status": status,
                "quota_source": source,
                "assets": _shape(asset_counts.get(tenant_id, 0), max_assets),
                "scans": _shape(scan_counts.get(tenant_id, 0), max_scans),
            }
        )
    out.sort(key=lambda item: str(item.get("name") or item["tenant_id"]).lower())
    return {"period_start": start, "period_end": end, "tenants": out}


def reset_for_tests(settings: Settings) -> None:
    """Clear every stored quota (test isolation only)."""
    with get_session(settings.postgres_url) as session:
        session.query(models.TenantQuota).delete()
