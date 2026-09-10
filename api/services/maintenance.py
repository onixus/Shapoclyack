"""Maintenance windows, blackout calendars and the change freeze (#352).

The platform could express when a scan repeats (``scan_schedules``) and
nothing at all about when it must not happen. Every customer has periods
during which their estate is not to be touched — quarter close, a payment
window, the night of a migration — and honouring one meant an operator
disabling the schedules by hand and remembering to switch them back on. The
second half of that is the half that gets forgotten, and the scan that runs
during a change freeze is the one the customer remembers.

A window is a recurring period, per tenant or per asset group, with a
polarity:

* ``blackout`` — no scan may start while it is open.
* ``allowed`` — the tenant's scans may start **only** while one of its allowed
  windows is open. A single allowed window therefore turns the tenant opt-in;
  that is why it is a separate kind and not an inverted blackout.

On top of the calendar sits the **change freeze**: a boolean on the tenant for
the case that has no end date yet ("we are frozen until the migration lands").
A blackout expires by itself and the refusal can say when; a freeze does not,
and the refusal says so rather than inventing a retry time.

Admission
---------
:func:`assert_scan_admitted` runs inside ``jobs_service.start_scan``, which is
the one place every scan passes through — the console's ``POST /api/jobs``,
the recurring dispatcher, and the platform's own re-scans alike. A blackout
only the route honoured would be a blackout the scheduler walks through at
02:00, which is exactly when maintenance windows exist.

Refusal is a :class:`MaintenanceBlocked` carrying the reason, the window that
said no and — when it is knowable — the moment the block lifts. The route
answers 409 with ``Retry-After``; the dispatcher does not lose the tick, it
moves the schedule's ``next_run_at`` to that moment, so a nightly scan blacked
out tonight runs when the window closes instead of vanishing (see
``scan_schedules.defer_dispatch``).

Recurrence: the supported RRULE subset
--------------------------------------
Recurrence is an RFC 5545 ``RRULE``, deliberately **not** the whole standard
and deliberately without a new dependency (``python-dateutil`` is not in
``requirements.txt``, and the repo already hand-parses cron in
``scanner/scheduler.py``). Supported:

``FREQ``
    ``DAILY``, ``WEEKLY`` or ``MONTHLY``. Required.
``INTERVAL``
    Positive integer, default 1 — every *n*-th day, week or month, counted
    from ``dtstart``.
``BYDAY``
    ``WEEKLY`` only: ``MO,TU,WE,TH,FR,SA,SU``. Defaults to ``dtstart``'s day.
``BYMONTHDAY``
    ``MONTHLY`` only: 1–31. Defaults to ``dtstart``'s day of month. A day a
    month does not have (31 in February) simply has no occurrence that month,
    as in RFC 5545.
``UNTIL``
    ``YYYYMMDDTHHMMSSZ`` or ``YYYYMMDD`` — the last moment an occurrence may
    start, in UTC.

Anything else — ``COUNT``, ``BYHOUR``, ``BYSETPOS``, ``BYMONTH``, an ordinal
``BYDAY`` such as ``-1SU`` — is **refused at write time** with a message
naming the part that is not supported. A rule accepted and then interpreted as
something narrower than what the operator typed would be a blackout that does
not blackout, and the operator would have no way to notice.

Time zones
----------
A window is a wall clock in the *tenant's* zone, never the server's:
``timezone`` is an IANA name and ``dtstart_local`` is naive local time. So
"every Saturday at 22:00" stays 22:00 for the customer across a DST change,
and a window that crosses midnight or a DST boundary is still
``duration_minutes`` of *absolute* time — a four-hour window over a
spring-forward ends four real hours after it opened, not three.
"""

from __future__ import annotations

import ipaddress
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import tenants as tenants_service
from api.services.targets import split_target_lines
from api.settings import Settings
from scanner.pipeline import scan_scope as scope_rules
from scanner.pipeline.utils import is_fqdn, is_ip_or_cidr

_log = logging.getLogger(__name__)

KIND_BLACKOUT = "blackout"
KIND_ALLOWED = "allowed"
KINDS = (KIND_BLACKOUT, KIND_ALLOWED)

SCOPE_TENANT = "tenant"
SCOPE_ASSET_GROUP = "asset_group"
SCOPE_KINDS = (SCOPE_TENANT, SCOPE_ASSET_GROUP)

#: Why a scan was refused, in the exception, the API response and the audit row.
REASON_BLACKOUT = "maintenance_blackout"
REASON_OUTSIDE_ALLOWED = "outside_allowed_window"
REASON_CHANGE_FREEZE = "change_freeze"

#: How far ahead "when does this lift?" is willing to look. A tenant whose only
#: allowed window is a yearly one gets ``retry_at=None`` rather than a search
#: that walks a decade of occurrences on every refused scan.
LOOKAHEAD_DAYS = 90

#: An occurrence longer than this is a configuration mistake, not a window —
#: a month-long "window" is what the change freeze is for, and the generator
#: has to look back at most this far for an occurrence that is still open.
MAX_DURATION_MINUTES = 14 * 24 * 60

_WEEKDAYS = ("MO", "TU", "WE", "TH", "FR", "SA", "SU")


class MaintenanceBlocked(PermissionError):
    """A scan refused because the tenant's calendar says not now.

    A ``PermissionError`` for the reason ``QuotaExceeded`` and
    ``ScanScopeDenied`` are: the request is well-formed and the caller is
    authenticated, they are simply not entitled to it *at this moment*.

    ``retry_at`` is when the block lifts — the end of the blackout, or the
    start of the next allowed window — and is None when that is not knowable
    (a change freeze, or an allowed window further out than
    :data:`LOOKAHEAD_DAYS`). None means "ask an admin", not "try again soon",
    and the routes leave ``Retry-After`` off rather than guess.
    """

    def __init__(
        self,
        message: str,
        *,
        tenant_id: str,
        reason: str,
        window_id: str = "",
        window_name: str = "",
        retry_at: datetime | None = None,
    ) -> None:
        super().__init__(message)
        self.tenant_id = tenant_id
        self.reason = reason
        self.window_id = window_id
        self.window_name = window_name
        self.retry_at = retry_at

    @property
    def retry_after_seconds(self) -> int | None:
        if self.retry_at is None:
            return None
        return max(1, int((self.retry_at - _now()).total_seconds()))


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


# ---------------------------------------------------------------------------
# RRULE (the subset in this module's docstring)


@dataclass(frozen=True)
class Recurrence:
    """A parsed RRULE. Pure — no database, no clock."""

    freq: str
    interval: int = 1
    byday: tuple[int, ...] = ()  # Python weekdays, Monday=0
    bymonthday: tuple[int, ...] = ()
    until: datetime | None = None  # aware UTC


def _rrule_error(detail: str) -> ValueError:
    return ValueError(
        f"unsupported RRULE: {detail}. Supported: FREQ=DAILY|WEEKLY|MONTHLY, "
        "INTERVAL, BYDAY (weekly), BYMONTHDAY (monthly), UNTIL"
    )


def _parse_until(raw: str) -> datetime:
    value = raw.strip().upper()
    try:
        return datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        pass
    try:
        # The date-only form is the *whole* day, so it reads as its last
        # instant. Taken as midnight it would drop the final occurrence of
        # every window whose wall clock falls later in the UTC day — a blackout
        # written "…;UNTIL=20271231" to cover New Year's Eve would be absent on
        # New Year's Eve, and RFC 5545 calls UNTIL inclusive.
        day = datetime.strptime(value, "%Y%m%d").replace(tzinfo=UTC)
    except ValueError:
        raise _rrule_error(f"UNTIL={raw!r} is not YYYYMMDDTHHMMSSZ or YYYYMMDD") from None
    return day + timedelta(hours=23, minutes=59, seconds=59)


def parse_rrule(text: str) -> Recurrence:
    """Parse the supported RRULE subset, or raise ``ValueError`` naming the part
    that is not supported.

    Refusing is the whole point: a rule quietly reduced to something narrower
    than the operator typed is a blackout that does not blackout on the nights
    they were counting on.
    """
    raw = (text or "").strip()
    if raw.upper().startswith("RRULE:"):
        raw = raw.split(":", 1)[1]
    if not raw:
        raise _rrule_error("empty rule")

    parts: dict[str, str] = {}
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" not in chunk:
            raise _rrule_error(f"{chunk!r} is not KEY=VALUE")
        key, value = chunk.split("=", 1)
        key = key.strip().upper()
        if key in parts:
            raise _rrule_error(f"{key} given twice")
        parts[key] = value.strip()

    freq = parts.pop("FREQ", "").upper()
    if freq not in ("DAILY", "WEEKLY", "MONTHLY"):
        raise _rrule_error(f"FREQ={freq or '(missing)'}")

    interval = 1
    if "INTERVAL" in parts:
        try:
            interval = int(parts.pop("INTERVAL"))
        except ValueError as exc:
            raise _rrule_error("INTERVAL must be a positive integer") from exc
        if interval < 1:
            raise _rrule_error("INTERVAL must be a positive integer")

    byday: list[int] = []
    if "BYDAY" in parts:
        if freq != "WEEKLY":
            raise _rrule_error("BYDAY is only supported with FREQ=WEEKLY")
        for token in parts.pop("BYDAY").split(","):
            day = token.strip().upper()
            if day not in _WEEKDAYS:
                # Covers the ordinal form (`-1SU`) as well as a typo: both mean
                # "this rule fires on days this module does not compute".
                raise _rrule_error(f"BYDAY={day!r} (expected one of {', '.join(_WEEKDAYS)})")
            byday.append(_WEEKDAYS.index(day))

    bymonthday: list[int] = []
    if "BYMONTHDAY" in parts:
        if freq != "MONTHLY":
            raise _rrule_error("BYMONTHDAY is only supported with FREQ=MONTHLY")
        for token in parts.pop("BYMONTHDAY").split(","):
            try:
                day_of_month = int(token.strip())
            except ValueError as exc:
                raise _rrule_error(f"BYMONTHDAY={token.strip()!r}") from exc
            if not 1 <= day_of_month <= 31:
                raise _rrule_error(f"BYMONTHDAY={day_of_month} is outside 1-31")
            bymonthday.append(day_of_month)

    until = _parse_until(parts.pop("UNTIL")) if "UNTIL" in parts else None
    if parts:
        raise _rrule_error(f"{', '.join(sorted(parts))} not supported")

    return Recurrence(
        freq=freq,
        interval=interval,
        byday=tuple(sorted(set(byday))),
        bymonthday=tuple(sorted(set(bymonthday))),
        until=until,
    )


def _months_between(start: date, other: date) -> int:
    return (other.year - start.year) * 12 + (other.month - start.month)


def _fires_on(rule: Recurrence, dtstart: datetime, day: date) -> bool:
    """Does an occurrence *start* on this local date?"""
    if day < dtstart.date():
        return False
    if rule.freq == "DAILY":
        return (day - dtstart.date()).days % rule.interval == 0
    if rule.freq == "WEEKLY":
        wanted = rule.byday or (dtstart.weekday(),)
        if day.weekday() not in wanted:
            return False
        # Weeks are counted from the Monday of dtstart's week, so INTERVAL=2
        # with BYDAY=MO,FR keeps both days inside the same fortnight instead of
        # counting each matching day as its own step.
        start_week = dtstart.date() - timedelta(days=dtstart.weekday())
        this_week = day - timedelta(days=day.weekday())
        return ((this_week - start_week).days // 7) % rule.interval == 0
    wanted_days = rule.bymonthday or (dtstart.day,)
    if day.day not in wanted_days:
        return False
    return _months_between(dtstart.date(), day) % rule.interval == 0


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown timezone: {name!r}") from exc


def occurrences(
    rule: Recurrence,
    dtstart_local: datetime,
    *,
    timezone: str,
    duration_minutes: int,
    since: datetime,
    until: datetime,
) -> list[tuple[datetime, datetime]]:
    """Every occurrence ``(start, end)`` in aware UTC that overlaps
    ``[since, until]``.

    ``dtstart_local`` is a wall clock in ``timezone``; the duration is added in
    *absolute* time afterwards, which is what makes a window over a DST change
    last as long as the operator said.
    """
    if duration_minutes < 1 or duration_minutes > MAX_DURATION_MINUTES:
        # The write path already refuses this; a row that got here anyway would
        # make the day-by-day scan below walk its whole duration backwards, so
        # it is refused here too rather than turned into a long loop on every
        # admission check.
        raise ValueError(f"duration_minutes out of range: {duration_minutes}")
    tz = _zone(timezone)
    duration = timedelta(minutes=duration_minutes)
    # An occurrence that started before `since` can still be open now, so the
    # scan begins a whole duration early rather than at `since`.
    first_local = (since - duration).astimezone(tz).date()
    last_local = until.astimezone(tz).date()
    if last_local < first_local:
        return []

    found: list[tuple[datetime, datetime]] = []
    day = max(first_local, dtstart_local.date())
    local_time: time = dtstart_local.time()
    while day <= last_local:
        if _fires_on(rule, dtstart_local, day):
            local_start = datetime.combine(day, local_time)
            if local_start >= dtstart_local:
                # A wall clock a DST jump skipped (02:30 on a spring-forward
                # morning) does not exist; zoneinfo resolves it with the
                # pre-transition offset, which lands the window at the first
                # real instant after the jump. That is the least surprising
                # reading of "start at 02:30" on a day with no 02:30, and it
                # never silently drops the occurrence.
                start = local_start.replace(tzinfo=tz).astimezone(UTC)
                end = start + duration
                if (rule.until is None or start <= rule.until) and end > since and start <= until:
                    found.append((start, end))
        day += timedelta(days=1)
    return found


# ---------------------------------------------------------------------------
# Which scans a window covers


def _selector_covers(window: dict[str, Any], ranges: list[str], domains: list[str]) -> bool:
    """Does this window apply to a scan of these targets?

    A tenant-wide window covers every scan. An asset-group window covers a scan
    whose targets *intersect* the group, and a scan with no targets at all —
    one that runs on the installation defaults — is covered by every window of
    its tenant: the control plane cannot tell what such a run will touch, and a
    blackout that could be dodged by omitting targets is not a blackout.

    The question here is intersection, which is deliberately not the question
    ``scan_scope.ScanScope`` answers: that one asks whether a target is
    *contained* in an approved range, and by that rule a scan of ``10.0.0.0/16``
    would miss a window covering ``10.0.5.0/24`` — the half of the scan that is
    inside the group. Domain suffixes match as they do there (``example.com``
    covers its subdomains).
    """
    if window.get("scope_kind") != SCOPE_ASSET_GROUP:
        return True
    selector = [str(value) for value in (window.get("scope_targets") or [])]
    if not selector:
        # A group with nothing in it covers nothing rather than everything: the
        # fail-closed reading would make an empty draft window stop every scan
        # in the tenant. Writes refuse such a window (_assert_group_defined),
        # so this is the hand-edited-database path.
        return False
    if not ranges and not domains:
        return True

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    suffixes: list[str] = []
    for value in selector:
        if is_ip_or_cidr(value):
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
            except ValueError:
                _log.warning("Ignoring unparseable maintenance-window target %r", value)
        else:
            suffixes.append(scope_rules.normalize_domain(value))

    for target in ranges:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            continue
        if any(net.version == network.version and net.overlaps(network) for net in networks):
            return True
    for target in domains:
        name = scope_rules.normalize_domain(target)
        if any(name == suffix or name.endswith("." + suffix) for suffix in suffixes):
            return True
    return False


# ---------------------------------------------------------------------------
# Storage


def _to_dict(row: models.MaintenanceWindow) -> dict[str, Any]:
    return {
        "window_id": row.window_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "kind": row.kind,
        "enabled": row.enabled,
        "timezone": row.timezone,
        "rrule": row.rrule,
        # Local wall clock, so it goes out without a Z: stamping one on would
        # claim a UTC instant this column deliberately does not hold.
        "dtstart_local": row.dtstart_local.isoformat(timespec="minutes"),
        "duration_minutes": row.duration_minutes,
        "scope_kind": row.scope_kind,
        "asset_group": row.asset_group,
        "scope_targets": list(row.scope_targets or []),
        "note": row.note or "",
        "created_at": _iso(row.created_at),
        "created_by": row.created_by,
        "updated_at": _iso(row.updated_at),
        "updated_by": row.updated_by,
    }


def _rows(session, tenant_id: str, *, enabled_only: bool = False) -> list[models.MaintenanceWindow]:
    stmt = select(models.MaintenanceWindow).where(models.MaintenanceWindow.tenant_id == tenant_id)
    if enabled_only:
        stmt = stmt.where(models.MaintenanceWindow.enabled.is_(True))
    return list(
        session.execute(
            stmt.order_by(models.MaintenanceWindow.name, models.MaintenanceWindow.window_id)
        )
        .scalars()
        .all()
    )


def list_windows(settings: Settings, tenant_id: str) -> list[dict[str, Any]]:
    """One tenant's calendar, by name."""
    with get_session(settings.postgres_url) as session:
        return [_to_dict(row) for row in _rows(session, tenant_id)]


def get_window(settings: Settings, window_id: str) -> dict[str, Any] | None:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.MaintenanceWindow, window_id)
        return _to_dict(row) if row else None


def _parse_dtstart(value: Any) -> datetime:
    """A wall clock in the window's zone.

    An offset is refused rather than converted: an operator who wrote one meant
    "and this is the real instant", and a recurring window is not an instant —
    accepting it would silently pin the whole series to one UTC offset and the
    series would drift by an hour every DST change.
    """
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).strip())
        except ValueError as exc:
            raise ValueError(f"dtstart_local is not an ISO date-time: {value!r}") from exc
    if parsed.tzinfo is not None:
        raise ValueError(
            "dtstart_local is local wall clock in the window's timezone and must "
            "carry no offset (e.g. 2026-09-12T22:00)"
        )
    return parsed.replace(second=0, microsecond=0)


def _validate(fields: dict[str, Any]) -> dict[str, Any]:
    """Normalise one window's writable fields.

    Raises ValueError naming the offending value; every check is cheap and none
    of them touch the database.

    An explicit ``None`` means "leave this alone", not "set the falsy value":
    a ``PATCH`` carrying ``{"enabled": null}`` — which the request model accepts,
    every field on it being optional — must not switch a blackout off. The one
    field where ``None`` is a real instruction is ``asset_group``, where it
    clears the label.
    """
    fields = {
        key: value
        for key, value in fields.items()
        if value is not None or key == "asset_group"
    }
    validated: dict[str, Any] = {}
    if "name" in fields:
        name = str(fields["name"] or "").strip()
        if not name:
            raise ValueError("window name required")
        validated["name"] = name[:128]
    if "kind" in fields:
        kind = str(fields["kind"] or "").strip().lower()
        if kind not in KINDS:
            raise ValueError(f"kind must be one of {', '.join(KINDS)}: {kind!r}")
        validated["kind"] = kind
    if "enabled" in fields:
        validated["enabled"] = bool(fields["enabled"])
    if "timezone" in fields:
        zone_name = str(fields["timezone"] or "UTC").strip() or "UTC"
        _zone(zone_name)  # raises ValueError on an unknown IANA name
        validated["timezone"] = zone_name
    if "rrule" in fields:
        rule = str(fields["rrule"] or "").strip()
        parse_rrule(rule)  # raises ValueError naming the unsupported part
        validated["rrule"] = rule
    if "dtstart_local" in fields:
        validated["dtstart_local"] = _parse_dtstart(fields["dtstart_local"])
    if "duration_minutes" in fields:
        try:
            duration = int(fields["duration_minutes"])
        except (TypeError, ValueError) as exc:
            raise ValueError("duration_minutes must be an integer") from exc
        if duration < 1 or duration > MAX_DURATION_MINUTES:
            raise ValueError(
                f"duration_minutes must be between 1 and {MAX_DURATION_MINUTES} "
                "(a longer period is a change freeze, not a window)"
            )
        validated["duration_minutes"] = duration
    if "scope_kind" in fields:
        scope_kind = str(fields["scope_kind"] or SCOPE_TENANT).strip().lower()
        if scope_kind not in SCOPE_KINDS:
            raise ValueError(f"scope_kind must be one of {', '.join(SCOPE_KINDS)}")
        validated["scope_kind"] = scope_kind
    if "asset_group" in fields:
        group = str(fields["asset_group"] or "").strip()
        validated["asset_group"] = group[:128] or None
    if "scope_targets" in fields:
        targets: list[str] = []
        for raw in fields["scope_targets"] or []:
            value = str(raw).strip()
            if not value:
                continue
            if is_ip_or_cidr(value):
                targets.append(str(ipaddress.ip_network(value, strict=False)))
            elif is_fqdn(scope_rules.normalize_domain(value)):
                targets.append(scope_rules.normalize_domain(value))
            else:
                raise ValueError(f"scope_targets entry is neither a CIDR nor a domain: {value!r}")
        validated["scope_targets"] = targets
    if "note" in fields:
        validated["note"] = str(fields["note"] or "").strip()[:500]
    return validated


def _assert_group_defined(scope_kind: str, asset_group: str | None, targets: list[str]) -> None:
    """An asset-group window has to say which group and which addresses.

    Stored empty it would match nothing (see :func:`_selector_covers`) — a
    blackout that silently protects nobody, which is worse than a 422.
    """
    if scope_kind != SCOPE_ASSET_GROUP:
        return
    if not asset_group:
        raise ValueError("asset_group is required when scope_kind=asset_group")
    if not targets:
        raise ValueError(
            "scope_targets is required when scope_kind=asset_group: the platform has "
            "no asset-group entity, so a group is defined by the CIDRs and domains it covers"
        )


def create_window(
    settings: Settings,
    *,
    tenant_id: str,
    fields: dict[str, Any],
    created_by: str,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Add one window to a tenant's calendar.

    Raises LookupError for an unknown tenant and ValueError for a malformed
    rule, zone, duration or selector.
    """
    if tenants_service.get_tenant(tenant_id) is None:
        raise LookupError(f"tenant not found: {tenant_id}")
    for required in ("name", "rrule", "dtstart_local"):
        if fields.get(required) in (None, ""):
            raise ValueError(f"{required} is required")
    validated = _validate(fields)
    scope_kind = validated.get("scope_kind", SCOPE_TENANT)
    _assert_group_defined(
        scope_kind, validated.get("asset_group"), validated.get("scope_targets", [])
    )

    now = _now()
    row = models.MaintenanceWindow(
        window_id=f"mw_{uuid.uuid4().hex[:12]}",
        tenant_id=tenant_id,
        name=validated["name"],
        kind=validated.get("kind", KIND_BLACKOUT),
        enabled=validated.get("enabled", True),
        timezone=validated.get("timezone", "UTC"),
        rrule=validated["rrule"],
        dtstart_local=validated["dtstart_local"],
        duration_minutes=validated.get("duration_minutes", 60),
        scope_kind=scope_kind,
        asset_group=validated.get("asset_group"),
        scope_targets=validated.get("scope_targets", []),
        note=validated.get("note", ""),
        created_at=now,
        created_by=created_by,
    )
    with get_session(settings.postgres_url) as session:
        session.add(row)
        session.flush()
        stored = _to_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_MAINTENANCE_WINDOW_CREATE,
            resource_type="maintenance_window",
            resource_id=row.window_id,
            tenant_id=tenant_id,
            after=stored,
        )
        return stored


def update_window(
    settings: Settings,
    window_id: str,
    *,
    fields: dict[str, Any],
    updated_by: str,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any] | None:
    """Patch one window. ``None`` when there is no such window."""
    validated = _validate(fields)
    with get_session(settings.postgres_url) as session:
        row = session.get(models.MaintenanceWindow, window_id)
        if row is None:
            return None
        before = _to_dict(row)
        for key, value in validated.items():
            setattr(row, key, value)
        # Checked on the merged result, not on the patch: switching a
        # tenant-wide window to a group is what makes the (absent) selector a
        # problem, and the answer has to be about what will be stored.
        _assert_group_defined(row.scope_kind, row.asset_group, list(row.scope_targets or []))
        row.updated_at = _now()
        row.updated_by = updated_by
        session.flush()
        after = _to_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_MAINTENANCE_WINDOW_UPDATE,
            resource_type="maintenance_window",
            resource_id=window_id,
            tenant_id=row.tenant_id,
            before=before,
            after=after,
        )
        return after


def delete_window(
    settings: Settings,
    window_id: str,
    *,
    audit: "audit_service.AuditContext | None" = None,
) -> bool:
    with get_session(settings.postgres_url) as session:
        row = session.get(models.MaintenanceWindow, window_id)
        if row is None:
            return False
        before = _to_dict(row)
        session.delete(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_MAINTENANCE_WINDOW_DELETE,
            resource_type="maintenance_window",
            resource_id=window_id,
            tenant_id=before["tenant_id"],
            before=before,
        )
        return True


def _freeze_dict(row: models.Tenant) -> dict[str, Any]:
    return {
        "tenant_id": row.tenant_id,
        "change_freeze": bool(row.change_freeze),
        "change_freeze_note": row.change_freeze_note or "",
        "change_freeze_at": _iso(row.change_freeze_at),
        "change_freeze_by": row.change_freeze_by,
    }


def set_change_freeze(
    settings: Settings,
    tenant_id: str,
    *,
    frozen: bool,
    note: str = "",
    actor: str,
    audit: "audit_service.AuditContext | None" = None,
) -> dict[str, Any]:
    """Freeze or thaw a tenant. Raises LookupError for an unknown tenant.

    The stamp (``change_freeze_at``/``_by``) is rewritten on a thaw rather than
    cleared: "who lifted the freeze, and when" is the question asked after the
    scan that followed it.
    """
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Tenant, tenant_id)
        if row is None:
            raise LookupError(f"tenant not found: {tenant_id}")
        before = _freeze_dict(row)
        row.change_freeze = bool(frozen)
        row.change_freeze_note = (note or "").strip()[:500] or None
        row.change_freeze_at = _now()
        row.change_freeze_by = actor
        session.flush()
        after = _freeze_dict(row)
        audit_service.record(
            session,
            audit,
            action=audit_service.ACTION_TENANT_CHANGE_FREEZE,
            resource_type="tenant",
            resource_id=tenant_id,
            tenant_id=tenant_id,
            before=before,
            after=after,
        )
        return after


def change_freeze(settings: Settings, tenant_id: str) -> dict[str, Any]:
    """One tenant's freeze state. Raises LookupError for an unknown tenant."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Tenant, tenant_id)
        if row is None:
            raise LookupError(f"tenant not found: {tenant_id}")
        return _freeze_dict(row)


# ---------------------------------------------------------------------------
# Admission


@dataclass(frozen=True)
class Admission:
    """The calendar's answer for one scan, at one moment."""

    allowed: bool
    reason: str = ""
    detail: str = ""
    window_id: str = ""
    window_name: str = ""
    retry_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "detail": self.detail,
            "window_id": self.window_id,
            "window_name": self.window_name,
            "retry_at": _iso(self.retry_at),
        }


def _window_occurrences(
    window: dict[str, Any], *, since: datetime, until: datetime
) -> list[tuple[datetime, datetime]]:
    """Occurrences of one stored window, or ``[]`` if it cannot be read.

    A window whose rule or zone no longer parses is dropped and logged as an
    error — the same treatment an unparseable scan-scope row gets. Writes are
    validated, so this is the "somebody edited the database by hand" path, and
    a loud log is the only way an operator learns their blackout is not
    blacking anything out.
    """
    try:
        rule = parse_rrule(window["rrule"])
        dtstart = _parse_dtstart(window["dtstart_local"])
        return occurrences(
            rule,
            dtstart,
            timezone=window["timezone"],
            duration_minutes=int(window["duration_minutes"]),
            since=since,
            until=until,
        )
    except (ValueError, KeyError, TypeError):
        _log.error(
            "Ignoring unreadable maintenance window %s of tenant %s: rrule=%r tz=%r",
            window.get("window_id"),
            window.get("tenant_id"),
            window.get("rrule"),
            window.get("timezone"),
        )
        return []


def open_at(window: dict[str, Any], at: datetime) -> tuple[datetime, datetime] | None:
    """The occurrence containing ``at``, or None. Half-open: ``[start, end)``."""
    for start, end in _window_occurrences(window, since=at, until=at):
        if start <= at < end:
            return start, end
    return None


def next_start_after(window: dict[str, Any], at: datetime) -> datetime | None:
    """When this window next opens, within :data:`LOOKAHEAD_DAYS`."""
    horizon = at + timedelta(days=LOOKAHEAD_DAYS)
    for start, _end in _window_occurrences(window, since=at, until=horizon):
        if start > at:
            return start
    return None


def evaluate(
    settings: Settings,
    *,
    tenant_id: str,
    ranges_text: str | None = None,
    domains_text: str | None = None,
    at: datetime | None = None,
) -> Admission:
    """Whether a scan of these targets may start now, and if not, when it may.

    Order matters. The freeze is checked first because it is the answer that
    does not expire, and an operator told "retry at 04:00" by a blackout while
    the tenant is frozen until further notice has been told the wrong thing. A
    blackout beats an allowed window for the reason deny beats allow in the
    approved scan scope: the entry that says "not now" is the one somebody
    wrote to stop something.
    """
    at = at or _now()
    frozen = change_freeze(settings, tenant_id)
    if frozen["change_freeze"]:
        note = frozen["change_freeze_note"]
        return Admission(
            allowed=False,
            reason=REASON_CHANGE_FREEZE,
            detail=(
                f"tenant {tenant_id} is under a change freeze"
                + (f": {note}" if note else "")
                + " — an admin must lift it (PUT /api/change-freeze) before any "
                "scan can start"
            ),
        )

    with get_session(settings.postgres_url) as session:
        windows = [_to_dict(row) for row in _rows(session, tenant_id, enabled_only=True)]
    if not windows:
        return Admission(allowed=True)

    ranges = split_target_lines(ranges_text)
    domains = split_target_lines(domains_text)
    applicable = [window for window in windows if _selector_covers(window, ranges, domains)]

    # The first open blackout wins, and its end is the retry time. With two
    # overlapping blackouts that means the answer is re-derived at the end of
    # the first one and the second refuses again — a second deferral rather
    # than a lost run, which is why this does not need the longest end of the
    # set.
    for window in (w for w in applicable if w["kind"] == KIND_BLACKOUT):
        span = open_at(window, at)
        if span is None:
            continue
        _start, end = span
        where = f" for asset group {window['asset_group']}" if window["asset_group"] else ""
        return Admission(
            allowed=False,
            reason=REASON_BLACKOUT,
            detail=(
                f"maintenance blackout {window['name']!r}{where} is open until "
                f"{_iso(end)}; scanning is not allowed until then"
            ),
            window_id=window["window_id"],
            window_name=window["name"],
            retry_at=end,
        )

    allowed_windows = [w for w in applicable if w["kind"] == KIND_ALLOWED]
    if not allowed_windows:
        return Admission(allowed=True)
    if any(open_at(window, at) is not None for window in allowed_windows):
        return Admission(allowed=True)

    starts = [start for start in (next_start_after(w, at) for w in allowed_windows) if start]
    names = ", ".join(sorted(window["name"] for window in allowed_windows))
    return Admission(
        allowed=False,
        reason=REASON_OUTSIDE_ALLOWED,
        detail=(
            f"tenant {tenant_id} may only scan inside its maintenance window(s) "
            f"({names}), and none is open"
            + (f"; the next one opens at {_iso(min(starts))}" if starts else "")
        ),
        window_id=allowed_windows[0]["window_id"],
        window_name=allowed_windows[0]["name"],
        retry_at=min(starts) if starts else None,
    )


def assert_scan_admitted(
    settings: Settings,
    *,
    tenant_id: str,
    ranges_text: str | None = None,
    domains_text: str | None = None,
    at: datetime | None = None,
) -> None:
    """Refuse a scan the tenant's calendar does not allow right now.

    Called from ``jobs_service.start_scan`` rather than from a route, so the
    recurring dispatcher and every other caller are held to the same calendar.
    """
    admission = evaluate(
        settings,
        tenant_id=tenant_id,
        ranges_text=ranges_text,
        domains_text=domains_text,
        at=at,
    )
    if admission.allowed:
        return
    raise MaintenanceBlocked(
        admission.detail,
        tenant_id=tenant_id,
        reason=admission.reason,
        window_id=admission.window_id,
        window_name=admission.window_name,
        retry_at=admission.retry_at,
    )


def record_block(*, username: str, blocked: MaintenanceBlocked) -> None:
    """Write the refusal to the administrative trail (``audit_events``).

    Best-effort by design, like ``scan_scopes.record_denial``: the scan has
    already been refused when this runs, and losing the row must not turn a
    clean 409 into a 500 — but it is logged, because "the platform did not scan
    us last night, and which window said so" is precisely the question this
    feature is asked afterwards.

    ``actor_type`` is ``system`` even when a person asked for the scan: the
    decision recorded here is the platform's, and ``actor`` names who was
    refused rather than who changed something. It is also the only actor_type
    this layer could honestly claim — the service does not see the principal,
    and the same refusal is written for the dispatcher, which has none.
    """
    try:
        audit_service.record_standalone(
            audit_service.system_context(actor=username or "system"),
            action=audit_service.ACTION_SCAN_MAINTENANCE_BLOCK,
            resource_type="tenant",
            resource_id=blocked.tenant_id,
            tenant_id=blocked.tenant_id,
            after={
                "reason": blocked.reason,
                "window_id": blocked.window_id,
                "window_name": blocked.window_name,
                "retry_at": _iso(blocked.retry_at),
                "detail": str(blocked)[:1000],
            },
        )
    except Exception:  # noqa: BLE001 - see docstring
        _log.exception(
            "Failed to record maintenance refusal for tenant %s in the audit trail",
            blocked.tenant_id,
        )


def calendar_status(
    settings: Settings, tenant_id: str, *, at: datetime | None = None
) -> dict[str, Any]:
    """What the console shows beside a tenant's schedules: the freeze, the
    windows, which of them is open now and when each opens next."""
    at = at or _now()
    items: list[dict[str, Any]] = []
    for window in list_windows(settings, tenant_id):
        span = open_at(window, at) if window["enabled"] else None
        items.append(
            {
                **window,
                "open_now": span is not None,
                "open_until": _iso(span[1]) if span else None,
                "next_start_at": _iso(next_start_after(window, at)) if window["enabled"] else None,
            }
        )
    return {
        "tenant_id": tenant_id,
        **change_freeze(settings, tenant_id),
        "admission": evaluate(settings, tenant_id=tenant_id, at=at).as_dict(),
        "windows": items,
    }
