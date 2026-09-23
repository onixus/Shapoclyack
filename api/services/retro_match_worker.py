"""Re-matches stored service fingerprints whenever the CVE data moves.

The software matcher's worker (``software_match_worker.py``) wakes on *new
inventory*. This one's main trigger is the opposite: the fingerprints stay put
and the **dataset** changes — tonight's NVD refresh adds a range for a CVE
published this afternoon, and every OpenSSH banner recorded in the last three
months has to be asked about it. ``docs/retro-cve-matching.md`` is the design.

**The queue is a column, not a list.** A listener is due when
``asset_services.matched_dataset_version`` differs from :func:`current_marker`
— the NVD dataset's own marker (feed date + digest of its bytes) joined with
the feed dates and sizes of the Debian and Ubuntu advisory datasets, because a
new vendor feed can turn a ``possible`` into a ``vulnerable`` as surely as a
new range can. So:

* a refreshed dataset makes every listener due, once;
* a new or changed fingerprint (``asset_services.record_run`` clears the
  column) makes that listener due;
* nothing else does. An unchanged dataset and unchanged fingerprints leave the
  queue empty, and a tick costs one indexed query.

It survives a restart, it is the same answer in every replica, and it cannot
drift the way an in-memory "last dataset I saw" would.

**A tick drains within a budget**, like the software worker, and shares the
budget across tenants so the first tenant in sort order cannot starve the
rest. A listener that raises is held off with a capped backoff
(``retro_findings._hold_off``) instead of heading every batch forever.

**Leader-locked** (``RETRO_MATCH_LOCK_ID``): the fold takes no per-row claim,
so two replicas would match the same listeners and — worse — each publish the
same ``new_cve`` events. The lock is not fencing; what makes a brief double run
harmless is that the fold is keyed on ``finding_key`` under a row lock (the
second writer finds the first one's row and refreshes it) and the event ids are
content-derived (JetStream drops the duplicate).

**No dataset, no matching.** With the NVD file missing or empty the worker does
nothing — it does not stamp listeners as matched against nothing, which would
leave them un-matched when the dataset arrives.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select, update

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import advisories, cpe_ranges, retro_findings
from api.services.cpe_ranges import CpeRangeDataset
from api.services.leader_lock import RETRO_MATCH_LOCK_ID, LeaderLock
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.retro-match")


def _now() -> datetime:
    return datetime.now(UTC)


def current_marker(dataset: CpeRangeDataset) -> str | None:
    """The version every listener is matched against, or ``None`` with no data.

    The NVD marker alone would miss the case the backport logic exists for: a
    new Debian tracker that now names the fix a banner's revision carries. The
    advisory side is summarised by feed date and record count rather than
    hashed, because those files are tens of megabytes and this is asked every
    tick; a feed whose content changed without either moving is a feed that
    did not change in any way the matcher can see.
    """
    if not dataset.available or not dataset.marker:
        return None
    parts = [
        f"{provider.name}={provider.feed_date() or ''}/{provider.entry_count()}"
        for provider in advisories.providers().values()
    ]
    advisory = hashlib.sha256("|".join(sorted(parts)).encode("utf-8")).hexdigest()[:8]
    return f"{dataset.marker}+adv:{advisory}"


def pending_service_ids(
    settings: Settings, *, tenant_id: str, marker: str, limit: int
) -> list[int]:
    """Listeners not yet matched against ``marker``, oldest change first."""
    now = _now().replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.AssetService.id)
            .where(
                models.AssetService.tenant_id == tenant_id,
                or_(
                    models.AssetService.matched_dataset_version.is_(None),
                    models.AssetService.matched_dataset_version != marker,
                ),
                or_(
                    models.AssetService.match_retry_after.is_(None),
                    models.AssetService.match_retry_after <= now,
                ),
            )
            .order_by(
                models.AssetService.fingerprint_changed_at.asc(), models.AssetService.id.asc()
            )
            .limit(limit)
        ).scalars().all()
    return list(rows)


def _state_row(session: Any, tenant_id: str) -> models.RetroMatchState:
    """The tenant's state row, locked; created on first use.

    Two writers can meet here — the worker finishing a sweep and an operator's
    refresh — and both would otherwise insert the same primary key when the
    row does not exist yet. ``insert_if_absent`` makes losing that race a
    re-read instead of a 500.
    """
    row = session.get(models.RetroMatchState, tenant_id, with_for_update=True)
    if row is None:
        insert_if_absent(
            session,
            models.RetroMatchState(tenant_id=tenant_id, last_stats={}),
            f"retro_match_state:{tenant_id}",
        )
        row = session.get(models.RetroMatchState, tenant_id, with_for_update=True)
    return row


def _record_state(
    settings: Settings,
    *,
    tenant_id: str,
    marker: str,
    stats: retro_findings.RetroStats,
    events: dict[str, int],
) -> None:
    now = _now().replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        row = _state_row(session, tenant_id)
        row.dataset_version = marker
        row.last_run_at = now
        row.findings_created = int(row.findings_created or 0) + stats.created
        row.events_published = int(row.events_published or 0) + events.get("published", 0)
        row.events_suppressed = int(row.events_suppressed or 0) + events.get("summarised", 0)
        row.last_stats = {**stats.as_dict(), **events}


def sweep_tenant(
    settings: Settings,
    tenant_id: str,
    *,
    dataset: CpeRangeDataset | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Drain one tenant's due listeners, in batches, until the budget runs out.

    Events for the findings created are published once, after the drain, so
    the per-tick cap in ``retro_findings.build_events`` is per tick and not
    per batch.
    """
    dataset = dataset if dataset is not None else cpe_ranges.dataset()
    marker = current_marker(dataset)
    if marker is None:
        return {"services": 0, "skipped": "no_dataset"}
    batch_size = max(1, settings.retro_match_batch_size)
    if deadline is None:
        deadline = time.monotonic() + max(1.0, float(settings.retro_match_tick_budget_seconds))
    stats = retro_findings.RetroStats()
    created: list[dict[str, Any]] = []
    batches = 0
    # A listener the fold neither marks nor holds off would come back at the
    # head of every batch; this keeps such a path, if one is ever introduced,
    # from spinning the tick for its whole budget.
    seen: set[int] = set()
    while True:
        service_ids = pending_service_ids(
            settings, tenant_id=tenant_id, marker=marker, limit=batch_size
        )
        if not service_ids or seen.issuperset(service_ids):
            break
        seen.update(service_ids)
        batch_stats, batch_created = retro_findings.fold_services(
            settings,
            tenant_id=tenant_id,
            service_ids=service_ids,
            dataset=dataset,
            marker=marker,
            lookup=advisories.get_provider,
        )
        stats.add(batch_stats)
        created.extend(batch_created)
        batches += 1
        if time.monotonic() >= deadline:
            LOG.info(
                "Retro match sweep: tenant=%s out of tick budget after %d batches",
                tenant_id,
                batches,
            )
            break
    if not batches:
        return {"services": 0}
    events = retro_findings.publish_created(settings, tenant_id=tenant_id, created=created)
    _record_state(settings, tenant_id=tenant_id, marker=marker, stats=stats, events=events)
    LOG.info("Retro match sweep: tenant=%s %s events=%s", tenant_id, stats.as_dict(), events)
    return {**stats.as_dict(), **events}


def sweep(settings: Settings) -> dict[str, Any]:
    """One pass across every tenant; fail-soft per tenant."""
    from api.services import tenants as tenants_service

    totals: dict[str, Any] = {"tenants": 0, "services": 0, "created": 0, "errors": 0}
    dataset = cpe_ranges.dataset()
    if current_marker(dataset) is None:
        return {**totals, "skipped": "no_dataset"}
    try:
        tenant_ids = [t["tenant_id"] for t in tenants_service.list_tenants()]
    except Exception:  # noqa: BLE001 - a tenant-store hiccup must not kill the worker
        LOG.exception("Retro match: could not list tenants")
        totals["errors"] += 1
        return totals

    budget = max(1.0, float(settings.retro_match_tick_budget_seconds))
    started = time.monotonic()
    for index, tenant_id in enumerate(tenant_ids):
        totals["tenants"] += 1
        share = max(0.0, budget - (time.monotonic() - started)) / (len(tenant_ids) - index)
        try:
            result = sweep_tenant(
                settings, tenant_id, dataset=dataset, deadline=time.monotonic() + share
            )
        except Exception:  # noqa: BLE001 - keep sweeping the remaining tenants
            totals["errors"] += 1
            LOG.exception("Retro match sweep failed for tenant %s", tenant_id)
            continue
        for key in ("services", "created", "errors"):
            totals[key] += int(result.get(key, 0) or 0)
    return totals


def request_refresh(settings: Settings, *, tenant_id: str, actor: str | None) -> dict[str, Any]:
    """Put every listener of the tenant back on the queue and wake the worker.

    The operator's "check again now". Nothing is matched in the request: a
    tenant-wide re-match is a workload, and the worker is where workloads run
    — this only makes it due, which the worker then drains within its budget.
    """
    now = _now().replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        queued = session.execute(
            update(models.AssetService)
            .where(models.AssetService.tenant_id == tenant_id)
            .values(matched_dataset_version=None, match_retry_after=None, match_failure_count=0)
        ).rowcount
        state = _state_row(session, tenant_id)
        state.refresh_requested_at = now
        state.refresh_requested_by = actor
    notify()
    return {"queued": queued, "worker_running": _WORKER is not None}


def status(settings: Settings, *, tenant_id: str) -> dict[str, Any]:
    """What the retro matcher knows and has done for one tenant."""
    from api.services import retro_findings as findings
    from api.services import vuln_states

    dataset = cpe_ranges.dataset()
    marker = current_marker(dataset)
    with get_session(settings.postgres_url) as session:
        services_total = session.scalar(
            select(func.count()).select_from(models.AssetService).where(
                models.AssetService.tenant_id == tenant_id
            )
        ) or 0
        pending = (
            session.scalar(
                select(func.count()).select_from(models.AssetService).where(
                    models.AssetService.tenant_id == tenant_id,
                    or_(
                        models.AssetService.matched_dataset_version.is_(None),
                        models.AssetService.matched_dataset_version != marker,
                    ),
                )
            )
            or 0
        ) if marker else services_total
        by_confidence = dict(
            session.execute(
                select(models.Vulnerability.match_confidence, func.count())
                .where(
                    models.Vulnerability.tenant_id == tenant_id,
                    models.Vulnerability.source == findings.SOURCE,
                    models.Vulnerability.state != vuln_states.CLOSED,
                )
                .group_by(models.Vulnerability.match_confidence)
            ).all()
        )
        # Summed in the database: a tenant's summaries are one JSON document
        # per listener, and a status read must not pull the estate into memory.
        summary = models.AssetService.match_summary
        matched_rows = (
            models.AssetService.tenant_id == tenant_id,
            models.AssetService.matched_dataset_version.is_not(None),
        )
        possible = session.scalar(
            select(func.coalesce(func.sum(summary["counts"]["possible"].as_integer()), 0)).where(
                *matched_rows
            )
        ) or 0
        assessed = session.scalar(
            select(func.count())
            .select_from(models.AssetService)
            .where(*matched_rows, summary["status"].as_string() == "matched")
        ) or 0
        state = session.get(models.RetroMatchState, tenant_id)
        state_view = {
            "last_run_at": _iso(state.last_run_at) if state else None,
            "last_dataset_version": state.dataset_version if state else None,
            "findings_created": int(state.findings_created or 0) if state else 0,
            "events_published": int(state.events_published or 0) if state else 0,
            "events_summarised": int(state.events_suppressed or 0) if state else 0,
            "last_stats": dict(state.last_stats or {}) if state else {},
            "refresh_requested_at": _iso(state.refresh_requested_at) if state else None,
            "refresh_requested_by": state.refresh_requested_by if state else None,
        }
    return {
        "enabled": bool(settings.retro_match_enabled),
        "worker_running": _WORKER is not None,
        "dataset": cpe_ranges.status(),
        "dataset_version": marker,
        "services_total": int(services_total),
        "services_pending": int(pending),
        "services_assessed": int(assessed),
        "open_findings": {str(k or "unknown"): int(v) for k, v in by_confidence.items()},
        "possible_matches": int(possible),
        **state_view,
    }


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    naive = value.astimezone(UTC).replace(tzinfo=None) if value.tzinfo else value
    return naive.replace(tzinfo=UTC).isoformat().replace("+00:00", "Z")


class RetroMatchWorker:
    def __init__(self, *, settings: Settings, interval_seconds: float | None = None) -> None:
        self._settings = settings
        self._interval = float(
            interval_seconds if interval_seconds is not None else settings.retro_match_interval_seconds
        )
        self._stop = threading.Event()
        # Separate from ``_stop`` so a new fingerprint or a refresh request can
        # shorten the wait without the loop confusing "work" with "exit".
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = LeaderLock(
            settings.postgres_url, object_id=RETRO_MATCH_LOCK_ID, name="retro match worker"
        )
        self._stats: dict[str, Any] = {
            "runs": 0,
            "services": 0,
            "created": 0,
            "errors": 0,
            "skipped_not_leader": 0,
            "last_run_at": None,
        }

    @property
    def stats(self) -> dict[str, Any]:
        return {**self._stats, "is_leader": int(self._lock.is_leader)}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-retro-match", daemon=True)
        self._thread.start()
        LOG.info(
            "Retro match worker started (interval=%.0fs, batch=%d, matches only while leader)",
            self._interval,
            self._settings.retro_match_batch_size,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        # After the join, so the loop cannot re-acquire behind us.
        self._lock.release()
        LOG.info("Retro match worker stopped stats=%s", self.stats)

    def notify(self) -> None:
        self._wake.set()

    def tick(self) -> dict[str, Any] | None:
        """One iteration of the loop: sweep if this replica leads, else count it."""
        if not self._lock.acquire():
            self._stats["skipped_not_leader"] += 1
            return None
        return self.run_once()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Retro match tick failed")
            self._wake.wait(self._interval)
            self._wake.clear()

    def run_once(self) -> dict[str, Any]:
        totals = sweep(self._settings)
        self._stats["runs"] += 1
        for key in ("services", "created", "errors"):
            self._stats[key] += int(totals.get(key, 0) or 0)
        self._stats["last_run_at"] = _now().isoformat().replace("+00:00", "Z")
        return totals

    def release(self) -> None:
        self._lock.release()


_WORKER: RetroMatchWorker | None = None


def start_worker(settings: Settings) -> RetroMatchWorker | None:
    global _WORKER
    if not settings.retro_match_enabled:
        return None
    if _WORKER is not None:
        return _WORKER
    worker = RetroMatchWorker(settings=settings)
    worker.start()
    _WORKER = worker
    return worker


def stop_worker() -> None:
    global _WORKER
    if _WORKER is not None:
        _WORKER.stop()
        _WORKER = None


def notify() -> None:
    """Ask the worker to look now. A no-op without one in this process — the
    queue is the column, so nothing is lost, it just waits for a tick."""
    if _WORKER is not None:
        _WORKER.notify()


def worker_stats() -> dict[str, Any] | None:
    if _WORKER is None:
        return None
    return _WORKER.stats
