"""Re-matches stored service fingerprints whenever the CVE data moves.

The software matcher's worker (``software_match_worker.py``) wakes on *new
inventory*. This one's main trigger is the opposite: the fingerprints stay put
and the **dataset** changes — tonight's NVD refresh adds a range for a CVE
published this afternoon, and every OpenSSH banner recorded in the last three
months has to be asked about it. ``docs/retro-cve-matching.md`` is the design.

**The queue is a column, not a list.** A listener is due when
``asset_services.matched_dataset_version`` differs from :func:`current_marker`
— a digest of what the NVD dataset *says* joined with digests of what the
Debian and Ubuntu advisory datasets say, because a new vendor statement can
turn a ``possible`` into a ``vulnerable`` as surely as a new range can. Content,
not dates: a daily refresh that brought nothing new leaves the marker alone.
So:

* a dataset whose content changed makes every listener due, once;
* a new or changed fingerprint (``asset_services.record_run`` clears the
  column) makes that listener due;
* nothing else does. An unchanged dataset and unchanged fingerprints leave the
  queue empty, and a tick costs one index range scan per tenant.

It survives a restart, it is the same answer in every replica, and it cannot
drift the way an in-memory "last dataset I saw" would.

**A tick drains within a budget**, like the software worker, and shares the
budget across tenants so the first tenant in sort order cannot starve the
rest. A listener that raises is held off with a capped backoff
(``retro_findings._hold_off``) instead of heading every batch forever.

**Leader-locked** (``RETRO_MATCH_LOCK_ID``): the fold takes no per-row claim,
so two replicas would match the same listeners and — worse — each publish the
same ``new_cve`` events. The lock is not fencing; what makes a brief double run
harmless is that the fold is keyed on ``finding_key`` with a SAVEPOINT insert
(the second writer finds the first one's row and refreshes it), the listener
row is locked for its fold, and the event ids are content-derived (JetStream
drops the duplicate).

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
from api.db.engine import get_session
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
    new Debian tracker that now names the fix a banner's revision carries. So
    the advisory providers' content digests are folded in — digests of what
    they say, not of when they were fetched: a daily refresh that brought
    nothing new must not re-match the estate (``cpe_ranges`` does the same for
    the NVD side).
    """
    if not dataset.available or not dataset.marker:
        return None
    parts = [
        f"{provider.name}={provider.content_digest()}"
        for provider in advisories.providers().values()
    ]
    advisory = hashlib.sha256("|".join(sorted(parts)).encode("utf-8")).hexdigest()[:8]
    return f"{dataset.marker}+adv:{advisory}"


def pending_service_ids(
    settings: Settings, *, tenant_id: str, marker: str, limit: int
) -> list[int]:
    """Listeners not yet matched against ``marker``.

    ``< marker OR > marker`` rather than ``!= marker``: two range conditions
    the ``(tenant_id, matched_dataset_version)`` index can answer, so a tick
    with nothing due does not read the tenant's rows to find that out.
    """
    now = _now().replace(tzinfo=None)
    column = models.AssetService.matched_dataset_version
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.AssetService.id)
            .where(
                models.AssetService.tenant_id == tenant_id,
                or_(column.is_(None), column < marker, column > marker),
                or_(
                    models.AssetService.match_retry_after.is_(None),
                    models.AssetService.match_retry_after <= now,
                ),
            )
            .order_by(models.AssetService.id.asc())
            .limit(limit)
        ).scalars().all()
    return list(rows)


def _record_state(
    settings: Settings,
    *,
    tenant_id: str,
    marker: str,
    stats: retro_findings.RetroStats | None,
) -> None:
    """Remember the marker (always) and the sweep (when there was one)."""
    now = _now().replace(tzinfo=None)
    # The worker's view of the dataset, kept for the status route: it may be
    # answered by a replica that never loaded the file and must not load it
    # inside a request (see :func:`status`).
    dataset_view = cpe_ranges.status(load=False)
    with get_session(settings.postgres_url) as session:
        row = retro_findings._state_row(session, tenant_id)  # noqa: SLF001
        row.dataset_version = marker
        previous = dict(row.last_stats or {})
        if stats is not None:
            row.last_run_at = now
            row.findings_created = int(row.findings_created or 0) + stats.created
            previous = stats.as_dict()
        row.last_stats = {**previous, "dataset": dataset_view}


def sweep_tenant(
    settings: Settings,
    tenant_id: str,
    *,
    dataset: CpeRangeDataset | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    """Drain one tenant's due listeners, in batches, until the budget runs out,
    then announce whatever is still unannounced — this tick's findings, and any
    a killed predecessor committed but never published."""
    dataset = dataset if dataset is not None else cpe_ranges.dataset()
    marker = current_marker(dataset)
    if marker is None:
        return {"services": 0, "skipped": "no_dataset"}
    batch_size = max(1, settings.retro_match_batch_size)
    if deadline is None:
        deadline = time.monotonic() + max(1.0, float(settings.retro_match_tick_budget_seconds))
    stats = retro_findings.RetroStats()
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
        stats.add(
            retro_findings.fold_services(
                settings,
                tenant_id=tenant_id,
                service_ids=service_ids,
                dataset=dataset,
                marker=marker,
                lookup=advisories.get_provider,
            )
        )
        batches += 1
        if time.monotonic() >= deadline:
            LOG.info(
                "Retro match sweep: tenant=%s out of tick budget after %d batches",
                tenant_id,
                batches,
            )
            break
    events = retro_findings.announce_pending(settings, tenant_id=tenant_id, marker=marker)
    if not batches:
        if events["announced"]:
            LOG.info("Retro match: tenant=%s announced leftovers %s", tenant_id, events)
        _record_state_if_moved(settings, tenant_id=tenant_id, marker=marker)
        return {"services": 0, **{k: v for k, v in events.items() if v}}
    _record_state(settings, tenant_id=tenant_id, marker=marker, stats=stats)
    LOG.info("Retro match sweep: tenant=%s %s events=%s", tenant_id, stats.as_dict(), events)
    return {**stats.as_dict(), **events}


def _record_state_if_moved(settings: Settings, *, tenant_id: str, marker: str) -> None:
    """Keep the status route's idea of the current marker current, without a
    write per tenant per tick when nothing moved."""
    with get_session(settings.postgres_url) as session:
        row = session.get(models.RetroMatchState, tenant_id)
        if row is not None and row.dataset_version == marker:
            return
    _record_state(settings, tenant_id=tenant_id, marker=marker, stats=None)


def sweep(settings: Settings) -> dict[str, Any]:
    """One pass across every tenant; fail-soft per tenant."""
    from api.services import tenants as tenants_service

    totals: dict[str, Any] = {"tenants": 0, "services": 0, "created": 0, "errors": 0}
    dataset = cpe_ranges.dataset()
    if current_marker(dataset) is None:
        return {**totals, "skipped": "no_dataset"}
    try:
        # Active tenants only (#325): a suspended tenant's findings are not
        # announced, and a tenant being purged must not have rows written for
        # it while its tables are emptied.
        tenant_ids = [
            t["tenant_id"]
            for t in tenants_service.list_tenants()
            if t["status"] == tenants_service.STATUS_ACTIVE
        ]
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
        state = retro_findings._state_row(session, tenant_id)  # noqa: SLF001
        state.refresh_requested_at = now
        state.refresh_requested_by = actor
    notify()
    return {"queued": queued, "worker_running": _WORKER is not None}


def status(settings: Settings, *, tenant_id: str) -> dict[str, Any]:
    """What the retro matcher knows and has done for one tenant.

    Reads no dataset: the marker is the one the worker last matched against
    (``retro_match_state``), and the dataset panel is whatever this process
    already has loaded (``cpe_ranges.status(load=False)``). Parsing the NVD
    corpus inside a status request, on every replica, after every refresh is
    exactly the cost this route must not have.
    """
    from api.services import vuln_states

    column = models.AssetService.matched_dataset_version
    with get_session(settings.postgres_url) as session:
        state = session.get(models.RetroMatchState, tenant_id)
        marker = state.dataset_version if state is not None else None
        services_total = session.scalar(
            select(func.count()).select_from(models.AssetService).where(
                models.AssetService.tenant_id == tenant_id
            )
        ) or 0
        due = (
            or_(column.is_(None), column < marker, column > marker)
            if marker
            else column.is_(None)
        )
        pending = session.scalar(
            select(func.count()).select_from(models.AssetService).where(
                models.AssetService.tenant_id == tenant_id, due
            )
        ) or 0
        by_confidence = dict(
            session.execute(
                select(models.Vulnerability.match_confidence, func.count())
                .where(
                    models.Vulnerability.tenant_id == tenant_id,
                    models.Vulnerability.source == retro_findings.SOURCE,
                    models.Vulnerability.state != vuln_states.CLOSED,
                )
                .group_by(models.Vulnerability.match_confidence)
            ).all()
        )
        # Summed in the database: a tenant's summaries are one JSON document
        # per listener, and a status read must not pull the estate into memory.
        summary = models.AssetService.match_summary
        matched_rows = (models.AssetService.tenant_id == tenant_id, column.is_not(None))
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
        state_view = {
            "last_run_at": _iso(state.last_run_at) if state else None,
            "last_dataset_version": marker,
            "findings_created": int(state.findings_created or 0) if state else 0,
            "events_published": int(state.events_published or 0) if state else 0,
            "events_summarised": int(state.events_suppressed or 0) if state else 0,
            "last_stats": dict(state.last_stats or {}) if state else {},
            "refresh_requested_at": _iso(state.refresh_requested_at) if state else None,
            "refresh_requested_by": state.refresh_requested_by if state else None,
        }
    dataset_view = cpe_ranges.status(load=False)
    if not dataset_view.get("present") and state is not None:
        # This replica has not loaded the file (it is not the leader, or has
        # not needed to); the leader's view as of its last tick is the answer.
        dataset_view = (state.last_stats or {}).get("dataset") or dataset_view
    return {
        "enabled": bool(settings.retro_match_enabled),
        "worker_running": _WORKER is not None,
        "dataset": dataset_view,
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
