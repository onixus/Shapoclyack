"""The half of "two-way ticket sync" that nobody was running (#347).

Outbound worked: every lifecycle transition reflected onto the linked ticket.
Inbound was a button. ``POST /api/vulnerabilities/{id}/ticket/sync`` read one
ticket when an operator clicked it, and nothing read a ticket otherwise — so a
fix an assignee marked Done in Jira on Monday stayed OPEN here, inside its SLA,
accruing an overdue count, until somebody happened to open that finding's page.
The README promised two-way sync; what shipped was one-way plus a refresh
button.

This worker is the poller. Structurally it is the report dispatcher
(``api/services/reports/dispatcher.py``): a daemon thread per replica, a
Postgres advisory lock so only one of them acts, a fixed wake interval and a
crash-restart loop. Four things are specific to it.

**A poller may not overrule a person.** ``apply_ticket_status`` is called with
``only_on_remote_change=True``, so a suggestion lands only when the tracker's
own status string has moved since the last read. A button that re-imposes the
tracker's verdict is an operator's own request; a thread that does it every
fifteen minutes makes a finding impossible to keep open — reopen one whose Jira
issue is still ``Done`` and, without that rule, the next tick closes it again,
and the one after that, forever.

**The cadence is per subscription, not per tick.** The thread wakes every
``OCTO_TICKET_SYNC_POLL_INTERVAL_SECONDS``; how often the *same ticket* is read
is ``transport_config.sync_interval_seconds`` on the tenant's subscription,
falling back to ``OCTO_TICKET_SYNC_INTERVAL_SECONDS``. That knob has to be per
subscription because the trackers are not alike: a self-hosted Jira behind a
corporate proxy and a Cloud instance with a published rate limit want
different answers, and they can belong to different tenants of the same
installation.

**Backoff is per subscription, not per finding.** A tracker that is down fails
identically for every ticket on it, so failing one is enough to know. The
subscription is held off for ``base * 2**(failures-1)``, capped, and the rest
of its findings stay due — rather than being burned through at one futile
request each, every tick, for as long as the outage lasts. A *non*-retryable
answer (a 404 on a renamed key, a 403 on one issue) is that ticket's problem:
it is recorded in ``vulnerabilities.ticket_sync_error`` and the sweep moves on.
The backoff state is in memory and a restart forgets it, which is the right
trade for a GET: the cost of re-learning an outage is one request per
subscription.

**Leadership is not fenced**, as everywhere else this lock is used, so the
work stays idempotent under a brief double-run: reading a ticket twice yields
the same suggestion, and ``apply_ticket_status`` refuses a move that is not
legal from the finding's current state — the second reader's suggestion has
already been applied and is now a same-state no-op.

**What it does not do.** It does not push. Outbound reflection stays where it
was, on the transition itself (``vulnerabilities.push_ticket_state``), because
a state change the operator just made should reach the assignee now and not at
the end of an interval.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, nulls_first, or_, select

from api.db import models
from api.db.engine import get_session
from api.services import metrics as metrics_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.services.integrations import ticket_sync
from api.services.integrations.tickets import TICKET_TRANSPORTS, TicketSpecError
from api.services.leader_lock import TICKET_SYNC_LOCK_ID, LeaderLock
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.ticket-sync")


def _now() -> datetime:
    return datetime.now(UTC)


def subscriptions(settings: Settings) -> list[dict[str, Any]]:
    """The tracker endpoints to poll, one per tenant and transport.

    "One per" matters: a tenant may hold several Jira subscriptions (different
    projects to open tickets in), but a finding's ``ticket_system`` names a
    tracker, not a subscription. The newest enabled one wins, which is exactly
    what ``vulnerabilities._ticket_endpoint`` picks for the manual button and
    for the outbound push — polling through a different credential than the
    button uses is a support call nobody can reproduce.

    Credentials are decrypted here, once per tick, and never logged.
    """
    from api.services.integrations import webhooks as webhooks_service

    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    with get_session(settings.postgres_url) as session:
        rows = session.scalars(
            select(models.WebhookSubscription)
            .where(
                models.WebhookSubscription.enabled.is_(True),
                models.WebhookSubscription.transport.in_(TICKET_TRANSPORTS),
            )
            .order_by(models.WebhookSubscription.created_at.desc())
        ).all()
        for row in rows:
            key = (str(row.tenant_id), str(row.transport))
            if key in endpoints:
                continue
            try:
                secret, headers = webhooks_service.endpoint_credentials(row)
            except Exception:  # noqa: BLE001 - an unreadable KEK is not a reason
                # to stop polling every *other* tenant's tracker. The startup
                # check (crypto/startup.py) is what surfaces a missing key.
                LOG.warning(
                    "Ticket sync: could not decrypt credentials for subscription %s",
                    row.subscription_id,
                    exc_info=True,
                )
                continue
            endpoints[key] = {
                "subscription_id": str(row.subscription_id),
                "tenant_id": str(row.tenant_id),
                "transport": str(row.transport),
                "base_url": str(row.url),
                "secret": secret,
                "headers": headers,
                "config": dict(row.transport_config or {}),
            }
    return list(endpoints.values())


def due_findings(
    settings: Settings,
    *,
    tenant_id: str,
    transport: str,
    cutoff: datetime,
    limit: int,
    reopen_window_days: int = 30,
) -> list[dict[str, Any]]:
    """Linked findings whose ticket has not been read since ``cutoff``.

    Ordered oldest cursor first, nulls first — a finding whose ticket has never
    been read is the one most likely to be out of date, and the ordering is
    also what makes the tick's ``lag`` metric meaningful (the head of the batch
    is the oldest thing waiting).

    **Which findings.** Every still-active one, plus the ``CLOSED`` ones whose
    ``closure_reason`` is ``ticket_resolved`` and whose ``closed_at`` is inside
    ``reopen_window_days``. The second half is the reopen path: the tracker
    closed it, so the tracker reopening it is news, and it is the only way a
    ticket-driven closure can be undone by the same tracker. A finding closed
    by a verified re-scan or by a false-positive verdict is *not* polled — that
    closure was made on evidence a ticket cannot overturn.

    The window is what keeps this queue bounded. Without it, an installation
    closing a couple of hundred findings a month through Jira accumulates them
    forever, and since the order is by cursor and not by state, a year of dead
    tickets fills the batch ahead of the findings somebody is working on — and
    spends a GET on each, against a tracker that belongs to somebody else.
    """
    naive_cutoff = cutoff.replace(tzinfo=None)
    reopen_cutoff = (cutoff - timedelta(days=max(0, reopen_window_days))).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(
                models.Vulnerability.vuln_id,
                models.Vulnerability.ticket_key,
                models.Vulnerability.state,
                models.Vulnerability.ticket_synced_at,
                models.Vulnerability.first_seen_at,
            )
            .where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.ticket_system == transport,
                models.Vulnerability.ticket_key.is_not(None),
                or_(
                    models.Vulnerability.ticket_synced_at.is_(None),
                    models.Vulnerability.ticket_synced_at <= naive_cutoff,
                ),
                or_(
                    models.Vulnerability.state.in_(tuple(vuln_states.ACTIVE)),
                    and_(
                        models.Vulnerability.state == vuln_states.CLOSED,
                        models.Vulnerability.closure_reason == "ticket_resolved",
                        models.Vulnerability.closed_at.is_not(None),
                        models.Vulnerability.closed_at >= reopen_cutoff,
                    ),
                ),
            )
            .order_by(nulls_first(models.Vulnerability.ticket_synced_at.asc()))
            .limit(limit)
        ).all()
    return [
        {
            "vuln_id": row.vuln_id,
            "ticket_key": row.ticket_key,
            "state": row.state,
            # The cursor a never-polled finding gets for the lag metric is its
            # own discovery, not "no lag": the point of the metric is how stale
            # the reconciliation is, and never having run is the worst case.
            "waiting_since": row.ticket_synced_at or row.first_seen_at,
        }
        for row in rows
    ]


class TicketSyncWorker:
    def __init__(
        self,
        *,
        settings: Settings,
        poll_interval_seconds: float | None = None,
        request_fn=None,
    ) -> None:
        self._settings = settings
        # Injected the same way ``ticket_sync``'s own functions take it: the
        # wire is the one thing a test of this worker must not use.
        self._request_fn = request_fn
        self._poll_interval = float(
            poll_interval_seconds
            if poll_interval_seconds is not None
            else settings.ticket_sync_poll_interval_seconds
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = LeaderLock(
            settings.postgres_url,
            object_id=TICKET_SYNC_LOCK_ID,
            name="ticket sync worker",
        )
        # subscription_id -> (consecutive retryable failures, not before).
        self._backoff: dict[str, tuple[int, datetime]] = {}
        self._stats: dict[str, Any] = {
            "ticks": 0,
            "polled": 0,
            "applied": 0,
            "failed": 0,
            "errors": 0,
            "skipped_backoff": 0,
            "skipped_not_leader": 0,
            # Seconds the oldest still-due linked ticket has waited, as of the
            # last tick. The number an alert is written against: it grows when
            # a tracker is down, when a batch size is too small for the estate,
            # and when nobody is the leader.
            "lag_seconds": 0,
            "last_run_at": None,
        }

    @property
    def stats(self) -> dict[str, Any]:
        return {**self._stats, "is_leader": int(self._lock.is_leader)}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="octo-ticket-sync", daemon=True)
        self._thread.start()
        LOG.info(
            "Ticket sync worker started (poll_interval=%.0fs, default cadence=%ds, "
            "polls only while leader)",
            self._poll_interval,
            self._settings.ticket_sync_interval_seconds,
        )

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        # After the join, so the loop cannot re-acquire behind us.
        self._lock.release()
        metrics_service.TICKET_SYNC_IS_LEADER.set(0)
        self._report_lag({})
        LOG.info("Ticket sync worker stopped stats=%s", self.stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                leader = self._lock.acquire()
                metrics_service.TICKET_SYNC_IS_LEADER.set(int(leader))
                if leader:
                    self.tick()
                else:
                    self._stats["skipped_not_leader"] += 1
                    # Zeroed rather than left alone. A replica that leads
                    # through an outage, reports a five-figure lag and then
                    # loses the lock would otherwise export that number for
                    # the rest of its life, and every max() alert over the
                    # cluster would stay lit while the new leader drained the
                    # queue.
                    self._report_lag({})
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("Ticket sync tick failed")
            self._stop.wait(self._poll_interval)

    def tick(self, now: datetime | None = None) -> dict[str, Any]:
        """One pass over every tracker subscription. Public so tests drive it."""

        now = now or _now()
        self._stats["ticks"] += 1
        self._stats["last_run_at"] = now.isoformat().replace("+00:00", "Z")
        lag = 0.0
        # Per transport, so one unreachable Jira does not read as a
        # ServiceNow problem on the dashboard.
        by_transport: dict[str, float] = {}
        for endpoint in subscriptions(self._settings):
            transport = endpoint["transport"]
            try:
                subscription_lag = self._sync_subscription(endpoint, now)
                by_transport[transport] = max(
                    by_transport.get(transport, 0.0), subscription_lag
                )
                lag = max(lag, subscription_lag)
            except Exception:  # noqa: BLE001 - one tenant's tracker must not
                # stop the sweep, the same way the retention sweeps fail soft
                # per tenant.
                self._stats["errors"] += 1
                LOG.exception(
                    "Ticket sync failed for subscription %s", endpoint["subscription_id"]
                )
        self._stats["lag_seconds"] = int(lag)
        self._report_lag(by_transport)
        return dict(self.stats)

    def _report_lag(self, by_transport: dict[str, float]) -> None:
        """Publish one series per transport, zeroing the ones with nothing due."""
        for transport in TICKET_TRANSPORTS:
            metrics_service.TICKET_SYNC_LAG_SECONDS.labels(transport=transport).set(
                int(by_transport.get(transport, 0.0))
            )

    def _interval(self, endpoint: dict[str, Any]) -> int:
        """This subscription's cadence, or the platform default."""
        configured = endpoint["config"].get("sync_interval_seconds") or 0
        try:
            seconds = int(configured)
        except (TypeError, ValueError):
            seconds = 0
        return seconds or self._settings.ticket_sync_interval_seconds

    def _sync_subscription(self, endpoint: dict[str, Any], now: datetime) -> float:
        """Poll one tracker's due findings. Returns the batch's lag in seconds."""
        subscription_id = endpoint["subscription_id"]
        cutoff = now - timedelta(seconds=self._interval(endpoint))
        batch = due_findings(
            self._settings,
            tenant_id=endpoint["tenant_id"],
            transport=endpoint["transport"],
            cutoff=cutoff,
            limit=self._settings.ticket_sync_batch_size,
            reopen_window_days=self._settings.ticket_sync_reopen_window_days,
        )
        if not batch:
            self._backoff.pop(subscription_id, None)
            return 0.0

        waiting = batch[0]["waiting_since"]
        lag = max(0.0, (now.replace(tzinfo=None) - waiting).total_seconds()) if waiting else 0.0

        # The due read happens before the backoff check on purpose: a
        # subscription that is being held off is precisely the one whose lag an
        # operator needs to see growing. Reporting 0 while a tracker is down
        # would make the metric silent in the one case it exists for.
        failures, not_before = self._backoff.get(subscription_id, (0, now))
        if failures and now < not_before:
            self._stats["skipped_backoff"] += 1
            return lag

        for item in batch:
            extra = {"request_fn": self._request_fn} if self._request_fn else {}
            try:
                suggested, raw_status, payload = ticket_sync.fetch_ticket_status(
                    transport=endpoint["transport"],
                    base_url=endpoint["base_url"],
                    ticket_key=item["ticket_key"],
                    secret=endpoint["secret"],
                    extra_headers=endpoint["headers"],
                    auth_mode=endpoint["config"].get("auth_mode"),
                    timeout_seconds=self._settings.webhook_timeout_seconds,
                    allow_private=self._settings.webhook_allow_private_targets,
                    **extra,
                )
            except TicketSpecError as exc:
                # The subscription is misconfigured in a way only the request
                # can discover — `auth_mode: basic` with a secret that is not a
                # `user:token` pair is the one that exists. Left to propagate,
                # it aborted the whole tick with a traceback and nothing on the
                # rows, so the documented "read ticket_sync_error" was useless
                # and the only symptom was a growing lag. Recorded like any
                # other permanent per-ticket failure instead; no HTTP happened,
                # so there is nothing to back off from.
                suggested, raw_status, payload = None, None, {"error": str(exc)}
            self._stats["polled"] += 1
            error = payload.get("error")
            after = vulns_service.apply_ticket_status(
                self._settings,
                tenant_id=endpoint["tenant_id"],
                vuln_id=item["vuln_id"],
                suggested_state=suggested,
                raw_status=raw_status,
                error=error,
                actor=f"system:ticket_sync:{endpoint['transport']}",
                # The worker records only what changed — see
                # ``apply_ticket_status`` on why a per-tick "nothing happened"
                # row per finding is not an audit trail.
                record_unchanged=False,
                # And on why a poller must not re-impose its own last verdict
                # on an operator who overruled it.
                only_on_remote_change=True,
            )
            if error:
                self._stats["failed"] += 1
                metrics_service.TICKET_SYNC_POLLS_TOTAL.labels(
                    transport=endpoint["transport"], outcome="failed"
                ).inc()
                if payload.get("retryable"):
                    # The tracker, not this ticket. Stop asking it this tick.
                    self._hold_off(subscription_id, now, error)
                    return lag
                continue
            moved = after is not None and after["state"] != item["state"]
            metrics_service.TICKET_SYNC_POLLS_TOTAL.labels(
                transport=endpoint["transport"],
                outcome="applied" if moved else "unchanged",
            ).inc()
            if moved:
                self._stats["applied"] += 1
                LOG.info(
                    "Ticket sync moved %s %s → %s (ticket %s reports %r)",
                    item["vuln_id"],
                    item["state"],
                    after["state"],
                    item["ticket_key"],
                    raw_status,
                )
            # One readable ticket is enough to know the tracker is back.
            self._backoff.pop(subscription_id, None)
        return lag

    def _hold_off(self, subscription_id: str, now: datetime, error: str | None) -> None:
        failures = self._backoff.get(subscription_id, (0, now))[0] + 1
        delay = min(
            self._settings.ticket_sync_retry_base_seconds * (2 ** (failures - 1)),
            self._settings.ticket_sync_retry_max_seconds,
        )
        self._backoff[subscription_id] = (failures, now + timedelta(seconds=delay))
        LOG.warning(
            "Ticket sync: subscription %s held off %ds after %d failure(s): %s",
            subscription_id,
            delay,
            failures,
            error,
        )


_WORKER: TicketSyncWorker | None = None


def start_worker(settings: Settings) -> TicketSyncWorker | None:
    global _WORKER
    if not (settings.webhooks_enabled and settings.ticket_sync_enabled):
        return None
    if _WORKER is not None:
        return _WORKER
    worker = TicketSyncWorker(settings=settings)
    worker.start()
    _WORKER = worker
    return worker


def stop_worker() -> None:
    global _WORKER
    if _WORKER is not None:
        _WORKER.stop()
        _WORKER = None


def worker_stats() -> dict[str, Any] | None:
    return None if _WORKER is None else _WORKER.stats
