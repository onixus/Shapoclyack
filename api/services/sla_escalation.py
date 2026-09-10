"""The worker that makes a missed deadline an event (#349).

``sla_state`` is derived on read (``api/services/vulnerabilities.py``): a
finding is breached because ``due_at`` is in the past, not because anything
wrote it down. That is the right model for the column — a stored breach flag
needs a sweeper to stay true and can be frozen wrong by whichever replica wrote
last — but it left the platform unable to *tell* anyone. Nothing happened when
a deadline passed; the breach existed for as long as somebody had the console
open on the list it appeared in.

This thread is the missing half. Every tick it looks for four things and turns
each into an event exactly once:

``sla_breached`` / ``sla_due_soon``
    Findings whose deadline has passed, or falls inside
    ``vulnerabilities.DUE_SOON_DAYS``.

``exception_expiring``
    Accepted risk about to lapse, at 30, 14 and 7 days. The event and its
    emitter are here; the *approval* workflow for exceptions is #348 and this
    module deliberately does not touch it — it reads ``exception_until`` and
    says what it sees.

``agent_offline``
    An agent whose ``last_seen_at`` crossed ``OCTO_AGENT_STALE_SECONDS``.
    Derived on read for the same reason SLA state is (``Agent.status`` never
    stores "stale"), and therefore invisible to anyone not looking, for the
    same reason.

The escalation *actions* — reassign, raise severity — are applied only where
the tenant asked for them (``sla_escalation_policies``), and the daily digest
only where the tenant asked for that. See ``models.SlaEscalationPolicy``.

**Once, not every tick.** The predicate is true again a minute later, so
without a durable record this thread would page a tenant's on-call in a loop.
``workflow_events.emit_once`` claims the occurrence in
``workflow_event_markers`` first and emits only if the claim was won; the claim
key includes the deadline, so a clock that restarts is announced again and the
same deadline is not.

The escalation *write* is claimed the same way, under its own marker kind
(``workflow_events.MARKER_KIND_ESCALATION``), because "already assigned where
the policy points" is not a durable no-op: an operator who takes a breached
finding off the escalation address would otherwise have it taken back on the
next tick, with another ``escalated`` row in the trail each time.

**Leader-locked**, by the pattern of ``api/services/reports/dispatcher.py``:
every replica would otherwise wake for the same due finding. The lock is not
fenced, which does not matter for either half — the markers' unique constraint
decides between two brief leaders for the notifications and for the escalation
alike.
"""

from __future__ import annotations

import logging
import math
import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, tuple_

from api.db import models
from api.db.engine import get_session
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.services import workflow_events
from api.services.leader_lock import SLA_ESCALATION_LOCK_ID, LeaderLock
from api.services.reports import delivery as mail
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.sla-escalation")

#: When an accepted exception is announced as expiring, in days remaining.
#: Three notices rather than one, because an exception is somebody's decision
#: to revisit and the revisiting takes longer than the notice period does. Only
#: the nearest threshold that has been reached is announced — a 5-day exception
#: produces one event, not three (see :meth:`SlaEscalationWorker._exceptions`).
EXCEPTION_WARN_DAYS = (30, 14, 7)

#: How many findings one digest email lists before it stops and says how many
#: more there are. A mail with four hundred rows in it is not read.
DIGEST_MAX_ROWS = 25


def _now() -> datetime:
    return datetime.now(UTC)


def _naive(value: datetime | None) -> datetime | None:
    """Drop the tzinfo, as ``vulnerabilities`` does: the columns are naive UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=None) if value.tzinfo is not None else value


def _stamp(value: datetime | None) -> str:
    """A deadline as a marker token. Empty for NULL, which cannot happen for a
    candidate (the query requires ``due_at``) but must not crash if it does."""
    return value.isoformat() if value is not None else ""


class SlaEscalationWorker:
    def __init__(self, *, settings: Settings, interval_seconds: float | None = None) -> None:
        self._settings = settings
        self._interval = float(
            interval_seconds
            if interval_seconds is not None
            else settings.sla_escalation_interval_seconds
        )
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = LeaderLock(
            settings.postgres_url,
            object_id=SLA_ESCALATION_LOCK_ID,
            name="SLA escalation worker",
        )
        self._stats: dict[str, Any] = {
            "ticks": 0,
            "breached": 0,
            "due_soon": 0,
            "exception_expiring": 0,
            "agents_offline": 0,
            "escalated": 0,
            "digests_sent": 0,
            "digest_failures": 0,
            "pruned": 0,
            "skipped_not_leader": 0,
            "errors": 0,
            "last_run_at": None,
        }
        self._last_prune: datetime | None = None
        #: Per-tenant keyset cursor over the due-finding window, see
        #: :meth:`_due_findings`. In memory rather than in a table: a worker
        #: that restarts (or a lock that moves to another replica) starts the
        #: sweep from the oldest deadline again, which the markers make
        #: harmless — the claims are already taken and nothing is announced
        #: twice.
        self._due_cursor: dict[str, tuple[datetime, str] | None] = {}
        #: The same cursor over the expiring-exception window, and for the same
        #: reason: an exception stays inside the 30-day horizon for a month, so
        #: a re-read window would warn about the first N and starve the rest.
        self._exception_cursor: dict[str, tuple[datetime, str] | None] = {}

    @property
    def stats(self) -> dict[str, Any]:
        return {**self._stats, "is_leader": int(self._lock.is_leader)}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="octo-sla-escalation", daemon=True
        )
        self._thread.start()
        LOG.info("SLA escalation worker started (interval=%.0fs)", self._interval)

    def stop(self, *, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        self._lock.release()
        LOG.info("SLA escalation worker stopped stats=%s", self.stats)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                if self._lock.acquire():
                    self.tick()
                else:
                    self._stats["skipped_not_leader"] += 1
            except Exception:  # noqa: BLE001
                self._stats["errors"] += 1
                LOG.exception("SLA escalation tick failed")
            self._stop.wait(self._interval)

    # ----------------------------------------------------------------------
    # One pass
    # ----------------------------------------------------------------------

    def tick(self, now: datetime | None = None) -> dict[str, Any]:
        """One pass over every tenant. Public so tests drive it directly."""
        from api.services import tenants as tenants_service

        now = now or _now()
        self._stats["ticks"] += 1
        self._stats["last_run_at"] = now.isoformat().replace("+00:00", "Z")
        self._prune(now)

        try:
            tenant_ids = [tenant["tenant_id"] for tenant in tenants_service.list_tenants()]
        except Exception:  # noqa: BLE001 - a tenant-store hiccup must not kill the thread
            self._stats["errors"] += 1
            LOG.exception("SLA escalation: could not list tenants")
            return dict(self._stats)

        for tenant_id in tenant_ids:
            try:
                self._tenant_tick(tenant_id, now)
            except Exception:  # noqa: BLE001 - keep going through the other tenants
                self._stats["errors"] += 1
                LOG.exception("SLA escalation failed for tenant %s", tenant_id)
        try:
            self._agents(now)
        except Exception:  # noqa: BLE001
            self._stats["errors"] += 1
            LOG.exception("SLA escalation: offline-agent sweep failed")
        return dict(self._stats)

    def _tenant_tick(self, tenant_id: str, now: datetime) -> None:
        policy = vulns_service.get_escalation_policy(self._settings, tenant_id=tenant_id)
        candidates = self._due_findings(tenant_id, now)
        # ``enabled`` is the policy's one off switch and covers the mail as well
        # as the writes: a tenant that turned escalation off did not ask to keep
        # receiving its digests.
        digest_on = policy["enabled"] and policy["digest_enabled"]
        for finding, owner_email in candidates:
            state = finding["sla_state"]
            if state not in ("breached", "due_soon"):  # pragma: no cover
                # The query selects only these two, but a row whose acceptance
                # expired between the SELECT and here would read differently,
                # and ``sla_{state}`` has to name a real kind.
                continue
            escalation = self._escalate(finding, policy, now) if state == "breached" else None
            emitted = workflow_events.emit_once(
                self._settings,
                f"sla_{state}",
                tenant_id=tenant_id,
                subject_id=finding["vuln_id"],
                # The deadline, so a reopen (which recomputes ``due_at``) is a
                # new occurrence and the same deadline is not.
                marker=_stamp(finding["_due_at"]),
                data=vulns_service.workflow_event_data(
                    finding,
                    owner_email=owner_email,
                    days_overdue=_days_between(finding["_due_at"], now),
                    escalation=escalation,
                ),
                now=now,
            )
            if emitted:
                self._stats["breached" if state == "breached" else "due_soon"] += 1
        self._exceptions(tenant_id, now)
        if digest_on:
            self._send_digests(tenant_id, self._digest_population(tenant_id, now), now)

    # ----------------------------------------------------------------------
    # Candidates
    # ----------------------------------------------------------------------

    def _due_findings(
        self, tenant_id: str, now: datetime
    ) -> list[tuple[dict[str, Any], str | None]]:
        """One window of active findings at or inside their deadline, with the
        asset's owner.

        Ordered by deadline, so the tick budget
        (``OCTO_SLA_ESCALATION_MAX_FINDINGS``) spends itself on the oldest
        breaches: a tenant that imports a backlog of ten thousand overdue
        findings must not turn one tick into ten thousand deliveries.

        The budget is a *window*, not a ceiling, and the cursor is what makes
        the difference. Nothing drops out of this query once it has been
        announced — the finding is still open, still past its deadline and
        still the oldest — so a query that re-read the first N rows every tick
        would announce those N and nothing else, ever: the (N+1)th breach would
        wait for somebody to close one of the first N by hand. Instead each
        tick continues after the last row the previous one saw (a keyset cursor
        on ``(due_at, vuln_id)`` — the pair, because deadlines tie). A tick
        that does not fill its window has reached the end of the backlog and
        resets, so the next one starts from the oldest deadline again and picks
        up whatever became due meanwhile; the markers make that pass silent.

        Accepted risk is excluded here rather than filtered afterwards. An
        acceptance suspends the clock, so a suspended finding is not breached —
        that is what ``sla_state`` returns and this query has to agree with it,
        or the two would disagree about the same row.
        """
        limit = max(1, int(self._settings.sla_escalation_max_findings))
        naive_now = _naive(now)
        after = self._due_cursor.get(tenant_id)
        query = (
            select(models.Vulnerability, models.Asset.owner_email)
            .join(models.Asset, models.Asset.asset_id == models.Vulnerability.asset_id)
            .where(*self._due_clause(tenant_id, naive_now))
        )
        if after is not None:
            query = query.where(
                tuple_(models.Vulnerability.due_at, models.Vulnerability.vuln_id) > after
            )
        with get_session(self._settings.postgres_url) as session:
            rows = session.execute(
                query.order_by(
                    models.Vulnerability.due_at.asc(), models.Vulnerability.vuln_id.asc()
                ).limit(limit)
            ).all()
            out: list[tuple[dict[str, Any], str | None]] = []
            for row, owner_email in rows:
                finding = vulns_service._to_dict(row, now=naive_now)  # noqa: SLF001
                # The datetime itself, next to its serialised form: the marker
                # and the overdue arithmetic both want the object, and
                # re-parsing the ISO string to get it back would be the same
                # value said twice.
                finding["_due_at"] = row.due_at
                out.append((finding, owner_email))
            self._due_cursor[tenant_id] = (
                (rows[-1][0].due_at, rows[-1][0].vuln_id) if len(rows) == limit else None
            )
        return out

    def _due_clause(self, tenant_id: str, naive_now: datetime) -> tuple[Any, ...]:
        """What "at or inside the deadline" means, for the two queries that ask.

        Shared rather than repeated: the announcement window and the digest
        population have to describe the same set of findings, and two copies of
        this predicate would eventually describe two.
        """
        horizon = naive_now + timedelta(days=vulns_service.DUE_SOON_DAYS)
        return (
            models.Vulnerability.tenant_id == tenant_id,
            models.Vulnerability.state != vuln_states.CLOSED,
            models.Vulnerability.due_at.is_not(None),
            models.Vulnerability.due_at <= horizon,
            (models.Vulnerability.exception_until.is_(None))
            | (models.Vulnerability.exception_until <= naive_now),
        )

    def _digest_population(
        self, tenant_id: str, now: datetime
    ) -> dict[str, list[dict[str, Any]]]:
        """Everything on each asset owner's plate today, grouped by owner.

        Read separately from the announcement window on purpose. The digest is
        "what is overdue for you", not a change feed — a breach announced
        yesterday is still overdue this morning — so it must not shrink to the
        findings this particular tick happened to announce, which is what
        sharing the cursored query of :meth:`_due_findings` would do. Bounded
        by the same ``OCTO_SLA_ESCALATION_MAX_FINDINGS``, oldest deadline
        first; the mail itself lists ``DIGEST_MAX_ROWS`` and counts the rest.
        """
        naive_now = _naive(now)
        digest: dict[str, list[dict[str, Any]]] = {}
        with get_session(self._settings.postgres_url) as session:
            rows = session.execute(
                select(models.Vulnerability, models.Asset.owner_email)
                .join(models.Asset, models.Asset.asset_id == models.Vulnerability.asset_id)
                .where(
                    *self._due_clause(tenant_id, naive_now),
                    models.Asset.owner_email.is_not(None),
                    models.Asset.owner_email != "",
                )
                .order_by(models.Vulnerability.due_at.asc())
                .limit(max(1, int(self._settings.sla_escalation_max_findings)))
            ).all()
            for row, owner_email in rows:
                finding = vulns_service._to_dict(row, now=naive_now)  # noqa: SLF001
                if finding["sla_state"] in ("breached", "due_soon"):
                    digest.setdefault(owner_email, []).append(finding)
        return digest

    def _exceptions(self, tenant_id: str, now: datetime) -> None:
        """Announce accepted risk that is about to lapse, once per threshold.

        Only the *nearest* threshold reached is announced, and the ones above
        it are claimed silently: an exception granted for five days would
        otherwise trip 30, 14 and 7 on its first tick and send three mails
        about one decision.

        Windowed by the same cursor as :meth:`_due_findings`, for the reason
        given there.
        """
        limit = max(1, int(self._settings.sla_escalation_max_findings))
        naive_now = _naive(now)
        horizon = naive_now + timedelta(days=max(EXCEPTION_WARN_DAYS))
        after = self._exception_cursor.get(tenant_id)
        query = select(models.Vulnerability).where(
            models.Vulnerability.tenant_id == tenant_id,
            models.Vulnerability.state != vuln_states.CLOSED,
            models.Vulnerability.exception_until.is_not(None),
            models.Vulnerability.exception_until > naive_now,
            models.Vulnerability.exception_until <= horizon,
        )
        if after is not None:
            query = query.where(
                tuple_(models.Vulnerability.exception_until, models.Vulnerability.vuln_id)
                > after
            )
        with get_session(self._settings.postgres_url) as session:
            rows = session.execute(
                query.order_by(
                    models.Vulnerability.exception_until.asc(),
                    models.Vulnerability.vuln_id.asc(),
                ).limit(limit)
            ).scalars().all()
            pending = [
                (vulns_service._to_dict(row, now=naive_now), row.exception_until)  # noqa: SLF001
                for row in rows
            ]
            self._exception_cursor[tenant_id] = (
                (rows[-1].exception_until, rows[-1].vuln_id) if len(rows) == limit else None
            )

        for finding, until in pending:
            days_left = _days_between(until, now, ceiling=True)
            reached = [days for days in EXCEPTION_WARN_DAYS if days_left <= days]
            if not reached:
                continue
            claimed = [
                days
                for days in reached
                if workflow_events.claim(
                    self._settings,
                    tenant_id=tenant_id,
                    kind="exception_expiring",
                    subject_id=finding["vuln_id"],
                    marker=f"{_stamp(until)}:{days}",
                    now=now,
                )
            ]
            if not claimed:
                continue
            threshold = min(reached)
            self._stats["exception_expiring"] += 1
            workflow_events.emit(
                self._settings,
                "exception_expiring",
                tenant_id=tenant_id,
                subject_id=finding["vuln_id"],
                marker=f"{_stamp(until)}:{threshold}",
                data=vulns_service.workflow_event_data(
                    finding,
                    exception_until=finding["exception_until"],
                    exception_reason=finding["exception_reason"],
                    exception_by=finding["exception_by"],
                    days_remaining=days_left,
                    threshold_days=threshold,
                ),
                occurred_at=now,
            )

    def _agents(self, now: datetime) -> None:
        """Announce agents that have gone quiet, once per silence.

        The marker is the agent's ``last_seen_at``, so an agent that comes back
        and later goes quiet again is announced again, while one that has been
        down for a week is announced once. Retired and quarantined agents are
        skipped: an agent an operator deliberately took out of service is not
        news, and paging on it is how a fleet's alerts get muted.
        """
        cutoff = _naive(now) - timedelta(seconds=self._settings.agent_stale_seconds)
        with get_session(self._settings.postgres_url) as session:
            rows = session.execute(
                select(models.Agent).where(
                    models.Agent.lifecycle_status == "active",
                    models.Agent.last_seen_at < cutoff,
                )
            ).scalars().all()
            pending = [
                {
                    "agent_id": row.agent_id,
                    "tenant_id": row.tenant_id,
                    "hostname": row.hostname,
                    "version": row.version,
                    "status": row.status,
                    "last_seen_at": row.last_seen_at,
                }
                for row in rows
            ]

        for agent in pending:
            last_seen = agent.pop("last_seen_at")
            emitted = workflow_events.emit_once(
                self._settings,
                "agent_offline",
                tenant_id=agent["tenant_id"],
                subject_id=agent["agent_id"],
                marker=_stamp(last_seen),
                data={
                    **agent,
                    "last_seen_at": _stamp(last_seen),
                    "silent_for_seconds": int(_seconds_between(last_seen, now)),
                    "stale_after_seconds": self._settings.agent_stale_seconds,
                },
                now=now,
            )
            if emitted:
                self._stats["agents_offline"] += 1

    # ----------------------------------------------------------------------
    # Actions
    # ----------------------------------------------------------------------

    def _escalate(
        self, finding: dict[str, Any], policy: dict[str, Any], now: datetime
    ) -> dict[str, Any] | None:
        """Apply the tenant's escalation to one breached finding, if it applies.

        Once per missed deadline, claimed in ``workflow_event_markers`` like
        the events: the write is not idempotent against a human being, only
        against itself.

        Returns what changed, so the event that follows carries it — an
        ``sla_breached`` that quietly reassigned the finding, and did not say
        so, would leave the receiver's copy of the owner wrong.
        """
        if not policy["enabled"]:
            return None
        grace = timedelta(days=int(policy["escalate_after_days"] or 0))
        due = finding["_due_at"]
        if due is not None and _naive(now) < due + grace:
            return None
        if not workflow_events.claim(
            self._settings,
            tenant_id=finding["tenant_id"],
            kind=workflow_events.MARKER_KIND_ESCALATION,
            subject_id=finding["vuln_id"],
            marker=_stamp(due),
            now=now,
        ):
            # This deadline has already been escalated. Claimed rather than
            # inferred from the row's current state: "already assigned where
            # the policy points" stops being true the moment an operator picks
            # the finding up, and re-applying the policy then would take it
            # back off them every fifteen minutes and write an ``escalated``
            # row in the trail each time. Once per missed deadline means once.
            return None
        result = vulns_service.escalate(
            self._settings,
            tenant_id=finding["tenant_id"],
            vuln_id=finding["vuln_id"],
            assignee=policy["escalate_to"],
            owner_team=policy["escalate_owner_team"],
            bump_severity=policy["bump_severity"],
        )
        if result is None:
            # Nothing left to change: already assigned there, already critical.
            return None
        self._stats["escalated"] += 1
        # The event describes the finding *after* the escalation, so the caller
        # re-reads the fields the write touched rather than announcing the row
        # it had before.
        for key in ("assignee", "owner_team", "severity", "state"):
            finding[key] = result[key]
        return result["escalation"]

    def _send_digests(
        self, tenant_id: str, digest: dict[str, list[dict[str, Any]]], now: datetime
    ) -> None:
        """One mail per asset owner per day, listing their overdue work.

        Claimed through the marker table like the events, keyed on the calendar
        day: a worker ticking every fifteen minutes must not mail somebody
        ninety-six times. A relay that refuses releases the claim again, so the
        failure costs a quarter of an hour rather than the day. The recipient
        is ``Asset.owner_email`` — who runs the
        box — deliberately, not ``Vulnerability.assignee``: the assignee gets
        the ``sla_breached`` event on whatever channel their tenant configured,
        while the digest exists for the person whose machine it is and who has
        no webhook.
        """
        day = _naive(now).date().isoformat()
        for owner_email, findings in sorted(digest.items()):
            if not workflow_events.claim(
                self._settings,
                tenant_id=tenant_id,
                kind=workflow_events.MARKER_KIND_DIGEST,
                subject_id=owner_email,
                marker=day,
                now=now,
            ):
                continue
            subject, body = _digest_message(tenant_id, findings, now)
            # #351 substitutes the tenant's own channel here; see
            # ``reports.delivery.send_notice``.
            error = mail.send_notice(
                self._settings, to=owner_email, subject=subject, body=body
            )
            if error:
                self._stats["digest_failures"] += 1
                # Give the day back. The claim exists so a fifteen-minute tick
                # does not mail somebody ninety-six times, not so that one
                # "421 too many connections" at 00:07 costs the owner the whole
                # day's digest; the next tick tries again.
                workflow_events.release(
                    self._settings,
                    tenant_id=tenant_id,
                    kind=workflow_events.MARKER_KIND_DIGEST,
                    subject_id=owner_email,
                    marker=day,
                )
                LOG.warning("SLA digest to %s was not sent: %s", owner_email, error)
            else:
                self._stats["digests_sent"] += 1

    def _prune(self, now: datetime) -> None:
        """Marker retention, at most hourly. Folded into this thread rather
        than given its own: it is a bounded DELETE that only the leader should
        run, which is exactly the thread already elected for that."""
        if self._last_prune is not None and now - self._last_prune < timedelta(hours=1):
            return
        self._last_prune = now
        try:
            self._stats["pruned"] += workflow_events.prune_markers(self._settings, now=now)
        except Exception:  # noqa: BLE001
            self._stats["errors"] += 1
            LOG.exception("Workflow marker retention sweep failed")


def _seconds_between(earlier: datetime | None, later: datetime) -> float:
    if earlier is None:
        return 0.0
    delta = _naive(later) - _naive(earlier)
    return delta.total_seconds()


def _days_between(earlier: datetime | None, later: datetime, *, ceiling: bool = False) -> int:
    """Whole days between two naive-UTC stamps, signed.

    ``ceiling`` is for a countdown: an exception with 6 hours left has one day
    remaining, not zero, because "0 days" reads as expired.
    """
    seconds = _seconds_between(earlier, later)
    days = seconds / 86400.0
    return int(math.ceil(-days)) if ceiling else int(days)


def _digest_message(
    tenant_id: str, findings: list[dict[str, Any]], now: datetime
) -> tuple[str, str]:
    """Subject and plain-text body for one owner's digest.

    Plain text and no HTML: it is an operational mail listing rows, the report
    mailer next to it is the thing that sends attachments, and an HTML body
    would be one more template to keep in step with the branding tables.
    """
    breached = [item for item in findings if item["sla_state"] == "breached"]
    due_soon = [item for item in findings if item["sla_state"] == "due_soon"]
    subject = (
        f"[{tenant_id}] {len(breached)} finding(s) past SLA, "
        f"{len(due_soon)} due within {vulns_service.DUE_SOON_DAYS} days"
    )
    lines = [
        f"Remediation SLA summary for {now.date().isoformat()} (tenant {tenant_id}).",
        "",
    ]
    for title, group in (("Past SLA", breached), ("Due soon", due_soon)):
        if not group:
            continue
        lines.append(f"{title} ({len(group)}):")
        for item in group[:DIGEST_MAX_ROWS]:
            name = item["cve"] or item["script_id"] or item["title"] or item["vuln_id"]
            port = f":{item['port']}" if item["port"] else ""
            lines.append(
                f"  - {name} [{item['severity']}] {item['asset_id']}{port} "
                f"due {item['due_at']} state {item['state']}"
            )
        if len(group) > DIGEST_MAX_ROWS:
            lines.append(f"  … and {len(group) - DIGEST_MAX_ROWS} more")
        lines.append("")
    lines.append("Open the console for the full list and to record what you are doing about it.")
    return subject, "\n".join(lines)


_WORKER: SlaEscalationWorker | None = None


def start_worker(settings: Settings) -> SlaEscalationWorker | None:
    global _WORKER
    if not (settings.workflow_events_enabled and settings.sla_escalation_enabled):
        return None
    if _WORKER is not None:
        return _WORKER
    worker = SlaEscalationWorker(settings=settings)
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
