"""Retro matches as tracked findings, and the events that announce them.

``retro_match.py`` answers *which CVEs does this stored fingerprint carry*; this
module folds that answer into the ``vulnerabilities`` table the scanner writes,
so a CVE found by re-asking the NVD dataset is the same kind of object — with
an owner, a deadline, a ticket — as one a scan found. The design and the
reasoning for each rule below are in ``docs/retro-cve-matching.md``.

**Identity is the scan's.** A retro finding is keyed with
``vulnerabilities.finding_key(asset, CVE, port)`` — the very key the scan path
uses — because it *is* the same finding: "CVE-2024-6387 on port 22 of this
host" does not become a second piece of work because a dataset said so before
a scanner did. One row, whichever observer got there first.

**Retro creates and refreshes; it never closes and never reopens.**

* No row for the key: a new ``OPEN`` finding, ``source = "retro_match"``, with
  the tenant's SLA like any other.
* A row from another observer (a scan saw it): left exactly as it is, and not
  even locked. The scan observed the listener directly and owns the row.
* A ``retro_match`` row still open: its assessment is refreshed (severity,
  score, confidence, evidence) and nothing is written to its audit trail — a
  re-match of the same fingerprint is not an observation.
* A ``retro_match`` row that is ``CLOSED``: left closed. Whoever closed it
  decided about exactly this statement, and the dataset re-stating it is not
  new evidence. A regression reopens through the scan path, which observes the
  listener.

And absence closes nothing: a fingerprint that stops matching leaves the
finding open. Closure of a network finding is the scan path's.

**The fold always yields to the scan.** The two write the same keys, and the
scan's fold of a whole run is one transaction that must not be the one that
dies. So a listener is folded in a transaction of its own, lock waits in it
are capped at :data:`LOCK_TIMEOUT` (below Postgres's ``deadlock_timeout``, so
the retro side times out before a deadlock can be detected and a victim
chosen), and a timeout is an ordinary failure: the listener is held off and
retried. Only ``retro_match`` rows are ever locked here. The other half is in
``vulnerabilities.register_findings_from_run``, whose insert is a SAVEPOINT so
that losing the race to a retro insert is a re-observation, not a lost run.

**Only ``vulnerable`` becomes a finding.** ``possible`` — NVD says affected,
the banner names a distribution whose backports we cannot see — stays on the
service row (``asset_services.match_summary``), with no deadline.

**Announcements are durable and bounded.** A new finding is committed with
``match_announced_at`` NULL; :func:`announce_pending` publishes what is still
unannounced and only then stamps it. A process killed in between re-announces
on the next tick — the event ids are content-derived, so JetStream drops the
duplicate — and one killed before publishing loses nothing. Per tenant and per
dataset version at most ``OCTO_RETRO_MATCH_MAX_EVENTS`` findings are announced
one by one, worst first; everything beyond is one aggregate ``new_cve`` per
tick (``data.aggregate = true``). Every finding is created regardless.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import case, func, select, update

from api.db import models
from api.db.engine import get_session, insert_if_absent
from api.services import retro_match, vuln_states
from api.services import vulnerabilities as vulns_service
from api.services.cpe_ranges import CpeRangeDataset
from api.services.risk_scoring import get_scorer
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.retro-findings")

#: ``Vulnerability.source`` for everything this module writes.
SOURCE = "retro_match"

#: How many ``possible`` statements are kept on a service row. The count is
#: always exact; the list is for the asset page, which shows the worst first.
POSSIBLE_SAMPLE = 50

#: Longest a retro transaction waits for a row lock. Postgres's default
#: ``deadlock_timeout`` is 1 s: waiting less means the retro side gives up
#: before the deadlock detector would pick a victim, which could be the scan.
LOCK_TIMEOUT = "500ms"

#: Unannounced findings read per announcement pass. The rest wait for the next
#: tick, still unannounced.
ANNOUNCE_BATCH = 5000

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

#: Backoff after consecutive failures on one service row, worst case six hours
#: — the same ladder the software matcher uses, for the same reason.
_RETRY_BACKOFF_SECONDS = (60, 300, 900, 3600, 21600)


def _now() -> datetime:
    return vulns_service._now()  # noqa: SLF001 - one clock for the whole table


@dataclass
class RetroStats:
    """What one fold pass did. Mutable, because a sweep accumulates it."""

    services: int = 0
    #: Services the matcher could say something about (a known product with
    #: a disclosed version).
    assessed: int = 0
    vulnerable: int = 0
    possible: int = 0
    fixed: int = 0
    not_affected: int = 0
    created: int = 0
    refreshed: int = 0
    #: A scan's own finding already carries the key; left to the scan.
    already_tracked: int = 0
    #: A retro finding an operator (or a ticket) closed; left closed.
    held_closed: int = 0
    #: Listeners not observed within ``OCTO_RETRO_MATCH_MAX_AGE_DAYS``.
    too_old: int = 0
    errors: int = 0

    def add(self, other: RetroStats) -> None:
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


def _fingerprint(row: models.AssetService) -> retro_match.Fingerprint:
    return retro_match.Fingerprint(
        product=row.product or "",
        version=row.version or "",
        banner=row.banner or "",
        cpe=tuple(str(c) for c in (row.cpe or [])),
        service=row.service or "",
    )


def _summary(outcome: retro_match.MatchOutcome, *, status: str) -> dict[str, Any]:
    possible = sorted(
        (m for m in outcome.matches if m.verdict == retro_match.POSSIBLE),
        key=lambda m: (_SEVERITY_RANK.get(m.severity, 0), m.cvss or 0.0),
        reverse=True,
    )
    return {
        "status": status,
        "counts": outcome.counts(),
        "product_keys": list(outcome.product_keys),
        "upstream_version": outcome.upstream_version,
        "possible": [
            {
                "cve": m.cve,
                "severity": m.severity,
                "cvss": m.cvss,
                "reason": (m.evidence.get("advisory") or {}).get("reason"),
            }
            for m in possible[:POSSIBLE_SAMPLE]
        ],
    }


def _latest(
    match: retro_match.Match,
    *,
    service: models.AssetService,
    asset: models.Asset,
) -> dict[str, Any]:
    """The assessment columns for one match, through the scan path's scorer."""
    item = {
        "cve": match.cve,
        "severity": match.severity,
        "cvss": match.cvss,
        # A listener a scan reached, so the address is a real observation and
        # exposure may be resolved from it, unlike the endpoint inventory's.
        "host": service.host or None,
        "port": str(service.port),
        # The class Pulse gives its own version-to-CVE hits, which is what this
        # is; no confidence discount, same as Pulse's.
        "finding_class": "version_cve",
    }
    scored = get_scorer().score_vulnerability(
        item,
        operator_exposure=asset.exposure_level,
        asset_criticality_override=asset.asset_criticality,
    )
    product = " ".join(part for part in (service.product, match.evidence.get("upstream_version")) if part)
    return {
        "severity": match.severity,
        "risk_level": scored.get("risk_level"),
        "contextual_score": scored.get("contextual_score"),
        "cvss": match.cvss if match.cvss is not None else (scored.get("base_cvss") or None),
        "in_kev": bool(scored.get("exploit_active")),
        "exploit_maturity": scored.get("exploit_maturity"),
        "network_exposure": scored.get("network_exposure"),
        "network_exposure_source": scored.get("network_exposure_source"),
        "title": f"{match.cve} — {product}"[:500] if product else match.cve,
        "match_confidence": match.confidence,
        "match_evidence": match.evidence,
    }


def _find(session: Any, *, tenant_id: str, key: str, lock: bool) -> models.Vulnerability | None:
    query = select(models.Vulnerability).where(
        models.Vulnerability.tenant_id == tenant_id,
        models.Vulnerability.finding_key == key,
    )
    if lock:
        query = query.with_for_update()
    return session.execute(query).scalar_one_or_none()


def _fold_service(
    session: Any,
    *,
    tenant_id: str,
    service: models.AssetService,
    dataset: CpeRangeDataset,
    lookup: retro_match.AdvisoryLookup,
    max_age_days: int,
    now: datetime,
) -> tuple[RetroStats, dict[str, Any]]:
    """One listener: ``(stats, match summary)``. Raises on anything unexpected;
    the caller owns the transaction and the backoff."""
    stats = RetroStats(services=1)
    if max_age_days > 0 and service.last_seen_at < now - timedelta(days=max_age_days):
        # A port nobody has seen open for months is not a statement about the
        # host any more; matching it would page on a service that is gone.
        stats.too_old = 1
        return stats, {"status": "too_old"}
    asset = session.get(models.Asset, service.asset_id)
    if asset is None or asset.tenant_id != tenant_id:  # pragma: no cover - FK cascade
        return stats, {"status": "no_asset"}

    outcome = retro_match.match(_fingerprint(service), dataset, lookup=lookup)
    if outcome.reason:
        return stats, _summary(outcome, status=outcome.reason)
    stats.assessed = 1
    counts = outcome.counts()
    stats.vulnerable = counts[retro_match.VULNERABLE]
    stats.possible = counts[retro_match.POSSIBLE]
    stats.fixed = counts[retro_match.FIXED]
    stats.not_affected = counts[retro_match.NOT_AFFECTED]

    port = str(service.port)
    for match in outcome.matches:
        if not match.is_finding:
            continue
        key = vulns_service.finding_key(
            asset_id=asset.asset_id, cve=match.cve, script_id=None, port=port
        )
        latest = _latest(match, service=service, asset=asset)
        # Read without a lock first: a row that is not ours is the scan's, and
        # locking it would make the scan's fold wait on a retro transaction.
        row = _find(session, tenant_id=tenant_id, key=key, lock=False)

        if row is None:
            days, sla_source = vulns_service._resolve_sla_days(  # noqa: SLF001
                session,
                tenant_id=tenant_id,
                severity=match.severity,
                criticality=asset.asset_criticality,
            )
            candidate = models.Vulnerability(
                vuln_id=f"vln_{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                asset_id=asset.asset_id,
                finding_key=key,
                source=SOURCE,
                cve=match.cve,
                script_id=None,
                port=port,
                state=vuln_states.OPEN,
                state_changed_at=now,
                assignee=asset.owner_email,
                owner_team=asset.business_unit,
                # From the match, not from when the listener was scanned: the
                # CVE was not knowable about this host until the dataset said so.
                due_at=now + timedelta(days=days),
                sla_days=days,
                sla_source=sla_source,
                first_seen_at=now,
                last_seen_at=now,
                sla_started_at=now,
                first_seen_run_id=service.last_run_id,
                last_seen_run_id=service.last_run_id,
                observation_count=1,
                created_at=now,
                updated_at=now,
                # Committed unannounced; announce_pending publishes and stamps.
                match_announced_at=None,
                **latest,
            )
            if insert_if_absent(session, candidate, f"retro {key}"):
                stats.created += 1
                vulns_service._record_event(  # noqa: SLF001
                    session,
                    vuln_id=candidate.vuln_id,
                    tenant_id=tenant_id,
                    kind="observed",
                    occurred_at=now,
                    to_state=vuln_states.OPEN,
                    detail={
                        "source": SOURCE,
                        "first_seen": True,
                        "confidence": match.confidence,
                        "severity": match.severity,
                        "product": service.product,
                        "version": service.version,
                        "range": match.evidence.get("range"),
                        "dataset": match.evidence.get("dataset"),
                        "due_at": vulns_service._iso(candidate.due_at),  # noqa: SLF001
                        "sla_days": days,
                        "sla_source": sla_source,
                    },
                )
                continue
            # A scan committed the key between the read and the insert.
            row = _find(session, tenant_id=tenant_id, key=key, lock=False)
            if row is None:  # pragma: no cover - the winner's row was deleted under us
                continue

        if row.source != SOURCE:
            stats.already_tracked += 1
            continue
        # Ours: now lock it (bounded by LOCK_TIMEOUT) and re-check, since a scan
        # may have taken it over, or someone closed it, since the plain read.
        row = _find(session, tenant_id=tenant_id, key=key, lock=True)
        if row is None or row.source != SOURCE:
            stats.already_tracked += 1
            continue
        if row.state == vuln_states.CLOSED:
            stats.held_closed += 1
            continue
        for name, value in latest.items():
            setattr(row, name, value)
        if service.last_seen_at > row.last_seen_at:
            # The listener was scanned again since the finding was last
            # touched: that, and only that, is a fresh observation of it.
            row.last_seen_at = service.last_seen_at
            row.last_seen_run_id = service.last_run_id
            row.observation_count += 1
        row.updated_at = now
        stats.refreshed += 1
    return stats, _summary(outcome, status="matched")


def _bound_lock_waits(session: Any) -> None:
    """Cap every lock wait in this transaction at :data:`LOCK_TIMEOUT` (Postgres).

    ``is_local = true``: the setting dies with the transaction and never leaks
    into the pooled connection's next user.
    """
    if session.get_bind().dialect.name == "postgresql":
        session.execute(select(func.set_config("lock_timeout", LOCK_TIMEOUT, True)))


def _hold_off(settings: Settings, *, service_id: int, now: datetime) -> None:
    """Keep a listener that raised out of the queue for a while.

    In a transaction of its own — the listener's own one has been rolled back
    by the time this runs. The marker is not advanced, so it is still due,
    just not yet.
    """
    with get_session(settings.postgres_url) as session:
        service = session.get(models.AssetService, service_id)
        if service is None:  # pragma: no cover - deleted with its asset meanwhile
            return
        failures = int(service.match_failure_count or 0) + 1
        delay = _RETRY_BACKOFF_SECONDS[min(failures, len(_RETRY_BACKOFF_SECONDS)) - 1]
        service.match_failure_count = failures
        service.match_retry_after = now + timedelta(seconds=delay)


def fold_services(
    settings: Settings,
    *,
    tenant_id: str,
    service_ids: list[int],
    dataset: CpeRangeDataset,
    marker: str,
    lookup: retro_match.AdvisoryLookup,
) -> RetroStats:
    """Match a batch of listeners and fold the result into the lifecycle.

    One transaction per listener, not per batch: a batch-long transaction held
    the locks of two hundred listeners' findings while the scan's fold waited
    on them. The listener's own row is locked first, so a scan recording a new
    fingerprint for it (``asset_services.record_run``) cannot be overwritten by
    a verdict about the old one. Whatever the fold concluded, the listener is
    stamped with ``marker``; one that raised — including a lock wait that ran
    past :data:`LOCK_TIMEOUT` — is held off instead.
    """
    stats = RetroStats()
    now = _now()
    max_age_days = int(settings.retro_match_max_age_days)
    for service_id in service_ids:
        try:
            with get_session(settings.postgres_url) as session:
                _bound_lock_waits(session)
                service = session.get(models.AssetService, service_id, with_for_update=True)
                if service is None or service.tenant_id != tenant_id:
                    continue
                one, summary = _fold_service(
                    session,
                    tenant_id=tenant_id,
                    service=service,
                    dataset=dataset,
                    lookup=lookup,
                    max_age_days=max_age_days,
                    now=now,
                )
                service.match_summary = summary
                service.matched_dataset_version = marker
                service.matched_at = now
                service.match_failure_count = 0
                service.match_retry_after = None
        except Exception:  # noqa: BLE001 - one listener must not stop the tenant
            stats.errors += 1
            LOG.exception(
                "Retro match: service %s failed to fold (tenant %s)", service_id, tenant_id
            )
            _hold_off(settings, service_id=service_id, now=now)
            continue
        stats.add(one)
    return stats


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------


def _event_id(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:48]


def build_events(
    created: list[dict[str, Any]],
    *,
    tenant_id: str,
    max_events: int,
    occurred_at: str,
) -> tuple[list[dict[str, Any]], int]:
    """``new_cve`` envelopes for new retro findings: ``(envelopes, summarised)``.

    Worst first, up to ``max_events`` one-per-finding; the rest collapse into a
    single aggregate event so a new dataset over a large estate is one
    notification and not ten thousand. ``summarised`` is how many findings the
    aggregate stands for. Ids are content-derived — one finding is one event
    id, one aggregate is the hash of the findings it covers — so a republish
    is dropped by JetStream as a duplicate.
    """
    if not created:
        return [], 0
    ordered = sorted(
        created,
        key=lambda item: (_SEVERITY_RANK.get(str(item.get("severity")), 0), item.get("cvss") or 0.0),
        reverse=True,
    )
    limit = max(0, int(max_events))
    individual, rest = ordered[:limit], ordered[limit:]
    envelopes: list[dict[str, Any]] = []
    for item in individual:
        envelopes.append(
            {
                "kind": "new_cve",
                "tenant_id": tenant_id,
                "run_id": None,
                "job_id": None,
                "asset_id": item["asset_id"],
                "host": item["host"],
                "port": item["port"],
                "occurred_at": occurred_at,
                "source": SOURCE,
                "data": {
                    "host": item["host"],
                    "port": item["port"],
                    "cve": item["cve"],
                    "severity": item["severity"],
                    "cvss": item.get("cvss"),
                    "asset_id": item["asset_id"],
                    "vuln_id": item["vuln_id"],
                    "confidence": item.get("confidence"),
                    "dataset": item.get("dataset"),
                    "source": SOURCE,
                },
                "event_id": _event_id(tenant_id, SOURCE, item["vuln_id"]),
            }
        )
    if rest:
        worst = max((_SEVERITY_RANK.get(str(i.get("severity")), 0) for i in rest), default=0)
        severity = next(
            (name for name, rank in _SEVERITY_RANK.items() if rank == worst), "unknown"
        )
        by_severity: dict[str, int] = {}
        for item in rest:
            name = str(item.get("severity") or "unknown")
            by_severity[name] = by_severity.get(name, 0) + 1
        envelopes.append(
            {
                "kind": "new_cve",
                "tenant_id": tenant_id,
                "run_id": None,
                "job_id": None,
                "host": None,
                "port": None,
                "occurred_at": occurred_at,
                "source": SOURCE,
                "data": {
                    "aggregate": True,
                    "count": len(rest),
                    # The worst of what is summarised, so a subscription's
                    # min_severity filter still lets a critical through.
                    "severity": severity,
                    "by_severity": by_severity,
                    "assets": len({i["asset_id"] for i in rest}),
                    "cves": sorted({i["cve"] for i in rest})[:20],
                    "dataset": rest[0].get("dataset"),
                    "source": SOURCE,
                },
                "event_id": _event_id(
                    tenant_id, SOURCE, "aggregate", *sorted(i["vuln_id"] for i in rest)
                ),
            }
        )
    return envelopes, len(rest)


def _pending(session: Any, *, tenant_id: str) -> list[dict[str, Any]]:
    """Unannounced retro findings, worst first, as event material."""
    severity_rank = case(
        *((models.Vulnerability.severity == name, rank) for name, rank in _SEVERITY_RANK.items()),
        else_=0,
    )
    rows = session.execute(
        select(models.Vulnerability)
        .where(
            models.Vulnerability.tenant_id == tenant_id,
            models.Vulnerability.source == SOURCE,
            models.Vulnerability.match_announced_at.is_(None),
        )
        .order_by(severity_rank.desc(), models.Vulnerability.created_at.asc())
        .limit(ANNOUNCE_BATCH)
    ).scalars().all()
    # The address the listener was scanned on, for the envelope's ``host`` —
    # what a scan's own new_cve names.
    hosts: dict[tuple[str, str], str] = {}
    if rows:
        for asset_id, port, host in session.execute(
            select(
                models.AssetService.asset_id, models.AssetService.port, models.AssetService.host
            ).where(
                models.AssetService.tenant_id == tenant_id,
                models.AssetService.asset_id.in_({row.asset_id for row in rows}),
            )
        ).all():
            hosts[(asset_id, str(port))] = host
    return [
        {
            "vuln_id": row.vuln_id,
            "asset_id": row.asset_id,
            "host": hosts.get((row.asset_id, str(row.port))),
            "port": row.port,
            "cve": row.cve,
            "severity": row.severity,
            "cvss": row.cvss,
            "confidence": row.match_confidence,
            "dataset": (row.match_evidence or {}).get("dataset"),
        }
        for row in rows
    ]


def announce_pending(settings: Settings, *, tenant_id: str, marker: str) -> dict[str, int]:
    """Publish the tenant's unannounced retro findings, then stamp them.

    At-least-once: publish first, stamp after. A process killed between the
    two re-announces on the next tick under the same event ids, which
    JetStream drops as duplicates; a broker that refuses is the outbox's
    problem (``asset_events.publish_events`` hands the envelopes over). With
    no bus configured nothing can ever be sent, so the findings are stamped
    without publishing — turning a bus on later must not flood it with a
    backlog of old "new" CVEs.

    The one-by-one budget is per tenant **per dataset version**
    (``retro_match_state.events_marker``): the wave a new dataset causes can
    span many ticks, and a per-tick cap would repeat itself on every one.
    """
    result = {"published": 0, "summarised": 0, "announced": 0}
    with get_session(settings.postgres_url) as session:
        pending = _pending(session, tenant_id=tenant_id)
        state = session.get(models.RetroMatchState, tenant_id)
        spent = (
            int(state.events_marker_individual or 0)
            if state is not None and state.events_marker == marker
            else 0
        )
    if not pending:
        return result
    budget = max(0, int(settings.retro_match_max_events) - spent)
    bus = bool(settings.asset_events_enabled and settings.nats_url)
    individual = 0
    if bus:
        from api.services import asset_events

        envelopes, summarised = build_events(
            pending,
            tenant_id=tenant_id,
            max_events=budget,
            occurred_at=asset_events._now_iso(),  # noqa: SLF001 - same clock as run events
        )
        individual = len(pending) - summarised
        result["summarised"] = summarised
        # Never raises: what the broker refuses goes to the outbox, which is
        # the retry for everything after this point.
        result["published"] = asset_events.publish_events(
            settings.nats_url, envelopes, settings=settings
        )
    now = _now()
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Vulnerability)
            .where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.vuln_id.in_([item["vuln_id"] for item in pending]),
            )
            .values(match_announced_at=now)
            .execution_options(synchronize_session=False)
        )
        state = _state_row(session, tenant_id)
        if state.events_marker != marker:
            state.events_marker = marker
            state.events_marker_individual = 0
        state.events_marker_individual = int(state.events_marker_individual or 0) + individual
        state.events_published = int(state.events_published or 0) + result["published"]
        state.events_suppressed = int(state.events_suppressed or 0) + result["summarised"]
    result["announced"] = len(pending)
    return result


def _state_row(session: Any, tenant_id: str) -> models.RetroMatchState:
    """The tenant's state row, locked; created on first use.

    Two writers can meet here — the worker and an operator's refresh — and
    both would otherwise insert the same primary key when the row does not
    exist yet. ``insert_if_absent`` makes losing that race a re-read.
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
