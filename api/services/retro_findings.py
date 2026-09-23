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
* A row from another observer (a scan saw it): left exactly as it is. The scan
  observed the listener directly and owns the row's lifecycle; a range
  statement adds nothing to that and must not overwrite it.
* A ``retro_match`` row still open: its assessment is refreshed (severity,
  score, confidence, evidence) and nothing is written to its audit trail — a
  re-match of the same fingerprint is not an observation.
* A ``retro_match`` row that is ``CLOSED``: left closed. Whoever closed it
  (an operator, a ticket, a false-positive verdict) decided about exactly this
  statement, and the dataset re-stating it is not new evidence. A regression
  reopens through the scan path, which observes the listener.

And absence closes nothing: a fingerprint that stops matching (the host was
upgraded, the vendor published a backport) leaves the finding open. Closure of
a network finding is the scan path's, and only for a scan it dispatched.

**Only ``vulnerable`` becomes a finding.** ``possible`` — NVD says affected,
the banner names a distribution whose backports we cannot see — stays on the
service row (``asset_services.match_summary``), with no deadline, because a
deadline on "maybe" is how an SLA report stops being read.

**Event volume is bounded.** A new dataset over a large estate can create
thousands of findings in one tick. Each tenant gets at most
``OCTO_RETRO_MATCH_MAX_EVENTS`` individual ``new_cve`` events per tick, worst
first; everything beyond that is one aggregate ``new_cve`` event carrying the
count and a sample (``data.aggregate = true``). Every finding is still created;
only the notification is summarised.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
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


def _fold_service(
    session: Any,
    *,
    tenant_id: str,
    service: models.AssetService,
    dataset: CpeRangeDataset,
    lookup: retro_match.AdvisoryLookup,
    max_age_days: int,
    now: datetime,
) -> tuple[RetroStats, dict[str, Any], list[dict[str, Any]]]:
    """One listener: ``(stats, match summary, findings created)``.

    Raises on anything unexpected; the caller holds the SAVEPOINT and the
    backoff.
    """
    stats = RetroStats(services=1)
    if max_age_days > 0 and service.last_seen_at < now - timedelta(days=max_age_days):
        # A port nobody has seen open for months is not a statement about the
        # host any more; matching it would page on a service that is gone.
        stats.too_old = 1
        return stats, {"status": "too_old"}, []
    asset = session.get(models.Asset, service.asset_id)
    if asset is None or asset.tenant_id != tenant_id:  # pragma: no cover - FK cascade
        return stats, {"status": "no_asset"}, []

    outcome = retro_match.match(_fingerprint(service), dataset, lookup=lookup)
    if outcome.reason:
        return stats, _summary(outcome, status=outcome.reason), []
    stats.assessed = 1
    counts = outcome.counts()
    stats.vulnerable = counts[retro_match.VULNERABLE]
    stats.possible = counts[retro_match.POSSIBLE]
    stats.fixed = counts[retro_match.FIXED]
    stats.not_affected = counts[retro_match.NOT_AFFECTED]

    created: list[dict[str, Any]] = []
    port = str(service.port)
    for match in outcome.matches:
        if not match.is_finding:
            continue
        key = vulns_service.finding_key(
            asset_id=asset.asset_id, cve=match.cve, script_id=None, port=port
        )
        row = session.execute(
            select(models.Vulnerability)
            .where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.finding_key == key,
            )
            .with_for_update()
        ).scalar_one_or_none()
        latest = _latest(match, service=service, asset=asset)

        if row is None:
            days, sla_source = vulns_service._resolve_sla_days(  # noqa: SLF001
                session,
                tenant_id=tenant_id,
                severity=match.severity,
                criticality=asset.asset_criticality,
            )
            row = models.Vulnerability(
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
                **latest,
            )
            session.add(row)
            session.flush()
            stats.created += 1
            vulns_service._record_event(  # noqa: SLF001
                session,
                vuln_id=row.vuln_id,
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
                    "due_at": vulns_service._iso(row.due_at),  # noqa: SLF001
                    "sla_days": days,
                    "sla_source": sla_source,
                },
            )
            created.append(
                {
                    "vuln_id": row.vuln_id,
                    "asset_id": asset.asset_id,
                    "host": service.host,
                    "port": service.port,
                    "protocol": service.protocol,
                    "cve": match.cve,
                    "severity": match.severity,
                    "cvss": match.cvss,
                    "confidence": match.confidence,
                    "dataset": match.evidence.get("dataset"),
                }
            )
            continue

        if row.source != SOURCE:
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
    return stats, _summary(outcome, status="matched"), created


def _hold_off(service: models.AssetService, *, now: datetime) -> None:
    """Keep a row that raised out of the queue for a while; its marker is not
    advanced, so it is still due, just not yet."""
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
) -> tuple[RetroStats, list[dict[str, Any]]]:
    """Match a batch of listeners and fold the result into the lifecycle.

    Each listener runs in its own SAVEPOINT and, whatever it concluded, is
    stamped with ``marker`` — the durable statement "matched against this
    dataset". A listener that raised is held off instead, with its marker left
    alone. Returns the stats and the findings created, for the events.
    """
    stats = RetroStats()
    created: list[dict[str, Any]] = []
    if not service_ids:
        return stats, created
    now = _now()
    with get_session(settings.postgres_url) as session:
        for service_id in service_ids:
            service = session.get(models.AssetService, service_id)
            if service is None or service.tenant_id != tenant_id:
                continue
            try:
                with session.begin_nested():
                    one, summary, new = _fold_service(
                        session,
                        tenant_id=tenant_id,
                        service=service,
                        dataset=dataset,
                        lookup=lookup,
                        max_age_days=int(settings.retro_match_max_age_days),
                        now=now,
                    )
            except Exception:  # noqa: BLE001 - one listener must not stop the tenant
                stats.errors += 1
                LOG.exception(
                    "Retro match: service %s failed to fold (tenant %s)", service_id, tenant_id
                )
                _hold_off(service, now=now)
                continue
            stats.add(one)
            created.extend(new)
            service.match_summary = summary
            service.matched_dataset_version = marker
            service.matched_at = now
            service.match_failure_count = 0
            service.match_retry_after = None
    return stats, created


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
    from the outbox is dropped by JetStream as a duplicate.
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
                "port": str(item["port"]),
                "occurred_at": occurred_at,
                "source": SOURCE,
                "data": {
                    "host": item["host"],
                    "port": str(item["port"]),
                    "protocol": item.get("protocol"),
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


def publish_created(
    settings: Settings, *, tenant_id: str, created: list[dict[str, Any]]
) -> dict[str, int]:
    """Announce new retro findings on the asset event bus. Never raises.

    The same bus, subject and outbox as a run's ``new_cve``, so
    ``asset.vulnerability.new`` webhooks fire for these too; ``source`` on the
    envelope is ``retro_match`` so a consumer can tell the two apart.
    """
    result = {"published": 0, "summarised": 0}
    if not created or not settings.asset_events_enabled or not settings.nats_url:
        return result
    from api.services import asset_events

    envelopes, summarised = build_events(
        created,
        tenant_id=tenant_id,
        max_events=settings.retro_match_max_events,
        occurred_at=asset_events._now_iso(),  # noqa: SLF001 - same clock as run events
    )
    result["summarised"] = summarised
    try:
        result["published"] = asset_events.publish_events(
            settings.nats_url, envelopes, settings=settings
        )
    except Exception:  # noqa: BLE001 - publish_events never raises; belt and braces
        # A notification lost here is not a finding lost: every row is already
        # committed, and the outbox (inside publish_events) is the retry.
        LOG.exception("Retro match: event publish failed (tenant %s)", tenant_id)
    return result
