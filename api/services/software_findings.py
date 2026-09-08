"""Software→CVE matches as tracked findings (ROADMAP Track E, M3).

``software_cve_match.py`` answers *is this package vulnerable on this host*.
That answer had nowhere to live: its rows are keyed on ``device_id``, replaced
wholesale on every run, and therefore carried no ``finding_key``, no deadline,
no owner, no ticket, no NIST risk and no line in ``vulnerability_events``. An
authenticated finding was visible on one panel and invisible to the SLA report,
the Vulnerability Center, the remediation board and every report. This module
folds those matches into the same ``vulnerabilities`` table the scanner writes,
so that a finding found by looking *inside* a host is the same kind of object
as one found by looking at it from outside.

It is a separate module rather than more of ``vulnerabilities.py`` because that
module is the run path — its 1700 lines are about run artifacts, verification
jobs and scan dispatch, none of which apply here. What it *does* reuse from
there is everything that must not fork: SLA resolution, the audit-trail writer,
the state machine, and the row shape.

Five decisions carry the weight.

**Identity.** ``finding_key`` for a scan finding is
``sha256(asset_id|cve-or-script|port)`` and is **never** touched. Adding an
element to that hash would rename every finding that exists and reopen the
entire backlog on the next ingest. Software findings get their own
:func:`software_finding_key`, over ``(asset_id, device_id, cve)`` with its own
namespace element in the hash, which cannot collide with the scan key. The
``device_id`` is in the key because one asset can carry several endpoints, and
"on which host" is part of what the finding is: closing it on one host says
nothing about the other.

**What becomes a finding.** Only ``status == "vulnerable"``. ``fixed`` and
``not_applicable`` are the evidence that the matcher looked and answered, and
``unknown`` is the honest "we could not tell" — a tracked finding with a
deadline attached to "we do not know this endpoint's OS" would put the SLA
report's credibility behind a non-statement. Those rows stay in
``software_cve_matches`` and on the endpoint panel, where they belong.

**Volume is a correctness property, not an optimisation.** A full advisory feed
across a large estate produces millions of ``vulnerable`` matches, and every
one of them would become a row with a deadline. An SLA dashboard with a million
breaches is unreadable on its first day and is then never read again. So a
tracked finding is created only for a match that has a **published fix** — the
patch-gap set, the things somebody can actually go and do — with a severity
threshold available on top (see ``Settings.software_finding_min_severity``).
A ``vulnerable`` match with no fix yet stays a match: it is real risk, it is
reported as ``unfixed_findings`` by ``patch_gap.py``, and there is no
remediation to put a clock on.

**Closure is the new semantics.** The run path may close a finding only when a
scan it dispatched went and looked. There is no equivalent here — the inventory
is not something we can aim — so the observation that closes a software finding
is *the next accepted snapshot*. All three of these must hold, or the finding
stays open:

1. the match is gone, or has become ``fixed``;
2. the device has submitted a newer accepted snapshot than the finding's
   ``last_seen_at``;
3. the distribution and provider still resolved (``packages_assessed > 0``).

Condition 2 is the whole point. A device that went quiet produces exactly the
same "no match" as a device that was patched, and closing on it would mean the
platform forgives findings whenever the agent stops reporting — the failure
mode ``docs/vulnerability-lifecycle.md`` refuses for the scan path. Condition 3
covers the same absence produced by a release we stopped being able to resolve.
When a finding is not closed, ``last_seen_at`` is **not** moved either: absence
of observation is not observation.

**Livepatched kernels.** A livepatched host reports the package version it
booted from, so it reads as ``vulnerable`` and will now get a deadline. The
inventory carries no signal that would let this module know better. The
supported path is ``POST /api/vulnerabilities/{id}/exception`` — an accepted
risk with a reason and an expiry — and not a heuristic here.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import software_cve_match as match_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from api.services.risk_scoring import get_scorer
from api.settings import Settings
from scanner.pipeline.cvss4 import Cvss4Database, normalize_cwes

LOG = logging.getLogger("shapoclyack.software-findings")

#: ``Vulnerability.source`` for everything this module writes.
SOURCE = "endpoint_software"

#: Hash namespace. Present so a software key can never equal a scan key even if
#: the remaining material somehow coincided.
_KEY_NAMESPACE = "endpoint_software"

#: The vendor severities the matcher emits, mapped onto the tracker's
#: vocabulary (``scanner.pipeline.report.SEVERITY_ORDER``). Ubuntu's
#: ``negligible`` is a real judgement about a real fix, so it is folded into
#: ``low`` rather than into ``unknown``, which means "nobody said".
_SEVERITY_ALIASES = {"negligible": "low"}

#: Ordering for the ``min_severity`` threshold. Worst first.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}


def _now() -> datetime:
    return vulns_service._now()  # noqa: SLF001 - one clock for the whole table


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def software_finding_key(*, asset_id: str, device_id: str, cve: str) -> str:
    """Stable identity for one CVE on one endpoint.

    Deliberately **not** ``vulnerabilities.finding_key``. That function's hash
    is the identity of every finding already in the table, and widening it to
    tell the two sources apart would rename all of them at once — every open
    finding would look new and every closed one would come back. A second
    function with its own namespace costs one comparison at read time and
    nothing at all to the existing backlog.

    ``device_id`` is part of the key rather than only of the row: an asset can
    have several endpoints reporting into it (a synthetic ``ep_…`` asset per
    device is the common case, but an FQDN match links several), and "openssl
    is behind on this host" is not the same piece of work as "openssl is behind
    on that one".
    """
    material = "|".join([_KEY_NAMESPACE, asset_id, device_id, cve.strip().upper()])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Scoring inputs
# --------------------------------------------------------------------------

_CVSS4_DB: Cvss4Database | None = None
_CVSS4_PATH: str | None = None


def _cvss4_database() -> Cvss4Database:
    """The process-wide CVSS4 overlay, loaded once per configured path.

    Same file the report pipeline enriches run findings from, so a software
    finding and a scan finding for one CVE carry the same base score and the
    same vector. Reloaded only when the path changes (which is how tests point
    it at a fixture); an empty database is a supported configuration and scores
    the finding from the vendor severity alone.
    """
    global _CVSS4_DB, _CVSS4_PATH
    path = os.environ.get("OCTO_CVSS4_DATABASE", "scanner/data/cvss4/cvss4.json")
    if _CVSS4_DB is None or _CVSS4_PATH != path:
        _CVSS4_DB = Cvss4Database.load(Path(path))
        _CVSS4_PATH = path
    return _CVSS4_DB


def reset_cvss4_cache_for_tests() -> None:
    global _CVSS4_DB, _CVSS4_PATH
    _CVSS4_DB = None
    _CVSS4_PATH = None


def _severity_of(match: models.SoftwareCveMatch) -> str:
    severity = str(match.severity or "").strip().lower()
    severity = _SEVERITY_ALIASES.get(severity, severity)
    return severity if severity in _SEVERITY_RANK else "unknown"


def scoring_item(match: models.SoftwareCveMatch) -> dict[str, Any]:
    """The scorer's input for one match.

    ``host`` is deliberately absent. The inventory knows what is installed, not
    what is reachable, and inventing an address here would make
    ``resolve_network_exposure`` read a routing fact as a scan observation.
    With no host the exposure resolves to the asset's operator-set level, or to
    ``unknown`` when nobody set one — which is the honest answer.
    """
    cve = str(match.cve_id or "").strip().upper()
    item: dict[str, Any] = {
        "cve": cve,
        "severity": _severity_of(match),
        "host": None,
        "port": None,
    }
    hit = _cvss4_database().lookup(cve)
    if hit:
        item["cvss4"] = hit.get("score")
        item["cvss4_vector"] = hit.get("vector")
        item["cvss4_severity"] = hit.get("severity")
        item["cve_published"] = hit.get("published")
        item["cwe"] = normalize_cwes(hit.get("cwe"))
    return item


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------


def _min_severity(settings: Settings) -> str:
    value = str(getattr(settings, "software_finding_min_severity", "") or "").strip().lower()
    return value if value in _SEVERITY_RANK else ""


def is_trackable(match: models.SoftwareCveMatch, *, min_severity: str = "") -> bool:
    """Should this match become a tracked finding with a deadline?

    ``vulnerable`` **and** a published fix, above the configured severity
    floor. See the module docstring for why the fix is required rather than
    merely preferred.
    """
    if match.status != match_service.VULNERABLE:
        return False
    if not (match.fixed_version or "").strip():
        return False
    if not (match.cve_id or "").strip():
        return False
    if min_severity:
        return _SEVERITY_RANK[_severity_of(match)] >= _SEVERITY_RANK[min_severity]
    return True


# --------------------------------------------------------------------------
# Ingest
# --------------------------------------------------------------------------


@dataclass
class SoftwareFindingStats:
    """What one ingest pass did. Mutable, because a batch accumulates it."""

    devices: int = 0
    matches_seen: int = 0
    trackable: int = 0
    created: int = 0
    reobserved: int = 0
    reopened: int = 0
    closed: int = 0
    #: Devices with no ``asset_id`` — the quota-refused ``unlinked`` case. The
    #: run path skips findings with no asset for the same reason: a finding
    #: against nothing addressable is not a record of anything.
    skipped_unlinked: int = 0
    #: Open findings whose match is gone but which the rules above refuse to
    #: close, kept as a counter so "why is this still open" has an answer.
    held_open_stale_snapshot: int = 0

    def add(self, other: SoftwareFindingStats) -> None:
        for name in self.__dataclass_fields__:
            setattr(self, name, getattr(self, name) + getattr(other, name))

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass
class _DeviceContext:
    """Everything one device's fold needs, read once."""

    device: models.EndpointDevice
    asset: models.Asset
    observed_at: datetime
    packages_assessed: int
    matches: list[models.SoftwareCveMatch] = field(default_factory=list)


def _snapshot_received_at(session: Any, snapshot_id: str | None) -> datetime | None:
    if not snapshot_id:
        return None
    received = session.execute(
        select(models.EndpointInventorySnapshot.received_at).where(
            models.EndpointInventorySnapshot.snapshot_id == snapshot_id
        )
    ).scalar_one_or_none()
    return vulns_service._naive(received)  # noqa: SLF001


def _fold_device(
    session: Any,
    *,
    tenant_id: str,
    context: _DeviceContext,
    min_severity: str,
    now: datetime,
) -> SoftwareFindingStats:
    """Reconcile one device's matches against its tracked findings."""
    stats = SoftwareFindingStats(devices=1, matches_seen=len(context.matches))
    device = context.device
    asset = context.asset
    observed_at = context.observed_at

    existing = {
        row.finding_key: row
        for row in session.scalars(
            select(models.Vulnerability).where(
                models.Vulnerability.tenant_id == tenant_id,
                models.Vulnerability.source == SOURCE,
                models.Vulnerability.device_id == device.device_id,
            )
        ).all()
    }

    seen_keys: set[str] = set()
    for match in context.matches:
        if not is_trackable(match, min_severity=min_severity):
            continue
        stats.trackable += 1
        cve = str(match.cve_id).strip().upper()
        key = software_finding_key(
            asset_id=asset.asset_id, device_id=device.device_id, cve=cve
        )
        seen_keys.add(key)
        severity = _severity_of(match)
        scored = get_scorer().score_vulnerability(
            scoring_item(match),
            operator_exposure=asset.exposure_level,
            asset_criticality_override=asset.asset_criticality,
        )
        latest = {
            "severity": severity,
            "risk_level": scored.get("risk_level"),
            "contextual_score": scored.get("contextual_score"),
            "cvss": scored.get("base_cvss") or None,
            "in_kev": bool(scored.get("exploit_active")),
            "exploit_maturity": scored.get("exploit_maturity"),
            "network_exposure": scored.get("network_exposure"),
            "network_exposure_source": scored.get("network_exposure_source"),
            "cwe": normalize_cwes((_cvss4_database().lookup(cve) or {}).get("cwe")),
            # The package is what an operator acts on, so it is the title
            # rather than a repeat of the CVE id the row already carries.
            "title": f"{match.installed_package} {match.installed_version} → {match.fixed_version}"[
                :500
            ],
        }

        row = existing.get(key)
        if row is None:
            days, sla_source = vulns_service._resolve_sla_days(  # noqa: SLF001
                session,
                tenant_id=tenant_id,
                severity=severity,
                criticality=asset.asset_criticality,
            )
            row = models.Vulnerability(
                vuln_id=f"vln_{uuid.uuid4().hex[:16]}",
                tenant_id=tenant_id,
                asset_id=asset.asset_id,
                finding_key=key,
                source=SOURCE,
                device_id=device.device_id,
                cve=cve,
                script_id=None,
                # A software finding has no port by construction: it is a
                # statement about an installed package, not about a listener.
                port=None,
                state=vuln_states.OPEN,
                state_changed_at=now,
                assignee=asset.owner_email,
                owner_team=asset.business_unit,
                due_at=observed_at + timedelta(days=days),
                sla_days=days,
                sla_source=sla_source,
                first_seen_at=observed_at,
                last_seen_at=observed_at,
                # The SLA clock runs from the snapshot that observed it, not
                # from whenever the worker got round to folding it in.
                sla_started_at=observed_at,
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
                    "device_id": device.device_id,
                    "snapshot_id": device.latest_snapshot_id,
                    "severity": severity,
                    "installed_package": match.installed_package,
                    "installed_version": match.installed_version,
                    "fixed_version": match.fixed_version,
                    "advisory_id": match.advisory_id,
                    "due_at": vulns_service._iso(row.due_at),  # noqa: SLF001
                    "sla_days": days,
                    "sla_source": sla_source,
                },
            )
            continue

        for name, value in latest.items():
            setattr(row, name, value)
        row.updated_at = now
        if observed_at <= row.last_seen_at:
            # The same snapshot, re-folded. The matcher is re-run on a timer
            # and by hand, and counting each pass as a fresh observation would
            # fill the audit trail with events at which nothing happened. The
            # assessment above is still refreshed — a new advisory feed can
            # change the severity of a match the host has not moved on.
            continue

        row.last_seen_at = observed_at
        row.observation_count += 1
        stats.reobserved += 1

        if row.state == vuln_states.CLOSED:
            days, sla_source = vulns_service._resolve_sla_days(  # noqa: SLF001
                session,
                tenant_id=tenant_id,
                severity=severity,
                criticality=asset.asset_criticality,
            )
            previous = row.state
            row.state = vuln_states.OPEN
            row.state_changed_at = now
            row.state_changed_by = None
            row.closed_at = None
            row.machine_verified = False
            row.closure_reason = None
            row.sla_started_at = observed_at
            row.due_at = observed_at + timedelta(days=days)
            row.sla_days = days
            row.sla_source = sla_source
            row.reopen_count += 1
            stats.reopened += 1
            vulns_service._record_event(  # noqa: SLF001
                session,
                vuln_id=row.vuln_id,
                tenant_id=tenant_id,
                kind="reopened",
                occurred_at=now,
                from_state=previous,
                to_state=vuln_states.OPEN,
                note="Matched again by a later inventory snapshot",
                detail={
                    "source": SOURCE,
                    "device_id": device.device_id,
                    "snapshot_id": device.latest_snapshot_id,
                    "reopen_count": row.reopen_count,
                },
            )
        else:
            vulns_service._record_event(  # noqa: SLF001
                session,
                vuln_id=row.vuln_id,
                tenant_id=tenant_id,
                kind="observed",
                occurred_at=now,
                to_state=row.state,
                detail={
                    "source": SOURCE,
                    "device_id": device.device_id,
                    "snapshot_id": device.latest_snapshot_id,
                    "severity": severity,
                },
            )

    # --- closure -----------------------------------------------------------
    for key, row in existing.items():
        if key in seen_keys or row.state == vuln_states.CLOSED:
            continue
        fresh_snapshot = observed_at > (row.last_seen_at or observed_at)
        if not (fresh_snapshot and context.packages_assessed > 0):
            # Not observed is not fixed. ``last_seen_at`` deliberately does not
            # move either, so ``?stale_days=`` still surfaces this row.
            stats.held_open_stale_snapshot += 1
            continue
        previous = row.state
        row.state = vuln_states.CLOSED
        row.state_changed_at = now
        row.state_changed_by = "system:inventory"
        row.closed_at = now
        row.last_verified_at = now
        row.machine_verified = True
        row.closure_reason = "patched"
        row.updated_at = now
        if row.exception_until is not None:
            row.exception_until = None
            row.exception_reason = None
            row.exception_by = None
        stats.closed += 1
        vulns_service._record_event(  # noqa: SLF001
            session,
            vuln_id=row.vuln_id,
            tenant_id=tenant_id,
            kind="verification_passed",
            occurred_at=now,
            from_state=previous,
            to_state=vuln_states.CLOSED,
            actor="system:inventory",
            note=(
                f"No longer matched by inventory snapshot "
                f"{device.latest_snapshot_id} on {device.hostname}"
            ),
            detail={
                "source": SOURCE,
                "device_id": device.device_id,
                "snapshot_id": device.latest_snapshot_id,
                "packages_assessed": context.packages_assessed,
                "machine_verified": True,
                "closure_reason": "patched",
            },
        )
    return stats


def ingest_devices(
    settings: Settings,
    *,
    tenant_id: str,
    device_ids: list[str],
    run_matcher: bool = True,
) -> SoftwareFindingStats:
    """Re-match a batch of devices and fold the result into the lifecycle.

    ``run_matcher=False`` folds the rows already in ``software_cve_matches``,
    which is what a caller that has just run the matcher itself wants.
    ``packages_assessed`` then has to be recovered from the rows rather than
    from the run summary — see :func:`_assessed_from_rows`.
    """
    stats = SoftwareFindingStats()
    if not device_ids:
        return stats

    assessed: dict[str, int] = {}
    if run_matcher:
        for summary in match_service.run_for_devices(
            settings, tenant_id=tenant_id, device_ids=device_ids
        ):
            assessed[summary["device_id"]] = int(summary["packages_assessed"])

    min_severity = _min_severity(settings)
    now = _now()
    with get_session(settings.postgres_url) as session:
        for device_id in device_ids:
            device = session.get(models.EndpointDevice, device_id)
            if device is None or device.tenant_id != tenant_id:
                continue
            if device.asset_id is None:
                # ``unlinked``: reconciliation was refused by the asset quota.
                # The endpoint's matches are still recorded and visible; they
                # just have nothing to hang a tracked finding on.
                stats.skipped_unlinked += 1
                continue
            asset = session.get(models.Asset, device.asset_id)
            if asset is None:
                stats.skipped_unlinked += 1
                continue
            observed_at = _snapshot_received_at(session, device.latest_snapshot_id)
            if observed_at is None:
                continue
            matches = list(
                session.scalars(
                    select(models.SoftwareCveMatch).where(
                        models.SoftwareCveMatch.tenant_id == tenant_id,
                        models.SoftwareCveMatch.device_id == device_id,
                    )
                ).all()
            )
            stats.add(
                _fold_device(
                    session,
                    tenant_id=tenant_id,
                    context=_DeviceContext(
                        device=device,
                        asset=asset,
                        observed_at=observed_at,
                        packages_assessed=assessed.get(
                            device_id, _assessed_from_rows(matches)
                        ),
                        matches=matches,
                    ),
                    min_severity=min_severity,
                    now=now,
                )
            )
    return stats


def _assessed_from_rows(matches: list[models.SoftwareCveMatch]) -> int:
    """A lower bound on ``packages_assessed``, read back from the match rows.

    The matcher reports the real number, but a caller that did not run it has
    only the rows. Any row that is not an ``unknown`` placeholder is a package
    the provider actually answered about, so a non-zero count here means the
    distribution and provider resolved — which is all the closure rule asks.
    """
    return sum(1 for row in matches if row.status != match_service.UNKNOWN)


def ingest_device(
    settings: Settings, *, tenant_id: str, device_id: str, run_matcher: bool = True
) -> SoftwareFindingStats:
    return ingest_devices(
        settings, tenant_id=tenant_id, device_ids=[device_id], run_matcher=run_matcher
    )


def ingest_tenant(
    settings: Settings, *, tenant_id: str, run_matcher: bool = True, batch_size: int = 100
) -> SoftwareFindingStats:
    """Fold every device in the tenant, in batches."""
    with get_session(settings.postgres_url) as session:
        device_ids = list(
            session.scalars(
                select(models.EndpointDevice.device_id).where(
                    models.EndpointDevice.tenant_id == tenant_id
                )
            ).all()
        )
    batch_size = max(1, batch_size)
    stats = SoftwareFindingStats()
    for start in range(0, len(device_ids), batch_size):
        stats.add(
            ingest_devices(
                settings,
                tenant_id=tenant_id,
                device_ids=device_ids[start : start + batch_size],
                run_matcher=run_matcher,
            )
        )
    LOG.info("Software findings: tenant=%s %s", tenant_id, stats.as_dict())
    return stats
