"""Service fingerprints that outlive the run they came from.

A scan learns what each open port runs — ``OpenSSH 8.2p1 Ubuntu 4ubuntu0.5``,
``nginx 1.18.0`` — and until this module that knowledge lived only in the run
directory (``services.json`` from Pulse, the nmap XML), which
``run_retention_days`` deletes. The findings a scan produced were kept; the
facts that would let a *later* CVE be checked against the same host were not.
``docs/retro-cve-matching.md`` is what these rows are for.

**Where the rows come from.** :func:`record_run` is called from the post-run
projection of every succeeded run (``run_completion.project_published_run``),
next to the vulnerability fold and best-effort like it. The one-off
:func:`backfill_tenant` walks the succeeded runs still on disk, oldest first,
for an installation upgrading into this feature
(``scripts/backfill-asset-services.py``).

**Which record wins.** A run can carry the same listener twice — Pulse's
``services.json`` and nmap's XML on a hybrid or shadow run. They are merged:
nmap's CPE names and its ``version`` string (which is where nmap puts the
distribution revision) are kept, Pulse fills what nmap left empty, and the raw
banner is preferred over nmap's ``extrainfo``. A listener is identified by
``(tenant, asset, port, protocol)``; the next scan updates the row, and an
observation *older* than the stored one (a backfill that reached an old run
after a new one) never overwrites the fingerprint.

**What re-queues a row for matching.** A change to anything the matcher reads
— product, version, banner, CPE — clears ``matched_dataset_version``, so the
retro worker re-matches it on its next tick. A re-observation of the same
fingerprint does not: the verdict would be the same, and re-deriving it every
scan would make the worker's queue as long as the estate.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select, update

from api.db import models
from api.db.engine import get_session, insert_or_skip
from api.services import job_states
from api.services import runs as runs_service
from api.services import vulnerabilities as vulns_service
from api.settings import Settings
from scanner.pipeline.report import _parse_nmap_xml
from scanner.pipeline.service_schema import OsRecord, ServiceRecord

LOG = logging.getLogger("shapoclyack.asset-services")

#: Stored banner ceiling. A banner is evidence, not a document: the part that
#: identifies the product and the distribution is its first line.
BANNER_MAX = 512
#: Ceiling on product/version strings, which are prober-supplied.
FIELD_MAX = 256
#: CPE names kept per listener.
CPE_MAX = 8

#: The fields whose change re-queues a listener for matching.
FINGERPRINT_FIELDS = ("service", "product", "version", "banner", "cpe")


def _now() -> datetime:
    return vulns_service._now()  # noqa: SLF001 - one clock for the findings and their evidence


def _clip(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _port(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _normalized(entry: dict[str, Any], *, source: str) -> dict[str, Any] | None:
    host = _clip(entry.get("host") or entry.get("ip"), FIELD_MAX)
    port = _port(entry.get("port"))
    if not host or port is None:
        return None
    raw_cpe = entry.get("cpe")
    cpe = [str(c).strip()[:FIELD_MAX] for c in raw_cpe if str(c).strip()] if isinstance(raw_cpe, list) else []
    return {
        "host": host,
        "port": port,
        "protocol": (_clip(entry.get("protocol"), 16) or "tcp").lower(),
        "service": _clip(entry.get("service"), FIELD_MAX),
        "product": _clip(entry.get("product"), FIELD_MAX),
        "version": _clip(entry.get("version"), FIELD_MAX),
        "banner": _clip(entry.get("banner") or entry.get("extrainfo"), BANNER_MAX),
        "cpe": list(dict.fromkeys(cpe))[:CPE_MAX],
        "source": source,
    }


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        LOG.warning("Unreadable %s; its services are not recorded", path, exc_info=True)
        return None


def fingerprints_from_run_dir(run_dir: Path) -> list[dict[str, Any]]:
    """Every open listener a run fingerprinted, merged across probers.

    Reads the raw prober output rather than ``findings.json``: the nmap XML is
    the only place the ``<cpe>`` names survive (``report.py`` did not carry
    them before this feature), and ``findings.json`` is only written when the
    run asked for JSON export. ``findings.json`` is still read, last, so a run
    whose raw artifacts were not uploaded is not a run with no services.
    """
    merged: dict[tuple[str, int, str], dict[str, Any]] = {}

    def fold(record: dict[str, Any] | None) -> None:
        if record is None:
            return
        key = (record["host"], record["port"], record["protocol"])
        current = merged.get(key)
        if current is None:
            merged[key] = record
            return
        for name in ("service", "product", "version"):
            if not current[name] or current[name] == "unknown":
                current[name] = record[name]
        if record["source"] == "pulse" and record["banner"]:
            # A raw banner says more than nmap's extrainfo summary of it.
            current["banner"] = record["banner"]
        elif not current["banner"]:
            current["banner"] = record["banner"]
        current["cpe"] = list(dict.fromkeys([*current["cpe"], *record["cpe"]]))[:CPE_MAX]

    nmap_dir = run_dir / "nmap"
    if nmap_dir.is_dir():
        services, _, _ = _parse_nmap_xml(nmap_dir)
        for entry in services:
            fold(_normalized(entry, source="nmap"))

    raw_services = _load_json(run_dir / "services.json")
    if isinstance(raw_services, list):
        for row in raw_services:
            try:
                record = ServiceRecord.model_validate(row)
            except Exception:  # noqa: BLE001 - one malformed row is not the run
                continue
            if record.state and record.state != "open":
                continue
            fold(
                _normalized(
                    {**record.model_dump(), "host": record.ip},
                    source=record.source or "pulse",
                )
            )

    if not merged:
        findings = _load_json(run_dir / "findings.json")
        if isinstance(findings, list):
            for entry in findings:
                if isinstance(entry, dict):
                    fold(_normalized(entry, source=str(entry.get("source") or "scan")))
    return list(merged.values())


def os_guesses_from_run_dir(run_dir: Path) -> dict[str, dict[str, Any]]:
    """The best OS guess per host a run made: ``{host: {name, accuracy, source}}``.

    nmap's ``osmatch`` list and Pulse's ``os.json``, highest accuracy wins.
    Read for the retro matcher's host hint (``retro_match.host_hint``), which
    treats it as a guess: it can only make a match less certain or send it to
    the vendor, never create a finding on its own.
    """
    best: dict[str, dict[str, Any]] = {}

    def offer(host: str, name: str, accuracy: Any, source: str) -> None:
        host, name = _clip(host, FIELD_MAX), _clip(name, FIELD_MAX)
        if not host or not name:
            return
        try:
            score = int(float(accuracy))
        except (TypeError, ValueError):
            score = 0
        current = best.get(host)
        if current is None or score > (current["accuracy"] or 0):
            best[host] = {"name": name, "accuracy": score, "source": source}

    nmap_dir = run_dir / "nmap"
    if nmap_dir.is_dir():
        _, os_matches, _ = _parse_nmap_xml(nmap_dir)
        for entry in os_matches:
            offer(str(entry.get("host") or ""), str(entry.get("name") or ""), entry.get("accuracy"), "nmap")
    raw_os = _load_json(run_dir / "os.json")
    if isinstance(raw_os, list):
        for row in raw_os:
            try:
                record = OsRecord.model_validate(row)
            except Exception:  # noqa: BLE001 - one malformed row is not the run
                continue
            offer(record.ip, record.detail or record.family, record.confidence, record.source or "pulse")
    return best


def _record_os(
    session: Any,
    *,
    tenant_id: str,
    asset_id: str,
    guess: dict[str, Any],
    run_id: str,
    now: datetime,
) -> bool:
    """Keep the newest scan's guess for the asset. True when what the matcher
    reads (the name) changed."""
    row = session.get(models.AssetOs, asset_id, with_for_update=True)
    if row is None:
        candidate = models.AssetOs(
            asset_id=asset_id,
            tenant_id=tenant_id,
            os_name=guess["name"],
            accuracy=guess["accuracy"],
            source=guess["source"],
            last_seen_at=now,
            last_run_id=run_id,
        )
        if insert_or_skip(session, candidate, conflict=["asset_id"]):
            return True
        row = session.get(models.AssetOs, asset_id, with_for_update=True)
        if row is None:  # pragma: no cover - deleted with its asset meanwhile
            return False
    if now < row.last_seen_at:
        return False
    changed = row.os_name != guess["name"]
    row.os_name = guess["name"]
    row.accuracy = guess["accuracy"]
    row.source = guess["source"]
    row.last_seen_at = now
    row.last_run_id = run_id
    return changed


def _requeue_asset(session: Any, *, tenant_id: str, asset_id: str) -> None:
    """Every listener of the asset is due again.

    What the matcher concludes about one listener depends on the others (a
    Debian revision on port 22 is the host hint for Exim on port 25) and on
    the OS guess, so a change to any of them is a change to all of them.
    """
    session.execute(
        update(models.AssetService)
        .where(
            models.AssetService.tenant_id == tenant_id,
            models.AssetService.asset_id == asset_id,
        )
        .values(matched_dataset_version=None)
    )


def record_run(
    settings: Settings,
    *,
    tenant_id: str,
    run_id: str,
    observed_at: datetime | None = None,
) -> dict[str, int]:
    """Upsert a succeeded run's fingerprints and OS guesses. Idempotent per run.

    ``observed_at`` defaults to now; the projection passes the job's
    ``finished_at`` and the backfill its runs' so a run from June does not
    claim to be today's observation. Assets must already be upserted from the
    run — a listener on a host that never became an asset is skipped, as a
    finding would be.
    """
    stats = {"seen": 0, "created": 0, "changed": 0, "unchanged": 0, "stale": 0, "skipped": 0}
    run_dir = runs_service.get_written_run_dir(settings, run_id, tenant_id=tenant_id)
    if run_dir is None:
        return stats
    fingerprints = fingerprints_from_run_dir(run_dir)
    guesses = os_guesses_from_run_dir(run_dir)
    stats["seen"] = len(fingerprints)
    if not fingerprints and not guesses:
        return stats
    now = vulns_service._naive(observed_at) if observed_at else _now()  # noqa: SLF001

    with get_session(settings.postgres_url) as session:
        assets: dict[str, models.Asset | None] = {}

        def asset_for(host: str) -> models.Asset | None:
            if host not in assets:
                assets[host] = vulns_service._asset_for_finding(  # noqa: SLF001
                    session, tenant_id=tenant_id, host=host
                )
            return assets[host]

        moved: set[str] = set()
        for fp in fingerprints:
            asset = asset_for(fp["host"])
            if asset is None:
                stats["skipped"] += 1
                continue
            outcome = _upsert(session, tenant_id=tenant_id, asset_id=asset.asset_id, fp=fp, run_id=run_id, now=now)
            stats[outcome] += 1
            if outcome in ("created", "changed"):
                moved.add(asset.asset_id)
        for host, guess in guesses.items():
            asset = asset_for(host)
            if asset is not None and _record_os(
                session, tenant_id=tenant_id, asset_id=asset.asset_id, guess=guess, run_id=run_id, now=now
            ):
                moved.add(asset.asset_id)
        for asset_id in moved:
            _requeue_asset(session, tenant_id=tenant_id, asset_id=asset_id)

    if moved:
        from api.services import retro_match_worker

        retro_match_worker.notify()
    return stats
def _select_row(session: Any, *, tenant_id: str, asset_id: str, fp: dict[str, Any]) -> models.AssetService | None:
    return session.execute(
        select(models.AssetService)
        .where(
            models.AssetService.tenant_id == tenant_id,
            models.AssetService.asset_id == asset_id,
            models.AssetService.port == fp["port"],
            models.AssetService.protocol == fp["protocol"],
        )
        .with_for_update()
    ).scalar_one_or_none()


def _upsert(
    session: Any,
    *,
    tenant_id: str,
    asset_id: str,
    fp: dict[str, Any],
    run_id: str,
    now: datetime,
) -> str:
    """One listener. Returns ``created``/``changed``/``unchanged``/``stale``."""
    row = _select_row(session, tenant_id=tenant_id, asset_id=asset_id, fp=fp)
    if row is None:
        candidate = models.AssetService(
            tenant_id=tenant_id,
            asset_id=asset_id,
            host=fp["host"],
            port=fp["port"],
            protocol=fp["protocol"],
            service=fp["service"],
            product=fp["product"],
            version=fp["version"],
            banner=fp["banner"],
            cpe=fp["cpe"],
            source=fp["source"],
            first_seen_at=now,
            last_seen_at=now,
            last_run_id=run_id,
            fingerprint_changed_at=now,
            match_summary={},
        )
        # Two replicas projecting the same run (an agent upload retried into a
        # second pod) race on the unique key; the loser updates the winner's row.
        if insert_or_skip(
            session, candidate, conflict=["tenant_id", "asset_id", "port", "protocol"]
        ):
            return "created"
        row = _select_row(session, tenant_id=tenant_id, asset_id=asset_id, fp=fp)
        if row is None:  # pragma: no cover - the winner's row was deleted under us
            return "unchanged"

    if now < row.last_seen_at:
        # An older run reached after a newer one (the backfill does this by
        # design). It says the listener existed earlier; it does not say what
        # it runs now.
        if now < row.first_seen_at:
            row.first_seen_at = now
        return "stale"

    changed = any(getattr(row, name) != fp[name] for name in FINGERPRINT_FIELDS)
    row.last_seen_at = now
    row.last_run_id = run_id
    row.host = fp["host"]
    if changed:
        for name in FINGERPRINT_FIELDS:
            setattr(row, name, fp[name])
        row.source = fp["source"]
        row.fingerprint_changed_at = now
        row.matched_dataset_version = None
        row.match_failure_count = 0
        row.match_retry_after = None
        return "changed"
    if (row.match_summary or {}).get("status") == "too_old":
        # The matcher skipped this listener as not seen for too long; it has
        # just been seen, so it is due again.
        row.matched_dataset_version = None
    return "unchanged"


def backfill_tenant(settings: Settings, *, tenant_id: str, limit: int | None = None) -> dict[str, int]:
    """Record every succeeded run of the tenant still on disk, oldest first.

    For the upgrade into this feature: without it the table starts empty and
    fills one scan at a time, so a CVE published tomorrow would be checked only
    against hosts scanned since the upgrade. A run whose directory has been
    pruned is counted ``missing`` and skipped — it is gone, which is the whole
    reason this table exists.
    """
    with get_session(settings.postgres_url) as session:
        query = (
            select(models.Job.run_id, func.max(models.Job.finished_at))
            .where(
                models.Job.tenant_id == tenant_id,
                models.Job.status == job_states.SUCCEEDED,
                models.Job.run_id.is_not(None),
            )
            .group_by(models.Job.run_id)
            .order_by(func.max(models.Job.finished_at).asc())
        )
        if limit:
            query = query.limit(limit)
        runs = [(run_id, finished_at) for run_id, finished_at in session.execute(query)]

    totals = {"runs": 0, "missing": 0, "failed": 0, "seen": 0, "created": 0, "changed": 0, "unchanged": 0, "stale": 0, "skipped": 0}
    for run_id, finished_at in runs:
        totals["runs"] += 1
        try:
            if runs_service.get_written_run_dir(settings, run_id, tenant_id=tenant_id) is None:
                totals["missing"] += 1
                continue
            stats = record_run(settings, tenant_id=tenant_id, run_id=run_id, observed_at=finished_at)
        except Exception:  # noqa: BLE001 - one unreadable run must not stop the backfill
            totals["failed"] += 1
            LOG.exception("Backfill: run %s (tenant %s) could not be recorded", run_id, tenant_id)
            continue
        for key, value in stats.items():
            totals[key] += value
    LOG.info("Asset services backfill: tenant=%s %s", tenant_id, totals)
    return totals


def _iso(value: datetime | None) -> str | None:
    return vulns_service._iso(value)  # noqa: SLF001


def to_dict(row: models.AssetService) -> dict[str, Any]:
    summary = dict(row.match_summary or {})
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "host": row.host,
        "port": row.port,
        "protocol": row.protocol,
        "service": row.service,
        "product": row.product,
        "version": row.version,
        "banner": row.banner,
        "cpe": list(row.cpe or []),
        "source": row.source,
        "first_seen_at": _iso(row.first_seen_at),
        "last_seen_at": _iso(row.last_seen_at),
        "last_run_id": row.last_run_id,
        "fingerprint_changed_at": _iso(row.fingerprint_changed_at),
        "matched_dataset_version": row.matched_dataset_version,
        "matched_at": _iso(row.matched_at),
        "match_status": summary.get("status"),
        "match_counts": dict(summary.get("counts") or {}),
        "possible_cves": list(summary.get("possible") or []),
    }


def list_for_asset(settings: Settings, *, tenant_id: str, asset_id: str) -> list[dict[str, Any]]:
    """One asset's listeners, by port. The caller checks the asset is the tenant's."""
    with get_session(settings.postgres_url) as session:
        rows = session.scalars(
            select(models.AssetService)
            .where(
                models.AssetService.tenant_id == tenant_id,
                models.AssetService.asset_id == asset_id,
            )
            .order_by(models.AssetService.port.asc(), models.AssetService.protocol.asc())
        ).all()
        return [to_dict(row) for row in rows]
