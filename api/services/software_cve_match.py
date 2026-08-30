"""Software→CVE matching over the endpoint inventory (ROADMAP Track E, M1).

What this does, in one sentence: for every package in an endpoint's latest
accepted inventory snapshot, ask the distribution's own advisory source what it
says about that source package in that release, and compare the installed EVR
against the fixed EVR using the distribution's own comparison rules.

What it deliberately does **not** do is the thing most tools do — take an NVD
CPE range and report "installed 1.1.1f < fixed 1.1.1t, therefore vulnerable".
On any long-term-support distribution that is wrong for nearly every package,
because the fix arrives as ``1.1.1f-1ubuntu2.16`` and the upstream number never
moves. A tool that does this reports an estate as entirely critical, forever,
and the operator stops reading it. See docs/software-cve-matching.md.

**The four statuses, and why ``unknown`` is one of them.**

``vulnerable``
    The vendor says this release is affected and either names a fixed version
    the host is below, or has no fix yet.
``fixed``
    The vendor names a fixed version and the host is at or above it. This is
    the status a backport produces, and producing it correctly is the point.
``not_applicable``
    The vendor states this release is not affected.
``unknown``
    Something needed to answer was missing: the distro or release could not be
    resolved, the package does not come from a distribution package manager, or
    the version did not parse. Never a silent omission and never a guess — an
    endpoint with no resolvable OS must not read as clean.

Rows are replaced wholesale per device on each run, so a match cannot outlive
the snapshot that produced it, and are deduplicated per ``(device, cve)``: two
packages built from the same source both carrying one CVE is one finding, not
two, and the worst status wins.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select

from api.db import models
from api.db.engine import get_session
from api.services import advisories, package_identity, version_compare
from api.settings import Settings

_log = logging.getLogger("shapoclyack.software-cve-match")

VULNERABLE = "vulnerable"
FIXED = "fixed"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"
STATUSES = (VULNERABLE, FIXED, NOT_APPLICABLE, UNKNOWN)

#: Worst-first. Used to collapse several advisories for one CVE into one row:
#: if any package on the host is still below a fixed version, the host is
#: vulnerable regardless of what the others say.
_STATUS_RANK = {NOT_APPLICABLE: 0, FIXED: 1, UNKNOWN: 2, VULNERABLE: 3}

#: Severity ordering for the API's ``severity`` filter and for sorting.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "negligible", "unknown")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}

#: Example package names carried on an ``unknown`` row. Bounded on purpose: a
#: Windows endpoint has thousands of unassessable packages and the useful
#: statement is "3184 packages, here are a few", not 3184 rows.
_MAX_UNKNOWN_SAMPLES = 25


@dataclass
class MatchCandidate:
    """One prospective row, before deduplication."""

    cve_id: str
    status: str
    source_package: str = ""
    installed_package: str = ""
    installed_version: str | None = None
    fixed_version: str | None = None
    advisory_id: str | None = None
    advisory_url: str | None = None
    provider: str = ""
    severity: str = "unknown"
    distro: str | None = None
    distro_release: str | None = None
    purl: str | None = None
    cpe23: str | None = None
    unknown_reason: str | None = None
    feed_date: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def match_key(self) -> str:
        """Stable identity of a row within a device.

        Hashed rather than a composite column for the same reason
        ``EndpointSoftwareItem.comparison_key`` is: the tuple has a nullable
        member (``unknown_reason``), and a unique constraint over a nullable
        column does not constrain anything in Postgres.
        """
        raw = "|".join(
            [self.cve_id, self.source_package, self.unknown_reason or ""]
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def _worse(left: MatchCandidate, right: MatchCandidate) -> MatchCandidate:
    """Keep the candidate an operator needs to see. Ties break on severity, so
    the surviving row's evidence is the one worth reading."""
    left_rank = (_STATUS_RANK[left.status], -_SEVERITY_RANK.get(left.severity, 5))
    right_rank = (_STATUS_RANK[right.status], -_SEVERITY_RANK.get(right.severity, 5))
    return left if left_rank >= right_rank else right


def _compare_status(
    *, installed: str, fixed: str, flavor: str
) -> tuple[str, str | None]:
    """``fixed``/``vulnerable`` for one advisory, or ``unknown`` with a reason.

    An advisory that names a fixed version with no release (``1.2.3``) against
    an installed ``1.2.3-4`` is a tie here rather than "installed is newer" or
    "installed is older": the vendor said what upstream version carries the fix
    and said nothing about packaging, so the host meets the statement. Erring
    the other way would be a false positive on every such advisory.
    """
    try:
        installed_evr = version_compare.parse_evr(installed, flavor=flavor)
        fixed_evr = version_compare.parse_evr(fixed, flavor=flavor)
    except version_compare.VersionParseError:
        return UNKNOWN, package_identity.REASON_UNPARSABLE_VERSION

    if not fixed_evr.release and installed_evr.release:
        installed = str(
            version_compare.Evr(
                epoch=installed_evr.epoch,
                version=installed_evr.version,
                release="",
                flavor=flavor,
            )
        )
    return (
        (FIXED, None)
        if version_compare.is_fixed(installed, fixed, flavor=flavor)
        else (VULNERABLE, None)
    )


def evaluate_package(
    identity: package_identity.PackageIdentity,
    provider: advisories.JsonAdvisoryProvider | None,
) -> list[MatchCandidate]:
    """Every candidate row one installed package produces.

    Returns ``[]`` — not an ``unknown`` row — when the package *was* assessed
    and the vendor simply has nothing on file for it. That is a real answer:
    the provider was asked and had no advisory. ``unknown`` is reserved for the
    cases where the question could not be put at all, which the caller detects
    from ``identity.matchable``.
    """
    if not identity.matchable or provider is None or not provider.available():
        return []

    release = identity.distro_release or ""
    installed = identity.version or ""
    feed_date = provider.feed_date()
    candidates: list[MatchCandidate] = []

    records: tuple[advisories.AdvisoryRecord, ...] = ()
    matched_package = ""
    for name in identity.source_package_candidates:
        records = provider.advisories_for(release=release, source_package=name)
        if records:
            matched_package = name
            break
    if not records:
        return []

    for record in records:
        if record.state == advisories.STATE_NOT_AFFECTED:
            status, reason = NOT_APPLICABLE, None
        elif record.state == advisories.STATE_OPEN or not record.fixed_version:
            status, reason = VULNERABLE, None
        else:
            status, reason = _compare_status(
                installed=installed,
                fixed=record.fixed_version,
                flavor=identity.flavor or version_compare.DEB,
            )
        for cve_id in record.cve_ids:
            candidates.append(
                MatchCandidate(
                    cve_id=cve_id,
                    status=status,
                    source_package=matched_package,
                    installed_package=identity.name,
                    installed_version=identity.version,
                    fixed_version=record.fixed_version,
                    advisory_id=record.advisory_id,
                    advisory_url=record.url,
                    provider=record.provider or provider.name,
                    severity=record.severity,
                    distro=identity.distro,
                    distro_release=identity.distro_release,
                    purl=identity.purl,
                    cpe23=identity.cpe23,
                    unknown_reason=reason,
                    feed_date=feed_date,
                    evidence={
                        "advisory_state": record.state,
                        "source_package_lookup": (
                            "exact"
                            if matched_package == identity.name
                            else "derived_from_binary_name"
                        ),
                        "comparison": (
                            f"{identity.version} vs fixed {record.fixed_version}"
                            if record.fixed_version
                            else "no fixed version published"
                        ),
                    },
                )
            )
    return candidates


@dataclass
class DeviceMatchResult:
    """What one device's run produced, before it is written."""

    device_id: str
    snapshot_id: str | None
    distro: str | None
    distro_release: str | None
    candidates: list[MatchCandidate]
    packages_total: int = 0
    packages_assessed: int = 0
    packages_unassessed: int = 0

    def counts(self) -> dict[str, int]:
        tally = dict.fromkeys(STATUSES, 0)
        for candidate in self.candidates:
            tally[candidate.status] += 1
        return tally


def match_software(
    *,
    device: dict[str, Any],
    software: list[dict[str, Any]],
    provider_for: Any = advisories.get_provider,
) -> DeviceMatchResult:
    """Pure matching pass over one device's software. No database access.

    Kept free of I/O so the interesting behaviour — backports not reported as
    vulnerable, unknown distros not reported as anything — is testable without
    Postgres.
    """
    ctx = package_identity.resolve_distro(
        os_family=device.get("os_family"),
        os_name=device.get("os_name"),
        os_version=device.get("os_version"),
    )
    provider = provider_for(ctx.distro) if ctx.supported else None

    by_cve: dict[str, MatchCandidate] = {}
    unassessed: dict[str, list[str]] = {}
    assessed = 0

    for item in software:
        identity = package_identity.identify(
            name=item.get("name") or "",
            version=item.get("version"),
            architecture=item.get("architecture"),
            source=item.get("source") or "other",
            distro=ctx,
        )
        if not identity.matchable:
            unassessed.setdefault(identity.reason or package_identity.REASON_UNKNOWN_DISTRO, []).append(
                identity.name
            )
            continue
        assessed += 1
        for candidate in evaluate_package(identity, provider):
            existing = by_cve.get(candidate.cve_id)
            by_cve[candidate.cve_id] = (
                candidate if existing is None else _worse(existing, candidate)
            )

    # One ``unknown`` row per reason, not per package: the answer an operator
    # needs is "1842 packages on this host could not be assessed because the
    # distribution is unknown", and 1842 rows say it worse.
    for reason, names in sorted(unassessed.items()):
        by_cve[f"\x00{reason}"] = MatchCandidate(
            cve_id="",
            status=UNKNOWN,
            unknown_reason=reason,
            distro=ctx.distro,
            distro_release=ctx.release,
            installed_package=names[0] if len(names) == 1 else "",
            provider=(provider.name if provider is not None else ""),
            evidence={
                "reason": reason,
                "package_count": len(names),
                "packages": sorted(names)[:_MAX_UNKNOWN_SAMPLES],
                "truncated": len(names) > _MAX_UNKNOWN_SAMPLES,
            },
        )

    return DeviceMatchResult(
        device_id=str(device.get("device_id") or ""),
        snapshot_id=device.get("latest_snapshot_id"),
        distro=ctx.distro,
        distro_release=ctx.release,
        candidates=list(by_cve.values()),
        packages_total=len(software),
        packages_assessed=assessed,
        packages_unassessed=sum(len(names) for names in unassessed.values()),
    )


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def _load_device_software(session, device: models.EndpointDevice) -> list[dict[str, Any]]:
    if not device.latest_snapshot_id:
        return []
    rows = (
        session.execute(
            select(models.EndpointSoftwareItem).where(
                models.EndpointSoftwareItem.snapshot_id == device.latest_snapshot_id
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "name": row.name,
            "version": row.version,
            "architecture": row.architecture,
            "source": row.source,
        }
        for row in rows
    ]


def _write_matches(
    session, *, tenant_id: str, device: models.EndpointDevice, result: DeviceMatchResult
) -> None:
    """Replace this device's rows. Whole-set replacement rather than an upsert:
    a match is a statement about the current snapshot, and a CVE that no longer
    matches must disappear rather than linger as a stale ``vulnerable``."""
    session.execute(
        delete(models.SoftwareCveMatch).where(
            models.SoftwareCveMatch.tenant_id == tenant_id,
            models.SoftwareCveMatch.device_id == device.device_id,
        )
    )
    matched_at = _now()
    for candidate in result.candidates:
        session.add(
            models.SoftwareCveMatch(
                tenant_id=tenant_id,
                device_id=device.device_id,
                snapshot_id=result.snapshot_id,
                match_key=candidate.match_key,
                cve_id=candidate.cve_id,
                status=candidate.status,
                severity=candidate.severity,
                source_package=candidate.source_package,
                installed_package=candidate.installed_package,
                installed_version=candidate.installed_version,
                fixed_version=candidate.fixed_version,
                advisory_id=candidate.advisory_id,
                advisory_url=candidate.advisory_url,
                provider=candidate.provider,
                distro=candidate.distro,
                distro_release=candidate.distro_release,
                purl=candidate.purl,
                cpe23=candidate.cpe23,
                unknown_reason=candidate.unknown_reason,
                feed_date=candidate.feed_date,
                evidence=candidate.evidence,
                matched_at=matched_at,
            )
        )


def run_for_device(settings: Settings, *, tenant_id: str, device_id: str) -> dict[str, Any] | None:
    """(Re-)run the matcher for one device. ``None`` when it is not this tenant's."""
    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, device_id)
        if device is None or device.tenant_id != tenant_id:
            return None
        software = _load_device_software(session, device)
        result = match_software(
            device={
                "device_id": device.device_id,
                "os_family": device.os_family,
                "os_name": device.os_name,
                "os_version": device.os_version,
                "latest_snapshot_id": device.latest_snapshot_id,
            },
            software=software,
        )
        _write_matches(session, tenant_id=tenant_id, device=device, result=result)
        summary = {
            "device_id": device.device_id,
            "snapshot_id": result.snapshot_id,
            "distro": result.distro,
            "distro_release": result.distro_release,
            "packages_total": result.packages_total,
            "packages_assessed": result.packages_assessed,
            "packages_unassessed": result.packages_unassessed,
            "matches": len(result.candidates),
            "by_status": result.counts(),
        }
    _log.info(
        "software-cve-match: device=%s distro=%s matches=%d",
        summary["device_id"],
        summary["distro"],
        summary["matches"],
    )
    return summary


def run_for_tenant(settings: Settings, *, tenant_id: str) -> dict[str, Any]:
    """(Re-)run the matcher for every device in a tenant."""
    with get_session(settings.postgres_url) as session:
        device_ids = list(
            session.execute(
                select(models.EndpointDevice.device_id).where(
                    models.EndpointDevice.tenant_id == tenant_id
                )
            )
            .scalars()
            .all()
        )
    devices: list[dict[str, Any]] = []
    for device_id in device_ids:
        summary = run_for_device(settings, tenant_id=tenant_id, device_id=device_id)
        if summary is not None:
            devices.append(summary)
    totals = dict.fromkeys(STATUSES, 0)
    for summary in devices:
        for status, count in summary["by_status"].items():
            totals[status] += count
    return {
        "tenant_id": tenant_id,
        "devices": len(devices),
        "matches": sum(summary["matches"] for summary in devices),
        "by_status": totals,
        "results": devices,
    }


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------

_MAX_LIMIT = 500


def _row_to_dict(row: models.SoftwareCveMatch, hostname: str | None = None) -> dict[str, Any]:
    return {
        "device_id": row.device_id,
        "hostname": hostname,
        "snapshot_id": row.snapshot_id,
        "cve_id": row.cve_id,
        "status": row.status,
        "severity": row.severity,
        "source_package": row.source_package,
        "installed_package": row.installed_package,
        "installed_version": row.installed_version,
        "fixed_version": row.fixed_version,
        "advisory_id": row.advisory_id,
        "advisory_url": row.advisory_url,
        "provider": row.provider,
        "distro": row.distro,
        "distro_release": row.distro_release,
        "purl": row.purl,
        "cpe23": row.cpe23,
        "unknown_reason": row.unknown_reason,
        "feed_date": row.feed_date,
        "evidence": dict(row.evidence or {}),
        "matched_at": _iso(row.matched_at),
    }


def _sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    return (
        -_STATUS_RANK.get(item["status"], 0),
        _SEVERITY_RANK.get(item.get("severity") or "unknown", 5),
        item.get("cve_id") or "",
    )


def list_for_device(
    settings: Settings,
    *,
    tenant_id: str,
    device_id: str,
    status: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, device_id)
        if device is None or device.tenant_id != tenant_id:
            return []
        stmt = select(models.SoftwareCveMatch).where(
            models.SoftwareCveMatch.tenant_id == tenant_id,
            models.SoftwareCveMatch.device_id == device_id,
        )
        if status:
            stmt = stmt.where(models.SoftwareCveMatch.status == status)
        if severity:
            stmt = stmt.where(models.SoftwareCveMatch.severity == severity)
        rows = session.execute(stmt).scalars().all()
        items = [_row_to_dict(row, device.hostname) for row in rows]
    items.sort(key=_sort_key)
    return items


def list_for_tenant(
    settings: Settings,
    *,
    tenant_id: str,
    status: str | None = None,
    severity: str | None = None,
    cve_id: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    limit = max(1, min(limit, _MAX_LIMIT))
    with get_session(settings.postgres_url) as session:
        stmt = (
            select(models.SoftwareCveMatch, models.EndpointDevice.hostname)
            .join(
                models.EndpointDevice,
                models.EndpointDevice.device_id == models.SoftwareCveMatch.device_id,
            )
            .where(models.SoftwareCveMatch.tenant_id == tenant_id)
        )
        if status:
            stmt = stmt.where(models.SoftwareCveMatch.status == status)
        if severity:
            stmt = stmt.where(models.SoftwareCveMatch.severity == severity)
        if cve_id:
            stmt = stmt.where(models.SoftwareCveMatch.cve_id == cve_id.strip().upper())
        rows = session.execute(stmt).all()
        items = [_row_to_dict(row, hostname) for row, hostname in rows]
    items.sort(key=_sort_key)
    return items[:limit]


def summary(settings: Settings, *, tenant_id: str) -> dict[str, Any]:
    """Per-status and per-severity tallies for the tenant's matches."""
    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(
                    models.SoftwareCveMatch.status,
                    models.SoftwareCveMatch.severity,
                    models.SoftwareCveMatch.matched_at,
                ).where(models.SoftwareCveMatch.tenant_id == tenant_id)
            )
            .all()
        )
    by_status = dict.fromkeys(STATUSES, 0)
    by_severity = dict.fromkeys(SEVERITY_ORDER, 0)
    last: datetime | None = None
    for status, severity, matched_at in rows:
        if status in by_status:
            by_status[status] += 1
        if status == VULNERABLE and severity in by_severity:
            by_severity[severity] += 1
        if matched_at is not None and (last is None or matched_at > last):
            last = matched_at
    return {
        "total": len(rows),
        "by_status": by_status,
        # Severity is only meaningful for a finding that is actually open, so
        # this counts vulnerable rows rather than every row.
        "vulnerable_by_severity": by_severity,
        "last_matched_at": _iso(last),
        "providers": advisories.status(),
    }
