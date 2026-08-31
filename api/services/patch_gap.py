"""Patch-gap analysis over the software→CVE matcher (ROADMAP Track E, M2).

The matcher answers *"is this package vulnerable"*, one row per CVE. That is
the right unit for a finding and the wrong unit for the work: an operator does
not fix twelve CVEs on a host, they run one upgrade that closes twelve CVEs.
This module regroups the matcher's ``vulnerable`` rows by the thing that
actually gets upgraded — the installed package — and names the command.

**No table of its own.** A patch gap is a view over ``software_cve_matches``,
computed on read. The matcher already replaces its rows wholesale per device on
each run, so deriving means a gap can never outlive the snapshot behind it or
disagree with the finding it came from. A stored gap would need its own
invalidation and would eventually be wrong.

**A vulnerable package with no published fix is not a patch gap.** The vendor
saying "affected, no fix yet" is an open risk, and putting it in a list headed
"run these commands" would be telling the operator to do something that cannot
work. Those are counted separately as ``unfixed`` and carry no command. The
distinction is the same one the matcher makes with ``unknown``: the honest
answer is a first-class result, not an omission.

**The target version is the highest fix among the CVEs on that package**,
ordered by the distribution's own comparison rules — upgrading to the newest
required version closes every advisory below it, so one command per package is
correct rather than a convenient simplification.
"""

from __future__ import annotations

import logging
import shlex
from typing import Any

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import software_cve_match as matcher
from api.services import version_compare
from api.settings import Settings

_log = logging.getLogger("shapoclyack.patch-gap")

#: ``purl`` type → version grammar. The matcher stores a purl on every row it
#: could identify, and the purl type is exactly the grammar the fixed versions
#: are written in.
_PURL_FLAVORS = {"deb": version_compare.DEB, "rpm": version_compare.RPM}

#: Distro → the upgrade a single package takes. Debian and Ubuntu are the
#: distributions the advisory providers actually cover today, so the ``rpm``
#: branch is written and dormant rather than exercised; it is here so an rpm
#: provider does not also need a command mapping written under time pressure.
_UPGRADE_TEMPLATES = {
    version_compare.DEB: "sudo apt-get update && sudo apt-get install --only-upgrade {packages}",
    version_compare.RPM: "sudo dnf upgrade {packages}",
}


def _flavor_for(purl: str | None) -> str | None:
    """The version grammar a row's fixed versions are written in."""
    if not purl or not purl.startswith("pkg:"):
        return None
    return _PURL_FLAVORS.get(purl[4:].split("/", 1)[0].strip().lower())


def upgrade_command(flavor: str | None, packages: list[str]) -> str | None:
    """The command that installs ``packages``, or ``None`` when unknown.

    Names are shell-quoted. They come from a remote endpoint's inventory and
    the result is rendered for an operator to paste into a root shell, so a
    package name is data here, never syntax.
    """
    template = _UPGRADE_TEMPLATES.get(flavor or "")
    if template is None or not packages:
        return None
    return template.format(packages=" ".join(shlex.quote(name) for name in sorted(set(packages))))


def _highest_fix(candidates: list[str], *, flavor: str | None) -> str | None:
    """The newest of several fixed versions, by the distro's own ordering.

    Returns ``None`` when the versions cannot be ordered — an unparseable
    version is not silently treated as the smallest, because that would name a
    target that does not close every advisory on the package.
    """
    usable = [value for value in candidates if value]
    if not usable:
        return None
    if flavor is None:
        # One fix needs no ordering; several without a grammar cannot be ranked.
        return usable[0] if len(set(usable)) == 1 else None
    best = usable[0]
    for candidate in usable[1:]:
        try:
            if version_compare.compare(candidate, best, flavor=flavor) > 0:
                best = candidate
        except version_compare.VersionParseError:
            _log.warning(
                "Cannot order fixed versions %r and %r as %s", candidate, best, flavor
            )
            return None
    return best


def _worst_severity(severities: list[str]) -> str:
    ranked = [s for s in severities if s in matcher.SEVERITY_ORDER]
    if not ranked:
        return "unknown"
    return min(ranked, key=matcher.SEVERITY_ORDER.index)


def _vulnerable_rows(session, *, tenant_id: str, device_id: str | None):
    filters = [
        models.SoftwareCveMatch.tenant_id == tenant_id,
        models.SoftwareCveMatch.status == matcher.VULNERABLE,
    ]
    if device_id is not None:
        filters.append(models.SoftwareCveMatch.device_id == device_id)
    return session.scalars(select(models.SoftwareCveMatch).where(*filters)).all()


def _build_gaps(rows) -> tuple[list[dict[str, Any]], int]:
    """``(gaps, unfixed)`` for one device's vulnerable rows."""
    grouped: dict[str, list[Any]] = {}
    unfixed = 0
    for row in rows:
        if not row.fixed_version:
            # Affected, no fix published. Real risk, no command to give.
            unfixed += 1
            continue
        package = row.installed_package or row.source_package
        if not package:
            continue
        grouped.setdefault(package, []).append(row)

    gaps: list[dict[str, Any]] = []
    for package, group in grouped.items():
        flavor = _flavor_for(next((r.purl for r in group if r.purl), None))
        target = _highest_fix([r.fixed_version for r in group], flavor=flavor)
        cves = sorted({r.cve_id for r in group if r.cve_id})
        severities = [r.severity for r in group]
        gaps.append(
            {
                "installed_package": package,
                "source_package": group[0].source_package or "",
                "installed_version": group[0].installed_version,
                # ``None`` when the fixes could not be ordered; the caller must
                # not render a command that may not close every CVE listed.
                "target_version": target,
                "cve_ids": cves,
                "cve_count": len(cves),
                "worst_severity": _worst_severity(severities),
                "by_severity": {
                    name: sum(1 for s in severities if s == name)
                    for name in matcher.SEVERITY_ORDER
                    if any(s == name for s in severities)
                },
                "distro": group[0].distro,
                "distro_release": group[0].distro_release,
                "upgrade_command": (
                    upgrade_command(flavor, [package]) if target else None
                ),
            }
        )

    gaps.sort(
        key=lambda gap: (
            matcher.SEVERITY_ORDER.index(gap["worst_severity"])
            if gap["worst_severity"] in matcher.SEVERITY_ORDER
            else len(matcher.SEVERITY_ORDER),
            -gap["cve_count"],
            gap["installed_package"],
        )
    )
    return gaps, unfixed


def for_device(
    settings: Settings, *, tenant_id: str, device_id: str
) -> dict[str, Any] | None:
    """One device's outstanding upgrades, worst first.

    ``None`` when the device is not in the tenant. A device with nothing
    outstanding returns an empty gap list rather than ``None`` — "no gaps" and
    "no such device" are different answers.
    """
    with get_session(settings.postgres_url) as session:
        device = session.scalar(
            select(models.EndpointDevice).where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.device_id == device_id,
            )
        )
        if device is None:
            return None
        rows = _vulnerable_rows(session, tenant_id=tenant_id, device_id=device_id)
        hostname = device.hostname

    gaps, unfixed = _build_gaps(rows)
    flavors = {_flavor_for(row.purl) for row in rows if row.purl}
    # One command for the whole host, but only for packages we can actually
    # name a target for, and only when the host speaks one package grammar.
    actionable = [gap["installed_package"] for gap in gaps if gap["target_version"]]
    combined = (
        upgrade_command(next(iter(flavors)), actionable) if len(flavors) == 1 else None
    )
    return {
        "device_id": device_id,
        "hostname": hostname,
        "packages_to_upgrade": len(gaps),
        "cves_closed_by_upgrade": sum(gap["cve_count"] for gap in gaps),
        # Vulnerable, but the vendor has published no fix. Not a gap.
        "unfixed_findings": unfixed,
        "worst_severity": _worst_severity([gap["worst_severity"] for gap in gaps]),
        "combined_upgrade_command": combined,
        "gaps": gaps,
    }


def for_tenant(settings: Settings, *, tenant_id: str, limit: int = 50) -> dict[str, Any]:
    """Estate-wide patch gap: the tally, plus the worst devices.

    ``devices`` is capped by ``limit``; the totals are over the whole tenant, so
    a truncated list never makes the estate look smaller than it is.
    """
    with get_session(settings.postgres_url) as session:
        rows = _vulnerable_rows(session, tenant_id=tenant_id, device_id=None)
        hostnames = dict(
            session.execute(
                select(models.EndpointDevice.device_id, models.EndpointDevice.hostname).where(
                    models.EndpointDevice.tenant_id == tenant_id
                )
            ).all()
        )

    by_device: dict[str, list[Any]] = {}
    for row in rows:
        by_device.setdefault(row.device_id, []).append(row)

    devices: list[dict[str, Any]] = []
    packages_total = cves_total = unfixed_total = 0
    for device_id, device_rows in by_device.items():
        gaps, unfixed = _build_gaps(device_rows)
        packages_total += len(gaps)
        cves_total += sum(gap["cve_count"] for gap in gaps)
        unfixed_total += unfixed
        if not gaps and not unfixed:
            continue
        devices.append(
            {
                "device_id": device_id,
                "hostname": hostnames.get(device_id),
                "packages_to_upgrade": len(gaps),
                "cves_closed_by_upgrade": sum(gap["cve_count"] for gap in gaps),
                "unfixed_findings": unfixed,
                "worst_severity": _worst_severity([gap["worst_severity"] for gap in gaps]),
            }
        )

    devices.sort(
        key=lambda item: (
            matcher.SEVERITY_ORDER.index(item["worst_severity"])
            if item["worst_severity"] in matcher.SEVERITY_ORDER
            else len(matcher.SEVERITY_ORDER),
            -item["cves_closed_by_upgrade"],
            item["device_id"],
        )
    )
    return {
        "tenant_id": tenant_id,
        "devices_with_gaps": len(devices),
        "packages_to_upgrade": packages_total,
        "cves_closed_by_upgrade": cves_total,
        "unfixed_findings": unfixed_total,
        "devices": devices[:limit],
        "truncated": len(devices) > limit,
    }
