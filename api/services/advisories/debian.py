"""Debian advisory provider (Security Tracker JSON).

The Debian Security Tracker publishes, per source package, a per-release status
for every CVE it knows about: ``resolved`` with the version the fix landed in,
``open``, or ``undetermined``. That is precisely the statement this feature
needs and precisely the statement NVD cannot make — the tracker knows that
``openssl 1.1.1n-0+deb11u4`` on bullseye carries the fix for CVE-2023-0286 even
though upstream 1.1.1n is listed as affected.

``normalize_tracker_json`` converts the tracker's own shape into the flat
dataset the offline loader reads, so the transformation lives next to the
provider that depends on it and can be tested without a network.
"""

from __future__ import annotations

from typing import Any, Iterator

from api.services.advisories import base
from api.services.package_identity import DEBIAN

#: Tracker statuses that mean "this release is not affected". ``undetermined``
#: is deliberately *not* here: "we have not decided" is not "you are safe", and
#: dropping it entirely is the honest handling — the matcher then has nothing
#: to say about that CVE for that package, which is the truth.
_NOT_AFFECTED = {"not-affected", "not affected", "removed"}

#: Debian urgency → the severity vocabulary the rest of the platform uses.
#: Debian's own words are kept where they map cleanly and anything unfamiliar
#: becomes ``unknown`` rather than being rounded to a level nobody stated.
_URGENCY_SEVERITY = {
    "end-of-life": "unknown",
    "high": "high",
    "low": "low",
    "medium": "medium",
    "negligible": "negligible",
    "not yet assigned": "unknown",
    "unimportant": "negligible",
}


def _severity(urgency: Any) -> str:
    text = str(urgency or "").strip().lower()
    # The tracker appends "**" to an urgency it has flagged for review.
    text = text.rstrip("*").strip()
    return _URGENCY_SEVERITY.get(text, "unknown")


class DebianAdvisoryProvider(base.JsonAdvisoryProvider):
    name = "debian-security-tracker"
    distro = DEBIAN
    env_var = "OCTO_DEBIAN_ADVISORY_DATABASE"
    default_path = "scanner/data/advisories/debian-advisories.json"


def normalize_tracker_json(payload: Any) -> Iterator[dict[str, Any]]:
    """``security-tracker/tracker/data/json`` → flat dataset entries.

    The tracker's shape is ``{source_package: {CVE-…: {"releases": {codename:
    {"status": …, "fixed_version": …, "urgency": …}}}}}``. Everything this
    yields is a dict in the dataset's ``entries`` format; the caller wraps it in
    the ``{version, source, updated, entries}`` envelope.
    """
    if not isinstance(payload, dict):
        return
    for source_package, cves in payload.items():
        if not isinstance(cves, dict):
            continue
        for cve_id, detail in cves.items():
            if not isinstance(detail, dict):
                continue
            releases = detail.get("releases")
            if not isinstance(releases, dict):
                continue
            for release, info in releases.items():
                if not isinstance(info, dict):
                    continue
                status = str(info.get("status") or "").strip().lower()
                fixed_version = info.get("fixed_version") or None
                if status in _NOT_AFFECTED:
                    state = base.STATE_NOT_AFFECTED
                    fixed_version = None
                elif status == "resolved" and fixed_version and str(fixed_version) != "0":
                    state = base.STATE_RESOLVED
                elif status == "open":
                    state = base.STATE_OPEN
                    fixed_version = None
                else:
                    # "undetermined", or "resolved" with the tracker's sentinel
                    # ``fixed_version: "0"`` meaning "never affected in this
                    # release". Neither is a statement we can act on.
                    continue
                yield {
                    # The tracker is keyed by CVE, not by DSA: a per-release
                    # status often exists with no advisory published (a fix
                    # that rode in on a point release). Naming the CVE as the
                    # advisory id is honest; inventing a DSA number would not be.
                    "advisory_id": str(cve_id),
                    "cve_ids": [str(cve_id)],
                    "release": str(release),
                    "source_package": str(source_package),
                    "fixed_version": str(fixed_version) if fixed_version else None,
                    "severity": _severity(info.get("urgency")),
                    "state": state,
                    "url": f"https://security-tracker.debian.org/tracker/{cve_id}",
                }
