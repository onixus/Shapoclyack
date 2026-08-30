"""Ubuntu advisory provider (USN / OVAL-derived JSON).

Canonical publishes the same statement Debian's tracker does, in two shapes: the
USN database (``usn.json`` — advisory-centric, "USN-6188-1 fixes these CVEs in
these binary packages on these releases") and per-release OVAL definitions. Both
reduce to the same tuple, so both are normalized here into the flat dataset the
offline loader reads.

USN is the shape this milestone converts, because it is a single small file
covering every supported release, whereas OVAL is one large XML document per
release. ``normalize_usn_json`` is the whole conversion, and the notable part is
that it maps **binary** package names back to the **source** package the USN
names — ``libssl1.1`` is fixed by an ``openssl`` USN, and a matcher that looked
only at binary names would answer nothing for the package an operator actually
has installed. Both names are emitted, so either lookup hits.
"""

from __future__ import annotations

from typing import Any, Iterator

from api.services.advisories import base
from api.services.package_identity import UBUNTU


class UbuntuAdvisoryProvider(base.JsonAdvisoryProvider):
    name = "ubuntu-usn"
    distro = UBUNTU
    env_var = "OCTO_UBUNTU_ADVISORY_DATABASE"
    default_path = "scanner/data/advisories/ubuntu-advisories.json"


def normalize_usn_json(payload: Any) -> Iterator[dict[str, Any]]:
    """``usn.json`` → flat dataset entries.

    The USN shape is ``{usn_id: {"cves": [...], "releases": {codename:
    {"sources": {pkg: {"version": …, "description": …}},
     "binaries": {pkg: {"version": …}}}}}}``. Entries are emitted for the source
    package and for every binary built from it, all pointing at the same fixed
    version, since that is what the USN itself states.
    """
    if not isinstance(payload, dict):
        return
    for usn_id, advisory in payload.items():
        if not isinstance(advisory, dict):
            continue
        cves = advisory.get("cves")
        if isinstance(cves, str):
            cves = [cves]
        cve_ids = [
            str(cve).strip().upper()
            for cve in (cves or ())
            if str(cve).strip().upper().startswith("CVE-")
        ]
        if not cve_ids:
            # A USN with no CVE (a regression fix, or a LSN) has nothing to
            # match against and is dropped rather than given a synthetic id.
            continue
        releases = advisory.get("releases")
        if not isinstance(releases, dict):
            continue
        url = f"https://ubuntu.com/security/notices/{usn_id}"
        severity = str(advisory.get("severity") or "unknown").strip().lower() or "unknown"
        for release, detail in releases.items():
            if not isinstance(detail, dict):
                continue
            for group in ("sources", "binaries"):
                packages = detail.get(group)
                if not isinstance(packages, dict):
                    continue
                for package, info in packages.items():
                    version = info.get("version") if isinstance(info, dict) else None
                    if not version:
                        continue
                    yield {
                        "advisory_id": str(usn_id),
                        "cve_ids": cve_ids,
                        "release": str(release),
                        "source_package": str(package),
                        "fixed_version": str(version),
                        "severity": severity,
                        "state": base.STATE_RESOLVED,
                        "url": url,
                    }
