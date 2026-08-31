"""Software to CVE Matcher and Patch Gap Engine over Endpoint Inventory (Sprint 3).

Translates Lariska package inventory items into standardized Package URLs (PURL)
and CPE 2.3 identifiers, matches installed packages against OSV / vendor security
advisories (Debian, Ubuntu, RHEL, Alpine, PyPI, npm, generic), performs patch gap
analysis, and bridges detected findings into Shapoclyack's unified Vulnerability Center.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import vuln_states
from api.settings import Settings

_log = logging.getLogger("shapoclyack.software-matcher")


# ---------------------------------------------------------------------------
# PURL & CPE Derivation
# ---------------------------------------------------------------------------

def derive_purl(
    name: str,
    version: str | None = None,
    source: str = "system",
    os_name: str | None = None,
    os_family: str | None = None,
) -> str:
    """Generate a standard Package URL (PURL) for an endpoint software item."""
    clean_name = (name or "").strip().lower()
    clean_ver = f"@{version.strip()}" if version and version.strip() else ""
    os_n = (os_name or "").lower()
    os_f = (os_family or "").lower()
    src = (source or "").lower()

    if src in ("deb", "dpkg", "apt") or "ubuntu" in os_n:
        distro = "ubuntu" if "ubuntu" in os_n else "debian"
        return f"pkg:deb/{distro}/{clean_name}{clean_ver}"
    if src in ("rpm", "yum", "dnf") or any(d in os_n for d in ("rhel", "redhat", "centos", "rocky", "alma", "fedora")):
        return f"pkg:rpm/redhat/{clean_name}{clean_ver}"
    if src in ("apk", "alpine") or "alpine" in os_n:
        return f"pkg:apk/alpine/{clean_name}{clean_ver}"
    if src in ("pip", "pypi", "python"):
        return f"pkg:pypi/{clean_name}{clean_ver}"
    if src in ("npm", "node", "nodejs", "javascript"):
        return f"pkg:npm/{clean_name}{clean_ver}"
    if src in ("gem", "ruby"):
        return f"pkg:gem/{clean_name}{clean_ver}"
    if src in ("cargo", "crates", "rust"):
        return f"pkg:cargo/{clean_name}{clean_ver}"
    if src in ("go", "golang"):
        return f"pkg:golang/{clean_name}{clean_ver}"
    if "windows" in os_f or "windows" in os_n:
        return f"pkg:generic/windows/{clean_name}{clean_ver}"

    return f"pkg:generic/{clean_name}{clean_ver}"


def derive_cpe(name: str, version: str | None = None, publisher: str | None = None) -> str:
    """Generate a standard CPE 2.3 URI for a software package."""
    clean_name = re.sub(r"[^a-zA-Z0-9_\-.]", "_", (name or "").strip().lower())
    clean_ver = re.sub(r"[^a-zA-Z0-9_\-.]", "_", (version or "*").strip())
    clean_pub = re.sub(r"[^a-zA-Z0-9_\-.]", "_", (publisher or "*").strip().lower())
    return f"cpe:2.3:a:{clean_pub}:{clean_name}:{clean_ver}:*:*:*:*:*:*:*"


# ---------------------------------------------------------------------------
# Version Comparison
# ---------------------------------------------------------------------------

def _split_version_chunks(ver_str: str) -> list[int | str]:
    """Tokenize version into integer and string components."""
    clean = re.sub(r"^[vV]", "", ver_str.strip())
    chunks = re.findall(r"\d+|\D+", clean)
    result: list[int | str] = []
    for c in chunks:
        if c.isdigit():
            result.append(int(c))
        else:
            # normalize punctuation / separators
            norm = c.strip(".-_+~:")
            if norm:
                result.append(norm)
    return result


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2."""
    if v1 == v2:
        return 0
    c1 = _split_version_chunks(v1)
    c2 = _split_version_chunks(v2)

    for a, b in zip(c1, c2):
        if isinstance(a, int) and isinstance(b, int):
            if a != b:
                return -1 if a < b else 1
        else:
            sa, sb = str(a), str(b)
            if sa != sb:
                return -1 if sa < sb else 1

    if len(c1) != len(c2):
        return -1 if len(c1) < len(c2) else 1
    return 0


def is_version_vulnerable(
    installed_version: str | None,
    fixed_version: str | None,
    introduced_version: str | None = None,
) -> bool:
    """Determine if an installed package version is vulnerable given advisory version bounds."""
    if not installed_version:
        return False
    if introduced_version and compare_versions(installed_version, introduced_version) < 0:
        return False
    if fixed_version:
        return compare_versions(installed_version, fixed_version) < 0
    return True


# ---------------------------------------------------------------------------
# Advisory Registry & Matching
# ---------------------------------------------------------------------------

# Built-in curated advisory database covering common critical enterprise & Linux packages
CURATED_ADVISORIES: list[dict[str, Any]] = [
    {
        "ecosystem": "deb",
        "packages": ["openssl", "libssl1.1", "libssl3"],
        "cve": "CVE-2023-0286",
        "advisory_id": "DSA-5343-1",
        "severity": "high",
        "cvss": 7.5,
        "title": "OpenSSL X.400 address type confusion vulnerability",
        "introduced": "1.1.1",
        "fixed": "1.1.1t-1+deb11u1",
    },
    {
        "ecosystem": "deb",
        "packages": ["openssh-server", "openssh-client"],
        "cve": "CVE-2024-6387",
        "advisory_id": "DSA-5724-1",
        "severity": "critical",
        "cvss": 9.8,
        "title": "regreSSHion: Remote Unauthenticated Code Execution in OpenSSH server (sshd)",
        "introduced": "9.2p1",
        "fixed": "9.2p1-2+deb12u3",
    },
    {
        "ecosystem": "deb",
        "packages": ["sudo"],
        "cve": "CVE-2021-3156",
        "advisory_id": "DSA-4839-1",
        "severity": "critical",
        "cvss": 9.8,
        "title": "Baron Samedit: Heap-based buffer overflow in Sudo privilege escalation",
        "introduced": "1.8.2",
        "fixed": "1.8.31p2",
    },
    {
        "ecosystem": "deb",
        "packages": ["curl", "libcurl4"],
        "cve": "CVE-2023-38545",
        "advisory_id": "DSA-5522-1",
        "severity": "critical",
        "cvss": 9.8,
        "title": "curl: SOCKS5 heap buffer overflow vulnerability",
        "introduced": "7.69.0",
        "fixed": "7.88.1-10+deb12u4",
    },
    {
        "ecosystem": "rpm",
        "packages": ["openssl", "openssl-libs"],
        "cve": "CVE-2023-0286",
        "advisory_id": "RHSA-2023:0800",
        "severity": "high",
        "cvss": 7.5,
        "title": "OpenSSL X.400 address type confusion vulnerability",
        "introduced": "1.1.1",
        "fixed": "1.1.1k-9.el8_7",
    },
    {
        "ecosystem": "rpm",
        "packages": ["openssh", "openssh-server"],
        "cve": "CVE-2024-6387",
        "advisory_id": "RHSA-2024:4312",
        "severity": "critical",
        "cvss": 9.8,
        "title": "regreSSHion: OpenSSH Remote Code Execution vulnerability",
        "introduced": "9.2p1",
        "fixed": "9.3p1-13.el9_4.1",
    },
    {
        "ecosystem": "apk",
        "packages": ["busybox", "busybox-binsh"],
        "cve": "CVE-2022-30065",
        "advisory_id": "ALPINESEC-2022-001",
        "severity": "high",
        "cvss": 7.8,
        "title": "Busybox use-after-free in awk implementation",
        "introduced": "1.30.0",
        "fixed": "1.35.0-r1",
    },
    {
        "ecosystem": "pypi",
        "packages": ["requests", "urllib3"],
        "cve": "CVE-2023-43804",
        "advisory_id": "GHSA-j7hp-h8jx-5ppr",
        "severity": "high",
        "cvss": 8.1,
        "title": "urllib3 Cookie header leak on cross-origin redirect",
        "introduced": "1.26.0",
        "fixed": "2.0.6",
    },
    {
        "ecosystem": "npm",
        "packages": ["axios"],
        "cve": "CVE-2023-45857",
        "advisory_id": "GHSA-wf5p-g6vw-rhxx",
        "severity": "high",
        "cvss": 7.5,
        "title": "Axios Cross-Site Request Forgery (CSRF) via unauthorized redirect headers",
        "introduced": "0.8.0",
        "fixed": "1.6.0",
    },
]


def find_matching_advisories(
    software_name: str,
    installed_version: str | None,
    source: str = "system",
    os_name: str | None = None,
) -> list[dict[str, Any]]:
    """Query known advisories for an installed package."""
    if not installed_version or not software_name:
        return []

    clean_name = software_name.strip().lower()
    matches: list[dict[str, Any]] = []

    for adv in CURATED_ADVISORIES:
        pkg_names = [p.lower() for p in adv["packages"]]
        if clean_name not in pkg_names:
            continue

        if is_version_vulnerable(
            installed_version=installed_version,
            fixed_version=adv.get("fixed"),
            introduced_version=adv.get("introduced"),
        ):
            matches.append(adv)

    return matches


# ---------------------------------------------------------------------------
# Matcher Orchestration & Vulnerability Center Integration
# ---------------------------------------------------------------------------

def match_device_software(
    settings: Settings,
    tenant_id: str,
    device_id: str,
) -> list[dict[str, Any]]:
    """Match all installed software for a device against security advisories,
    persist findings in `endpoint_software_advisories`, and bridge into Vulnerability Center."""
    now = datetime.now(UTC)

    with get_session(settings.postgres_url) as session:
        # 1. Fetch device
        device = session.execute(
            select(models.EndpointDevice).where(
                models.EndpointDevice.tenant_id == tenant_id,
                models.EndpointDevice.device_id == device_id,
            )
        ).scalar_one_or_none()

        if not device:
            return []

        # 2. Fetch latest software items for this device
        if not device.latest_snapshot_id:
            return []

        software_items = (
            session.execute(
                select(models.EndpointSoftwareItem).where(
                    models.EndpointSoftwareItem.snapshot_id == device.latest_snapshot_id,
                    models.EndpointSoftwareItem.tenant_id == tenant_id,
                )
            )
            .scalars()
            .all()
        )

        # 3. Match against advisories
        detected_advisories: list[dict[str, Any]] = []
        observed_advisory_keys: set[tuple[str, str]] = set()

        for item in software_items:
            matches = find_matching_advisories(
                software_name=item.name,
                installed_version=item.version,
                source=item.source,
                os_name=device.os_name,
            )
            purl = derive_purl(
                name=item.name,
                version=item.version,
                source=item.source,
                os_name=device.os_name,
                os_family=device.os_family,
            )
            cpe = derive_cpe(name=item.name, version=item.version, publisher=item.publisher)

            for adv in matches:
                key = (item.name, adv["cve"])
                observed_advisory_keys.add(key)

                # Upsert EndpointSoftwareAdvisory
                existing = session.execute(
                    select(models.EndpointSoftwareAdvisory).where(
                        models.EndpointSoftwareAdvisory.device_id == device_id,
                        models.EndpointSoftwareAdvisory.software_name == item.name,
                        models.EndpointSoftwareAdvisory.cve == adv["cve"],
                    )
                ).scalar_one_or_none()

                vuln_id = None
                # Bridge to Vulnerability Center if asset_id is present
                target_asset_id = device.asset_id or device.hostname or device_id
                if target_asset_id:
                    finding_key = hashlib.sha256(
                        f"{target_asset_id}|{item.name}|{adv['cve']}".encode("utf-8")
                    ).hexdigest()

                    vuln = session.execute(
                        select(models.Vulnerability).where(
                            models.Vulnerability.tenant_id == tenant_id,
                            models.Vulnerability.finding_key == finding_key,
                        )
                    ).scalar_one_or_none()

                    if not vuln:
                        vuln_id = f"vln_{hashlib.sha256(f'{tenant_id}:{finding_key}'.encode('utf-8')).hexdigest()[:12]}"
                        vuln = models.Vulnerability(
                            vuln_id=vuln_id,
                            tenant_id=tenant_id,
                            asset_id=target_asset_id,
                            finding_key=finding_key,
                            cve=adv["cve"],
                            title=f"[{item.name}] {adv['title']}",
                            severity=adv["severity"],
                            cvss=adv.get("cvss"),
                            state=vuln_states.OPEN,
                            state_changed_at=now,
                            first_seen_at=now,
                            last_seen_at=now,
                            sla_started_at=now,
                            created_at=now,
                            updated_at=now,
                        )
                        session.add(vuln)
                    else:
                        vuln_id = vuln.vuln_id
                        vuln.last_seen_at = now
                        vuln.updated_at = now

                if existing:
                    existing.installed_version = item.version
                    existing.fixed_version = adv.get("fixed")
                    existing.purl = purl
                    existing.cpe = cpe
                    existing.severity = adv["severity"]
                    existing.cvss = adv.get("cvss")
                    existing.title = adv["title"]
                    existing.asset_id = device.asset_id
                    existing.vuln_id = vuln_id
                    existing.matched_at = now
                else:
                    new_adv = models.EndpointSoftwareAdvisory(
                        tenant_id=tenant_id,
                        device_id=device_id,
                        asset_id=device.asset_id,
                        software_name=item.name,
                        installed_version=item.version,
                        fixed_version=adv.get("fixed"),
                        purl=purl,
                        cpe=cpe,
                        cve=adv["cve"],
                        advisory_id=adv.get("advisory_id"),
                        severity=adv["severity"],
                        cvss=adv.get("cvss"),
                        title=adv["title"],
                        vuln_id=vuln_id,
                        matched_at=now,
                    )
                    session.add(new_adv)

                detected_advisories.append({
                    "software_name": item.name,
                    "installed_version": item.version,
                    "fixed_version": adv.get("fixed"),
                    "purl": purl,
                    "cpe": cpe,
                    "cve": adv["cve"],
                    "advisory_id": adv.get("advisory_id"),
                    "severity": adv["severity"],
                    "cvss": adv.get("cvss"),
                    "title": adv["title"],
                    "vuln_id": vuln_id,
                })

        # 4. Clean up stale advisories for this device that are no longer detected (e.g. package updated or removed)
        all_stored = session.execute(
            select(models.EndpointSoftwareAdvisory).where(
                models.EndpointSoftwareAdvisory.device_id == device_id,
                models.EndpointSoftwareAdvisory.tenant_id == tenant_id,
            )
        ).scalars().all()

        for stored in all_stored:
            if (stored.software_name, stored.cve) not in observed_advisory_keys:
                session.delete(stored)

        session.commit()
        return detected_advisories


# ---------------------------------------------------------------------------
# Patch Gap Analysis & Queries
# ---------------------------------------------------------------------------

def get_device_advisories(
    settings: Settings,
    tenant_id: str,
    device_id: str,
) -> list[dict[str, Any]]:
    """List detected software advisories for a device."""
    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(models.EndpointSoftwareAdvisory)
                .where(
                    models.EndpointSoftwareAdvisory.tenant_id == tenant_id,
                    models.EndpointSoftwareAdvisory.device_id == device_id,
                )
                .order_by(models.EndpointSoftwareAdvisory.cvss.desc().nullslast())
            )
            .scalars()
            .all()
        )
        return [_advisory_to_dict(r) for r in rows]


def get_asset_advisories(
    settings: Settings,
    tenant_id: str,
    asset_id: str,
) -> list[dict[str, Any]]:
    """List detected software advisories for an asset."""
    with get_session(settings.postgres_url) as session:
        rows = (
            session.execute(
                select(models.EndpointSoftwareAdvisory)
                .where(
                    models.EndpointSoftwareAdvisory.tenant_id == tenant_id,
                    models.EndpointSoftwareAdvisory.asset_id == asset_id,
                )
                .order_by(models.EndpointSoftwareAdvisory.cvss.desc().nullslast())
            )
            .scalars()
            .all()
        )
        return [_advisory_to_dict(r) for r in rows]


def compute_patch_gaps(
    settings: Settings,
    tenant_id: str,
    device_id: str | None = None,
) -> dict[str, Any]:
    """Calculate patch gap metrics and actionable upgrade commands."""
    with get_session(settings.postgres_url) as session:
        query = select(models.EndpointSoftwareAdvisory).where(
            models.EndpointSoftwareAdvisory.tenant_id == tenant_id
        )
        if device_id:
            query = query.where(models.EndpointSoftwareAdvisory.device_id == device_id)

        rows = session.execute(query).scalars().all()

        total_advisories = len(rows)
        vulnerable_packages: set[str] = set()
        affected_devices: set[str] = set()
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        remediations: list[dict[str, Any]] = []

        for r in rows:
            vulnerable_packages.add(r.software_name)
            affected_devices.add(r.device_id)
            sev = (r.severity or "").lower()
            if sev == "critical":
                critical_count += 1
            elif sev == "high":
                high_count += 1
            elif sev == "medium":
                medium_count += 1
            else:
                low_count += 1

            if r.fixed_version:
                remediations.append({
                    "software_name": r.software_name,
                    "installed_version": r.installed_version,
                    "fixed_version": r.fixed_version,
                    "cve": r.cve,
                    "severity": r.severity,
                    "upgrade_command": _suggest_upgrade_command(r.purl, r.software_name),
                })

        return {
            "tenant_id": tenant_id,
            "device_id": device_id,
            "total_advisories": total_advisories,
            "vulnerable_package_count": len(vulnerable_packages),
            "affected_device_count": len(affected_devices),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "remediations": remediations,
        }


def _suggest_upgrade_command(purl: str | None, package_name: str) -> str:
    """Generate the package manager command to resolve a package advisory."""
    if not purl:
        return f"upgrade {package_name}"
    if "pkg:deb/" in purl:
        return f"apt-get --only-upgrade install {package_name}"
    if "pkg:rpm/" in purl:
        return f"dnf update {package_name}"
    if "pkg:apk/" in purl:
        return f"apk add --upgrade {package_name}"
    if "pkg:pypi/" in purl:
        return f"pip install --upgrade {package_name}"
    if "pkg:npm/" in purl:
        return f"npm update {package_name}"
    return f"upgrade {package_name}"


def _advisory_to_dict(r: models.EndpointSoftwareAdvisory) -> dict[str, Any]:
    return {
        "id": r.id,
        "tenant_id": r.tenant_id,
        "device_id": r.device_id,
        "asset_id": r.asset_id,
        "software_name": r.software_name,
        "installed_version": r.installed_version,
        "fixed_version": r.fixed_version,
        "purl": r.purl,
        "cpe": r.cpe,
        "cve": r.cve,
        "advisory_id": r.advisory_id,
        "severity": r.severity,
        "cvss": r.cvss,
        "title": r.title,
        "vuln_id": r.vuln_id,
        "matched_at": r.matched_at.isoformat() if r.matched_at else None,
    }
