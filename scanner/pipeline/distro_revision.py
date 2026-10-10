"""Distribution and package revision as a banner states them.

``SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13`` is OpenSSH *8.2p1* built as the
Ubuntu package revision *4ubuntu0.13*. The two are different facts: the first
is what an NVD range is compared with, the second is what tells a backported
fix from an unpatched build. Probers glue them into one string (nmap) or drop
the second (Pulse), so the scanner records the revision in its own field
(``ServiceRecord.distro_revision``) and the API reads that field first.

This module is the one place the revision grammar lives. The scanner fills the
fields with it; ``api/services/retro_match.py`` falls back to it for rows
recorded before the fields existed, so the two can never disagree on what
counts as a revision. (The API may import the scanner package, not the other
way round, hence the home.)
"""

from __future__ import annotations

import re

UBUNTU = "ubuntu"
DEBIAN = "debian"

#: ``Ubuntu-4ubuntu0.5`` / ``Ubuntu 3ubuntu0.6``: the distribution's word, then the revision.
UBUNTU_REVISION = re.compile(r"ubuntu[\s_-]+(\d[\w.+~]*ubuntu[\w.+~]*)", re.IGNORECASE)
#: ``7.4.3-4ubuntu2.19``: the revision as a suffix of the product's own version.
UBUNTU_BARE_REVISION = re.compile(r"(?<![\w.])(\d+[\w.+~]*ubuntu\d[\w.+~]*)", re.IGNORECASE)
DEBIAN_REVISION = re.compile(r"debian[\s_-]+(\d[\w.+~]*)", re.IGNORECASE)
#: ``+deb12u3`` / ``~bpo11``: the Debian release a revision belongs to.
DEBIAN_RELEASE = re.compile(r"[+~](?:deb|bpo)(\d{1,2})(?:u\d+)?", re.IGNORECASE)
UBUNTU_RELEASE = re.compile(r"(?:ubuntu\d*\.|~)(\d{2}\.\d{2})", re.IGNORECASE)
_DEBIAN_TOKEN = re.compile(r"(\d[\w.]*[+~](?:deb|bpo)\d[\w.+~]*)", re.IGNORECASE)

#: Distributions a banner can name that no advisory provider covers. Seeing one
#: is what turns an NVD hit into ``possible``: these vendors backport too, we
#: just cannot ask them. Checked before Debian: Raspbian's banner carries a
#: ``+deb10u2`` revision too, but its packages are its own builds.
OTHER_DISTROS: tuple[tuple[str, str], ...] = (
    ("red hat", "rhel"),
    ("rhel", "rhel"),
    ("centos", "centos"),
    ("rocky", "rocky"),
    ("almalinux", "almalinux"),
    ("fedora", "fedora"),
    ("amazon linux", "amazonlinux"),
    ("oracle linux", "oraclelinux"),
    ("suse", "suse"),
    ("raspbian", "raspbian"),
    ("freebsd", "freebsd"),
    ("alpine", "alpine"),
)

_BANNER_LINES = re.compile(r"\s+\|\s+|[\r\n]+")
#: Lines whose first token is the product's own greeting or ``Server`` header.
#: Not ``X-Powered-By`` (another product's version) and not a page body.
_OWN_LINE = re.compile(r"^\s*(?:ssh-\d|server\s*:)", re.IGNORECASE)


def read(text: str, *, labelled_only: bool = False) -> tuple[str, str | None] | None:
    """The distribution ``text`` names and the package revision it states, if any.

    ``labelled_only`` accepts a revision only when the distribution's own word
    precedes it (``Ubuntu-4ubuntu0.5``), not as a bare suffix of a version
    (``7.4.3-4ubuntu2.19``), which may belong to a different package than the
    one being described. Red Hat family markers (``.el9``) are not handled here.
    """
    lowered = (text or "").lower()
    if not lowered:
        return None
    if "ubuntu" in lowered:
        match = UBUNTU_REVISION.search(text) or (None if labelled_only else UBUNTU_BARE_REVISION.search(text))
        return UBUNTU, match.group(1) if match else None
    for needle, label in OTHER_DISTROS:
        if needle in lowered:
            return label, None
    release = DEBIAN_RELEASE.search(text)
    if "debian" in lowered or release:
        match = DEBIAN_REVISION.search(text)
        revision = match.group(1) if match else None
        if revision is None and release and not labelled_only:
            # "+deb12u3" with no "Debian" word before it: the revision is the
            # token that carries the marker.
            token = _DEBIAN_TOKEN.search(text)
            revision = token.group(1) if token else None
        return DEBIAN, revision
    return None


def for_service(version: str, banner: str) -> tuple[str, str]:
    """(distro, revision) a scanned service discloses; empty strings when none.

    The version field is read in full (a prober that glues the revision on puts
    it there). From the banner only the lines that describe the listener
    itself are read — an SSH greeting or a ``Server:`` header, not a page body
    or another product's ``X-Powered-By`` — and only a revision labelled with
    its distribution's name, so a neighbour product's package suffix is never
    attributed to this one.
    """
    candidates = [(version, False)]
    candidates += [(line, True) for line in _BANNER_LINES.split(banner or "") if _OWN_LINE.match(line)]
    first: str | None = None
    for text, labelled in candidates:
        found = read(text, labelled_only=labelled)
        if found is None:
            continue
        distro, revision = found
        if revision:
            return distro, revision
        first = first or distro
    return (first or ""), ""
