"""Retro CVE matching: a stored service fingerprint against the NVD range dataset.

Pure functions only — no session, no settings, no clock. The worker
(``retro_match_worker.py``) and the fold (``retro_findings.py``) own the
database; this module owns the one question they both ask: *given what a scan
recorded about this listener, which CVEs does the current dataset say it
carries, and how sure are we?* ``docs/retro-cve-matching.md`` is the design.

Four steps, each of which can decline to answer:

1. **Which product.** CPE names nmap attached to the service win (after a small
   alias table, because nmap and NVD disagree about who ships nginx). Without a
   CPE, a curated table maps the prober's product string to NVD
   ``vendor:product`` keys; without either, a raw banner that names a known
   product *immediately followed by its version* (``SSH-2.0-OpenSSH_8.2p1``).
   A product none of these knows is **not matched** — guessing a vendor from a
   loose word in a banner is how a matcher learns to call every "Apache" Tomcat.
2. **Which version.** The upstream version the banner discloses, compared with
   :func:`compare_upstream` — not dpkg's or rpm's grammar, because NVD ranges
   are upstream versions (``8.2p1``, ``1.1.1f``, ``2.4.41``).
3. **Which CVEs.** Every statement for the product whose window covers that
   version.
4. **Did the vendor backport the fix.** When the banner carries a Debian or
   Ubuntu revision (``OpenSSH_8.2p1 Ubuntu-4ubuntu0.5``), the question goes to
   the same advisory providers the endpoint matcher uses, and the vendor's
   answer replaces NVD's. When a distribution is visible but its answer cannot
   be had — RHEL, FreeBSD, a release we cannot pin down, a CVE the vendor feed
   says nothing about — the match is ``possible``, never ``vulnerable``.

The asymmetry is the one ``docs/software-cve-matching.md`` argues for: a false
``vulnerable`` costs an afternoon and, repeated, the tool's credibility, while
an honest "possible" costs a line on the asset page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from api.services import package_identity, version_compare
from api.services.advisories import base as advisory_base
from api.services.cpe_ranges import CpeRange, CpeRangeDataset

# --------------------------------------------------------------------------
# Verdicts and confidence
# --------------------------------------------------------------------------

#: The fingerprint is affected: becomes a tracked finding.
VULNERABLE = "vulnerable"
#: NVD says affected, the distribution says the fix is installed.
FIXED = "fixed"
#: NVD says affected, the distribution says this release never was.
NOT_AFFECTED = "not_affected"
#: NVD says affected and a distribution is visible whose answer we could not
#: get. Recorded on the service, never a tracked finding.
POSSIBLE = "possible"
VERDICTS = (VULNERABLE, FIXED, NOT_AFFECTED, POSSIBLE)

#: The vendor's own advisory decided it (Debian tracker / Ubuntu USN).
CONFIDENCE_VENDOR = "vendor_advisory"
#: Upstream version inside an NVD range, and nothing in the banner suggests a
#: distribution that might have backported the fix.
CONFIDENCE_RANGE = "version_range"
#: Upstream version inside an NVD range, but a distribution is visible whose
#: backports we cannot see. Only ever carried by ``POSSIBLE``.
CONFIDENCE_BACKPORT = "backport_possible"
CONFIDENCES = (CONFIDENCE_VENDOR, CONFIDENCE_RANGE, CONFIDENCE_BACKPORT)

#: Why a fingerprint produced no statement at all.
REASON_UNKNOWN_PRODUCT = "unknown_product"
REASON_NO_VERSION = "no_version"
REASON_NO_DATASET = "no_dataset"

# --------------------------------------------------------------------------
# Upstream version comparison
# --------------------------------------------------------------------------

#: Alphabetic runs that mark a pre-release: ``1.3.6rc2`` precedes ``1.3.6``.
_PRE_RELEASE = {"dev": 0, "alpha": 1, "beta": 2, "pre": 3, "preview": 3, "rc": 4}
#: Single letters that mean alpha/beta only when a number follows (``2.0a1``).
#: At the end of a version they are a letter release — OpenSSL ``1.1.1a``,
#: ProFTPD ``1.3.5a`` — which *follows* the bare number.
_PRE_LETTERS = {"a": 1, "b": 2}
_TOKEN_RE = re.compile(r"\d+|[a-z]+")

# Element kinds, ordered: a pre-release sorts before the end of the version,
# which sorts before a letter release, which sorts before another number.
_KIND_PRE, _KIND_END, _KIND_POST, _KIND_NUM = 0, 1, 2, 3


def _version_key(raw: str) -> list[tuple[int, int, str]]:
    text = (raw or "").strip().lower()
    if text.startswith("v") and text[1:2].isdigit():
        text = text[1:]
    tokens = _TOKEN_RE.findall(text)
    out: list[tuple[int, int, str]] = []
    for index, token in enumerate(tokens):
        if token.isdigit():
            out.append((_KIND_NUM, int(token), ""))
            continue
        followed_by_number = index + 1 < len(tokens) and tokens[index + 1].isdigit()
        if token in _PRE_RELEASE:
            out.append((_KIND_PRE, _PRE_RELEASE[token], token))
        elif token in _PRE_LETTERS and followed_by_number:
            out.append((_KIND_PRE, _PRE_LETTERS[token], token))
        else:
            # ``p`` in OpenSSH's ``8.2p1``, OpenSSL's letter releases, and
            # anything unrecognised: after the bare number, compared as text
            # (``z`` < ``za`` < ``zb`` is OpenSSL's own order).
            out.append((_KIND_POST, 0, token))
    return out


def compare_upstream(left: str, right: str) -> int:
    """Compare two *upstream* versions: -1, 0 or 1.

    Not dpkg's ``verrevcmp``, which would order ``8.2p1`` correctly but has no
    notion of ``rc`` preceding the release, and not semver, which rejects most
    of what a banner discloses. The rules, each a case NVD ranges exercise:

    * numbers compare as numbers (``2.4.9`` < ``2.4.41``);
    * trailing zero components are insignificant (``2.4`` == ``2.4.0``);
    * ``rc``/``beta``/``alpha``/``pre``/``dev`` — and ``a``/``b`` followed by a
      number — precede the release (``1.3.6rc2`` < ``1.3.6``);
    * any other letters follow it (``8.2`` < ``8.2p1`` < ``8.2p2`` < ``8.3``,
      ``1.1.1`` < ``1.1.1f`` < ``1.1.1n``, ``1.0.2z`` < ``1.0.2za``).
    """
    a, b = _version_key(left), _version_key(right)
    end = (_KIND_END, 0, "")
    zero = (_KIND_NUM, 0, "")
    for index in range(max(len(a), len(b))):
        x = a[index] if index < len(a) else end
        y = b[index] if index < len(b) else end
        if x == y or {x, y} == {end, zero}:
            # ``2.4`` and ``2.4.0`` are one version to NVD and to every
            # changelog. Only a *missing* component equals zero — ``2.0`` is
            # still after ``2.0a1``, whose zero is followed by a pre-release.
            continue
        return -1 if x < y else 1
    return 0


#: OpenSSH-portable's patch level. NVD keeps it in the CPE's ``update``
#: component (``openssh:7.7:p1``), not in ``version``, so a range bound is a
#: plain ``7.7`` and ``versionEndIncluding 7.7`` covers ``7.7p1``.
_PORTABLE_PATCH = re.compile(r"^(\d+(?:\.\d+)*)p\d+$", re.IGNORECASE)


def _against(version: str, bound: str) -> str:
    """``version`` as NVD would compare it with ``bound``.

    A bound with no letters is a ``version`` attribute alone; an observed
    ``7.7p1`` is version ``7.7`` with update ``p1`` to NVD, so the patch level
    is dropped for that comparison. A bound that carries one (the seed writes
    ``9.3p2``) is compared as written.
    """
    match = _PORTABLE_PATCH.match(version.strip())
    if match and not any(ch.isalpha() for ch in bound):
        return match.group(1)
    return version


def in_range(version: str, statement: CpeRange) -> bool:
    """Does ``statement``'s window cover ``version``?

    An exact statement is equality as written (``openssh:7.7:p1`` arrives as
    ``7.7p1``); only range bounds get the update-component treatment of
    :func:`_against`.
    """
    if statement.exact:
        return compare_upstream(version, statement.exact) == 0
    low_in, low_ex = statement.start_including, statement.start_excluding
    high_in, high_ex = statement.end_including, statement.end_excluding
    if low_in and compare_upstream(_against(version, low_in), low_in) < 0:
        return False
    if low_ex and compare_upstream(_against(version, low_ex), low_ex) <= 0:
        return False
    if high_in and compare_upstream(_against(version, high_in), high_in) > 0:
        return False
    if high_ex and compare_upstream(_against(version, high_ex), high_ex) >= 0:
        return False
    return True


# --------------------------------------------------------------------------
# Product identity
# --------------------------------------------------------------------------

#: Prober product string (lower-cased, whitespace collapsed) → NVD keys.
#:
#: Curated, and short on purpose. Every row is a claim that *this* string means
#: *that* NVD product, and a wrong row is a finding on every host that runs the
#: product. Strings are nmap's ``product`` values and Pulse's service names as
#: they arrive in ``services.json``; add a row with a banner that proves it.
PRODUCT_TABLE: dict[str, tuple[str, ...]] = {
    "openssh": ("a:openbsd:openssh",),
    "apache httpd": ("a:apache:http_server",),
    "apache http server": ("a:apache:http_server",),
    # NVD moved nginx from nginx:nginx to f5:nginx in 2022; old CVEs still
    # carry the first key, new ones the second.
    "nginx": ("a:f5:nginx", "a:nginx:nginx"),
    "openssl": ("a:openssl:openssl",),
    "vsftpd": ("a:vsftpd_project:vsftpd", "a:beasts:vsftpd"),
    "proftpd": ("a:proftpd:proftpd",),
    "exim smtpd": ("a:exim:exim",),
    "exim": ("a:exim:exim",),
    "microsoft iis httpd": (
        "a:microsoft:internet_information_services",
        "a:microsoft:iis",
    ),
    "microsoft-iis": ("a:microsoft:internet_information_services", "a:microsoft:iis"),
    "lighttpd": ("a:lighttpd:lighttpd",),
    "postfix smtpd": ("a:postfix:postfix",),
    "dropbear sshd": ("a:dropbear_ssh_project:dropbear_ssh",),
    "isc bind": ("a:isc:bind",),
    "dnsmasq": ("a:thekelleys:dnsmasq",),
    "samba smbd": ("a:samba:samba",),
    "apache tomcat": ("a:apache:tomcat",),
    "redis key-value store": ("a:redis:redis",),
}

#: nmap CPE key → the NVD keys it stands for. nmap's service database predates
#: some NVD renames; without these an nginx CPE from nmap matches nothing.
CPE_ALIASES: dict[str, tuple[str, ...]] = {
    "a:igor_sysoev:nginx": ("a:f5:nginx", "a:nginx:nginx"),
    "a:nginx:nginx": ("a:nginx:nginx", "a:f5:nginx"),
    "a:f5:nginx": ("a:f5:nginx", "a:nginx:nginx"),
    "a:beasts:vsftpd": ("a:vsftpd_project:vsftpd", "a:beasts:vsftpd"),
    "a:vsftpd_project:vsftpd": ("a:vsftpd_project:vsftpd", "a:beasts:vsftpd"),
    "a:microsoft:iis": ("a:microsoft:internet_information_services", "a:microsoft:iis"),
    "a:microsoft:internet_information_services": (
        "a:microsoft:internet_information_services",
        "a:microsoft:iis",
    ),
}

#: NVD key → the Debian/Ubuntu *source* package an advisory names. A product
#: missing here can still match on NVD ranges; it just cannot be checked for a
#: backport, so a visible distribution turns its matches into ``possible``.
SOURCE_PACKAGES: dict[str, tuple[str, ...]] = {
    "a:openbsd:openssh": ("openssh",),
    "a:apache:http_server": ("apache2",),
    "a:f5:nginx": ("nginx",),
    "a:nginx:nginx": ("nginx",),
    "a:openssl:openssl": ("openssl",),
    "a:vsftpd_project:vsftpd": ("vsftpd",),
    "a:beasts:vsftpd": ("vsftpd",),
    "a:proftpd:proftpd": ("proftpd-dfsg",),
    "a:exim:exim": ("exim4",),
    "a:lighttpd:lighttpd": ("lighttpd",),
    "a:postfix:postfix": ("postfix",),
    "a:dropbear_ssh_project:dropbear_ssh": ("dropbear",),
    "a:isc:bind": ("bind9",),
    "a:thekelleys:dnsmasq": ("dnsmasq",),
    "a:samba:samba": ("samba",),
    "a:redis:redis": ("redis",),
}

#: How the product appears inside a raw banner, for a fingerprint whose prober
#: reported no version field (``SSH-2.0-OpenSSH_8.2p1 …``, ``Server: nginx/1.18.0``).
_BANNER_NAMES: dict[str, tuple[str, ...]] = {
    "a:openbsd:openssh": ("openssh",),
    "a:apache:http_server": ("apache",),
    "a:f5:nginx": ("nginx",),
    "a:nginx:nginx": ("nginx",),
    "a:openssl:openssl": ("openssl",),
    "a:vsftpd_project:vsftpd": ("vsftpd",),
    "a:proftpd:proftpd": ("proftpd",),
    "a:exim:exim": ("exim",),
    "a:microsoft:internet_information_services": ("microsoft-iis",),
    "a:lighttpd:lighttpd": ("lighttpd",),
}

_VERSION_TOKEN_RE = re.compile(r"v?(\d+(?:\.\d+)*[a-z0-9.~+]*)", re.IGNORECASE)


def normalize_product(value: str | None) -> str:
    return " ".join((value or "").strip().lower().split())


def parse_cpe(name: str) -> tuple[str, str | None] | None:
    """A CPE name → ``("part:vendor:product", version-or-None)``.

    Accepts the 2.2 URI nmap writes (``cpe:/a:openbsd:openssh:8.2p1``) and the
    2.3 formatted string NVD uses. For 2.3 an ``update`` component is appended
    to the version, because that is where NVD keeps OpenSSH's ``p2``.
    """
    text = (name or "").strip().lower()
    if text.startswith("cpe:2.3:"):
        parts = text[len("cpe:2.3:") :].split(":")
        version_index, update_index = 3, 4
    elif text.startswith("cpe:/"):
        parts = text[len("cpe:/") :].split(":")
        version_index, update_index = 3, 4
    else:
        return None
    if len(parts) < 3 or parts[0] not in ("a", "o", "h") or not parts[1] or not parts[2]:
        return None
    key = f"{parts[0]}:{parts[1]}:{parts[2]}"
    version = parts[version_index] if len(parts) > version_index else ""
    update = parts[update_index] if len(parts) > update_index else ""
    if version in ("", "*", "-"):
        return key, None
    if update not in ("", "*", "-"):
        version = f"{version}{update}"
    return key, version.replace("\\", "")


@dataclass(frozen=True)
class Fingerprint:
    """What a scan recorded about one listener. The matcher's only input."""

    product: str = ""
    version: str = ""
    banner: str = ""
    cpe: tuple[str, ...] = ()
    service: str = ""

    @property
    def text(self) -> str:
        """Everything that can disclose a version or a distribution."""
        return " ".join(part for part in (self.version, self.banner) if part)


def product_keys(fingerprint: Fingerprint) -> tuple[tuple[str, ...], str, str | None]:
    """``(NVD keys, via, cpe version)`` for a fingerprint, keys best first.

    ``via`` is ``cpe``, ``product_table`` or ``banner`` (``""`` when nothing
    knows the product), recorded in the evidence so an operator can see
    whether the vendor was the prober's statement or our table's.
    """
    keys: list[str] = []
    cpe_version: str | None = None
    for name in fingerprint.cpe:
        parsed = parse_cpe(name)
        if parsed is None:
            continue
        key, version = parsed
        if not key.startswith("a:"):
            # nmap attaches the platform to a service line too
            # (``cpe:/o:linux:linux_kernel`` next to OpenSSH's own CPE). That is
            # the host, not this listener, and the listener's version applied
            # to it would match the kernel against OpenSSH's version number.
            continue
        keys.extend(CPE_ALIASES.get(key, (key,)))
        cpe_version = cpe_version or version
    if keys:
        return tuple(dict.fromkeys(keys)), "cpe", cpe_version
    table = PRODUCT_TABLE.get(normalize_product(fingerprint.product))
    if table:
        return table, "product_table", None
    # A prober that reported no product (or a generic one: Pulse's "ssh") may
    # still have kept the banner, and ``SSH-2.0-OpenSSH_8.2p1`` names its
    # product as plainly as nmap would. Only a name *immediately followed by a
    # version* counts — the same pattern :func:`upstream_version` reads — so a
    # banner that merely mentions "apache" somewhere identifies nothing.
    banner = fingerprint.banner or ""
    for key, names in _BANNER_NAMES.items():
        if any(_banner_version(banner, name) for name in names):
            return CPE_ALIASES.get(key, (key,)), "banner", None
    return (), "", None


def _banner_version(banner: str, name: str) -> str | None:
    match = re.search(
        rf"(?<![a-z]){re.escape(name)}[_/ -]v?(\d+(?:\.\d+)+[a-z0-9]*)", banner, re.IGNORECASE
    )
    return match.group(1) if match else None


def upstream_version(fingerprint: Fingerprint, keys: Iterable[str], cpe_version: str | None) -> str | None:
    """The upstream version the fingerprint discloses, or ``None``.

    The CPE's version first, then the first version-shaped token of the
    prober's ``version`` field (``8.2p1`` out of ``8.2p1 Ubuntu 4ubuntu0.5``),
    then the product's own name in the raw banner (``OpenSSH_8.2p1``). Never a
    number found just anywhere in the banner: ``protocol 2.0`` is not a version
    of OpenSSH.
    """
    if cpe_version:
        return cpe_version
    head = (fingerprint.version or "").strip().split()
    if head:
        match = _VERSION_TOKEN_RE.fullmatch(head[0].rstrip(".,;"))
        if match:
            return match.group(1)
    banner = fingerprint.banner or ""
    for key in keys:
        for name in _BANNER_NAMES.get(key, ()):
            version = _banner_version(banner, name)
            if version:
                return version
    return None


# --------------------------------------------------------------------------
# Distribution hints
# --------------------------------------------------------------------------

_UBUNTU_REVISION = re.compile(r"ubuntu[\s_-]+(\d[\w.+~]*ubuntu[\w.+~]*)", re.IGNORECASE)
_UBUNTU_BARE_REVISION = re.compile(r"(?<![\w.])(\d+[\w.+~]*ubuntu\d[\w.+~]*)", re.IGNORECASE)
_DEBIAN_REVISION = re.compile(r"debian[\s_-]+(\d[\w.+~]*)", re.IGNORECASE)
_DEBIAN_RELEASE = re.compile(r"[+~](?:deb|bpo)(\d{1,2})(?:u\d+)?", re.IGNORECASE)
_UBUNTU_RELEASE = re.compile(r"(?:ubuntu\d*\.|~)(\d{2}\.\d{2})", re.IGNORECASE)
_EL_RELEASE = re.compile(r"\.el(\d+)", re.IGNORECASE)

#: Distributions a banner can name that no advisory provider covers. Seeing one
#: is what turns an NVD hit into ``possible``: these vendors backport too, we
#: just cannot ask them.
_OTHER_DISTROS: tuple[tuple[str, str], ...] = (
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


@dataclass(frozen=True)
class DistroHint:
    """What a banner gives away about the packaging behind a listener."""

    distro: str | None = None
    release: str | None = None
    revision: str | None = None

    @property
    def visible(self) -> bool:
        return self.distro is not None


def distro_hint(text: str) -> DistroHint:
    """Read a distribution, release and package revision out of banner text.

    Only what the text states: ``Debian-2+deb12u3`` pins release and revision
    (``deb12`` is bookworm), ``Ubuntu-4ubuntu0.5`` pins the revision and leaves
    the release to :func:`_releases_shipping`, a bare ``(Ubuntu)`` pins the
    distribution alone.
    """
    lowered = (text or "").lower()
    if not lowered:
        return DistroHint()
    if "ubuntu" in lowered:
        match = _UBUNTU_REVISION.search(text) or _UBUNTU_BARE_REVISION.search(text)
        revision = match.group(1) if match else None
        release = None
        if revision:
            numbered = _UBUNTU_RELEASE.search(revision)
            if numbered:
                release = _release_from_number(package_identity.UBUNTU, numbered.group(1))
        return DistroHint(package_identity.UBUNTU, release, revision)
    # Before Debian: Raspbian's banner carries a ``+deb10u2`` revision too, but
    # its packages are its own builds and the Debian tracker does not speak
    # for them.
    for needle, label in _OTHER_DISTROS:
        if needle in lowered:
            return DistroHint(label)
    debian_release = _DEBIAN_RELEASE.search(text)
    if "debian" in lowered or debian_release:
        match = _DEBIAN_REVISION.search(text)
        revision = match.group(1) if match else None
        if revision is None and debian_release:
            # "+deb12u3" with no "Debian" word before it: the revision is the
            # token that carries the marker.
            token = re.search(r"(\d[\w.]*[+~](?:deb|bpo)\d[\w.+~]*)", text, re.IGNORECASE)
            revision = token.group(1) if token else None
        release = (
            _release_from_number(package_identity.DEBIAN, debian_release.group(1))
            if debian_release
            else None
        )
        return DistroHint(package_identity.DEBIAN, release, revision)
    el = _EL_RELEASE.search(text)
    if el:
        return DistroHint("rhel", el.group(1))
    return DistroHint()


def _release_from_number(distro: str, number: str) -> str | None:
    name = "Ubuntu" if distro == package_identity.UBUNTU else "Debian"
    context = package_identity.resolve_distro(
        os_family="linux", os_name=name, os_version=number
    )
    return context.release


# --------------------------------------------------------------------------
# The vendor's word
# --------------------------------------------------------------------------

AdvisoryLookup = Callable[[str], Any]


def _fixed_upstream(fixed_version: str) -> str | None:
    try:
        return version_compare.parse_evr(fixed_version).version
    except version_compare.VersionParseError:
        return None


def _releases_shipping(provider: Any, packages: Iterable[str], upstream: str) -> list[str]:
    """Releases whose vendor records name a fix *built on this upstream version*.

    The banner of an Ubuntu OpenSSH says ``4ubuntu0.5`` and not ``focal``, but
    every focal OpenSSH advisory fixes a ``1:8.2p1-…`` build and no other
    release's does — so the upstream version identifies the release whenever
    the vendor feed has anything to say about it. Two releases sharing one
    upstream version is an ambiguity the caller has to respect.
    """
    found: list[str] = []
    for release in provider.releases():
        for package in packages:
            if any(
                record.fixed_version
                and compare_upstream(_fixed_upstream(record.fixed_version) or "", upstream) == 0
                for record in provider.advisories_for(release=release, source_package=package)
            ):
                found.append(release)
                break
    return found


def _installed_evr(upstream: str, revision: str, fixed_version: str) -> str:
    """The installed package version, rebuilt from what the banner discloses.

    A banner never carries the epoch (``1:`` on OpenSSH). The advisory's fixed
    version does, and the two are builds of the same upstream from the same
    source package, so its epoch is the installed one.
    """
    try:
        epoch = version_compare.parse_evr(fixed_version).epoch
    except version_compare.VersionParseError:
        epoch = 0
    head = f"{epoch}:{upstream}" if epoch else upstream
    return f"{head}-{revision}"


def _judge_release(
    records: list[advisory_base.AdvisoryRecord],
    *,
    upstream: str,
    revision: str | None,
) -> tuple[str, dict[str, Any]]:
    """One release's verdict on one CVE, from that release's records."""
    if not records:
        return POSSIBLE, {"reason": "no_vendor_statement"}
    if any(record.state == advisory_base.STATE_OPEN for record in records):
        record = next(r for r in records if r.state == advisory_base.STATE_OPEN)
        return VULNERABLE, _advisory_evidence(record)
    resolved = [r for r in records if r.state == advisory_base.STATE_RESOLVED and r.fixed_version]
    if not resolved:
        return NOT_AFFECTED, _advisory_evidence(records[0])
    # Several advisories for one CVE (a regression re-issue) — the latest fix
    # is the one the host has to be at.
    record = resolved[0]
    for other in resolved[1:]:
        try:
            if version_compare.compare_dpkg_version(other.fixed_version or "", record.fixed_version or "") > 0:
                record = other
        except version_compare.VersionParseError:
            continue
    fixed = record.fixed_version or ""
    evidence = _advisory_evidence(record)
    try:
        if revision:
            installed = _installed_evr(upstream, revision, fixed)
            evidence["installed_version"] = installed
            fixed_now = version_compare.is_fixed(installed, fixed, flavor=version_compare.DEB)
            return (FIXED if fixed_now else VULNERABLE), evidence
        fixed_upstream = _fixed_upstream(fixed)
        if fixed_upstream is None:
            return POSSIBLE, {**evidence, "reason": "unparsable_fixed_version"}
        order = version_compare.compare_dpkg_version(upstream, fixed_upstream)
    except version_compare.VersionParseError:
        return POSSIBLE, {**evidence, "reason": "unparsable_version"}
    if order < 0:
        # Older than the upstream the fix was built on: no revision of this
        # upstream carries it.
        return VULNERABLE, evidence
    if order > 0:
        return FIXED, evidence
    # Same upstream, revision unknown: exactly the backport question, unanswered.
    return POSSIBLE, {**evidence, "reason": "revision_not_disclosed"}


def _advisory_evidence(record: advisory_base.AdvisoryRecord) -> dict[str, Any]:
    return {
        "provider": record.provider,
        "advisory_id": record.advisory_id,
        "release": record.release,
        "state": record.state,
        "fixed_version": record.fixed_version,
        "feed_date": record.feed_date,
    }


def vendor_verdict(
    hint: DistroHint,
    *,
    product_key: str,
    cve: str,
    upstream: str,
    lookup: AdvisoryLookup,
    shipping: dict[tuple[str, str], list[str]] | None = None,
) -> tuple[str, dict[str, Any]]:
    """What the distribution says about ``cve`` on this build: a verdict and why.

    ``shipping`` memoises :func:`_releases_shipping` across the CVEs of one
    listener — the answer depends on the package and the upstream version,
    not on the CVE, and walking the releases once per CVE made a Ubuntu
    listener with thirty NVD hits thirty walks.
    """
    provider = lookup(hint.distro or "")
    if provider is None or not provider.available():
        return POSSIBLE, {"reason": "no_advisory_provider"}
    packages = SOURCE_PACKAGES.get(product_key, ())
    if not packages:
        return POSSIBLE, {"reason": "no_source_package"}
    if hint.release:
        releases = [hint.release]
    else:
        memo_key = (product_key, upstream)
        if shipping is not None and memo_key in shipping:
            releases = shipping[memo_key]
        else:
            releases = _releases_shipping(provider, packages, upstream)
            if shipping is not None:
                shipping[memo_key] = releases
        if not releases:
            return POSSIBLE, {"reason": "release_not_identified"}
    verdicts: list[tuple[str, dict[str, Any]]] = []
    for release in releases:
        records = [
            record
            for package in packages
            for record in provider.advisories_for(release=release, source_package=package)
            if cve in record.cve_ids
        ]
        verdict, evidence = _judge_release(records, upstream=upstream, revision=hint.revision)
        verdicts.append((verdict, {"release": release, **evidence}))
    if len({verdict for verdict, _ in verdicts}) == 1:
        return verdicts[0]
    return POSSIBLE, {
        "reason": "releases_disagree",
        "releases": [evidence.get("release") for _, evidence in verdicts],
    }


# --------------------------------------------------------------------------
# The match
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Match:
    cve: str
    verdict: str
    #: ``vendor_advisory`` | ``version_range`` | ``backport_possible``.
    confidence: str
    severity: str
    cvss: float | None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def is_finding(self) -> bool:
        return self.verdict == VULNERABLE


@dataclass(frozen=True)
class MatchOutcome:
    matches: tuple[Match, ...] = ()
    #: Set when the fingerprint produced no statement: ``REASON_*``.
    reason: str | None = None
    product_keys: tuple[str, ...] = ()
    upstream_version: str | None = None

    def counts(self) -> dict[str, int]:
        return {verdict: sum(1 for m in self.matches if m.verdict == verdict) for verdict in VERDICTS}


_SEVERITIES = ("critical", "high", "medium", "low")


def _severity(info: dict[str, Any]) -> tuple[str, float | None]:
    severity = str(info.get("severity") or "").strip().lower()
    cvss = info.get("cvss")
    try:
        score = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        score = None
    return (severity if severity in _SEVERITIES else "unknown"), score


def match(
    fingerprint: Fingerprint,
    dataset: CpeRangeDataset,
    *,
    lookup: AdvisoryLookup,
) -> MatchOutcome:
    """Every CVE the dataset says this fingerprint carries, with a verdict each.

    ``lookup`` is ``advisories.get_provider``; injected so a test can hand the
    matcher a provider without touching the environment.
    """
    if not dataset.available:
        return MatchOutcome(reason=REASON_NO_DATASET)
    keys, via, cpe_version = product_keys(fingerprint)
    if not keys:
        return MatchOutcome(reason=REASON_UNKNOWN_PRODUCT)
    upstream = upstream_version(fingerprint, keys, cpe_version)
    if not upstream:
        return MatchOutcome(reason=REASON_NO_VERSION, product_keys=keys)
    hint = distro_hint(fingerprint.text)

    # One statement per CVE: the first product key that covers the version
    # wins, so nginx:nginx and f5:nginx naming the same CVE is one match.
    hits: dict[str, tuple[str, CpeRange]] = {}
    for key in keys:
        for statement in dataset.ranges_for(key):
            if statement.cve in hits:
                continue
            if in_range(upstream, statement):
                hits[statement.cve] = (key, statement)

    matches: list[Match] = []
    shipping: dict[tuple[str, str], list[str]] = {}
    for cve, (key, statement) in sorted(hits.items()):
        severity, cvss = _severity(dataset.cve_info(cve))
        evidence: dict[str, Any] = {
            "product": fingerprint.product or None,
            "version": fingerprint.version or None,
            "upstream_version": upstream,
            "cpe": key,
            "via": via,
            "range": statement.describe(),
            "dataset": dataset.marker,
            "feed_date": dataset.updated,
        }
        if hint.visible:
            evidence["distro"] = hint.distro
            if hint.release:
                evidence["distro_release"] = hint.release
            if hint.revision:
                evidence["distro_revision"] = hint.revision
        if not hint.visible:
            verdict, confidence = VULNERABLE, CONFIDENCE_RANGE
        elif hint.distro in package_identity.SUPPORTED_DISTROS:
            verdict, advisory = vendor_verdict(
                hint,
                product_key=key,
                cve=cve,
                upstream=upstream,
                lookup=lookup,
                shipping=shipping,
            )
            evidence["advisory"] = advisory
            confidence = CONFIDENCE_VENDOR if verdict != POSSIBLE else CONFIDENCE_BACKPORT
        else:
            verdict, confidence = POSSIBLE, CONFIDENCE_BACKPORT
            evidence["advisory"] = {"reason": "unsupported_distro"}
        matches.append(
            Match(
                cve=cve,
                verdict=verdict,
                confidence=confidence,
                severity=severity,
                cvss=cvss,
                evidence=evidence,
            )
        )
    return MatchOutcome(matches=tuple(matches), product_keys=keys, upstream_version=upstream)
