"""Canonical identity for one installed-software record (ROADMAP Track E).

The endpoint inventory (Agent_plan.md S1-S7) stores what the collector saw:
a display name, a version string, an architecture and which package manager
reported it. That is not enough to ask a vendor advisory anything. This module
turns such a record, plus the OS context of the device it came from, into an
identity that carries:

* a **purl** — ``pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?arch=amd64&distro=focal``
  — which is the form the advisory layer actually keys on, because it names the
  distribution and its release alongside the package;
* a best-effort **CPE 2.3** string, which is *not* used for matching. It is
  there so a finding can be correlated with an external system that speaks CPE,
  and it is best-effort in a specific way documented on
  :func:`build_cpe23`: NVD's vendor for a distro package is usually the
  upstream project, not the distributor, and there is no mapping from a package
  name to an upstream vendor that is right often enough to match on.

**The unknown-distro rule.** A vendor advisory is a statement about a package
*in a release*: "fixed in 1.1.1f-1ubuntu2.16 on focal" says nothing about the
same version string on Debian, and nothing at all about a package whose release
we could not determine. So when the release cannot be resolved this module says
so — :attr:`PackageIdentity.matchable` is ``False`` and
:attr:`PackageIdentity.reason` names which piece was missing — and the matcher
emits ``unknown`` rather than guessing. A wrong "vulnerable" costs an operator
an afternoon; an honest "unknown" costs them a line in a report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from api.services import version_compare

#: Distributions this milestone has an advisory provider for. Anything else is
#: resolvable as an identity but not matchable — see ``reason``.
DEBIAN = "debian"
UBUNTU = "ubuntu"
SUPPORTED_DISTROS = (DEBIAN, UBUNTU)

#: Why an identity cannot be matched against a vendor advisory. These strings
#: are persisted on ``unknown`` rows and rendered in the UI, so they are part
#: of the contract.
REASON_NO_VERSION = "no_version"
REASON_UNPARSABLE_VERSION = "unparsable_version"
REASON_NON_DISTRO_SOURCE = "non_distro_source"
REASON_UNKNOWN_DISTRO = "unknown_distro"
REASON_UNKNOWN_RELEASE = "unknown_release"
REASON_UNSUPPORTED_DISTRO = "unsupported_distro"

#: Package-manager source (``EndpointSoftwareItem.source``) → version grammar.
#: ``winreg``/``msi``/``brew``/``other`` are deliberately absent: they are real
#: inventory, they are simply not things a Debian or Ubuntu advisory talks about.
_SOURCE_FLAVORS: dict[str, str] = {
    "apt": version_compare.DEB,
    "dpkg": version_compare.DEB,
    "rpm": version_compare.RPM,
}

#: purl package type per version grammar (purl-spec: ``deb`` and ``rpm``).
_PURL_TYPES = {version_compare.DEB: "deb", version_compare.RPM: "rpm"}

#: Ubuntu release number → codename. Advisories are published per codename, and
#: an inventory reports ``os_version`` as the number, so one of the two has to
#: be translated. Unlisted numbers resolve to no release rather than to a guess.
_UBUNTU_CODENAMES: dict[str, str] = {
    "14.04": "trusty",
    "16.04": "xenial",
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "23.04": "lunar",
    "23.10": "mantic",
    "24.04": "noble",
    "24.10": "oracular",
    "25.04": "plucky",
    "25.10": "questing",
}

#: Debian major version → codename, same reasoning as above.
_DEBIAN_CODENAMES: dict[str, str] = {
    "8": "jessie",
    "9": "stretch",
    "10": "buster",
    "11": "bullseye",
    "12": "bookworm",
    "13": "trixie",
    "14": "forky",
}

_KNOWN_CODENAMES = {
    UBUNTU: frozenset(_UBUNTU_CODENAMES.values()),
    DEBIAN: frozenset(_DEBIAN_CODENAMES.values()) | {"sid", "unstable"},
}

#: Distributions that are Debian- or RPM-derived but have no provider here.
#: Recognised on purpose: "we know what this is and we do not cover it" is a
#: different and more useful answer than "we could not tell what this is".
_OTHER_DISTRO_HINTS: tuple[tuple[str, str], ...] = (
    ("linux mint", "linuxmint"),
    ("pop!_os", "pop_os"),
    ("raspbian", "raspbian"),
    ("kali", "kali"),
    ("red hat", "rhel"),
    ("rhel", "rhel"),
    ("centos", "centos"),
    ("rocky", "rocky"),
    ("almalinux", "almalinux"),
    ("fedora", "fedora"),
    ("amazon linux", "amazonlinux"),
    ("opensuse", "opensuse"),
    ("suse", "sles"),
    ("oracle linux", "oraclelinux"),
)

# A *binary* package name often differs from the source package an advisory
# names (``libssl1.1`` is built from ``openssl``, ``openssh-server`` from
# ``openssh``). The collector does not report the source package, so these are
# the conventional decorations that get stripped to produce a fallback lookup —
# see ``source_package_candidates``, which never replaces the exact name.
_BINARY_SUFFIXES = (
    "-dev",
    "-dbg",
    "-dbgsym",
    "-doc",
    "-common",
    "-data",
    "-bin",
    "-utils",
    "-tools",
    "-server",
    "-client",
)
_SOVERSION_RE = re.compile(r"^(lib[a-z0-9+.-]*?)[0-9]+(?:\.[0-9]+)*(?:-[a-z0-9]+)?$")


@dataclass(frozen=True)
class PackageIdentity:
    """One installed package, named the way an advisory names it."""

    #: The collector's display name, lowercased and stripped.
    name: str
    #: Raw version exactly as the collector reported it.
    version: str | None
    architecture: str | None
    #: ``EndpointSoftwareItem.source`` (apt/dpkg/rpm/winreg/…).
    source: str
    #: ``deb`` | ``rpm`` | ``None`` when the source is not a distro manager.
    flavor: str | None
    distro: str | None
    distro_release: str | None
    #: The source package an advisory would name, tried in order: the package's
    #: own name first, then the conventionally-stripped form. The matcher takes
    #: the first candidate the provider knows, so a heuristic rewrite can only
    #: ever *add* a lookup, never replace a successful exact one.
    source_package_candidates: tuple[str, ...] = ()
    purl: str | None = None
    cpe23: str | None = None
    #: True only when distro, release, version and flavor are all resolved.
    matchable: bool = False
    #: Why not, when ``matchable`` is False. One of the ``REASON_*`` constants.
    reason: str | None = None
    #: Parsed epoch/upstream/revision, when the version parsed at all.
    evr: version_compare.Evr | None = field(default=None, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "architecture": self.architecture,
            "source": self.source,
            "flavor": self.flavor,
            "distro": self.distro,
            "distro_release": self.distro_release,
            "source_package_candidates": list(self.source_package_candidates),
            "purl": self.purl,
            "cpe23": self.cpe23,
            "matchable": self.matchable,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DistroContext:
    """The OS half of an identity, resolved once per device."""

    distro: str | None
    release: str | None
    #: True when both are resolved *and* a provider covers the distro.
    supported: bool = False
    reason: str | None = None


def _normalize(value: str | None) -> str:
    return (value or "").strip().lower()


def resolve_distro(
    *,
    os_family: str | None,
    os_name: str | None,
    os_version: str | None,
) -> DistroContext:
    """Resolve a device's OS metadata to ``(distro, release codename)``.

    Accepts a codename directly in ``os_version`` (``"focal"``) as well as the
    numbered form the Lariska collector reports (``"20.04"``, ``"20.04.6 LTS"``),
    because ``/etc/os-release`` gives both and different collectors pick
    different fields.
    """
    family = _normalize(os_family)
    name = _normalize(os_name)
    version = _normalize(os_version)

    if family and family not in ("linux", ""):
        # windows/darwin/… — recognised, and out of scope by construction.
        return DistroContext(distro=None, release=None, reason=REASON_UNSUPPORTED_DISTRO)

    distro: str | None = None
    if "ubuntu" in name:
        distro = UBUNTU
    elif "debian" in name:
        distro = DEBIAN
    else:
        for needle, label in _OTHER_DISTRO_HINTS:
            if needle in name:
                return DistroContext(distro=label, release=None, reason=REASON_UNSUPPORTED_DISTRO)
    if distro is None:
        return DistroContext(distro=None, release=None, reason=REASON_UNKNOWN_DISTRO)

    release = _resolve_release(distro, version) or _resolve_release(distro, name)
    if release is None:
        return DistroContext(distro=distro, release=None, reason=REASON_UNKNOWN_RELEASE)
    return DistroContext(distro=distro, release=release, supported=True)


def _resolve_release(distro: str, value: str) -> str | None:
    if not value:
        return None
    for token in re.split(r"[\s(),/]+", value):
        token = token.strip().strip(".")
        if not token:
            continue
        if token in _KNOWN_CODENAMES[distro]:
            return token
        table = _UBUNTU_CODENAMES if distro == UBUNTU else _DEBIAN_CODENAMES
        if token in table:
            return table[token]
        # "20.04.6" → "20.04"; "12.5" → "12".
        parts = token.split(".")
        if distro == UBUNTU and len(parts) >= 2:
            candidate = ".".join(parts[:2])
            if candidate in table:
                return table[candidate]
        if distro == DEBIAN and parts[0] in table:
            return table[parts[0]]
    return None


def source_package_candidates(name: str, *, flavor: str | None) -> tuple[str, ...]:
    """Source-package names to ask a provider about, best first.

    Debian binary packages carry conventional decorations that the source
    package does not — a SONAME (``libssl1.1`` is built from ``openssl``) or a
    role suffix (``openssh-server`` from ``openssh``) — and an advisory names
    the source. The collector does not report the source package, so the
    stripped form is *added* as a fallback rather than substituted: the
    package's own name is always tried first, so a heuristic rewrite can only
    turn a miss into a hit and never turn a correct exact lookup into a
    different package's advisory.
    """
    base = _normalize(name)
    if not base:
        return ()
    if flavor != version_compare.DEB:
        return (base,)
    candidates = [base]
    for suffix in _BINARY_SUFFIXES:
        if base.endswith(suffix) and len(base) > len(suffix) + 1:
            candidates.append(base[: -len(suffix)])
            break
    else:
        match = _SOVERSION_RE.match(base)
        if match:
            stripped = match.group(1).rstrip("-")
            if stripped and stripped != "lib":
                candidates.append(stripped)
    return tuple(dict.fromkeys(candidates))


def build_purl(
    *,
    flavor: str,
    distro: str | None,
    name: str,
    version: str | None,
    architecture: str | None,
    release: str | None,
) -> str:
    """A package-URL for this package (purl-spec ``deb``/``rpm`` types).

    ``distro`` is carried as a qualifier rather than only as the namespace
    because that is what makes the purl answerable: the namespace says who
    builds the package, the ``distro`` qualifier says which release it was built
    for, and an advisory is a statement about the pair.
    """
    ptype = _PURL_TYPES[flavor]
    namespace = quote(distro, safe="") if distro else ""
    head = f"pkg:{ptype}/{namespace}/{quote(name, safe='')}" if namespace else f"pkg:{ptype}/{quote(name, safe='')}"
    if version:
        # ':' and '+' are legal in a purl version and are left readable on
        # purpose — an epoch that renders as %3A is unusable in a bug report.
        head = f"{head}@{quote(version, safe=':+~.')}"
    qualifiers = []
    if architecture:
        qualifiers.append(("arch", architecture))
    if release:
        qualifiers.append(("distro", release))
    if qualifiers:
        head = head + "?" + "&".join(f"{k}={quote(v, safe='.-_~')}" for k, v in sorted(qualifiers))
    return head


def _cpe_escape(value: str) -> str:
    """Escape a CPE 2.3 formatted-string component (NIST IR 7695 §6.2.3)."""
    out = []
    for char in value:
        if char.isalnum() or char in "._-":
            out.append(char)
        else:
            out.append("\\" + char)
    return "".join(out) or "*"


def build_cpe23(
    *,
    distro: str | None,
    name: str,
    evr: version_compare.Evr | None,
) -> str:
    """Best-effort CPE 2.3 for this package. **Not** used for matching.

    Two honest limitations, both of which are why the matcher ignores this
    string. NVD's vendor for a distribution package is normally the upstream
    project (``openssl:openssl``), not the distributor, and there is no
    package-name → upstream-vendor mapping that is right often enough to base a
    finding on; and NVD's version is the upstream version, which is exactly the
    number that stops changing when a distribution backports a fix. So the
    vendor is the distribution when we know it and ``*`` when we do not, and
    the version is the upstream part with epoch and revision dropped.
    """
    vendor = _cpe_escape(distro) if distro else "*"
    product = _cpe_escape(name)
    version = _cpe_escape(evr.version) if evr and evr.version else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def identify(
    *,
    name: str,
    version: str | None,
    architecture: str | None = None,
    source: str = "other",
    distro: DistroContext | None = None,
) -> PackageIdentity:
    """Canonical identity for one inventory software record.

    ``distro`` comes from :func:`resolve_distro` on the owning device and is
    passed in rather than re-derived per package, since it is a property of the
    endpoint.
    """
    clean_name = _normalize(name)
    source = _normalize(source) or "other"
    flavor = _SOURCE_FLAVORS.get(source)
    ctx = distro or DistroContext(distro=None, release=None, reason=REASON_UNKNOWN_DISTRO)

    evr: version_compare.Evr | None = None
    version_reason: str | None = None
    if not (version or "").strip():
        version_reason = REASON_NO_VERSION
    elif flavor is not None:
        try:
            evr = version_compare.parse_evr(version or "", flavor=flavor)
        except version_compare.VersionParseError:
            version_reason = REASON_UNPARSABLE_VERSION

    candidates = source_package_candidates(clean_name, flavor=flavor)

    # Order matters: report the *first* thing that is missing, walking from the
    # package outward to the OS, so the reason names something actionable.
    reason: str | None = None
    if flavor is None:
        reason = REASON_NON_DISTRO_SOURCE
    elif version_reason is not None:
        reason = version_reason
    elif not ctx.supported:
        reason = ctx.reason or REASON_UNKNOWN_DISTRO

    purl = (
        build_purl(
            flavor=flavor,
            distro=ctx.distro,
            name=clean_name,
            version=version,
            architecture=architecture,
            release=ctx.release,
        )
        if flavor is not None
        else None
    )

    return PackageIdentity(
        name=clean_name,
        version=version,
        architecture=architecture,
        source=source,
        flavor=flavor,
        distro=ctx.distro,
        distro_release=ctx.release,
        source_package_candidates=candidates,
        purl=purl,
        cpe23=build_cpe23(distro=ctx.distro, name=clean_name, evr=evr),
        matchable=reason is None,
        reason=reason,
        evr=evr,
    )
