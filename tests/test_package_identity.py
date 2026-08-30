"""Canonical package identity: purl, CPE, and the honest-unknown rule."""

from __future__ import annotations

import pytest

from api.services import package_identity as pi
from api.services import version_compare


@pytest.mark.parametrize(
    ("os_family", "os_name", "os_version", "distro", "release"),
    [
        ("linux", "Ubuntu", "20.04", "ubuntu", "focal"),
        ("linux", "Ubuntu", "20.04.6 LTS", "ubuntu", "focal"),
        ("linux", "Ubuntu", "24.04", "ubuntu", "noble"),
        ("linux", "Ubuntu", "focal", "ubuntu", "focal"),
        ("linux", "ubuntu", "22.04", "ubuntu", "jammy"),
        ("linux", "Debian GNU/Linux", "12", "debian", "bookworm"),
        ("linux", "Debian GNU/Linux", "12.5", "debian", "bookworm"),
        ("linux", "Debian GNU/Linux", "bookworm", "debian", "bookworm"),
        ("linux", "Debian GNU/Linux", "11 (bullseye)", "debian", "bullseye"),
        # os_family is often absent; the name still decides.
        (None, "Ubuntu", "22.04", "ubuntu", "jammy"),
    ],
)
def test_resolve_distro(os_family, os_name, os_version, distro, release) -> None:
    ctx = pi.resolve_distro(os_family=os_family, os_name=os_name, os_version=os_version)
    assert (ctx.distro, ctx.release, ctx.supported) == (distro, release, True)
    assert ctx.reason is None


@pytest.mark.parametrize(
    ("os_family", "os_name", "os_version", "distro", "reason"),
    [
        # A distribution we recognise but do not cover is a different answer
        # from one we could not identify at all.
        ("linux", "Rocky Linux", "9.3", "rocky", pi.REASON_UNSUPPORTED_DISTRO),
        ("linux", "Red Hat Enterprise Linux", "9.2", "rhel", pi.REASON_UNSUPPORTED_DISTRO),
        ("linux", "Fedora Linux", "40", "fedora", pi.REASON_UNSUPPORTED_DISTRO),
        ("windows", "Windows 11 Pro", "10.0.22631", None, pi.REASON_UNSUPPORTED_DISTRO),
        ("darwin", "macOS", "14.5", None, pi.REASON_UNSUPPORTED_DISTRO),
        # Recognised distro, unrecognised release: still not matchable, and the
        # reason says which half was missing.
        ("linux", "Ubuntu", "99.04", "ubuntu", pi.REASON_UNKNOWN_RELEASE),
        ("linux", "Ubuntu", None, "ubuntu", pi.REASON_UNKNOWN_RELEASE),
        ("linux", None, None, None, pi.REASON_UNKNOWN_DISTRO),
        ("linux", "Some Appliance OS", "1.0", None, pi.REASON_UNKNOWN_DISTRO),
    ],
)
def test_resolve_distro_refuses_to_guess(os_family, os_name, os_version, distro, reason) -> None:
    ctx = pi.resolve_distro(os_family=os_family, os_name=os_name, os_version=os_version)
    assert ctx.supported is False
    assert ctx.distro == distro
    assert ctx.reason == reason


def _focal() -> pi.DistroContext:
    return pi.resolve_distro(os_family="linux", os_name="Ubuntu", os_version="20.04")


def test_purl_matches_the_roadmap_example() -> None:
    identity = pi.identify(
        name="openssl",
        version="1.1.1f-1ubuntu2.16",
        architecture="amd64",
        source="dpkg",
        distro=_focal(),
    )
    assert identity.purl == (
        "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.16?arch=amd64&distro=focal"
    )
    assert identity.matchable is True
    assert identity.flavor == version_compare.DEB


def test_purl_keeps_an_epoch_readable() -> None:
    identity = pi.identify(
        name="openssh-server",
        version="1:9.6p1-3ubuntu13",
        architecture="amd64",
        source="dpkg",
        distro=pi.resolve_distro(os_family="linux", os_name="Ubuntu", os_version="24.04"),
    )
    assert identity.purl == (
        "pkg:deb/ubuntu/openssh-server@1:9.6p1-3ubuntu13?arch=amd64&distro=noble"
    )
    assert identity.evr is not None
    assert (identity.evr.epoch, identity.evr.version, identity.evr.release) == (
        1,
        "9.6p1",
        "3ubuntu13",
    )


def test_purl_for_rpm_carries_the_release() -> None:
    # The distro is unsupported, so the identity is not matchable — but the purl
    # is still built, because it is useful to an operator and to an external
    # system regardless of whether we can answer a CVE question about it.
    ctx = pi.resolve_distro(os_family="linux", os_name="Rocky Linux", os_version="9.3")
    identity = pi.identify(
        name="openssl",
        version="1:3.0.7-24.el9",
        architecture="x86_64",
        source="rpm",
        distro=ctx,
    )
    assert identity.purl.startswith("pkg:rpm/rocky/openssl@1:3.0.7-24.el9?arch=x86_64")
    assert identity.matchable is False
    assert identity.reason == pi.REASON_UNSUPPORTED_DISTRO


def test_cpe_is_best_effort_and_drops_epoch_and_revision() -> None:
    identity = pi.identify(
        name="openssl",
        version="1:1.1.1f-1ubuntu2.16",
        architecture="amd64",
        source="dpkg",
        distro=_focal(),
    )
    # Upstream version only: the revision is exactly the part NVD does not know
    # about, which is why this string is not used for matching.
    assert identity.cpe23 == "cpe:2.3:a:ubuntu:openssl:1.1.1f:*:*:*:*:*:*:*"


def test_cpe_escapes_special_characters() -> None:
    identity = pi.identify(
        name="g++",
        version="4:12.2.0-3",
        source="dpkg",
        distro=pi.resolve_distro(os_family="linux", os_name="Debian", os_version="12"),
    )
    assert identity.cpe23 == "cpe:2.3:a:debian:g\\+\\+:12.2.0:*:*:*:*:*:*:*"


def test_cpe_has_a_wildcard_vendor_when_the_distro_is_unknown() -> None:
    identity = pi.identify(name="acme-agent", version="1.2.3", source="other")
    assert identity.cpe23 == "cpe:2.3:a:*:acme-agent:*:*:*:*:*:*:*:*"
    assert identity.purl is None


@pytest.mark.parametrize(
    ("name", "version", "source", "reason"),
    [
        # Windows / macOS / language-ecosystem inventory is real inventory that
        # no Debian or Ubuntu advisory talks about.
        ("Google Chrome", "126.0.6478.126", "winreg", pi.REASON_NON_DISTRO_SOURCE),
        ("wget", "1.21.4", "brew", pi.REASON_NON_DISTRO_SOURCE),
        ("some-agent", "1.0", "other", pi.REASON_NON_DISTRO_SOURCE),
        # A distro package with no usable version cannot be compared.
        ("openssl", None, "dpkg", pi.REASON_NO_VERSION),
        ("openssl", "   ", "dpkg", pi.REASON_NO_VERSION),
        ("openssl", "1:", "dpkg", pi.REASON_UNPARSABLE_VERSION),
    ],
)
def test_unmatchable_packages_name_their_reason(name, version, source, reason) -> None:
    identity = pi.identify(name=name, version=version, source=source, distro=_focal())
    assert identity.matchable is False
    assert identity.reason == reason


def test_reason_reports_the_package_before_the_os() -> None:
    """A Chrome install on a host with an unresolvable OS is unassessable for
    a reason that has nothing to do with the OS, and saying "unknown distro"
    would send an operator to fix the wrong thing."""
    identity = pi.identify(name="Google Chrome", version="126.0", source="winreg")
    assert identity.reason == pi.REASON_NON_DISTRO_SOURCE


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("curl", ("curl",)),
        ("openssh-server", ("openssh-server", "openssh")),
        ("openssh-client", ("openssh-client", "openssh")),
        ("libssl1.1", ("libssl1.1", "libssl")),
        ("libssl3", ("libssl3", "libssl")),
        ("libc6", ("libc6", "libc")),
        ("python3-dev", ("python3-dev", "python3")),
        ("nginx-common", ("nginx-common", "nginx")),
        # Nothing to strip, and nothing invented.
        ("bash", ("bash",)),
        ("lib", ("lib",)),
    ],
)
def test_source_package_candidates_always_try_the_exact_name_first(name, expected) -> None:
    assert pi.source_package_candidates(name, flavor=version_compare.DEB) == expected


def test_source_package_candidates_do_not_rewrite_rpm_names() -> None:
    # rpm inventory reports the binary name and the source is usually the same
    # word; there is no equivalent Debian SONAME convention to strip.
    assert pi.source_package_candidates("openssl-libs", flavor=version_compare.RPM) == (
        "openssl-libs",
    )


def test_identity_serialises_for_evidence() -> None:
    payload = pi.identify(
        name="curl", version="7.68.0-1ubuntu2.20", source="dpkg", distro=_focal()
    ).as_dict()
    assert payload["distro"] == "ubuntu"
    assert payload["distro_release"] == "focal"
    assert payload["matchable"] is True
    assert payload["source_package_candidates"] == ["curl"]
