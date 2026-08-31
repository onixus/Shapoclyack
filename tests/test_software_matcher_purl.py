"""Tests for PURL, CPE, and version comparator logic (Sprint 3)."""

import pytest

from api.services.software_matcher import (
    compare_versions,
    derive_cpe,
    derive_purl,
    find_matching_advisories,
    is_version_vulnerable,
)


def test_derive_purl_debian():
    purl = derive_purl("openssl", "1.1.1k-1+deb11u1", source="deb", os_name="Debian GNU/Linux 11 (bullseye)")
    assert purl == "pkg:deb/debian/openssl@1.1.1k-1+deb11u1"


def test_derive_purl_ubuntu():
    purl = derive_purl("openssh-server", "1:8.9p1-3ubuntu0.10", source="apt", os_name="Ubuntu 22.04.4 LTS")
    assert purl == "pkg:deb/ubuntu/openssh-server@1:8.9p1-3ubuntu0.10"


def test_derive_purl_rpm_redhat():
    purl = derive_purl("curl", "7.76.1-26.el9", source="dnf", os_name="Red Hat Enterprise Linux 9.2")
    assert purl == "pkg:rpm/redhat/curl@7.76.1-26.el9"


def test_derive_purl_alpine():
    purl = derive_purl("busybox", "1.35.0-r1", source="apk", os_name="Alpine Linux v3.16")
    assert purl == "pkg:apk/alpine/busybox@1.35.0-r1"


def test_derive_purl_pypi():
    purl = derive_purl("requests", "2.28.1", source="pip")
    assert purl == "pkg:pypi/requests@2.28.1"


def test_derive_purl_npm():
    purl = derive_purl("axios", "0.27.2", source="npm")
    assert purl == "pkg:npm/axios@0.27.2"


def test_derive_cpe():
    cpe = derive_cpe("openssh", "9.2p1", publisher="OpenBSD")
    assert cpe == "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*"


def test_compare_versions_simple():
    assert compare_versions("1.0.0", "1.0.1") == -1
    assert compare_versions("1.0.1", "1.0.0") == 1
    assert compare_versions("2.1.0", "2.1.0") == 0


def test_compare_versions_package_revisions():
    assert compare_versions("1.1.1k-1", "1.1.1k-2") == -1
    assert compare_versions("9.2p1-2+deb12u3", "9.2p1-2+deb12u2") == 1
    assert compare_versions("7.88.1-10+deb12u4", "7.88.1-10+deb12u5") == -1


def test_is_version_vulnerable_with_fixed():
    assert is_version_vulnerable(
        installed_version="1.1.1k-1",
        fixed_version="1.1.1t-1+deb11u1",
        introduced_version="1.1.1",
    )
    assert not is_version_vulnerable(
        installed_version="1.1.1t-1+deb11u1",
        fixed_version="1.1.1t-1+deb11u1",
        introduced_version="1.1.1",
    )
    assert not is_version_vulnerable(
        installed_version="1.0.2g",
        fixed_version="1.1.1t-1+deb11u1",
        introduced_version="1.1.1",
    )


def test_find_matching_advisories():
    matches = find_matching_advisories("openssl", "1.1.1k-1")
    assert len(matches) >= 1
    assert any(m["cve"] == "CVE-2023-0286" for m in matches)
