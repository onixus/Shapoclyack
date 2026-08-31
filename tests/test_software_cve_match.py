"""The matcher itself: backports, unknowns, and deduplication.

These exercise ``match_software``, which is deliberately free of database
access, so the behaviour that matters — a backported fix is *not* reported as
vulnerable, and an endpoint we cannot assess is *not* reported as clean — is
tested without a Postgres.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from api.services import software_cve_match as matcher
from api.services.advisories import debian, ubuntu

FIXTURES = Path(__file__).parent / "fixtures" / "advisories"


@pytest.fixture()
def providers():
    """A ``get_provider``-shaped callable over the test datasets."""
    registry = {
        "ubuntu": ubuntu.UbuntuAdvisoryProvider(FIXTURES / "ubuntu-test.json"),
        "debian": debian.DebianAdvisoryProvider(FIXTURES / "debian-test.json"),
    }
    return lambda distro: registry.get(distro or "")


FOCAL = {
    "device_id": "dev_focal",
    "os_family": "linux",
    "os_name": "Ubuntu",
    "os_version": "20.04",
    "latest_snapshot_id": "snap_1",
}
BULLSEYE = {
    "device_id": "dev_bullseye",
    "os_family": "linux",
    "os_name": "Debian GNU/Linux",
    "os_version": "11",
    "latest_snapshot_id": "snap_2",
}


def _pkg(name: str, version: str | None, source: str = "dpkg", arch: str = "amd64") -> dict:
    return {"name": name, "version": version, "architecture": arch, "source": source}


def _by_cve(result: matcher.DeviceMatchResult) -> dict[str, matcher.MatchCandidate]:
    return {c.cve_id: c for c in result.candidates if c.cve_id}


# --------------------------------------------------------------------------
# The point of the whole feature
# --------------------------------------------------------------------------


def test_backported_fix_is_reported_as_fixed(providers) -> None:
    """USN-5051-2 fixes CVE-2021-3711 in ``1.1.1f-1ubuntu2.8`` on focal. The
    host runs upstream 1.1.1f — which NVD lists as affected forever — with a
    later Ubuntu revision. Reporting this as vulnerable is the false-positive
    storm the roadmap warned about."""
    result = matcher.match_software(
        device=FOCAL,
        software=[_pkg("openssl", "1.1.1f-1ubuntu2.16")],
        provider_for=providers,
    )
    match = _by_cve(result)["CVE-2021-3711"]
    assert match.status == matcher.FIXED
    assert match.installed_version == "1.1.1f-1ubuntu2.16"
    assert match.fixed_version == "1.1.1f-1ubuntu2.8"
    assert match.advisory_id == "USN-5051-2"
    assert match.provider == "ubuntu-usn"
    assert match.feed_date == "2026-08-01"


def test_a_host_below_the_fixed_revision_is_vulnerable(providers) -> None:
    result = matcher.match_software(
        device=FOCAL,
        software=[_pkg("openssl", "1.1.1f-1ubuntu2.4")],
        provider_for=providers,
    )
    match = _by_cve(result)["CVE-2021-3711"]
    assert match.status == matcher.VULNERABLE
    assert match.severity == "high"
    assert match.purl == "pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.4?arch=amd64&distro=focal"


def test_the_fixed_version_itself_counts_as_fixed(providers) -> None:
    result = matcher.match_software(
        device=FOCAL,
        software=[_pkg("openssl", "1.1.1f-1ubuntu2.8")],
        provider_for=providers,
    )
    assert _by_cve(result)["CVE-2021-3711"].status == matcher.FIXED


def test_an_epoch_is_respected(providers) -> None:
    """``1:8.2p1-4ubuntu0.10`` is newer than ``8.2p1-4ubuntu0.11``: the epoch
    dominates. A comparison that ignored it would call this host fixed."""
    result = matcher.match_software(
        device=FOCAL,
        software=[_pkg("openssh-server", "8.2p1-4ubuntu0.11")],
        provider_for=providers,
    )
    assert _by_cve(result)["CVE-2023-48795"].status == matcher.VULNERABLE


def test_a_binary_package_falls_back_to_its_source_package(providers) -> None:
    """dpkg reports ``openssh-server``; the USN names ``openssh``."""
    result = matcher.match_software(
        device=FOCAL,
        software=[_pkg("openssh-server", "1:8.2p1-4ubuntu0.11")],
        provider_for=providers,
    )
    match = _by_cve(result)["CVE-2023-48795"]
    assert match.status == matcher.FIXED
    assert match.source_package == "openssh"
    assert match.installed_package == "openssh-server"
    assert match.evidence["source_package_lookup"] == "derived_from_binary_name"


def test_a_release_the_advisory_does_not_cover_produces_nothing(providers) -> None:
    """The focal fixed version says nothing about jammy, and the matcher must
    not carry it across."""
    jammy = dict(FOCAL, os_version="22.04", device_id="dev_jammy")
    result = matcher.match_software(
        device=jammy, software=[_pkg("curl", "7.81.0-1ubuntu1.2")], provider_for=providers
    )
    assert result.candidates == []
    assert result.packages_assessed == 1


# --------------------------------------------------------------------------
# Honest unknowns
# --------------------------------------------------------------------------


def test_an_unresolvable_distro_yields_unknown_not_silence(providers) -> None:
    device = {
        "device_id": "dev_mystery",
        "os_family": "linux",
        "os_name": "Some Appliance OS",
        "os_version": "1.0",
        "latest_snapshot_id": "snap_3",
    }
    result = matcher.match_software(
        device=device,
        software=[_pkg("openssl", "1.1.1f-1ubuntu2.4"), _pkg("curl", "7.68.0-1")],
        provider_for=providers,
    )
    assert [c.status for c in result.candidates] == [matcher.UNKNOWN]
    unknown = result.candidates[0]
    assert unknown.cve_id == ""
    assert unknown.unknown_reason == "unknown_distro"
    assert unknown.evidence["package_count"] == 2
    assert sorted(unknown.evidence["packages"]) == ["curl", "openssl"]
    assert result.packages_unassessed == 2
    assert result.packages_assessed == 0


def test_a_recognised_but_uncovered_distro_says_so(providers) -> None:
    device = {
        "device_id": "dev_rocky",
        "os_family": "linux",
        "os_name": "Rocky Linux",
        "os_version": "9.3",
        "latest_snapshot_id": "snap_4",
    }
    result = matcher.match_software(
        device=device, software=[_pkg("openssl", "1:3.0.7-24.el9", source="rpm")], provider_for=providers
    )
    assert result.candidates[0].unknown_reason == "unsupported_distro"
    assert result.candidates[0].distro == "rocky"


def test_windows_software_is_unknown_not_a_match(providers) -> None:
    device = {
        "device_id": "dev_win",
        "os_family": "windows",
        "os_name": "Windows 11 Pro",
        "os_version": "10.0.22631",
        "latest_snapshot_id": "snap_5",
    }
    result = matcher.match_software(
        device=device,
        software=[_pkg("Google Chrome", "126.0.6478.126", source="winreg", arch="x64")],
        provider_for=providers,
    )
    assert [c.status for c in result.candidates] == [matcher.UNKNOWN]
    assert result.candidates[0].unknown_reason == "non_distro_source"


def test_unknown_rows_are_grouped_by_reason_and_bounded(providers) -> None:
    """A host with thousands of unassessable packages gets a statement, not
    thousands of rows saying the same thing."""
    software = [_pkg(f"app-{index}", "1.0", source="winreg") for index in range(60)]
    software.append(_pkg("openssl", None))
    result = matcher.match_software(device=FOCAL, software=software, provider_for=providers)
    reasons = {c.unknown_reason for c in result.candidates}
    assert reasons == {"non_distro_source", "no_version"}
    grouped = next(c for c in result.candidates if c.unknown_reason == "non_distro_source")
    assert grouped.evidence["package_count"] == 60
    assert len(grouped.evidence["packages"]) == 25
    assert grouped.evidence["truncated"] is True
    assert result.packages_unassessed == 61


def test_a_provider_with_no_data_matches_nothing() -> None:
    """A missing dataset must not read as "the vendor knows of no advisories"."""
    empty = ubuntu.UbuntuAdvisoryProvider(Path("/nonexistent/advisories.json"))
    result = matcher.match_software(
        device=FOCAL,
        software=[_pkg("openssl", "1.1.1f-1ubuntu2.4")],
        provider_for=lambda distro: empty,
    )
    assert result.candidates == []
    assert result.packages_assessed == 1


# --------------------------------------------------------------------------
# Advisory states
# --------------------------------------------------------------------------


def test_not_affected_is_not_applicable(providers) -> None:
    """Debian states bullseye's curl is not affected by CVE-2023-38545. A naive
    "installed 7.74 < upstream 8.4" comparison would report it as vulnerable."""
    result = matcher.match_software(
        device=BULLSEYE, software=[_pkg("curl", "7.74.0-1.3+deb11u7")], provider_for=providers
    )
    assert _by_cve(result)["CVE-2023-38545"].status == matcher.NOT_APPLICABLE


def test_an_open_advisory_with_no_fix_is_vulnerable(providers) -> None:
    result = matcher.match_software(
        device=BULLSEYE, software=[_pkg("tar", "1.34+dfsg-1")], provider_for=providers
    )
    match = _by_cve(result)["CVE-2005-2541"]
    assert match.status == matcher.VULNERABLE
    assert match.fixed_version is None
    assert match.evidence["comparison"] == "no fixed version published"


def test_debian_backport_is_fixed(providers) -> None:
    result = matcher.match_software(
        device=BULLSEYE, software=[_pkg("openssl", "1.1.1n-0+deb11u5")], provider_for=providers
    )
    assert _by_cve(result)["CVE-2023-0286"].status == matcher.FIXED


# --------------------------------------------------------------------------
# Deduplication
# --------------------------------------------------------------------------


def test_one_row_per_cve_with_the_worst_status_winning(providers) -> None:
    """``openssl`` and ``libssl1.1`` both resolve to the openssl USN. One is
    patched, one is not: the endpoint is vulnerable to that CVE, once."""
    result = matcher.match_software(
        device=FOCAL,
        software=[
            _pkg("openssl", "1.1.1f-1ubuntu2.16"),
            _pkg("libssl1.1", "1.1.1f-1ubuntu2.4"),
        ],
        provider_for=providers,
    )
    matches = _by_cve(result)
    assert matches["CVE-2021-3711"].status == matcher.VULNERABLE
    assert len([c for c in result.candidates if c.cve_id == "CVE-2021-3711"]) == 1


def test_an_advisory_covering_several_cves_produces_a_row_each(providers) -> None:
    result = matcher.match_software(
        device=FOCAL, software=[_pkg("openssl", "1.1.1f-1ubuntu2.4")], provider_for=providers
    )
    assert set(_by_cve(result)) == {"CVE-2021-3711", "CVE-2021-3712"}


def test_match_keys_are_distinct_per_row(providers) -> None:
    result = matcher.match_software(
        device=FOCAL,
        software=[
            _pkg("openssl", "1.1.1f-1ubuntu2.4"),
            _pkg("curl", "7.68.0-1ubuntu2.1"),
            _pkg("Chrome", "1.0", source="winreg"),
        ],
        provider_for=providers,
    )
    keys = [c.match_key for c in result.candidates]
    assert len(keys) == len(set(keys))


def test_counts_summarise_the_run(providers) -> None:
    result = matcher.match_software(
        device=FOCAL,
        software=[
            _pkg("openssl", "1.1.1f-1ubuntu2.16"),
            _pkg("curl", "7.68.0-1ubuntu2.1"),
        ],
        provider_for=providers,
    )
    counts = result.counts()
    assert counts[matcher.FIXED] == 2  # both openssl CVEs
    assert counts[matcher.VULNERABLE] == 1  # curl
    assert result.packages_total == 2
    assert result.packages_assessed == 2
    assert result.packages_unassessed == 0
