"""Matching a Windows host against Microsoft's remediations (#358).

The model under test: a Windows advisory is about an operating system *build*,
and a host is patched against a CVE exactly when its revision (UBR) is at or
past the one that carries the fix, because Windows servicing is cumulative.
Everything here is about that claim and about the ways of not knowing, which
have to stay distinguishable — "no dataset", "build not in the feed" and "the
host reported no build" are three different things to fix and would otherwise
all render as a clean host.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.services import software_cve_match as matcher
from api.services.advisories import msrc


def _dataset(entries: list[dict], tmp_path: Path, *, updated: str = "2026-09-15") -> msrc.MsrcDataset:
    path = tmp_path / "msrc.json"
    path.write_text(
        json.dumps({"version": 1, "source": "msrc-test", "updated": updated, "entries": entries}),
        encoding="utf-8",
    )
    dataset = msrc.MsrcDataset()
    dataset.load(path)
    return dataset


def _remediation(cve: str, fixed_build: str, kb: str = "KB5000001", severity: str = "high") -> dict:
    return {
        "cve_id": cve,
        "fixed_build": fixed_build,
        "kb": kb,
        "product": "Windows 11 Version 24H2 for x64-based Systems",
        "severity": severity,
        "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
    }


def _device(os_version: str | None = "10.0.26100.4000") -> dict:
    return {
        "device_id": "dev_test",
        "latest_snapshot_id": "snap_test",
        "os_family": "windows",
        "os_name": "Windows 11 Pro",
        "os_version": os_version,
    }


# ---------------------------------------------------------------------------
# The build model itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("10.0.26100.9445", "10.0.26100.9445"),
        # A registry that reports no UBR has said which product line it is on
        # and nothing about its revision.
        ("10.0.26100", "10.0.26100.0"),
        ("6.3.9600.1", "6.3.9600.1"),
    ],
)
def test_a_windows_version_parses_into_family_and_revision(value, expected) -> None:
    build = msrc.parse_build(value)
    assert build is not None
    assert str(build) == expected


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "Windows 11 Pro",
        # Visual Studio, straight out of a real CVRF month. It matches the
        # shape of a build exactly and is not one.
        "15.9.83.0",
        # Products versioned like an NT build but with an impossible minor.
        "10.19.10658.0",
        "6.2511.7533.0",
        # No NT release has a build number this low.
        "10.0.42.1",
    ],
)
def test_things_that_look_like_builds_and_are_not(value) -> None:
    assert msrc.parse_build(value) is None


def test_the_revision_decides_because_servicing_is_cumulative(tmp_path: Path) -> None:
    dataset = _dataset(
        [
            _remediation("CVE-2026-1111", "10.0.26100.3000"),
            _remediation("CVE-2026-2222", "10.0.26100.5000"),
        ],
        tmp_path,
    )
    verdicts = {
        verdict.cve_id: verdict.status
        for verdict in msrc.evaluate(
            installed=msrc.parse_build("10.0.26100.4000"),
            installed_kbs=[],
            dataset=dataset,
        )
    }
    # Past the first fix, short of the second. The update that took this host
    # to 4000 contained everything shipped for this build before it.
    assert verdicts == {"CVE-2026-1111": "fixed", "CVE-2026-2222": "vulnerable"}


def test_a_fix_for_another_build_is_not_reported_at_all(tmp_path: Path) -> None:
    """Not "not applicable" — not reported.

    The dataset covers every supported Windows at once. A host would otherwise
    carry thousands of rows about operating systems it is not running, and the
    one row that matters would be somewhere in them.
    """
    dataset = _dataset(
        [
            _remediation("CVE-2026-1111", "10.0.22631.3000"),
            _remediation("CVE-2026-2222", "10.0.26100.3000"),
        ],
        tmp_path,
    )
    verdicts = msrc.evaluate(
        installed=msrc.parse_build("10.0.26100.4000"), installed_kbs=[], dataset=dataset
    )
    assert [verdict.cve_id for verdict in verdicts] == ["CVE-2026-2222"]


def test_an_installed_kb_can_only_make_a_host_more_patched(tmp_path: Path) -> None:
    """Out-of-band and hotpatched updates are real, and raise no UBR."""
    dataset = _dataset([_remediation("CVE-2026-3333", "10.0.26100.5000", kb="KB5044444")], tmp_path)

    without = msrc.evaluate(
        installed=msrc.parse_build("10.0.26100.4000"), installed_kbs=[], dataset=dataset
    )
    assert [v.status for v in without] == ["vulnerable"]

    with_kb = msrc.evaluate(
        installed=msrc.parse_build("10.0.26100.4000"),
        installed_kbs=["KB5044444"],
        dataset=dataset,
    )
    assert [v.status for v in with_kb] == ["fixed"]
    # Which signal decided it is carried, because "why is this host patched"
    # has two different answers.
    assert with_kb[0].fixed_by_installed_kb is True


# ---------------------------------------------------------------------------
# What the matcher makes of it
# ---------------------------------------------------------------------------


def test_the_operating_system_is_what_gets_assessed(tmp_path: Path) -> None:
    dataset = _dataset(
        [
            _remediation("CVE-2026-1111", "10.0.26100.3000"),
            _remediation("CVE-2026-2222", "10.0.26100.5000", severity="critical"),
        ],
        tmp_path,
    )
    software = [
        {"name": "7-Zip", "version": "25.01", "source": "winreg"},
        {"name": "Google Chrome", "version": "126.0", "source": "msi"},
        {"name": "KB5044444", "version": None, "source": "kb"},
    ]

    result = matcher._match_windows(
        device=_device(), software=software, dataset_for=lambda: dataset
    )

    # One assessment — the OS — not one per product. The operating system is
    # counted in the total because it is the subject of the assessment and is
    # not one of the rows in the software list; the updates are not, because
    # they are evidence for that assessment rather than a second subject.
    assert result.packages_assessed == 1
    assert result.packages_total == 3  # two products, plus the operating system
    assert result.packages_unassessed == 2
    assert result.packages_assessed + result.packages_unassessed == result.packages_total
    assert result.distro == "windows"
    assert result.distro_release == "10.0.26100"

    by_cve = {c.cve_id: c for c in result.candidates if c.cve_id}
    assert by_cve["CVE-2026-1111"].status == matcher.FIXED
    assert by_cve["CVE-2026-2222"].status == matcher.VULNERABLE
    assert by_cve["CVE-2026-2222"].severity == "critical"
    assert by_cve["CVE-2026-2222"].fixed_version == "10.0.26100.5000"
    assert by_cve["CVE-2026-2222"].advisory_id == "KB5000001"
    assert by_cve["CVE-2026-2222"].installed_version == "10.0.26100.4000"


def test_the_products_are_reported_once_as_inventory_not_as_findings(tmp_path: Path) -> None:
    """A Windows host has hundreds of products and one operating system.

    They are real inventory that this matcher does not speak about, and saying
    so once is the useful statement; saying it three hundred times is not.
    """
    dataset = _dataset([_remediation("CVE-2026-1111", "10.0.26100.3000")], tmp_path)
    software = [{"name": f"Product {i}", "version": "1.0", "source": "winreg"} for i in range(300)]

    result = matcher._match_windows(
        device=_device(), software=software, dataset_for=lambda: dataset
    )

    unknown = [c for c in result.candidates if c.status == matcher.UNKNOWN]
    assert len(unknown) == 1
    assert unknown[0].unknown_reason == "windows_product"
    assert unknown[0].evidence["package_count"] == 300
    assert unknown[0].evidence["truncated"] is True


@pytest.mark.parametrize(
    ("os_version", "entries", "reason"),
    [
        # Three ways of not knowing that would otherwise be one silence.
        ("10.0.26100.4000", [], "no_msrc_data"),
        ("10.0.99999.1", [_remediation("CVE-2026-1111", "10.0.26100.3000")], "unknown_windows_build"),
        ("Windows 11 Pro", [_remediation("CVE-2026-1111", "10.0.26100.3000")], "unparsable_os_version"),
    ],
)
def test_every_way_of_not_knowing_says_which_one_it_is(
    tmp_path: Path, os_version, entries, reason
) -> None:
    dataset = _dataset(entries, tmp_path)
    result = matcher._match_windows(
        device=_device(os_version), software=[], dataset_for=lambda: dataset
    )

    assert result.packages_assessed == 0
    # Still consistent when nothing could be assessed: the operating system is
    # then one of the things that was not.
    assert result.packages_assessed + result.packages_unassessed == result.packages_total
    reasons = {c.unknown_reason for c in result.candidates if c.status == matcher.UNKNOWN}
    assert reasons == {reason}


def test_a_missing_dataset_is_never_reported_as_a_clean_host(tmp_path: Path) -> None:
    """The failure that matters most: silence reads as safety."""
    dataset = _dataset([], tmp_path)
    result = matcher._match_windows(
        device=_device(), software=[{"name": "7-Zip", "version": "25.01", "source": "winreg"}],
        dataset_for=lambda: dataset,
    )

    assert not [c for c in result.candidates if c.status == matcher.FIXED]
    assert not [c for c in result.candidates if c.status == matcher.VULNERABLE]
    assert any(c.unknown_reason == "no_msrc_data" for c in result.candidates)


def test_match_software_routes_windows_to_the_build_matcher(tmp_path: Path, monkeypatch) -> None:
    """The entry point, not the private function: a Windows device must not go
    down the distribution path, where it resolves to `unsupported_distro` and
    every product becomes an unassessable package."""
    dataset = _dataset([_remediation("CVE-2026-1111", "10.0.26100.5000")], tmp_path)
    monkeypatch.setattr(msrc, "get_dataset", lambda: dataset)

    result = matcher.match_software(
        device=_device(),
        software=[{"name": "7-Zip", "version": "25.01", "source": "winreg"}],
    )

    assert result.distro == "windows"
    assert [c.cve_id for c in result.candidates if c.cve_id] == ["CVE-2026-1111"]


# ---------------------------------------------------------------------------
# The feed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Windows 11 Version 25H2 for ARM64-based Systems", "Windows 11 Version 25H2"),
        ("Windows 10 Version 1607 for 32-bit Systems", "Windows 10 Version 1607"),
        ("Windows Server 2022", "Windows Server 2022"),
    ],
)
def test_the_product_name_drops_an_architecture_the_build_cannot_establish(
    name, expected
) -> None:
    assert msrc.product_line(name) == expected


def test_cvrf_normalization_keeps_only_windows_builds() -> None:
    """A CVRF month covers everything Microsoft ships.

    Azure Linux packages and Visual Studio carry a `FixedBuild` too, in their
    own versioning. Matching those against a host's OS build would compare two
    unrelated number lines.
    """
    payload = {
        "ProductTree": {
            "FullProductName": [
                {"ProductID": "11929", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
                {"ProductID": "99999", "Value": "Microsoft Visual Studio 2017"},
            ]
        },
        "Vulnerability": [
            {
                "CVE": "CVE-2026-1111",
                "Threats": [
                    {"Type": 3, "Description": {"Value": "Critical"}, "ProductID": ["11929"]}
                ],
                "Remediations": [
                    {
                        "Type": 2,
                        "Description": {"Value": "5034123"},
                        "ProductID": ["11929"],
                        "FixedBuild": "10.0.26100.3000",
                        "URL": "https://example.invalid/kb",
                    },
                    {
                        "Type": 2,
                        "Description": {},
                        "ProductID": ["99999"],
                        "FixedBuild": "15.9.83.0",
                    },
                    # A workaround carries no build to compare against.
                    {"Type": 1, "Description": {"Value": "disable the service"}, "ProductID": ["11929"]},
                ],
            }
        ],
    }

    entries = msrc.normalize_cvrf(payload)

    assert len(entries) == 1
    assert entries[0] == {
        "cve_id": "CVE-2026-1111",
        "fixed_build": "10.0.26100.3000",
        "kb": "KB5034123",
        # Without the architecture: Microsoft names one product per
        # architecture and they share a build number, so a statement keyed
        # on the build cannot tell an x64 host from an ARM64 one. A live
        # x64 machine was shown a finding labelled ARM64 before this.
        "product": "Windows 11 Version 24H2",
        # Microsoft's "Critical" is this project's "critical"; its second rung,
        # "Important", is "high" here and would sort as unknown if passed
        # through.
        "severity": "critical",
        "url": "https://example.invalid/kb",
    }


def test_the_committed_seed_parses_and_says_it_is_a_seed() -> None:
    """The shipped file is a seed, and must not read as a corpus.

    An installation that never refreshes would otherwise match a real Windows
    host against ten statements and call it clean.
    """
    payload = json.loads(
        Path("scanner/data/advisories/msrc-advisories.json").read_text(encoding="utf-8")
    )
    assert payload["source"] == "msrc-seed"
    assert "seed" in payload["note"].lower()
    assert payload["entries"]

    dataset = msrc.MsrcDataset()
    dataset.load("scanner/data/advisories/msrc-advisories.json")
    assert dataset.available()
    assert dataset.entry_count() == len(payload["entries"])
