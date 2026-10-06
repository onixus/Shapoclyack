"""The retro matcher's pure half: versions, products, distributions, verdicts.

Every table here is made of strings real probers emit — nmap ``product`` /
``version`` / ``extrainfo`` and raw banners — because the matcher is only as
good as its reading of those, and a synthetic ``1.2.3`` proves nothing about
``8.2p1 Ubuntu 4ubuntu0.5``. The database side is ``test_retro_findings.py``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from api.services import advisories, cpe_ranges
from api.services import retro_match as rm
from api.services.advisories import base as advisory_base
from api.services.cpe_ranges import CpeRange

REPO_ROOT = Path(__file__).resolve().parent.parent
SEED = REPO_ROOT / "scanner" / "data" / "nvd-cpe" / "nvd-cpe-ranges.json"


@pytest.fixture(scope="module")
def seed() -> cpe_ranges.CpeRangeDataset:
    return cpe_ranges.load_dataset(SEED)


# --------------------------------------------------------------------------
# Upstream version order
# --------------------------------------------------------------------------

ORDERED = [
    # OpenSSH portable: the ``p`` release follows the bare number.
    ("8.2", "8.2p1"),
    ("8.2p1", "8.2p2"),
    ("8.2p2", "8.3"),
    ("8.9p1", "9.0"),
    ("9.7p1", "9.8"),
    ("9.3p1", "9.3p2"),
    # OpenSSL letter releases, including the two-letter tail.
    ("1.1.1", "1.1.1a"),
    ("1.1.1f", "1.1.1n"),
    ("1.0.2z", "1.0.2za"),
    ("1.0.2za", "1.0.2zd"),
    ("1.0.1f", "1.0.1g"),
    # Pre-releases precede the release.
    ("1.3.6rc2", "1.3.6"),
    ("1.3.6rc1", "1.3.6rc2"),
    ("2.0a1", "2.0"),
    ("2.0beta", "2.0rc1"),
    # ProFTPD letter releases follow the bare number and precede the next.
    ("1.3.5", "1.3.5a"),
    ("1.3.5b", "1.3.6rc1"),
    # Numbers are numbers.
    ("2.4.9", "2.4.41"),
    ("4.92.2", "4.92.10"),
    ("1.20.0", "1.20.1"),
]


@pytest.mark.parametrize(("lower", "higher"), ORDERED)
def test_upstream_order(lower: str, higher: str) -> None:
    assert rm.compare_upstream(lower, higher) == -1
    assert rm.compare_upstream(higher, lower) == 1


@pytest.mark.parametrize(
    ("left", "right"),
    [("2.4", "2.4.0"), ("10.0", "10"), ("8.2p1", "8.2P1"), ("v1.18.0", "1.18.0")],
)
def test_upstream_equal(left: str, right: str) -> None:
    assert rm.compare_upstream(left, right) == 0


@pytest.mark.parametrize(
    ("version", "statement", "expected"),
    [
        # CVE-2024-6387's second window: 8.5 <= v < 9.8.
        ("8.5p1", CpeRange("CVE-2024-6387", start_including="8.5", end_excluding="9.8"), True),
        ("9.7p1", CpeRange("CVE-2024-6387", start_including="8.5", end_excluding="9.8"), True),
        ("9.8p1", CpeRange("CVE-2024-6387", start_including="8.5", end_excluding="9.8"), False),
        ("8.4p1", CpeRange("CVE-2024-6387", start_including="8.5", end_excluding="9.8"), False),
        # Inclusive and exclusive ends, both sides.
        ("7.7", CpeRange("CVE-2018-15473", end_including="7.7"), True),
        # NVD keeps OpenSSH's "p1" in the CPE update component: a plain bound
        # of 7.7 covers the 7.7p1 release, and 7.8p1 is past it.
        ("7.7p1", CpeRange("CVE-2018-15473", end_including="7.7"), True),
        ("7.8p1", CpeRange("CVE-2018-15473", end_including="7.7"), False),
        # A bound that itself carries the patch level is compared as written.
        ("9.3p1", CpeRange("CVE-2023-38408", end_excluding="9.3p2"), True),
        ("9.3p2", CpeRange("CVE-2023-38408", end_excluding="9.3p2"), False),
        # 4.4p1 is the fix for the first CVE-2024-6387 window (< 4.4).
        ("4.4p1", CpeRange("CVE-2024-6387", end_excluding="4.4"), False),
        ("4.3p2", CpeRange("CVE-2024-6387", end_excluding="4.4"), True),
        # Only OpenSSH's pattern: an OpenSSL letter release is its version.
        ("1.0.1f", CpeRange("CVE-2014-0160", start_including="1.0.1", end_excluding="1.0.1g"), True),
        ("1.0.1g", CpeRange("CVE-2014-0160", start_including="1.0.1", end_excluding="1.0.1g"), False),
        ("4.87", CpeRange("CVE-X", start_excluding="4.87"), False),
        ("4.87.1", CpeRange("CVE-X", start_excluding="4.87"), True),
        # An exact statement is equality, not a floor.
        ("2.4.49", CpeRange("CVE-2021-41773", exact="2.4.49"), True),
        ("2.4.50", CpeRange("CVE-2021-41773", exact="2.4.49"), False),
        ("1.0.2zd", CpeRange("CVE-2022-0778", start_including="1.0.2", end_excluding="1.0.2zd"), False),
        ("1.0.2zc", CpeRange("CVE-2022-0778", start_including="1.0.2", end_excluding="1.0.2zd"), True),
    ],
)
def test_in_range(version: str, statement: CpeRange, expected: bool) -> None:
    assert rm.in_range(version, statement) is expected


# --------------------------------------------------------------------------
# Products and versions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("cpe:/a:openbsd:openssh:8.2p1", ("a:openbsd:openssh", "8.2p1")),
        ("cpe:/a:igor_sysoev:nginx:1.18.0", ("a:igor_sysoev:nginx", "1.18.0")),
        ("cpe:/o:linux:linux_kernel", ("o:linux:linux_kernel", None)),
        ("cpe:2.3:a:openbsd:openssh:7.2:p2:*:*:*:*:*:*", ("a:openbsd:openssh", "7.2p2")),
        ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", ("a:apache:http_server", None)),
        ("cpe:2.3:a:microsoft:internet_information_services:10.0:-:*:*:*:*:*:*", (
            "a:microsoft:internet_information_services",
            "10.0",
        )),
        ("not-a-cpe", None),
        ("cpe:/x:vendor:product:1", None),
    ],
)
def test_parse_cpe(name: str, expected) -> None:
    assert rm.parse_cpe(name) == expected


@pytest.mark.parametrize(
    ("fingerprint", "keys", "via", "version"),
    [
        # nmap with CPE: the CPE wins, the platform CPE is ignored.
        (
            rm.Fingerprint(
                product="OpenSSH",
                version="8.2p1 Ubuntu 4ubuntu0.5",
                cpe=("cpe:/a:openbsd:openssh:8.2p1", "cpe:/o:linux:linux_kernel"),
            ),
            ("a:openbsd:openssh",),
            "cpe",
            "8.2p1",
        ),
        # nmap's pre-rename nginx vendor reaches both NVD keys.
        (
            rm.Fingerprint(product="nginx", version="1.18.0", cpe=("cpe:/a:igor_sysoev:nginx:1.18.0",)),
            ("a:f5:nginx", "a:nginx:nginx"),
            "cpe",
            "1.18.0",
        ),
        # No CPE: the curated table.
        (rm.Fingerprint(product="Apache httpd", version="2.4.41"), ("a:apache:http_server",), "product_table", "2.4.41"),
        (rm.Fingerprint(product="Exim smtpd", version="4.92"), ("a:exim:exim",), "product_table", "4.92"),
        (
            rm.Fingerprint(product="Microsoft IIS httpd", version="10.0"),
            ("a:microsoft:internet_information_services", "a:microsoft:iis"),
            "product_table",
            "10.0",
        ),
        # Pulse with a generic product and the raw banner.
        (
            rm.Fingerprint(product="ssh", banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
            ("a:openbsd:openssh",),
            "banner",
            "8.9p1",
        ),
        (rm.Fingerprint(product="", banner="220 (vsFTPd 3.0.3)"), ("a:vsftpd_project:vsftpd",), "banner", "3.0.3"),
        (rm.Fingerprint(product="", banner="220 ProFTPD 1.3.5 Server (Debian)"), ("a:proftpd:proftpd",), "banner", "1.3.5"),
        (rm.Fingerprint(product="http", banner="HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"), ("a:f5:nginx", "a:nginx:nginx"), "banner", "1.18.0"),
    ],
)
def test_product_and_version(fingerprint, keys, via, version) -> None:
    found, found_via, cpe_version = rm.product_keys(fingerprint)
    assert (found, found_via) == (keys, via)
    assert rm.upstream_version(fingerprint, found, cpe_version, via=found_via) == version


@pytest.mark.parametrize(
    "fingerprint",
    [
        # Unknown products are not guessed at.
        rm.Fingerprint(product="Undertow", version="2.2.24"),
        rm.Fingerprint(product="Apache Tomcat/Coyote JSP engine", version="1.1"),
        # "apache" with no version right after it is not Apache httpd.
        rm.Fingerprint(product="", banner="Server: Apache-Coyote/1.1"),
        rm.Fingerprint(product="", banner="Powered by apache and friends 2.4"),
    ],
)
def test_an_unknown_product_is_not_guessed(fingerprint) -> None:
    assert rm.product_keys(fingerprint)[0] == ()


def test_protocol_2_0_is_not_a_version_of_openssh() -> None:
    fingerprint = rm.Fingerprint(product="OpenSSH", version="", banner="protocol 2.0")
    keys, _, cpe_version = rm.product_keys(fingerprint)
    assert rm.upstream_version(fingerprint, keys, cpe_version) is None


# --------------------------------------------------------------------------
# Distribution hints
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "hint"),
    [
        # nmap's version field for Ubuntu / Debian OpenSSH.
        ("8.2p1 Ubuntu 4ubuntu0.5 Ubuntu Linux; protocol 2.0", rm.DistroHint("ubuntu", None, "4ubuntu0.5")),
        ("9.2p1 Debian 2+deb12u3 protocol 2.0", rm.DistroHint("debian", "bookworm", "2+deb12u3")),
        ("7.9p1 Debian 10+deb10u2", rm.DistroHint("debian", "buster", "10+deb10u2")),
        # Raw banners.
        ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", rm.DistroHint("ubuntu", None, "3ubuntu0.6")),
        ("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1", rm.DistroHint("debian", "bullseye", "5+deb11u1")),
        # A backport revision naming its release.
        ("1.18.0-0ubuntu1.4~20.04.1", rm.DistroHint("ubuntu", "focal", "0ubuntu1.4~20.04.1")),
        # Distribution named, nothing more.
        ("2.4.41 (Ubuntu)", rm.DistroHint("ubuntu", None, None)),
        ("2.4.56 (Debian)", rm.DistroHint("debian", None, None)),
        # Families no provider covers.
        ("2.4.37 (Red Hat Enterprise Linux)", rm.DistroHint("rhel")),
        ("2.4.6 (CentOS)", rm.DistroHint("centos")),
        ("OpenSSH_7.8 FreeBSD-20180909", rm.DistroHint("freebsd")),
        ("SSH-2.0-OpenSSH_7.9p1 Raspbian-10+deb10u2", rm.DistroHint("raspbian")),
        ("openssh-8.0p1-19.el8_8", rm.DistroHint("rhel", "8")),
        # Nothing at all.
        ("7.4 protocol 2.0", rm.DistroHint()),
        ("", rm.DistroHint()),
    ],
)
def test_distro_hint(text: str, hint: rm.DistroHint) -> None:
    assert rm.distro_hint(text) == hint


# --------------------------------------------------------------------------
# Verdicts against the committed seed datasets
# --------------------------------------------------------------------------


def _verdicts(fingerprint, dataset, lookup=advisories.get_provider) -> dict[str, tuple[str, str]]:
    outcome = rm.match(fingerprint, dataset, lookup=lookup)
    return {m.cve: (m.verdict, m.confidence) for m in outcome.matches}


def test_no_distribution_is_a_range_finding(seed) -> None:
    verdicts = _verdicts(rm.Fingerprint(product="OpenSSH", version="7.4", banner="protocol 2.0"), seed)
    assert verdicts == {
        cve: ("vulnerable", "version_range")
        for cve in ("CVE-2018-15473", "CVE-2021-41617", "CVE-2023-38408", "CVE-2023-48795")
    }


def test_a_debian_build_at_the_fixed_revision_is_fixed(seed) -> None:
    """Debian's tracker: CVE-2024-6387 fixed in 1:9.2p1-2+deb12u3, CVE-2023-48795
    in +deb12u2. The banner has no epoch; the advisory's is borrowed."""
    verdicts = _verdicts(rm.Fingerprint(product="OpenSSH", version="9.2p1 Debian 2+deb12u3"), seed)
    assert verdicts["CVE-2024-6387"] == ("fixed", "vendor_advisory")
    assert verdicts["CVE-2023-48795"] == ("fixed", "vendor_advisory")


def test_a_debian_build_below_the_fixed_revision_is_a_vendor_finding(seed) -> None:
    verdicts = _verdicts(rm.Fingerprint(product="OpenSSH", version="9.2p1 Debian 2+deb12u1"), seed)
    assert verdicts["CVE-2024-6387"] == ("vulnerable", "vendor_advisory")
    assert verdicts["CVE-2023-48795"] == ("vulnerable", "vendor_advisory")


def test_a_cve_the_vendor_is_silent_on_is_possible_not_vulnerable(seed) -> None:
    """The seed Debian feed has no statement on CVE-2023-38408; NVD's range
    covers 9.2p1. Silence from the vendor is not a verdict either way."""
    verdicts = _verdicts(rm.Fingerprint(product="OpenSSH", version="9.2p1 Debian 2+deb12u3"), seed)
    assert verdicts["CVE-2023-38408"] == ("possible", "backport_possible")


def test_the_ubuntu_release_is_identified_by_the_upstream_version(seed) -> None:
    """The banner says ``3ubuntu0.1``, not ``jammy``; the USN feed fixes
    ``1:8.9p1-3ubuntu0.6`` on jammy and on no other release."""
    outcome = rm.match(rm.Fingerprint(product="OpenSSH", version="8.9p1 Ubuntu 3ubuntu0.1"), seed, lookup=advisories.get_provider)
    terrapin = next(m for m in outcome.matches if m.cve == "CVE-2023-48795")
    assert (terrapin.verdict, terrapin.confidence) == ("vulnerable", "vendor_advisory")
    assert terrapin.evidence["advisory"]["release"] == "jammy"
    assert terrapin.evidence["advisory"]["installed_version"] == "1:8.9p1-3ubuntu0.1"
    assert terrapin.evidence["advisory"]["advisory_id"] == "USN-6560-1"


def test_an_unidentifiable_release_is_possible(seed) -> None:
    verdicts = _verdicts(rm.Fingerprint(product="OpenSSH", version="8.2p1 Ubuntu 4ubuntu0.5"), seed)
    assert set(verdicts.values()) == {("possible", "backport_possible")}


def test_a_distribution_without_a_provider_is_possible(seed) -> None:
    verdicts = _verdicts(
        rm.Fingerprint(product="Apache httpd", version="2.4.37", banner="(Red Hat Enterprise Linux)"), seed
    )
    assert verdicts and set(verdicts.values()) == {("possible", "backport_possible")}


def test_no_provider_dataset_is_possible_not_range(seed) -> None:
    """A Debian banner on an installation with no advisory data at all: the
    matcher must not fall back to calling NVD's range a finding."""
    verdicts = _verdicts(
        rm.Fingerprint(product="OpenSSH", version="9.2p1 Debian 2+deb12u1"), seed, lookup=lambda _d: None
    )
    assert set(verdicts.values()) == {("possible", "backport_possible")}


class _Provider:
    """A provider with exactly the records a test hands it."""

    name = "fake"

    def __init__(self, records: list[advisory_base.AdvisoryRecord]) -> None:
        self._records = records

    def available(self) -> bool:
        return True

    def releases(self) -> tuple[str, ...]:
        return tuple(sorted({r.release for r in self._records}))

    def advisories_for(self, *, release: str, source_package: str):
        return tuple(r for r in self._records if r.release == release and r.source_package == source_package)


def _record(state: str, *, fixed: str | None = None, release: str = "bookworm") -> advisory_base.AdvisoryRecord:
    return advisory_base.AdvisoryRecord(
        advisory_id="DSA-1",
        cve_ids=("CVE-2023-48795",),
        release=release,
        source_package="openssh",
        fixed_version=fixed,
        state=state,
        provider="fake",
    )


@pytest.mark.parametrize(
    ("records", "version", "verdict"),
    [
        # Affected, no fix published: reported, not tracked (endpoint rule).
        ([_record("open")], "9.2p1 Debian 2+deb12u9", "unfixed"),
        ([_record("not_affected")], "9.2p1 Debian 2+deb12u1", "not_affected"),
        ([_record("resolved", fixed="1:9.2p1-2+deb12u2")], "9.2p1 Debian 2+deb12u2", "fixed"),
        ([_record("resolved", fixed="1:9.2p1-2+deb12u2")], "9.2p1 Debian 2+deb12u1", "vulnerable"),
        # Two advisories (a regression re-issue): the later fix is the bar.
        (
            [_record("resolved", fixed="1:9.2p1-2+deb12u2"), _record("resolved", fixed="1:9.2p1-2+deb12u4")],
            "9.2p1 Debian 2+deb12u3",
            "vulnerable",
        ),
        # Distribution named, revision not disclosed, same upstream: unanswerable.
        ([_record("resolved", fixed="1:9.2p1-2+deb12u2")], "9.2p1 (Debian) +deb12", "possible"),
    ],
)
def test_vendor_verdicts(records, version, verdict) -> None:
    dataset = cpe_ranges.CpeRangeDataset(
        index={"a:openbsd:openssh": (CpeRange("CVE-2023-48795", end_excluding="9.6"),)},
        marker="t",
        present=True,
    )
    outcome = rm.match(
        rm.Fingerprint(product="OpenSSH", version=version),
        dataset,
        lookup=lambda _d: _Provider(records),
    )
    assert [m.verdict for m in outcome.matches] == [verdict]


def test_releases_that_disagree_are_possible() -> None:
    """One upstream shipped in two releases, one fixed and one not: without the
    release in the banner there is no honest single answer."""
    records = [
        _record("resolved", fixed="1:9.2p1-2+deb12u2", release="bookworm"),
        _record("open", release="trixie"),
        advisory_base.AdvisoryRecord(
            advisory_id="DSA-2", cve_ids=("CVE-OTHER",), release="trixie", source_package="openssh",
            fixed_version="1:9.2p1-9", state="resolved", provider="fake",
        ),
    ]
    dataset = cpe_ranges.CpeRangeDataset(
        index={"a:openbsd:openssh": (CpeRange("CVE-2023-48795", end_excluding="9.6"),)},
        marker="t",
        present=True,
    )
    outcome = rm.match(
        rm.Fingerprint(product="OpenSSH", version="9.2p1 Ubuntu 9ubuntu1"),
        dataset,
        lookup=lambda _d: _Provider(records),
    )
    assert outcome.matches[0].verdict == "possible"
    assert outcome.matches[0].evidence["advisory"]["reason"] == "releases_disagree"


def test_outcome_reasons(seed) -> None:
    assert rm.match(rm.Fingerprint(product="Undertow", version="2.2"), seed, lookup=advisories.get_provider).reason == "unknown_product"
    assert rm.match(rm.Fingerprint(product="OpenSSH"), seed, lookup=advisories.get_provider).reason == "no_version"
    empty = cpe_ranges.CpeRangeDataset()
    assert rm.match(rm.Fingerprint(product="OpenSSH", version="7.4"), empty, lookup=advisories.get_provider).reason == "no_dataset"


def test_the_evidence_names_what_was_matched(seed) -> None:
    outcome = rm.match(
        rm.Fingerprint(product="nginx", version="1.18.0", cpe=("cpe:/a:igor_sysoev:nginx:1.18.0",)),
        seed,
        lookup=advisories.get_provider,
    )
    resolver = next(m for m in outcome.matches if m.cve == "CVE-2021-23017")
    assert resolver.evidence["cpe"] == "a:f5:nginx"
    assert resolver.evidence["range"] == ">= 0.6.18, < 1.20.1"
    assert resolver.evidence["dataset"] == seed.marker
    assert (resolver.severity, resolver.cvss) == ("high", 7.7)


# --------------------------------------------------------------------------
# The dataset file
# --------------------------------------------------------------------------


def test_the_seed_loads_and_every_statement_is_bounded(seed) -> None:
    assert seed.available
    assert seed.updated and seed.marker and seed.marker.startswith("nvd:")
    for statements in seed.index.values():
        for statement in statements:
            assert statement.exact or any(
                (statement.start_including, statement.start_excluding,
                 statement.end_including, statement.end_excluding)
            )
            assert statement.cve in seed.cves


def test_the_marker_tracks_content_not_the_feed_date_or_the_order(tmp_path: Path) -> None:
    """A daily refresh re-stamps ``updated`` and re-appends the week's CVEs even
    when NVD changed nothing. If that moved the marker, the worker would
    re-match the whole estate every night for nothing."""
    path = tmp_path / "ranges.json"
    payload = json.loads(SEED.read_text(encoding="utf-8"))
    path.write_text(json.dumps(payload), encoding="utf-8")
    original = cpe_ranges.load_dataset(path).marker

    payload["updated"] = "2027-01-01"
    payload["entries"]["a:openbsd:openssh"].reverse()
    payload["entries"] = dict(reversed(list(payload["entries"].items())))
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    assert cpe_ranges.load_dataset(path).marker == original

    payload["cves"]["CVE-2024-6387"]["cvss"] = 8.2
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert cpe_ranges.load_dataset(path).marker != original


def test_an_unbounded_statement_is_dropped_and_new_content_moves_the_marker(tmp_path: Path) -> None:
    path = tmp_path / "ranges.json"
    payload = {
        "version": 1,
        "updated": "2026-09-01",
        "entries": {"a:vendor:product": [{"cve": "CVE-2026-1"}, {"cve": "CVE-2026-2", "ee": "2.0"}]},
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    first = cpe_ranges.load_dataset(path)
    assert [s.cve for s in first.ranges_for("a:vendor:product")] == ["CVE-2026-2"]

    payload["entries"]["a:vendor:product"].append({"cve": "CVE-2026-3", "v": "1.0"})
    path.write_text(json.dumps(payload), encoding="utf-8")
    second = cpe_ranges.load_dataset(path)
    # Same feed date, different content: a different version to match against.
    assert second.marker != first.marker
    assert second.updated == first.updated


@pytest.mark.parametrize(
    ("content", "error"),
    [(None, "missing"), ("{not json", "invalid JSON"), ('{"entries": []}', "entries is not a map")],
)
def test_a_bad_dataset_is_reported_not_raised(tmp_path: Path, content, error) -> None:
    path = tmp_path / "ranges.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    loaded = cpe_ranges.load_dataset(path)
    assert not loaded.available
    assert loaded.error.startswith(error)


# --------------------------------------------------------------------------
# Review of PR #444: uncertain versions, CPE aliases, host OS, vendor severity
# --------------------------------------------------------------------------


def _one(key: str, *ranges: CpeRange, severity: str = "high") -> cpe_ranges.CpeRangeDataset:
    return cpe_ranges.CpeRangeDataset(
        marker="t",
        index={key: tuple(ranges)},
        cves={r.cve: {"severity": severity, "cvss": 8.0} for r in ranges},
        present=True,
    )


@pytest.mark.parametrize(
    ("fingerprint", "key", "statement"),
    [
        # nmap's own uncertainty, copied verbatim into the version field.
        (
            rm.Fingerprint(product="Samba smbd", version="3.X - 4.X", cpe=("cpe:/a:samba:samba",)),
            "a:samba:samba",
            CpeRange("CVE-2017-7494", start_including="3.5.0", end_excluding="4.4.14"),
        ),
        (
            rm.Fingerprint(product="Samba smbd", version="4.x"),
            "a:samba:samba",
            CpeRange("CVE-2021-44142", end_excluding="4.13.17"),
        ),
        (
            rm.Fingerprint(product="vsftpd", version="2.0.8 or later", cpe=("cpe:/a:vsftpd:vsftpd",)),
            "a:vsftpd_project:vsftpd",
            CpeRange("CVE-2015-1419", end_including="3.0.2"),
        ),
        (
            rm.Fingerprint(product="vsftpd", version="2.0.8 or later"),
            "a:vsftpd_project:vsftpd",
            CpeRange("CVE-2015-1419", end_including="3.0.2"),
        ),
        # A CPE that pins only the major version: "4" is every Exim 4.
        (
            rm.Fingerprint(product="Exim smtpd", version="4.X", cpe=("cpe:/a:exim:exim:4",)),
            "a:exim:exim",
            CpeRange("CVE-2019-10149", start_including="4.87", end_including="4.91"),
        ),
        (
            rm.Fingerprint(product="Exim smtpd", cpe=("cpe:/a:exim:exim:4",)),
            "a:exim:exim",
            CpeRange("CVE-2019-10149", start_including="4.87", end_including="4.91"),
        ),
    ],
)
def test_an_uncertain_version_is_no_version_not_a_finding(fingerprint, key, statement) -> None:
    outcome = rm.match(fingerprint, _one(key, statement), lookup=lambda _d: None)
    assert outcome.matches == ()
    assert outcome.reason == "no_version"


@pytest.mark.parametrize(
    "fingerprint",
    [
        rm.Fingerprint(product="OpenSSH", version="for_Windows_8.1", cpe=("cpe:/a:openbsd:openssh:for_windows_8.1",)),
        rm.Fingerprint(product="OpenSSH", version="for_Windows_8.1"),
        rm.Fingerprint(product="ssh", banner="SSH-2.0-OpenSSH_for_Windows_8.1"),
    ],
)
def test_openssh_for_windows_is_not_openbsd_openssh(fingerprint) -> None:
    """Microsoft's port has its own versions and its own advisories; matched
    against openbsd:openssh a Windows Server got CVE-2024-6387 and three more."""
    dataset = _one(
        "a:openbsd:openssh",
        CpeRange("CVE-2024-6387", start_including="8.5", end_excluding="9.8"),
        CpeRange("CVE-2023-38408", end_excluding="9.3p2"),
    )
    outcome = rm.match(fingerprint, dataset, lookup=lambda _d: None)
    assert outcome.matches == ()
    assert "a:openbsd:openssh" not in outcome.product_keys


@pytest.mark.parametrize(
    ("cpe", "key"),
    [
        ("cpe:/a:vsftpd:vsftpd:3.0.3", "a:vsftpd_project:vsftpd"),
        ("cpe:/a:matt_johnston:dropbear_ssh_server:2019.78", "a:dropbear_ssh_project:dropbear_ssh"),
        ("cpe:/a:redislabs:redis:6.0.9", "a:redis:redis"),
    ],
)
def test_nmap_cpe_names_reach_the_nvd_key(cpe, key) -> None:
    keys, via, _ = rm.product_keys(rm.Fingerprint(cpe=(cpe,)))
    assert key in keys and via == "cpe"


def test_vsftpd_with_nmaps_cpe_finds_the_seed_cve(seed) -> None:
    outcome = rm.match(
        rm.Fingerprint(product="vsftpd", version="3.0.3", cpe=("cpe:/a:vsftpd:vsftpd:3.0.3",)),
        seed,
        lookup=advisories.get_provider,
    )
    assert [(m.cve, m.verdict) for m in outcome.matches] == [("CVE-2021-30047", "vulnerable")]


def test_a_cpe_key_the_dataset_lacks_falls_back_to_the_product_table() -> None:
    """An nmap CPE nobody aliased yet must not blind the product table."""
    dataset = _one("a:exim:exim", CpeRange("CVE-2019-15846", end_excluding="4.92.2"))
    outcome = rm.match(
        rm.Fingerprint(product="Exim smtpd", version="4.92", cpe=("cpe:/a:someone:exim_server:4.92",)),
        dataset,
        lookup=lambda _d: None,
    )
    assert [m.cve for m in outcome.matches] == ["CVE-2019-15846"]


def test_an_unaliased_cpes_version_still_speaks_for_the_listener() -> None:
    """The table knows the product, none of the line's CPEs is one of its keys
    (a vendor nobody aliased yet), and the version is only in the CPE: it is
    still the prober's statement about this listener."""
    dataset = _one("a:exim:exim", CpeRange("CVE-2019-15846", end_excluding="4.92.2"))
    outcome = rm.match(
        rm.Fingerprint(product="Exim smtpd", cpe=("cpe:/a:someone:exim_server:4.92",)),
        dataset,
        lookup=lambda _d: None,
    )
    assert outcome.upstream_version == "4.92"
    assert [m.cve for m in outcome.matches] == ["CVE-2019-15846"]


EXIM_DEBIAN = rm.Fingerprint(product="Exim smtpd", version="4.92")
EXIM_RANGE = _one("a:exim:exim", CpeRange("CVE-2019-15846", end_excluding="4.92.2"), severity="critical")


def test_a_daemon_on_a_known_debian_host_goes_to_the_vendor() -> None:
    """Exim 4.92 on buster: the banner says nothing, the host does. Debian
    fixed CVE-2019-15846 in 4.92-8+deb10u2 — same upstream, revision unknown:
    the backport question, unanswered, so possible, not a range finding."""
    provider = _Provider([
        advisory_base.AdvisoryRecord(
            advisory_id="DSA-4517-1", cve_ids=("CVE-2019-15846",), release="buster",
            source_package="exim4", fixed_version="4.92-8+deb10u2", state="resolved", provider="fake",
        )
    ])
    outcome = rm.match(
        EXIM_DEBIAN, EXIM_RANGE, lookup=lambda _d: provider, host=rm.DistroHint("debian", "buster")
    )
    assert [(m.verdict, m.confidence) for m in outcome.matches] == [("possible", "backport_possible")]
    assert outcome.matches[0].evidence["distro_source"] == "host"


def test_a_daemon_older_than_the_vendor_fix_on_a_known_host_is_a_vendor_finding() -> None:
    provider = _Provider([
        advisory_base.AdvisoryRecord(
            advisory_id="DSA-1", cve_ids=("CVE-2019-15846",), release="buster",
            source_package="exim4", fixed_version="4.93-1", state="resolved", provider="fake",
            severity="high",
        )
    ])
    outcome = rm.match(
        EXIM_DEBIAN, EXIM_RANGE, lookup=lambda _d: provider, host=rm.DistroHint("debian", "buster")
    )
    assert [(m.verdict, m.confidence) for m in outcome.matches] == [("vulnerable", "vendor_advisory")]


def test_a_distro_packaged_daemon_on_a_linux_host_of_unknown_distro_is_possible() -> None:
    outcome = rm.match(EXIM_DEBIAN, EXIM_RANGE, lookup=lambda _d: None, host=rm.DistroHint("linux"))
    assert [(m.verdict, m.confidence) for m in outcome.matches] == [("possible", "backport_possible")]
    assert outcome.matches[0].evidence["advisory"]["reason"] == "distro_packaged_on_linux"


def test_no_sign_of_a_distribution_anywhere_is_still_a_range_finding() -> None:
    outcome = rm.match(EXIM_DEBIAN, EXIM_RANGE, lookup=lambda _d: None, host=None)
    assert [(m.verdict, m.confidence) for m in outcome.matches] == [("vulnerable", "version_range")]


def test_a_product_not_built_by_distributions_ignores_the_host_hint() -> None:
    dataset = _one("a:microsoft:internet_information_services", CpeRange("CVE-2017-7269", exact="6.0"))
    outcome = rm.match(
        rm.Fingerprint(product="Microsoft IIS httpd", version="6.0"),
        dataset,
        lookup=lambda _d: None,
        host=rm.DistroHint("linux"),
    )
    assert [(m.verdict, m.confidence) for m in outcome.matches] == [("vulnerable", "version_range")]


def _debian_openssh(state: str, severity: str, fixed: str | None = None) -> _Provider:
    return _Provider([
        advisory_base.AdvisoryRecord(
            advisory_id="CVE-2023-48795", cve_ids=("CVE-2023-48795",), release="bookworm",
            source_package="openssh", fixed_version=fixed, state=state, provider="fake",
            severity=severity,
        )
    ])


def test_a_vendor_open_negligible_statement_is_not_a_finding() -> None:
    """Debian: open, unimportant. The first cut turned it into a
    vendor_advisory finding with NVD's "high" and a deadline."""
    dataset = _one("a:openbsd:openssh", CpeRange("CVE-2023-48795", end_excluding="9.6"))
    outcome = rm.match(
        rm.Fingerprint(product="OpenSSH", version="9.2p1 Debian 2+deb12u3"),
        dataset,
        lookup=lambda _d: _debian_openssh("open", "negligible"),
    )
    (only,) = outcome.matches
    assert only.is_finding is False
    assert only.severity == "negligible"


def test_a_vendor_verdict_carries_the_vendors_severity() -> None:
    dataset = _one("a:openbsd:openssh", CpeRange("CVE-2023-48795", end_excluding="9.6"), severity="high")
    outcome = rm.match(
        rm.Fingerprint(product="OpenSSH", version="9.2p1 Debian 2+deb12u1"),
        dataset,
        lookup=lambda _d: _debian_openssh("resolved", "medium", fixed="1:9.2p1-2+deb12u2"),
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence, only.severity) == ("vulnerable", "vendor_advisory", "medium")
    assert only.evidence["nvd_severity"] == "high"


def test_a_vendor_open_statement_with_a_real_severity_is_unfixed_not_tracked() -> None:
    """The endpoint matcher's rule: a vendor statement with no published fix
    is real risk with nothing to run, so it is reported, not given a deadline."""
    dataset = _one("a:openbsd:openssh", CpeRange("CVE-2023-48795", end_excluding="9.6"))
    outcome = rm.match(
        rm.Fingerprint(product="OpenSSH", version="9.2p1 Debian 2+deb12u3"),
        dataset,
        lookup=lambda _d: _debian_openssh("open", "high"),
    )
    (only,) = outcome.matches
    assert (only.verdict, only.is_finding) == ("unfixed", False)


# --------------------------------------------------------------------------
# Wider product coverage: each row proved by a string a prober really emits
# --------------------------------------------------------------------------
#
# nmap's strings are ``p//``/``v//``/``cpe:`` values from nmap-service-probes
# (7.99); Pulse's are the ``product`` its probe database (``probes.json``) or
# its banner parser (``fingerprint.rs``) writes into services.json. NVD keys and
# the ranges below were read from NVD's CPE and CVE APIs on 2026-10-06.

MYSQL = ("a:oracle:mysql", "a:mysql:mysql")
ELASTICSEARCH = ("a:elastic:elasticsearch", "a:elasticsearch:elasticsearch")
JETTY = ("a:eclipse:jetty", "a:mortbay:jetty")
PDNS_AUTHORITATIVE = ("a:powerdns:authoritative_server", "a:powerdns:authoritative")


@pytest.mark.parametrize(
    ("fingerprint", "keys", "via", "version"),
    [
        # nmap's Sendmail v/$2/ is "<binary>/<sendmail.cf>[/Debian-<revision>]".
        (
            rm.Fingerprint(
                product="Sendmail",
                version="8.15.2/8.15.2/Debian-8+deb9u1",
                cpe=("cpe:/a:sendmail:sendmail:8.15.2/8.15.2/Debian-8+deb9u1",),
            ),
            ("a:sendmail:sendmail",),
            "cpe",
            "8.15.2",
        ),
        # Pulse: ``sendmail\s+([0-9a-zA-Z._-]+)`` stops at the slash.
        (
            rm.Fingerprint(
                product="Sendmail",
                version="8.17.1.9",
                banner="220 mx.example.org ESMTP Sendmail 8.17.1.9/8.17.1.9/Debian-2+deb12u2; Mon, 6 Oct 2026",
            ),
            ("a:sendmail:sendmail",),
            "product_table",
            "8.17.1.9",
        ),
        (rm.Fingerprint(product="Dovecot imapd", version="2.0.11"), ("a:dovecot:dovecot",), "product_table", "2.0.11"),
        (rm.Fingerprint(product="Pure-FTPd", version="1.0.49"), ("a:pureftpd:pure-ftpd",), "product_table", "1.0.49"),
        # FileZilla Server 0.9.x calls every release "beta"; NVD does not.
        (
            rm.Fingerprint(
                product="FileZilla ftpd",
                version="0.9.41 beta",
                cpe=("cpe:/a:filezilla-project:filezilla_server:0.9.41 beta", "cpe:/o:microsoft:windows"),
            ),
            ("a:filezilla-project:filezilla_server",),
            "cpe",
            "0.9.41",
        ),
        (
            rm.Fingerprint(product="FileZilla Server", version="1.7.0"),
            ("a:filezilla-project:filezilla_server",),
            "product_table",
            "1.7.0",
        ),
        # nmap's MySQL version carries Ubuntu's package revision.
        (
            rm.Fingerprint(
                product="MySQL",
                version="5.7.33-0ubuntu0.18.04.1",
                cpe=("cpe:/a:mysql:mysql:5.7.33-0ubuntu0.18.04.1",),
            ),
            MYSQL,
            "cpe",
            "5.7.33",
        ),
        (rm.Fingerprint(product="MySQL", version="8.0.36", banner="J...", service="mysql"), MYSQL, "product_table", "8.0.36"),
        # MariaDB 10+ greets as "5.5.5-10.3.39-MariaDB-…"; nmap's $1 keeps the
        # compatibility prefix, and compared as written it is MariaDB 5.5.5.
        (
            rm.Fingerprint(product="MariaDB", version="5.5.5-10.3.39", cpe=("cpe:/a:mariadb:mariadb:5.5.5-10.3.39",)),
            ("a:mariadb:mariadb",),
            "cpe",
            "10.3.39",
        ),
        (rm.Fingerprint(product="MariaDB", version="10.11.6"), ("a:mariadb:mariadb",), "product_table", "10.11.6"),
        (rm.Fingerprint(product="MongoDB", version="4.4.6"), ("a:mongodb:mongodb",), "product_table", "4.4.6"),
        # nmap lists Lucene's CPE first; its version is not Elasticsearch's.
        (
            rm.Fingerprint(
                product="Elasticsearch REST API",
                version="7.17.9",
                cpe=("cpe:/a:apache:lucene:8.11.1", "cpe:/a:elasticsearch:elasticsearch:7.17.9"),
            ),
            ELASTICSEARCH,
            "cpe",
            "7.17.9",
        ),
        (rm.Fingerprint(product="Elasticsearch", version="7.17.0"), ELASTICSEARCH, "product_table", "7.17.0"),
        (
            rm.Fingerprint(product="Memcached", version="1.6.14", banner="VERSION 1.6.14", service="memcached"),
            ("a:memcached:memcached",),
            "product_table",
            "1.6.14",
        ),
        (rm.Fingerprint(product="CouchDB httpd", version="3.2.1"), ("a:apache:couchdb",), "product_table", "3.2.1"),
        (rm.Fingerprint(product="Apache CouchDB", version="3.3.3"), ("a:apache:couchdb",), "product_table", "3.3.3"),
        (rm.Fingerprint(product="Squid http proxy", version="4.13"), ("a:squid-cache:squid",), "product_table", "4.13"),
        # Pulse names a Server token it has no rule for by the token itself.
        (
            rm.Fingerprint(
                product="squid", version="5.7", banner="HTTP/1.1 400 Bad Request | Server: squid/5.7 | Mime-Version: 1.0"
            ),
            ("a:squid-cache:squid",),
            "product_table",
            "5.7",
        ),
        (
            rm.Fingerprint(
                product="HAProxy stats socket",
                version="2.6.12-1+deb12u1",
                cpe=("cpe:/a:haproxy:haproxy:2.6.12-1+deb12u1",),
            ),
            ("a:haproxy:haproxy",),
            "cpe",
            "2.6.12",
        ),
        # Jetty 7-9 date their releases; NVD's bounds do not carry the date.
        (
            rm.Fingerprint(product="Jetty", version="9.4.44.v20210927", cpe=("cpe:/a:mortbay:jetty:9.4.44.v20210927",)),
            JETTY,
            "cpe",
            "9.4.44",
        ),
        (rm.Fingerprint(product="Eclipse Jetty", version="10.0.13"), JETTY, "product_table", "10.0.13"),
        (
            rm.Fingerprint(
                product="PHP",
                version="7.4.3",
                banner="HTTP/1.1 200 OK | Date: Mon, 06 Oct 2026 10:00:00 GMT | X-Powered-By: PHP/7.4.3-4ubuntu2.19",
            ),
            ("a:php:php",),
            "product_table",
            "7.4.3",
        ),
        (rm.Fingerprint(product="Unbound", version="1.13.1"), ("a:nlnetlabs:unbound",), "product_table", "1.13.1"),
        # nmap's CPE for the authoritative server is NVD's newer key; NVD
        # still files older CVEs under authoritative_server.
        (
            rm.Fingerprint(
                product="PowerDNS Authoritative Server", version="4.1.6", cpe=("cpe:/a:powerdns:authoritative:4.1.6",)
            ),
            PDNS_AUTHORITATIVE,
            "cpe",
            "4.1.6",
        ),
        (rm.Fingerprint(product="PowerDNS Recursor", version="4.4.2"), ("a:powerdns:recursor",), "product_table", "4.4.2"),
        (
            rm.Fingerprint(product="libssh", version="0.8.1", banner="SSH-2.0-libssh_0.8.1"),
            ("a:libssh:libssh",),
            "product_table",
            "0.8.1",
        ),
        # Products covered before, under the strings Pulse writes for them.
        (
            rm.Fingerprint(product="Microsoft IIS", version="10.0"),
            ("a:microsoft:internet_information_services", "a:microsoft:iis"),
            "product_table",
            "10.0",
        ),
        (
            rm.Fingerprint(product="Dropbear", version="2020.81"),
            ("a:dropbear_ssh_project:dropbear_ssh", "a:matt_johnston:dropbear_ssh_server"),
            "product_table",
            "2020.81",
        ),
        # Pulse off its probe ports: a generic product and the raw banner, the
        # name immediately followed by its version.
        (rm.Fingerprint(product="SSH (libssh_0.7.5)", banner="SSH-2.0-libssh_0.7.5"), ("a:libssh:libssh",), "banner", "0.7.5"),
        (
            rm.Fingerprint(product="SMTP", banner="220 mx.example.org ESMTP Sendmail 8.15.2/8.15.2/Debian-18; Mon, 6 Oct 2026"),
            ("a:sendmail:sendmail",),
            "banner",
            "8.15.2",
        ),
        (
            rm.Fingerprint(
                product="CouchDB",
                version="3.2.2",
                banner="HTTP/1.1 400 Bad Request | Server: CouchDB/3.2.2 (Erlang OTP/24) | Content-Type: application/json",
            ),
            ("a:apache:couchdb",),
            "banner",
            "3.2.2",
        ),
    ],
)
def test_new_products_are_named_by_the_probers_own_strings(fingerprint, keys, via, version) -> None:
    found, found_via, cpe_version = rm.product_keys(fingerprint)
    assert (found, found_via) == (keys, via)
    assert rm.upstream_version(fingerprint, found, cpe_version, via=found_via) == version


@pytest.mark.parametrize(
    "fingerprint",
    [
        # Sendmail Inc.'s commercial MTA, versioned on its own (nmap: no CPE).
        rm.Fingerprint(product="Sendmail Switch smtpd", version="3.1.1"),
        # Pigeonhole's version is not Dovecot's.
        rm.Fingerprint(product="Dovecot Pigeonhole sieve", version="0.5.4"),
        # nmap's CouchDB-compatible line also matches Couchbase.
        rm.Fingerprint(product="CouchDB REST httpd", version="2.0.0"),
        # Couchbase's fork of CouchDB, whose Server token Pulse cuts at the "r".
        rm.Fingerprint(
            product="CouchDB",
            version="2.1.1",
            banner="HTTP/1.1 400 Bad Request | Server: CouchDB/2.1.1r-432-gc2af28d (Erlang OTP/R14B04)",
        ),
        # MiniServ serves both Webmin and Usermin, two version lines NVD keeps
        # under two keys; the banner does not say which.
        rm.Fingerprint(product="MiniServ", version="1.990"),
        # The ssh application's version, not the Erlang/OTP release NVD keys on.
        rm.Fingerprint(product="Erlang OTP SSH", version="5.1.4.4"),
        # Cisco's SSH stack version, not IOS's.
        rm.Fingerprint(product="Cisco SSH", version="1.25", banner="SSH-2.0-Cisco-1.25"),
        # NVD states Jenkins LTS and weekly ranges under one key, told apart
        # only by sw_edition, which the dataset does not keep: 2.426.3 LTS is
        # fixed for CVE-2024-23897 and still inside the weekly "< 2.442".
        rm.Fingerprint(product="Jenkins CI", version="2.426.3"),
        # nmap's Jenkins line (the agent listener) carries the CPE too, and the
        # CPE path would take any key the dataset knows.
        rm.Fingerprint(product="Jenkins httpd", version="2.426.3", cpe=("cpe:/a:jenkins:jenkins:2.426.3",)),
        # nmap's ``Server: CUPS/2.4 IPP/2.1`` line: a series, not a version, under
        # a key whose NVD ranges are in Apple's numbering (``< 499.4``).
        rm.Fingerprint(product="CUPS", version="2.4", cpe=("cpe:/a:apple:cups:2.4",), service="ipp"),
        rm.Fingerprint(product="CUPS", version="2.4.7", cpe=("cpe:/a:apple:cups:2.4.7",), service="ipp"),
        # Answers like Redis, versioned like nothing else.
        rm.Fingerprint(product="KeyDB", version="6.3.4"),
        # Pulse's "Redis" is whatever answers INFO with redis_version first:
        # valkey/valkey:8.1 (8.1.10) says redis_version:7.2.4, and Pulse's
        # redis_version rule precedes its KeyDB and Dragonfly rules.
        rm.Fingerprint(product="Redis", version="7.2.4", banner="+PONG", service="redis"),
        # The connector's version, not Tomcat's.
        rm.Fingerprint(product="Apache Tomcat Coyote", version="1.1"),
        rm.Fingerprint(product="OpenSearch", version="2.11.0"),
        rm.Fingerprint(product="Varnish http accelerator", version="4"),
        rm.Fingerprint(product="PostgreSQL DB", version="10.15 - 10.18 or 12.5"),
        rm.Fingerprint(product="Microsoft Exchange smtpd"),
        # nmap's generic "Served by POWERDNS": authoritative or recursor?
        rm.Fingerprint(product="PowerDNS", version="3.4.11"),
        # Pulse's banner parser reads "version N" anywhere as memcached; only
        # the memcached service is believed.
        rm.Fingerprint(
            product="memcached", version="0.9.41", banner="220-FileZilla Server version 0.9.41 beta", service="ftp"
        ),
        # Loose words.
        rm.Fingerprint(product="", banner="220 mx.example.org ESMTP Postfix (sendmail-compatible)"),
        rm.Fingerprint(product="", banner="SSH-2.0-libssh2_1.9.0"),
        rm.Fingerprint(product="Generic HTTP", banner="HTTP/1.1 302 Found | Location: /index.php/5.2/login"),
        rm.Fingerprint(product="Generic HTTP", banner="HTTP/1.1 200 OK | Via: 1.1 squidguard/1.4"),
    ],
)
def test_lookalikes_of_the_new_products_are_not_matched(fingerprint) -> None:
    assert rm.product_keys(fingerprint)[0] == ()


@pytest.mark.parametrize(
    ("fingerprint", "key", "statement"),
    [
        # A MariaDB greeting misread as MySQL 5.5.5 (no prober does this today).
        (
            rm.Fingerprint(product="MySQL", version="5.5.5-10.3.39"),
            "a:oracle:mysql",
            CpeRange("CVE-2023-22084", start_including="5.5.0", end_including="5.7.43"),
        ),
        # Pulse's MySQL rule takes the first x.y.z of a port-3306 reply; in a
        # refusal that is the scanner's own address.
        (
            rm.Fingerprint(
                product="MySQL",
                version="5.7.12",
                banner="G....j.Host '5.7.12.4' is not allowed to connect to this MySQL server",
                service="mysql",
            ),
            "a:oracle:mysql",
            CpeRange("CVE-2023-22084", start_including="5.7.0", end_including="5.7.43"),
        ),
        (
            rm.Fingerprint(product="Jetty", version="9.4.z-SNAPSHOT"),
            "a:eclipse:jetty",
            CpeRange("CVE-2021-28169", end_excluding="9.4.41"),
        ),
        (
            rm.Fingerprint(product="Jetty", version="9.4.0.RC1"),
            "a:eclipse:jetty",
            CpeRange("CVE-2021-28169", end_excluding="9.4.41"),
        ),
        (
            rm.Fingerprint(product="CouchDB httpd", version="2.1.1r-432-gc2af28d"),
            "a:apache:couchdb",
            CpeRange("CVE-2022-24706", end_excluding="3.2.2"),
        ),
        (
            rm.Fingerprint(product="HAProxy stats socket", version="2.4-dev5", cpe=("cpe:/a:haproxy:haproxy:2.4-dev5",)),
            "a:haproxy:haproxy",
            CpeRange("CVE-2023-25725", start_including="2.3.0", end_excluding="2.4.22"),
        ),
        # Sun's own Sendmail build.
        (
            rm.Fingerprint(product="Sendmail", version="8.9.3+Sun/8.9.3"),
            "a:sendmail:sendmail",
            CpeRange("CVE-2023-51765", end_excluding="8.18.0.2"),
        ),
        # Dovecot's greeting names no version; Pulse reports none.
        (
            rm.Fingerprint(
                product="Dovecot imapd",
                banner="* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ STARTTLS] Dovecot (Ubuntu) ready.",
            ),
            "a:dovecot:dovecot",
            CpeRange("CVE-2020-24386", start_including="2.2.26", end_excluding="2.3.13"),
        ),
        # FileZilla Server 0.9.x: Pulse's rule captures the word after
        # "Server", which is "version".
        (
            rm.Fingerprint(product="FileZilla Server", version="version", banner="220-FileZilla Server version 0.9.41 beta"),
            "a:filezilla-project:filezilla_server",
            CpeRange("CVE-2015-10003", end_excluding="0.9.51"),
        ),
    ],
)
def test_a_version_of_the_wrong_shape_is_no_version(fingerprint, key, statement) -> None:
    outcome = rm.match(fingerprint, _one(key, statement), lookup=lambda _d: None)
    assert outcome.matches == ()
    assert outcome.reason == "no_version"


@pytest.mark.parametrize(
    ("fingerprint", "key", "statements"),
    [
        # Patched LTS 2.426.3: fixed for CVE-2024-23897 (LTS "< 2.426.3"), yet
        # inside the weekly "< 2.442" NVD files under the same key.
        (
            rm.Fingerprint(product="Jenkins httpd", version="2.426.3", cpe=("cpe:/a:jenkins:jenkins:2.426.3",)),
            "a:jenkins:jenkins",
            (CpeRange("CVE-2024-23897", end_excluding="2.426.3"), CpeRange("CVE-2024-23897", end_excluding="2.442")),
        ),
        # CVE-2022-26691 under apple:cups is "< 499.4", Apple's numbering:
        # every Linux CUPS falls below it.
        (
            rm.Fingerprint(product="CUPS", version="2.4.7", cpe=("cpe:/a:apple:cups:2.4.7",), service="ipp"),
            "a:apple:cups",
            (CpeRange("CVE-2022-26691", end_excluding="499.4"),),
        ),
    ],
)
def test_products_whose_nvd_ranges_cannot_be_compared_are_not_matched_by_cpe(fingerprint, key, statements) -> None:
    for host in (None, rm.DistroHint("linux")):
        outcome = rm.match(fingerprint, _one(key, *statements), lookup=lambda _d: None, host=host)
        assert outcome.matches == ()
        assert outcome.reason == "unknown_product"


#: nmap's Redis line reads ``redis_version`` from INFO; Valkey, Dragonfly and
#: KeyDB report one too. NVD's redis:redis range of CVE-2025-49844, which
#: Valkey 8.1.10 does not carry.
REDIS_RANGE = (CpeRange("CVE-2025-49844", start_including="7.0", end_excluding="7.2.11"),)


def _nmap_redis(banner: str) -> rm.Fingerprint:
    return rm.Fingerprint(
        product="Redis key-value store",
        version="7.2.4",
        cpe=("cpe:/a:redislabs:redis:7.2.4",),
        banner=banner,
        service="redis",
    )


@pytest.mark.parametrize(
    "banner",
    [
        # Pulse keeps the INFO reply as the banner when its greeting read got
        # nothing; a hybrid run's merge prefers Pulse's raw banner.
        "$5764 | # Server | redis_version:7.2.4 | server_name:valkey | valkey_version:8.1.10 | redis_git_sha1:00000000",
        "$4310 | # Server | redis_version:7.4.0 | dragonfly_version:df-v1.21.2 | redis_mode:standalone",
    ],
)
def test_a_redis_fork_the_banner_names_is_a_lookalike_not_redis(banner) -> None:
    outcome = rm.match(_nmap_redis(banner), _one("a:redis:redis", *REDIS_RANGE), lookup=lambda _d: None)
    assert outcome.matches == ()
    assert outcome.reason == "lookalike"


def test_an_engine_named_only_in_the_cpe_is_a_lookalike() -> None:
    outcome = rm.match(
        rm.Fingerprint(cpe=("cpe:/a:mysql:mysql:5.7.25-TiDB-v7.1.5",), service="mysql"),
        _one("a:oracle:mysql", CpeRange("CVE-2023-22084", start_including="5.7.0", end_including="5.7.43")),
        lookup=lambda _d: None,
    )
    assert outcome.reason == "lookalike"


def test_a_fork_is_named_a_lookalike_even_without_a_version() -> None:
    """What the listener is outranks what it failed to say: a Valkey whose
    version nobody recorded is a lookalike, not "no version"."""
    fingerprint = rm.Fingerprint(
        product="Redis key-value store",
        banner="$5764 | # Server | redis_version:7.2.4 | server_name:valkey | valkey_version:8.1.10",
        service="redis",
    )
    outcome = rm.match(fingerprint, _one("a:redis:redis", *REDIS_RANGE), lookup=lambda _d: None)
    assert outcome.reason == "lookalike"


@pytest.mark.parametrize(
    ("version", "statement"),
    [
        # TiDB v7.1.5's real handshake, and Vitess's, through nmap's generic
        # MySQL line: engines that borrow MySQL's version and append their name.
        ("5.7.25-TiDB-v7.1.5", CpeRange("CVE-2023-22084", start_including="5.7.0", end_including="5.7.43")),
        ("8.0.30-Vitess", CpeRange("CVE-2024-20961", start_including="8.0.0", end_including="8.0.35")),
        # And every other engine nmap's generic MySQL line catches: a suffix
        # MySQL's own builds never use is not MySQL, whatever its name.
        ("5.7.25-OceanBase_CE-v4.2.1.2", CpeRange("CVE-2023-22084", start_including="5.7.0", end_including="5.7.43")),
        ("5.7.25-OceanBase-v4.2.1.0", CpeRange("CVE-2023-22084", start_including="5.7.0", end_including="5.7.43")),
        ("8.0.30-MatrixOne-v1.2.0", CpeRange("CVE-2024-20961", start_including="8.0.0", end_including="8.0.35")),
        ("5.7.25-TDDL-5.4.19", CpeRange("CVE-2023-22084", start_including="5.7.0", end_including="5.7.43")),
    ],
)
def test_an_engine_that_borrows_mysqls_version_is_a_lookalike(version, statement) -> None:
    outcome = rm.match(
        rm.Fingerprint(product="MySQL", version=version, cpe=(f"cpe:/a:mysql:mysql:{version}",), service="mysql"),
        _one("a:oracle:mysql", statement),
        lookup=lambda _d: None,
    )
    assert outcome.matches == ()
    assert outcome.reason == "lookalike"


def test_redis_that_says_it_is_redis_is_still_matched() -> None:
    banner = "$3910 | # Server | redis_version:7.2.4 | redis_git_sha1:00000000 | redis_mode:standalone"
    outcome = rm.match(_nmap_redis(banner), _one("a:redis:redis", *REDIS_RANGE), lookup=lambda _d: None)
    assert [(m.cve, m.verdict) for m in outcome.matches] == [("CVE-2025-49844", "vulnerable")]


@pytest.mark.parametrize(
    ("version", "upstream"),
    [
        # Ubuntu's revision, Debian's with binary logging on, Percona's build,
        # Oracle's own Windows build: MySQL, each.
        ("5.7.33-0ubuntu0.18.04.1", "5.7.33"),
        ("5.5.62-0+deb8u1-log", "5.5.62"),
        ("8.0.35-27", "8.0.35"),
        ("5.7.44-48-log", "5.7.44"),
        ("5.6.51-community", "5.6.51"),
        # Oracle's own commercial and cluster builds, CloudLinux's (cPanel's
        # MySQL, the most exposed there is) and debug builds.
        ("5.7.33-0+deb9u1", "5.7.33"),
        ("8.0.34-26.1", "8.0.34"),
        ("5.7.40-43-log", "5.7.40"),
        ("8.0.36-0ubuntu0.20.04.1-log", "8.0.36"),
        ("8.0.33-commercial", "8.0.33"),
        ("5.7.42-enterprise-commercial-advanced-log", "5.7.42"),
        ("5.7.42-cll-lve", "5.7.42"),
        ("8.0.35-cluster", "8.0.35"),
        ("8.0.33-25-debug", "8.0.33"),
        ("8.0.36-0ubuntu0.22.04.1-debug", "8.0.36"),
        ("8.0.36", "8.0.36"),
    ],
)
def test_mysql_builds_keep_their_upstream_version(version, upstream) -> None:
    fingerprint = rm.Fingerprint(product="MySQL", version=version, cpe=(f"cpe:/a:mysql:mysql:{version}",))
    keys, _, cpe_version = rm.product_keys(fingerprint)
    assert rm.upstream_version(fingerprint, keys, cpe_version) == upstream
    # And it is MySQL: matched, not a lookalike.
    outcome = rm.match(
        fingerprint,
        _one("a:oracle:mysql", CpeRange("CVE-2023-22084", start_including="5.0.0", end_excluding="9.0.0")),
        lookup=lambda _d: None,
    )
    assert (outcome.reason, outcome.upstream_version) == (None, upstream)


def test_mariadbs_compatibility_prefix_is_not_its_version() -> None:
    """``5.5.5-10.5.21`` compared as written is MariaDB 5.5.5: inside every 5.5
    range and outside the 10.5 one that actually applies."""
    dataset = _one(
        "a:mariadb:mariadb",
        CpeRange("CVE-2023-22084", start_including="10.5.0", end_excluding="10.5.23"),
        CpeRange("CVE-2020-2574", start_including="5.5.0", end_excluding="5.5.67"),
    )
    outcome = rm.match(
        rm.Fingerprint(product="MariaDB", version="5.5.5-10.5.21", cpe=("cpe:/a:mariadb:mariadb:5.5.5-10.5.21",)),
        dataset,
        lookup=lambda _d: None,
    )
    assert [(m.cve, m.verdict, m.confidence) for m in outcome.matches] == [
        ("CVE-2023-22084", "vulnerable", "version_range")
    ]
    assert outcome.upstream_version == "10.5.21"


@pytest.mark.parametrize(
    ("version", "matched"),
    [("9.4.40.v20210413", ["CVE-2021-28169"]), ("9.4.41.v20210516", []), ("10.0.2", ["CVE-2021-28169"])],
)
def test_jettys_dated_releases_compare_as_their_version(version, matched) -> None:
    dataset = _one(
        "a:eclipse:jetty",
        CpeRange("CVE-2021-28169", end_excluding="9.4.41"),
        CpeRange("CVE-2021-28169", start_including="10.0.0", end_excluding="10.0.3"),
    )
    outcome = rm.match(
        rm.Fingerprint(product="Jetty", version=version, cpe=(f"cpe:/a:mortbay:jetty:{version}",)),
        dataset,
        lookup=lambda _d: None,
    )
    assert [m.cve for m in outcome.matches] == matched


#: Products distributions do not build (vendor packages, containers, Windows):
#: a Linux host says nothing about a backport, and an NVD range stays a finding.
NOT_DISTRIBUTION_BUILT = [
    (
        rm.Fingerprint(product="Elasticsearch", version="7.17.9"),
        "a:elastic:elasticsearch",
        CpeRange("CVE-2023-31419", start_including="7.0.0", end_including="7.17.12"),
    ),
    (
        rm.Fingerprint(product="MongoDB", version="4.4.6"),
        "a:mongodb:mongodb",
        CpeRange("CVE-2024-1351", start_including="4.4.0", end_excluding="4.4.29"),
    ),
    (
        rm.Fingerprint(product="Apache CouchDB", version="3.2.1"),
        "a:apache:couchdb",
        CpeRange("CVE-2022-24706", end_excluding="3.2.2"),
    ),
    (
        rm.Fingerprint(product="Eclipse Jetty", version="9.4.40.v20210413"),
        "a:eclipse:jetty",
        CpeRange("CVE-2021-28169", end_excluding="9.4.41"),
    ),
    (
        rm.Fingerprint(product="FileZilla ftpd", version="0.9.41 beta"),
        "a:filezilla-project:filezilla_server",
        CpeRange("CVE-2015-10003", end_excluding="0.9.51"),
    ),
]

#: Products every distribution builds: on a Linux host of unknown distribution
#: an NVD range is no evidence against a backport.
DISTRIBUTION_BUILT = [
    (
        rm.Fingerprint(product="Sendmail", version="8.17.1.9"),
        "a:sendmail:sendmail",
        CpeRange("CVE-2023-51765", end_excluding="8.18.0.2"),
    ),
    (
        rm.Fingerprint(product="Dovecot imapd", version="2.3.7.2"),
        "a:dovecot:dovecot",
        CpeRange("CVE-2020-24386", start_including="2.2.26", end_excluding="2.3.13"),
    ),
    (
        rm.Fingerprint(product="Pure-FTPd", version="1.0.49"),
        "a:pureftpd:pure-ftpd",
        CpeRange("CVE-2020-9365", exact="1.0.49"),
    ),
    (
        rm.Fingerprint(product="Memcached", version="1.6.14", service="memcached"),
        "a:memcached:memcached",
        CpeRange("CVE-2023-46852", end_excluding="1.6.22"),
    ),
    (
        rm.Fingerprint(product="Squid http proxy", version="4.13"),
        "a:squid-cache:squid",
        CpeRange("CVE-2023-46846", start_including="2.6", end_excluding="6.4"),
    ),
    (
        rm.Fingerprint(product="HAProxy stats socket", version="2.4.20"),
        "a:haproxy:haproxy",
        CpeRange("CVE-2023-25725", start_including="2.3.0", end_excluding="2.4.22"),
    ),
    (
        rm.Fingerprint(product="Unbound", version="1.13.1"),
        "a:nlnetlabs:unbound",
        CpeRange("CVE-2023-50387", end_excluding="1.19.1"),
    ),
    (
        rm.Fingerprint(product="PowerDNS Authoritative Server", version="4.1.6"),
        "a:powerdns:authoritative_server",
        CpeRange("CVE-2022-27227", end_excluding="4.4.3"),
    ),
    (
        rm.Fingerprint(product="PowerDNS Recursor", version="4.4.2"),
        "a:powerdns:recursor",
        CpeRange("CVE-2022-27227", end_excluding="4.4.8"),
    ),
    (
        rm.Fingerprint(product="libssh", version="0.7.5"),
        "a:libssh:libssh",
        CpeRange("CVE-2018-10933", start_including="0.6.0", end_excluding="0.7.6"),
    ),
    (
        rm.Fingerprint(product="MySQL", version="8.0.35", service="mysql"),
        "a:oracle:mysql",
        CpeRange("CVE-2024-20961", start_including="8.0.0", end_including="8.0.35"),
    ),
    (
        rm.Fingerprint(product="MariaDB", version="10.5.21"),
        "a:mariadb:mariadb",
        CpeRange("CVE-2023-22084", start_including="10.5.0", end_excluding="10.5.23"),
    ),
    (
        rm.Fingerprint(product="PHP", version="7.4.3"),
        "a:php:php",
        CpeRange("CVE-2022-31625", start_including="7.4.0", end_excluding="7.4.30"),
    ),
]


@pytest.mark.parametrize(("fingerprint", "key", "statement"), NOT_DISTRIBUTION_BUILT)
def test_a_product_distributions_do_not_build_stays_a_range_finding_on_linux(fingerprint, key, statement) -> None:
    outcome = rm.match(fingerprint, _one(key, statement), lookup=lambda _d: None, host=rm.DistroHint("linux"))
    assert [(m.verdict, m.confidence) for m in outcome.matches] == [("vulnerable", "version_range")]


@pytest.mark.parametrize(("fingerprint", "key", "statement"), DISTRIBUTION_BUILT)
def test_a_product_distributions_build_is_possible_on_a_linux_host(fingerprint, key, statement) -> None:
    outcome = rm.match(fingerprint, _one(key, statement), lookup=lambda _d: None, host=rm.DistroHint("linux"))
    assert [(m.verdict, m.confidence) for m in outcome.matches] == [("possible", "backport_possible")]
    assert outcome.matches[0].evidence["advisory"]["reason"] == "distro_packaged_on_linux"
    # With nothing anywhere suggesting a distribution, the range is a finding.
    bare = rm.match(fingerprint, _one(key, statement), lookup=lambda _d: None, host=None)
    assert [(m.verdict, m.confidence) for m in bare.matches] == [("vulnerable", "version_range")]


def _advisory(
    cve: str, *, release: str, package: str, state: str = "resolved", fixed: str | None = None
) -> advisory_base.AdvisoryRecord:
    return advisory_base.AdvisoryRecord(
        advisory_id="ADV-1",
        cve_ids=(cve,),
        release=release,
        source_package=package,
        fixed_version=fixed,
        state=state,
        provider="fake",
        severity="medium",
    )


@pytest.mark.parametrize(
    ("key", "upstream", "packages"),
    [
        ("a:oracle:mysql", "8.0.36", ("mysql-8.0",)),
        ("a:mysql:mysql", "5.7.33", ("mysql-5.7",)),
        ("a:mariadb:mariadb", "10.5.21", ("mariadb-10.5",)),
        ("a:php:php", "8.1.2", ("php8.1",)),
        ("a:squid-cache:squid", "4.13", ("squid", "squid3")),
        ("a:powerdns:authoritative", "4.1.6", ("pdns",)),
        ("a:powerdns:recursor", "4.4.2", ("pdns-recursor",)),
        ("a:openbsd:openssh", "8.2p1", ("openssh",)),
        ("a:elastic:elasticsearch", "7.17.9", ()),
        # A version too short to name a series names no series package.
        ("a:php:php", "8", ()),
    ],
)
def test_source_packages_follow_the_upstream_series(key, upstream, packages) -> None:
    assert rm.source_packages(key, upstream) == packages


def test_mysql_with_ubuntus_revision_is_decided_by_its_series_package() -> None:
    """``5.7.33-0ubuntu0.18.04.1``: bionic's ``mysql-5.7``, not ``mysql-8.0``,
    whose not-affected statement is about another series."""
    provider = _Provider([
        _advisory("CVE-2023-22084", release="bionic", package="mysql-5.7", fixed="5.7.44-0ubuntu0.18.04.1"),
        _advisory("CVE-2023-22084", release="bionic", package="mysql-8.0", state="not_affected"),
    ])
    outcome = rm.match(
        rm.Fingerprint(
            product="MySQL", version="5.7.33-0ubuntu0.18.04.1", cpe=("cpe:/a:mysql:mysql:5.7.33-0ubuntu0.18.04.1",)
        ),
        _one("a:oracle:mysql", CpeRange("CVE-2023-22084", start_including="5.7.0", end_including="5.7.43")),
        lookup=lambda _d: provider,
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("vulnerable", "vendor_advisory")
    assert only.evidence["advisory"]["release"] == "bionic"
    assert only.evidence["advisory"]["installed_version"] == "5.7.33-0ubuntu0.18.04.1"


def test_mariadb_on_a_known_debian_host_goes_to_its_series_package() -> None:
    provider = _Provider([
        _advisory("CVE-2023-22084", release="bullseye", package="mariadb-10.5", fixed="1:10.5.23-0+deb11u1"),
    ])
    outcome = rm.match(
        rm.Fingerprint(product="MariaDB", version="5.5.5-10.5.21", cpe=("cpe:/a:mariadb:mariadb:5.5.5-10.5.21",)),
        _one("a:mariadb:mariadb", CpeRange("CVE-2023-22084", start_including="10.5.0", end_excluding="10.5.23")),
        lookup=lambda _d: provider,
        host=rm.DistroHint("debian", "bullseye"),
    )
    (only,) = outcome.matches
    # 10.5.21 is older than the upstream Debian's fix was built on.
    assert (only.verdict, only.confidence) == ("vulnerable", "vendor_advisory")
    assert only.evidence["advisory"]["fixed_version"] == "1:10.5.23-0+deb11u1"


MARIADB_10_11 = rm.Fingerprint(
    product="MariaDB", version="5.5.5-10.11.4", cpe=("cpe:/a:mariadb:mariadb:5.5.5-10.11.4",)
)
MARIADB_10_11_RANGE = _one(
    "a:mariadb:mariadb", CpeRange("CVE-2023-22084", start_including="10.11.0", end_excluding="10.11.6")
)


def test_mariadb_from_the_unversioned_source_is_decided_where_it_ships_that_series() -> None:
    """bookworm builds 10.11 from ``mariadb``, not ``mariadb-10.11``."""
    provider = _Provider([
        _advisory("CVE-2023-22084", release="bookworm", package="mariadb", fixed="1:10.11.6-0+deb12u1"),
    ])
    outcome = rm.match(
        MARIADB_10_11, MARIADB_10_11_RANGE, lookup=lambda _d: provider, host=rm.DistroHint("debian", "bookworm")
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("vulnerable", "vendor_advisory")


def test_the_unversioned_source_of_another_series_is_not_asked() -> None:
    """trixie's ``mariadb`` is 11.8. Its "not affected" is about 11.8; a 10.11
    on a trixie host (a container, say) is not that build."""
    provider = _Provider([
        _advisory("CVE-2023-22084", release="trixie", package="mariadb", state="not_affected"),
        _advisory("CVE-2025-0001", release="trixie", package="mariadb", fixed="1:11.8.2-0+deb13u1"),
    ])
    outcome = rm.match(
        MARIADB_10_11, MARIADB_10_11_RANGE, lookup=lambda _d: provider, host=rm.DistroHint("debian", "trixie")
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("possible", "backport_possible")
    assert only.evidence["advisory"]["reason"] == "no_vendor_statement"


#: trixie's ``mariadb`` as the Debian tracker states it (2026-10-06): fixes
#: inherited from unstable on the 10.11 and 11.4 series sit beside trixie's
#: own 11.8 ones, one of them without the epoch, and one CVE is open.
TRIXIE_MARIADB = _Provider([
    _advisory("CVE-2022-47015", release="trixie", package="mariadb", fixed="1:10.11.3-1"),
    _advisory("CVE-2023-22084", release="trixie", package="mariadb", fixed="1:10.11.6-1"),
    _advisory("CVE-2024-21096", release="trixie", package="mariadb", fixed="1:10.11.8-1"),
    _advisory("CVE-2025-21490", release="trixie", package="mariadb", fixed="1:11.4.5-1"),
    _advisory("CVE-2023-52969", release="trixie", package="mariadb", fixed="1:11.8.2-1"),
    _advisory("CVE-2025-13699", release="trixie", package="mariadb", fixed="11.8.6-0+deb13u1"),
    _advisory("CVE-2026-32710", release="trixie", package="mariadb", fixed="1:11.8.6-0+deb13u1"),
    _advisory("CVE-2026-44168", release="trixie", package="mariadb", state="open"),
])


@pytest.mark.parametrize(
    ("version", "statements"),
    [
        # A 10.11 container: the inherited 10.11 fixes made the first cut say
        # trixie ships 10.11, and handed it 11.8's verdicts.
        (
            "5.5.5-10.11.6",
            (
                CpeRange("CVE-2023-52969", start_including="10.11.0", end_excluding="10.11.12"),
                CpeRange("CVE-2026-44168", start_including="10.11.0", end_excluding="10.11.99"),
            ),
        ),
        # An 11.4 one: same major as trixie's 11.8, another series.
        ("5.5.5-11.4.3", (CpeRange("CVE-2025-21490", start_including="11.4.0", end_excluding="11.4.5"),)),
    ],
)
def test_a_release_ships_the_series_of_its_newest_fix_only(version, statements) -> None:
    outcome = rm.match(
        rm.Fingerprint(product="MariaDB", version=version, cpe=(f"cpe:/a:mariadb:mariadb:{version}",)),
        _one("a:mariadb:mariadb", *statements),
        lookup=lambda _d: TRIXIE_MARIADB,
        host=rm.DistroHint("debian", "trixie"),
    )
    assert {(m.verdict, m.evidence["advisory"].get("reason")) for m in outcome.matches} == {
        ("possible", "no_vendor_statement")
    }


def test_a_release_that_only_inherited_the_series_does_not_identify_it() -> None:
    """A Debian host whose release nobody named. The tracker's trixie and sid
    inherited 10.11 fixes built on 10.11.6, so "fixes built on this upstream"
    named four releases, three of which then refused to answer for 10.11 —
    "releases disagree" where bookworm alone ships 10.11."""
    inherited = [
        _advisory(cve, release=release, package="mariadb", fixed=fixed)
        for release in ("trixie", "sid")
        for cve, fixed in (
            ("CVE-2023-22084", "1:10.11.6-1"),
            ("CVE-2024-21096", "1:10.11.8-1"),
            ("CVE-2023-52969", "1:11.8.2-1"),
        )
    ]
    provider = _Provider([
        _advisory("CVE-2023-22084", release="bookworm", package="mariadb", fixed="1:10.11.6-0+deb12u1"),
        _advisory("CVE-2024-21096", release="bookworm", package="mariadb", fixed="1:10.11.8-0+deb12u1"),
        *inherited,
    ])
    outcome = rm.match(
        rm.Fingerprint(product="MariaDB", version="5.5.5-10.11.6", cpe=("cpe:/a:mariadb:mariadb:5.5.5-10.11.6",)),
        _one("a:mariadb:mariadb", CpeRange("CVE-2024-21096", start_including="10.11.0", end_excluding="10.11.8")),
        lookup=lambda _d: provider,
        host=rm.DistroHint("debian"),
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("vulnerable", "vendor_advisory")
    assert only.evidence["advisory"]["release"] == "bookworm"


def test_the_newest_fix_is_compared_without_the_epoch() -> None:
    """The tracker drops the epoch on some trixie records. Compared by dpkg,
    ``1:10.11.6-1`` (inherited) outranks ``11.8.6-0+deb13u1`` and made trixie a
    10.11 release; as upstream versions 11.8.6 is the newer."""
    provider = _Provider([
        _advisory("CVE-2023-22084", release="trixie", package="mariadb", fixed="1:10.11.6-1"),
        _advisory("CVE-2025-13699", release="trixie", package="mariadb", fixed="11.8.6-0+deb13u1"),
        _advisory("CVE-2024-21096", release="trixie", package="mariadb", state="not_affected"),
    ])
    outcome = rm.match(
        rm.Fingerprint(product="MariaDB", version="5.5.5-10.11.6", cpe=("cpe:/a:mariadb:mariadb:5.5.5-10.11.6",)),
        _one("a:mariadb:mariadb", CpeRange("CVE-2024-21096", start_including="10.11.0", end_excluding="10.11.8")),
        lookup=lambda _d: provider,
        host=rm.DistroHint("debian", "trixie"),
    )
    (only,) = outcome.matches
    assert (only.verdict, only.evidence["advisory"]["reason"]) == ("possible", "no_vendor_statement")


def test_the_release_is_found_through_the_unversioned_source() -> None:
    """A Debian host whose release nobody named: bookworm is the release whose
    ``mariadb`` fixes are built on 10.11.6 — found only by asking ``mariadb``."""
    provider = _Provider([
        _advisory("CVE-2023-22084", release="bookworm", package="mariadb", fixed="1:10.11.6-0+deb12u1"),
        _advisory("CVE-2024-21096", release="bookworm", package="mariadb", fixed="1:10.11.8-0+deb12u1"),
    ])
    outcome = rm.match(
        rm.Fingerprint(product="MariaDB", version="5.5.5-10.11.6", cpe=("cpe:/a:mariadb:mariadb:5.5.5-10.11.6",)),
        _one("a:mariadb:mariadb", CpeRange("CVE-2024-21096", start_including="10.11.0", end_excluding="10.11.8")),
        lookup=lambda _d: provider,
        host=rm.DistroHint("debian"),
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("vulnerable", "vendor_advisory")
    assert only.evidence["advisory"]["release"] == "bookworm"


#: Pulse keeps twelve header lines as an HTTP listener's banner, and a hybrid
#: run's merge prefers that raw banner to nmap's extrainfo: the web server's
#: banner carries PHP's package revision too.
FOCAL_WEB = _Provider([
    _advisory("CVE-2023-25690", release="focal", package="apache2", fixed="2.4.41-4ubuntu3.14"),
    _advisory("CVE-2021-23017", release="focal", package="nginx", fixed="1.18.0-0ubuntu1.1"),
    _advisory("CVE-2022-31625", release="focal", package="php7.4", fixed="7.4.3-4ubuntu2.12"),
])
FOCAL_WEB_RANGES = cpe_ranges.CpeRangeDataset(
    marker="t",
    index={
        "a:apache:http_server": (CpeRange("CVE-2023-25690", start_including="2.4.0", end_excluding="2.4.56"),),
        "a:f5:nginx": (CpeRange("CVE-2021-23017", start_including="0.6.18", end_excluding="1.20.1"),),
        "a:php:php": (CpeRange("CVE-2022-31625", start_including="7.4.0", end_excluding="7.4.30"),),
    },
    cves={
        "CVE-2023-25690": {"severity": "critical", "cvss": 9.8},
        "CVE-2021-23017": {"severity": "high", "cvss": 7.7},
        "CVE-2022-31625": {"severity": "critical", "cvss": 9.8},
    },
    present=True,
)


@pytest.mark.parametrize(
    "fingerprint",
    [
        rm.Fingerprint(
            product="Apache httpd",
            version="2.4.41",
            cpe=("cpe:/a:apache:http_server:2.4.41",),
            banner="HTTP/1.1 200 OK | Date: Mon, 06 Oct 2026 10:00:00 GMT | Server: Apache/2.4.41 (Ubuntu) | "
            "X-Powered-By: PHP/7.4.3-4ubuntu2.19 | Content-Type: text/html; charset=UTF-8",
        ),
        rm.Fingerprint(
            product="nginx",
            version="1.18.0",
            banner="HTTP/1.1 200 OK | Server: nginx/1.18.0 (Ubuntu) | Date: Mon, 06 Oct 2026 10:00:00 GMT | "
            "X-Powered-By: PHP/7.4.3-4ubuntu2.19",
        ),
    ],
)
def test_phps_revision_is_not_the_web_servers(fingerprint) -> None:
    """``4ubuntu2.19`` is php7.4's revision. Read as Apache's, a patched
    ``2.4.41-4ubuntu3.17`` became ``2.4.41-4ubuntu2.19`` < the fix (a finding);
    as nginx's, an unpatched one became newer than its fix (``fixed``). The
    distribution is Ubuntu either way; the revision is not disclosed."""
    (only,) = rm.match(fingerprint, FOCAL_WEB_RANGES, lookup=lambda _d: FOCAL_WEB).matches
    assert (only.verdict, only.confidence) == ("possible", "backport_possible")
    assert only.evidence["advisory"]["reason"] == "revision_not_disclosed"
    assert "distro_revision" not in only.evidence


@pytest.mark.parametrize(
    ("product", "version", "banner"),
    [
        # Pulse names the server by its Server rule and writes the server's
        # version; the PHP behind it is only in X-Powered-By.
        ("H2O", "2.2.6", "HTTP/1.1 200 OK | Server: h2o/2.2.6 | X-Powered-By: PHP/8.1.30"),
        (
            "OpenLiteSpeed",
            "1.7.19",
            "HTTP/1.1 200 OK | Server: OpenLiteSpeed/1.7.19 | X-Powered-By: PHP/8.1.30 | Content-Type: text/html",
        ),
    ],
)
def test_a_product_named_by_its_banner_takes_the_version_from_its_banner(product, version, banner) -> None:
    """Identified by ``X-Powered-By: PHP/8.1.30``, the listener's PHP is 8.1.30
    — not the web server's version in the ``version`` field, which made a
    patched PHP 8.1.30 "PHP 2.2.6" with CVE-2012-1823."""
    dataset = _one(
        "a:php:php",
        CpeRange("CVE-2012-1823", end_excluding="5.3.12"),
        CpeRange("CVE-2024-4577", start_including="8.1.0", end_excluding="8.1.29"),
    )
    outcome = rm.match(
        rm.Fingerprint(product=product, version=version, banner=banner, service="http"),
        dataset,
        lookup=lambda _d: None,
    )
    assert outcome.upstream_version == "8.1.30"
    assert outcome.matches == ()


def test_a_product_named_by_its_banner_takes_no_revision_from_the_version_field() -> None:
    """The version field is the named server's, revision and all."""
    outcome = rm.match(
        rm.Fingerprint(
            product="Cherokee Web Server",
            version="1.2.104-1ubuntu1",
            banner="HTTP/1.1 200 OK | Server: Cherokee/1.2.104 (Ubuntu) | X-Powered-By: PHP/7.4.3-4ubuntu2.19",
            service="http",
        ),
        FOCAL_WEB_RANGES,
        lookup=lambda _d: FOCAL_WEB,
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("fixed", "vendor_advisory")
    assert only.evidence["advisory"]["installed_version"] == "7.4.3-4ubuntu2.19"


def test_another_products_header_says_nothing_about_the_listeners_distribution() -> None:
    """``X-Powered-By`` is the application's, not the server's: a Debian PHP
    behind an Apache that names no distribution does not make the Apache a
    Debian build (its hit stays a range finding with no host hint)."""
    fingerprint = rm.Fingerprint(
        product="Apache httpd",
        version="2.4.41",
        banner="HTTP/1.1 200 OK | Server: Apache/2.4.41 | X-Powered-By: PHP/7.3.31-1~deb10u5",
    )
    assert rm.own_hint(fingerprint, ("a:apache:http_server",), None) == rm.DistroHint()
    (only,) = rm.match(fingerprint, FOCAL_WEB_RANGES, lookup=lambda _d: FOCAL_WEB).matches
    assert (only.verdict, only.confidence) == ("vulnerable", "version_range")
    # PHP's own reading of the same banner keeps both.
    assert rm.own_hint(fingerprint, ("a:php:php",), None) == rm.DistroHint("debian", "buster", "1~deb10u5")


def test_a_revision_comes_only_from_the_products_own_token() -> None:
    """Any line that is not the product's own carries someone else's package
    revision, whatever header it rides in."""
    fingerprint = rm.Fingerprint(
        product="Apache httpd",
        version="2.4.41",
        banner="HTTP/1.1 200 OK | Server: Apache/2.4.41 (Ubuntu) | X-Backend: php7.4-fpm/7.4.3-4ubuntu2.19",
    )
    assert rm.own_hint(fingerprint, ("a:apache:http_server",), None) == rm.DistroHint("ubuntu")


def test_nmaps_php_cpe_carries_the_revision_to_the_backport_check() -> None:
    """nmap's ``X-Powered-By: PHP/(\\d[\\w._-]+)`` softmatch writes the whole
    string into the CPE: compared as written, 7.4.3-4ubuntu2.19 is not 7.4.3."""
    fingerprint = rm.Fingerprint(
        banner="PHP 7.4.3-4ubuntu2.19", cpe=("cpe:/a:php:php:7.4.3-4ubuntu2.19",), service="http"
    )
    outcome = rm.match(fingerprint, FOCAL_WEB_RANGES, lookup=lambda _d: FOCAL_WEB)
    (only,) = outcome.matches
    assert outcome.upstream_version == "7.4.3"
    assert (only.verdict, only.confidence) == ("fixed", "vendor_advisory")
    assert only.evidence["advisory"]["installed_version"] == "7.4.3-4ubuntu2.19"


def test_php_with_ubuntus_revision_is_decided_by_the_release_that_ships_it() -> None:
    """``X-Powered-By: PHP/7.4.3-4ubuntu2.19``: focal's ``php7.4`` is the one
    release whose fixes are built on 7.4.3."""
    provider = _Provider([
        _advisory("CVE-2022-31625", release="focal", package="php7.4", fixed="7.4.3-4ubuntu2.12"),
        _advisory("CVE-2024-2756", release="focal", package="php7.4", fixed="7.4.3-4ubuntu2.22"),
        _advisory("CVE-2022-31625", release="jammy", package="php8.1", fixed="8.1.2-1ubuntu2.2"),
    ])
    dataset = cpe_ranges.CpeRangeDataset(
        marker="t",
        index={
            "a:php:php": (
                CpeRange("CVE-2022-31625", start_including="7.4.0", end_excluding="7.4.30"),
                CpeRange("CVE-2024-2756", start_including="7.4.0", end_excluding="8.1.28"),
            )
        },
        cves={
            "CVE-2022-31625": {"severity": "critical", "cvss": 9.8},
            "CVE-2024-2756": {"severity": "medium", "cvss": 6.5},
        },
        present=True,
    )
    outcome = rm.match(
        rm.Fingerprint(
            product="PHP",
            version="7.4.3",
            banner="HTTP/1.1 200 OK | X-Powered-By: PHP/7.4.3-4ubuntu2.19 | Content-Type: text/html; charset=UTF-8",
        ),
        dataset,
        lookup=lambda _d: provider,
    )
    verdicts = {m.cve: (m.verdict, m.confidence, m.evidence["advisory"].get("release")) for m in outcome.matches}
    assert verdicts == {
        "CVE-2022-31625": ("fixed", "vendor_advisory", "focal"),
        "CVE-2024-2756": ("vulnerable", "vendor_advisory", "focal"),
    }


def test_sendmails_debian_banner_is_decided_by_debian() -> None:
    provider = _Provider([
        _advisory("CVE-2023-51765", release="bookworm", package="sendmail", fixed="8.17.1.9-2+deb12u2"),
    ])
    outcome = rm.match(
        rm.Fingerprint(
            product="Sendmail",
            version="8.17.1.9/8.17.1.9/Debian-2+deb12u1",
            cpe=("cpe:/a:sendmail:sendmail:8.17.1.9/8.17.1.9/Debian-2+deb12u1",),
        ),
        _one("a:sendmail:sendmail", CpeRange("CVE-2023-51765", end_excluding="8.18.0.2")),
        lookup=lambda _d: provider,
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("vulnerable", "vendor_advisory")
    assert only.evidence["advisory"]["installed_version"] == "8.17.1.9-2+deb12u1"


def test_squid_on_a_known_ubuntu_host_asks_ubuntus_squid() -> None:
    """focal builds 4.10 from ``squid``; the listener does not say which
    revision — the backport question, asked of the right package."""
    provider = _Provider([
        _advisory("CVE-2023-46846", release="focal", package="squid", fixed="4.10-1ubuntu1.9"),
    ])
    outcome = rm.match(
        rm.Fingerprint(product="squid", version="4.10", banner="HTTP/1.1 400 Bad Request | Server: squid/4.10"),
        _one("a:squid-cache:squid", CpeRange("CVE-2023-46846", start_including="2.6", end_excluding="6.4")),
        lookup=lambda _d: provider,
        host=rm.DistroHint("ubuntu", "focal"),
    )
    (only,) = outcome.matches
    assert (only.verdict, only.confidence) == ("possible", "backport_possible")
    assert only.evidence["advisory"]["reason"] == "revision_not_disclosed"
    assert only.evidence["advisory"]["advisory_id"] == "ADV-1"


_FROB = "a:frob:frobnicator"


@pytest.mark.parametrize(
    "change",
    [
        lambda mp: mp.setitem(rm.PRODUCT_TABLE, "frobnicator httpd", (_FROB,)),
        lambda mp: mp.setitem(rm._PRODUCT_SERVICES, "frobnicator httpd", frozenset({"frob"})),
        lambda mp: mp.setitem(rm.CPE_ALIASES, "a:frob:frob", (_FROB,)),
        lambda mp: mp.setitem(rm.SOURCE_PACKAGES, _FROB, ("frobnicator",)),
        lambda mp: mp.setitem(rm.SERIES_SOURCE_PACKAGES, _FROB, "frob-{major}.{minor}"),
        lambda mp: mp.setitem(rm.SHARED_SOURCE_PACKAGES, _FROB, "frob"),
        lambda mp: mp.setattr(rm, "DISTRO_PACKAGED", rm.DISTRO_PACKAGED | {_FROB}),
        lambda mp: mp.setitem(rm._BANNER_NAMES, _FROB, ("frobnicator",)),
        lambda mp: mp.setitem(rm._VERSION_SHAPES, _FROB, re.compile(r"(\d+\.\d+)")),
        lambda mp: mp.setattr(rm, "_FIRST_NUMBER_VERSIONS", rm._FIRST_NUMBER_VERSIONS | {_FROB}),
        lambda mp: mp.setattr(rm, "_NOT_MATCHED_CPE", rm._NOT_MATCHED_CPE | {_FROB}),
        lambda mp: mp.setitem(rm._LOOKALIKES, _FROB, re.compile("frobfork")),
        lambda mp: mp.setattr(rm, "_MYSQL_OWN_SUFFIXES", rm._MYSQL_OWN_SUFFIXES | {"frob"}),
        lambda mp: mp.setattr(rm, "MATCHER_REVISION", rm.MATCHER_REVISION + 1),
    ],
    ids=[
        "products", "product_services", "aliases", "sources", "series_sources", "shared_sources",
        "distro_packaged", "banner_names", "shapes", "first_number", "not_matched_cpe", "lookalikes",
        "mysql_own_suffixes",
        "revision",
    ],
)
def test_the_rules_version_follows_every_table(monkeypatch, change) -> None:
    """Part of the worker's marker: a release that changes what decides a
    verdict must re-ask about listeners already matched against an unchanged
    dataset — once, so the digest is stable while nothing changes."""
    first = rm.rules_version()
    assert first == rm.rules_version()
    change(monkeypatch)
    assert rm.rules_version() != first
