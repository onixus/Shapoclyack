"""The retro matcher's pure half: versions, products, distributions, verdicts.

Every table here is made of strings real probers emit — nmap ``product`` /
``version`` / ``extrainfo`` and raw banners — because the matcher is only as
good as its reading of those, and a synthetic ``1.2.3`` proves nothing about
``8.2p1 Ubuntu 4ubuntu0.5``. The database side is ``test_retro_findings.py``.
"""

from __future__ import annotations

import json
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
    assert rm.upstream_version(fingerprint, found, cpe_version) == version


@pytest.mark.parametrize(
    "fingerprint",
    [
        # Unknown products are not guessed at.
        rm.Fingerprint(product="Jetty", version="9.4.44"),
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
    assert rm.match(rm.Fingerprint(product="Jetty", version="9"), seed, lookup=advisories.get_provider).reason == "unknown_product"
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
