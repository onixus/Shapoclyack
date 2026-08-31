"""dpkg/rpm EVR comparison against the canonical upstream test tables.

The matcher's whole claim to being better than naive NVD range matching rests
on these two functions being right, so the cases below are lifted from the
suites the package managers themselves ship (dpkg ``t-version``, rpm
``rpmvercmp.at``) rather than invented here, plus the backport shapes that
motivated the feature (``1.1.1f-1ubuntu2.16``, ``1:9.16.1-0ubuntu2.15``).
"""

from __future__ import annotations

import pytest

from api.services import version_compare as vc

# --------------------------------------------------------------------------
# dpkg — (left, right, expected sign)
# --------------------------------------------------------------------------
DPKG_CASES: list[tuple[str, str, int]] = [
    # Equality, including the implicit epoch and the implicit empty revision.
    ("1.0", "1.0", 0),
    ("0:1.0", "1.0", 0),
    ("1.0-1", "1.0-1", 0),
    # dpkg strips leading zeros in every numeric run, revision included, so an
    # explicit "-0" revision is the same version as none at all.
    ("1.0-0", "1.0", 0),
    # Epoch dominates everything after it.
    ("1:0.1", "2.0", 1),
    ("0:1.0", "1:0.1", -1),
    ("2:1.0-1", "10:0.1-1", -1),
    # Plain numeric ordering, with leading zeros ignored.
    ("1.0", "1.1", -1),
    ("1.2", "1.10", -1),
    ("1.010", "1.10", 0),
    ("0.0.0", "0.0", 1),
    ("1.0.0", "1.0", 1),
    # Letters sort before every other non-digit character…
    ("1.0a", "1.0", 1),
    ("1.0a", "1.0b", -1),
    ("1.0+", "1.0a", 1),
    ("1.0~", "1.0", -1),
    # …and ``~`` sorts before the empty string, which is the whole point of it.
    ("1.0~rc1", "1.0", -1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~~", "1.0~", -1),
    ("1.0~~a", "1.0~", -1),
    ("1.0~beta1~svn1245", "1.0~beta1", -1),
    ("1.0~beta1", "1.0", -1),
    ("7.6p2-4", "7.6-0", 1),
    # Revision compared only when the upstream part ties, and with the same
    # rules — this is where a backport lives.
    ("1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.15", 1),
    ("1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.16", 0),
    ("1.1.1f-1ubuntu2.9", "1.1.1f-1ubuntu2.16", -1),
    ("1.1.1f-1ubuntu2", "1.1.1f-1ubuntu2.1", -1),
    ("1:9.16.1-0ubuntu2.15", "1:9.16.1-0ubuntu2.11", 1),
    ("2.4.41-4ubuntu3.14", "2.4.41-4ubuntu3.20", -1),
    ("1.14.2-1ubuntu1.4+esm1", "1.14.2-1ubuntu1.4", 1),
    ("5.4.0-150.167", "5.4.0-99.112", 1),
    # An upstream version may itself contain hyphens: the revision is the part
    # after the *last* one.
    ("1.2-beta-3-1", "1.2-beta-3-2", -1),
    ("1.2-beta-3-1", "1.2-beta-4-1", -1),
    # Debian point releases.
    ("1.1.1n-0+deb11u3", "1.1.1n-0+deb11u4", -1),
    ("1.1.1n-0+deb11u5", "1.1.1n-0+deb11u4", 1),
    ("3.0.11-1~deb12u2", "3.0.11-1", -1),
    ("2.36-9+deb12u7", "2.36-9+deb12u10", -1),
]

# --------------------------------------------------------------------------
# rpm — (left, right, expected sign)
# --------------------------------------------------------------------------
RPM_CASES: list[tuple[str, str, int]] = [
    # rpmvercmp.at, verbatim where it applies to whole EVRs.
    ("1.0", "1.0", 0),
    ("1.0", "2.0", -1),
    ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0),
    ("2.0", "2.0.1", -1),
    ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0),
    ("2.0.1a", "2.0.1", 1),
    ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0),
    ("5.5p1", "5.5p2", -1),
    ("5.5p10", "5.5p10", 0),
    ("5.5p1", "5.5p10", -1),
    ("10xyz", "10.1xyz", -1),
    ("xyz10", "xyz10", 0),
    ("xyz10", "xyz10.1", -1),
    ("xyz.4", "xyz.4", 0),
    ("xyz.4", "8", -1),
    ("xyz.4", "2", -1),
    ("20101121", "20101121", 0),
    ("20101121", "20101122", -1),
    ("20101121", "20101112", 1),
    ("2_0", "2_0", 0),
    ("2.0", "2_0", 0),
    ("2_0", "2.0", 0),
    # Separators are insignificant, letters vs digits are not.
    ("a", "a", 0),
    ("a+", "a+", 0),
    ("a+", "a_", 0),
    ("a_", "a+", 0),
    ("+a", "+a", 0),
    ("+a", "_a", 0),
    ("+_", "_+", 0),
    ("_+", "+_", 0),
    ("+", "_", 0),
    ("_", "+", 0),
    # Tilde: strictly older than the version it decorates.
    ("1.0~rc1", "1.0~rc1", 0),
    ("1.0~rc1", "1.0", -1),
    ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0),
    ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0~rc1", "1.0~rc1~git123", 1),
    # Caret: newer than the bare base version, older than the next one.
    ("1.0^", "1.0^", 0),
    ("1.0^", "1.0", 1),
    ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0),
    ("1.0^git1", "1.0", 1),
    ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1),
    ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1),
    ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0),
    ("1.0^20160101", "1.0.1", -1),
    ("1.0.1", "1.0^20160101", 1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    # Tilde and caret together.
    ("1.0~rc1^git1", "1.0~rc1^git1", 0),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0),
    ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
    # Epoch:version-release, the form advisories actually publish.
    ("1:1.0-1", "1.0-1", 1),
    ("0:1.0-1", "1.0-1", 0),
    ("1:1.0-1", "2:0.9-1", -1),
    ("1.1.1k-12.el8_9", "1.1.1k-9.el8_7", 1),
    ("1.1.1k-9.el8_7", "1.1.1k-12.el8_9", -1),
    ("1:1.1.1k-12.el8_9", "1:1.1.1k-12.el8_9", 0),
    ("2.34-100.el9_4", "2.34-60.el9", 1),
    ("4.18.0-513.24.1.el8_9", "4.18.0-513.5.1.el8_9", 1),
    ("32:9.16.23-11.el9_4", "32:9.16.23-0.7.el9", 1),
]


@pytest.mark.parametrize(("left", "right", "expected"), DPKG_CASES)
def test_dpkg_comparison(left: str, right: str, expected: int) -> None:
    assert vc.compare_dpkg_version(left, right) == expected
    # Antisymmetry is a property of the algorithm, not of the table: an
    # implementation that only ever answered "greater" would pass every
    # forward case above.
    assert vc.compare_dpkg_version(right, left) == -expected


@pytest.mark.parametrize(("left", "right", "expected"), RPM_CASES)
def test_rpm_comparison(left: str, right: str, expected: int) -> None:
    assert vc.compare_rpm_version(left, right) == expected
    assert vc.compare_rpm_version(right, left) == -expected


def test_compare_dispatches_on_flavor() -> None:
    assert vc.compare("1.0-1", "1.0-2", flavor=vc.DEB) == -1
    assert vc.compare("1.0-1", "1.0-2", flavor=vc.RPM) == -1
    with pytest.raises(vc.VersionParseError):
        vc.compare("1.0", "1.0", flavor="pkgsrc")


def test_is_fixed_is_inclusive_of_the_fixed_version() -> None:
    # The version an advisory names as fixed is fixed, not "still below".
    assert vc.is_fixed("1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.16", flavor=vc.DEB)
    assert vc.is_fixed("1.1.1f-1ubuntu2.17", "1.1.1f-1ubuntu2.16", flavor=vc.DEB)
    assert not vc.is_fixed("1.1.1f-1ubuntu2.15", "1.1.1f-1ubuntu2.16", flavor=vc.DEB)


def test_backported_fix_is_not_reported_as_vulnerable() -> None:
    """The false-positive storm this whole feature exists to avoid.

    Upstream 1.1.1f is affected by CVE-2021-3711 and stays "1.1.1f" forever on
    focal; the fix arrives in the Ubuntu revision. A matcher comparing upstream
    versions calls this host vulnerable for the life of the release.
    """
    assert vc.is_fixed("1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.8", flavor=vc.DEB)


@pytest.mark.parametrize(
    ("raw", "epoch", "version", "release"),
    [
        ("1.2.3", 0, "1.2.3", ""),
        ("1.2.3-4", 0, "1.2.3", "4"),
        ("2:1.2.3-4", 2, "1.2.3", "4"),
        ("1.2-beta-3-1", 0, "1.2-beta-3", "1"),
        ("  1.2.3-4  ", 0, "1.2.3", "4"),
        # A colon whose prefix is not a number is part of the version, not an
        # epoch separator.
        ("weird:1.2-3", 0, "weird:1.2", "3"),
    ],
)
def test_parse_evr(raw: str, epoch: int, version: str, release: str) -> None:
    parsed = vc.parse_evr(raw, flavor=vc.DEB)
    assert (parsed.epoch, parsed.version, parsed.release) == (epoch, version, release)


def test_parse_evr_roundtrips_through_str() -> None:
    assert str(vc.parse_evr("2:1.2.3-4", flavor=vc.DEB)) == "2:1.2.3-4"
    assert str(vc.parse_evr("1.2.3", flavor=vc.DEB)) == "1.2.3"


@pytest.mark.parametrize("raw", ["", "   ", "1:", "-1"])
def test_parse_evr_rejects_malformed_versions(raw: str) -> None:
    with pytest.raises(vc.VersionParseError):
        vc.parse_evr(raw, flavor=vc.DEB)


def test_parse_evr_rejects_unknown_flavor() -> None:
    with pytest.raises(vc.VersionParseError):
        vc.parse_evr("1.0", flavor="ports")


def test_comparison_is_transitive_over_a_known_ordering() -> None:
    """A total order, checked as one: pairwise cases can be individually right
    and still not compose."""
    ordered = [
        "1.0~~",
        "1.0~~a",
        "1.0~",
        "1.0",
        "1.0-1",
        "1.0-1.1",
        "1.0-2",
        "1.0a-1",
        "1.1",
        "2.0",
        "1:0.1",
        "2:0.1",
    ]
    for i, low in enumerate(ordered):
        for high in ordered[i + 1 :]:
            assert vc.compare_dpkg_version(low, high) == -1, f"{low} should sort below {high}"
