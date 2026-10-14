"""Pulse ``tls[]`` suite enumeration (expected GenDec#34) and the probe top-up.

The enumeration form is a PROPOSAL (onixus/GenDec#34); Pulse v1.3.0 emits none.
The fixtures here are synthetic, built from the Nmap output recorded in
``tests/fixtures/nmap_pulse_corpus``, so that the Pulse path can be held to what
the nmap path says about the very same endpoints.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from scanner.pipeline.config_schema import TlsPostureConfig
from scanner.pipeline.tls_grading import normalize_suite_name
from scanner.pipeline.tls_posture import check_tls_posture, findings_from_pulse_tls
from tests.tls_corpus_helpers import CORPUS, nmap_enum_points, synthetic_gendec34_row

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)
CIPHER_KINDS = {"weak_protocol", "weak_cipher_grade", "weak_cipher_name"}


def _cipher_signature(issues: list[dict[str, Any]]) -> set[tuple]:
    return {
        (i["kind"], i.get("version"), i.get("grade"), i.get("cipher"))
        for i in issues
        if i["kind"] in CIPHER_KINDS
    }


def _from_pulse(row: dict[str, Any]) -> dict[str, Any]:
    out = findings_from_pulse_tls({"tls": [row]}, now=NOW, expiring_soon_days=30, max_targets=10)
    assert len(out) == 1
    return out[0]


def _row(enumeration: Any, **extra: Any) -> dict[str, Any]:
    return {"ip": "10.0.0.9", "host": "10.0.0.9", "port": 443, "negotiated_protocol": "TLSv1_2",
            "enumeration": enumeration, **extra}


# --- same answers as the nmap path, on the same endpoints --------------------


def test_synthetic_gendec_rows_match_the_nmap_path_endpoint_by_endpoint(tmp_path: Path):
    nmap_result = check_tls_posture(CORPUS / "nmap", TlsPostureConfig(enabled=True), tmp_path, now=NOW)
    assert nmap_result["source"] == "nmap-nse"
    by_nmap = {(f["host"], f["port"]): _cipher_signature(f["issues"]) for f in nmap_result["findings"]}
    points = nmap_enum_points()
    assert set(points) <= set(by_nmap) and len(points) == 4

    rows = [synthetic_gendec34_row(ip, port, versions) for (ip, port), versions in points.items()]
    pulse_rows = findings_from_pulse_tls({"tls": rows}, now=NOW, expiring_soon_days=30, max_targets=10)
    by_pulse = {(f["host"], f["port"]): _cipher_signature(f["issues"]) for f in pulse_rows}

    assert set(by_pulse) == set(points)
    for key in points:
        assert by_pulse[key] == by_nmap[key], key
    # the comparison is not vacuous: the legacy nginx point carries every kind
    legacy = next(k for k, v in points.items() if len(v) == 3)
    kinds = {sig[0] for sig in by_pulse[legacy]}
    assert kinds == CIPHER_KINDS
    assert {sig[1] for sig in by_pulse[legacy] if sig[0] == "weak_protocol"} == {"TLSv1.0", "TLSv1.1"}
    assert ("weak_cipher_grade", "TLSv1.2", "F", None) in by_pulse[legacy]
    # clean endpoints stay clean
    assert all(not by_pulse[k] for k in points if k != legacy)


def test_cipher_versions_have_the_nmap_shape_and_complete_means_no_confirmation(tmp_path: Path):
    points = nmap_enum_points()
    (ip, port), versions = next((k, v) for k, v in points.items() if len(v) == 3)
    nmap_result = check_tls_posture(CORPUS / "nmap", TlsPostureConfig(enabled=True), tmp_path, now=NOW)
    nmap_f = next(f for f in nmap_result["findings"] if (f["host"], f["port"]) == (ip, port))

    row = _from_pulse(synthetic_gendec34_row(ip, port, versions))
    assert row["source"] == "pulse-tls"
    assert row["enumeration_complete"] is True
    assert [v["version"] for v in row["cipher_versions"]] == [v["version"] for v in nmap_f["cipher_versions"]]
    for ours, theirs in zip(row["cipher_versions"], nmap_f["cipher_versions"]):
        assert {c["name"]: c["grade"] for c in ours["ciphers"]} == {
            normalize_suite_name(c["name"]): c["grade"] for c in theirs["ciphers"]
        }
        assert ours["least_strength"] == theirs["least_strength"]
        assert set(ours) - {"server_preference"} == {"version", "ciphers", "least_strength"}
        assert all(set(c) == {"name", "grade"} for c in ours["ciphers"])
    assert not any(i.get("requires_confirmation") for i in row["issues"] if i["kind"] in CIPHER_KINDS)
    assert all(v["server_preference"] is True for v in row["cipher_versions"])


def test_tls13_names_are_iana_names_after_reading_nmap_spelling():
    points = nmap_enum_points()
    versions = next(v for v in points.values() if any(x["version"] == "TLSv1.3" for x in v))
    ip_port = next(k for k, v in points.items() if v is versions)
    row = _from_pulse(synthetic_gendec34_row(*ip_port, versions))
    v13 = next(v for v in row["cipher_versions"] if v["version"] == "TLSv1.3")
    assert all(not c["name"].startswith("TLS_AKE_WITH_") for c in v13["ciphers"])
    assert "TLS_AES_128_GCM_SHA256" in {c["name"] for c in v13["ciphers"]}


# --- tolerant reading --------------------------------------------------------


@pytest.mark.parametrize(
    "label", ["TLSv1_0", "TLSv1.0", "TLS 1.0", "tls1.0", "TLS1.0", "TLSv1", "0x0301", 769, "0X0301"]
)
def test_version_spellings_all_mean_tls10(label):
    row = _from_pulse(_row({"complete": True, "versions": [{"version": label, "accepted": True}]}))
    assert [(i["kind"], i["version"]) for i in row["issues"] if i["kind"] == "weak_protocol"] == [
        ("weak_protocol", "TLSv1.0")
    ]


@pytest.mark.parametrize(
    ("label", "canon"),
    [("SSLv2", "SSLv2"), ("SSL 3.0", "SSLv3"), ("sslv3", "SSLv3"), (771, "TLSv1.2"), ("0x0304", "TLSv1.3"),
     ("TLS 1.1", "TLSv1.1"), ("TLSv1_3", "TLSv1.3")],
)
def test_normalize_version(label, canon):
    from scanner.pipeline.tls_enumeration import normalize_version

    assert normalize_version(label) == canon


@pytest.mark.parametrize("label", [None, True, "", "TLS 9", "SSLv4", "DTLS1.2", 12345, 3.5, [], {}, "x"])
def test_unreadable_versions_are_none(label):
    from scanner.pipeline.tls_enumeration import normalize_version

    assert normalize_version(label) is None


@pytest.mark.parametrize(
    "suite",
    [
        {"code": "0x0005"},
        {"code": 5},
        {"code": "0x00,0x05"},
        {"code": "0x0005", "name": "RC4-SHA"},  # not an IANA name: the code names it
        "0x0005",
        "TLS_RSA_WITH_RC4_128_SHA",
        {"name": "TLS_RSA_WITH_RC4_128_SHA", "code": "garbage"},
    ],
)
def test_suite_named_by_code_or_by_name_gives_the_same_findings(suite):
    row = _from_pulse(_row({"complete": True, "versions": [{"version": "TLSv1.2", "ciphers": [suite]}]}))
    assert row["cipher_versions"][0]["ciphers"] == [
        {"name": "TLS_RSA_WITH_RC4_128_SHA", "grade": "C", "grade_upper_bound": True}
    ]
    sig = _cipher_signature(row["issues"])
    assert ("weak_cipher_grade", "TLSv1.2", "C", None) in sig
    assert ("weak_cipher_name", "TLSv1.2", None, "TLS_RSA_WITH_RC4_128_SHA") in sig


def test_unknown_suite_is_kept_with_no_grade_and_makes_no_grade_finding():
    row = _from_pulse(
        _row({"complete": True, "versions": [{"version": "TLSv1.2", "ciphers": [
            {"name": "TLS_SOMETHING_NEW_WITH_FOO_BAR"}, {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}]}]})
    )
    v = row["cipher_versions"][0]
    assert {c["name"]: c["grade"] for c in v["ciphers"]} == {
        "TLS_SOMETHING_NEW_WITH_FOO_BAR": None, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "A"}
    assert v["least_strength"] == "A"  # unknown is not "worst"
    assert not _cipher_signature(row["issues"])


def test_kex_detail_changes_the_grade():
    def grade(**kex):
        row = _from_pulse(_row({"complete": True, "versions": [{"version": "TLSv1.2", "ciphers": [
            {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", **kex}]}]}))
        return row["cipher_versions"][0]["ciphers"][0]["grade"]

    assert grade(kex_bits=2048) == "A"
    assert grade(kex_bits=512) == "D"
    assert grade() == "B"


@pytest.mark.parametrize(
    "garbage",
    [
        None, 5, "x", [], {}, {"versions": None}, {"versions": "TLSv1.2"}, {"versions": [None, 3, "a", []]},
        {"complete": True, "versions": [{"version": {}, "ciphers": 7}]},
        {"complete": True, "versions": [{"version": "TLSv1.2", "ciphers": [None, 1.5, [], {}, {"code": {}},
                                                                             {"code": -1}, {"code": 70000},
                                                                             {"code": True}, "", "  "]}]},
        {"complete": "yes", "versions": [{"version": "TLSv1.2", "accepted": "maybe", "ciphers": "TLS_X"}]},
    ],
)
def test_garbage_enumeration_never_raises_and_changes_nothing(garbage):
    base = _from_pulse(_row(None, accepts_weak_protocols=["TLSv1.0"]))
    base.pop("cipher_versions")
    got = _from_pulse(_row(garbage, accepts_weak_protocols=["TLSv1.0"]))
    got.pop("cipher_versions")
    assert got == base


def test_enumeration_missing_the_enumeration_key_is_todays_behaviour():
    row = _from_pulse({"ip": "10.0.0.9", "port": 443, "negotiated_protocol": "TLSv1_3"})
    assert row["cipher_versions"] == [{"version": "TLSv1.3", "ciphers": [], "least_strength": None}]
    assert "enumeration_complete" not in row


# --- incomplete enumeration needs confirming ---------------------------------

_WEAK_ENUM = [
    {"version": "TLSv1.0", "accepted": True, "ciphers": [{"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kex_bits": 2048}]},
]


@pytest.mark.parametrize("complete", [False, None, "true", 1, "absent"])
def test_not_complete_marks_every_enumeration_finding_requires_confirmation(complete):
    block: dict[str, Any] = {"versions": _WEAK_ENUM}
    if complete != "absent":
        block["complete"] = complete
    row = _from_pulse(_row(block))
    found = [i for i in row["issues"] if i["kind"] in CIPHER_KINDS]
    assert {i["kind"] for i in found} == CIPHER_KINDS
    assert all(i["requires_confirmation"] is True for i in found)
    assert row["enumeration_complete"] is False


def test_complete_true_findings_are_firm():
    row = _from_pulse(_row({"complete": True, "versions": _WEAK_ENUM}))
    found = [i for i in row["issues"] if i["kind"] in CIPHER_KINDS]
    assert found and not any("requires_confirmation" in i for i in found)


def test_a_suite_missing_from_an_incomplete_list_is_not_read_as_not_accepted():
    # the legacy probe said TLS 1.0 is accepted; a partial list that never reached
    # TLS 1.0 must not erase that.
    row = _from_pulse(
        _row({"complete": False, "versions": [{"version": "TLSv1.2", "ciphers": [
            {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}]}]}, accepts_weak_protocols=["TLSv1.0"])
    )
    weak = [i for i in row["issues"] if i["kind"] == "weak_protocol"]
    assert [(i["version"], i["requires_confirmation"]) for i in weak] == [("TLSv1.0", True)]


def test_accepted_false_creates_no_finding_and_drops_nothing_else():
    row = _from_pulse(_row({"complete": True, "versions": [
        {"version": "SSLv3", "accepted": False},
        {"version": "TLSv1.2", "accepted": True, "ciphers": [{"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}]}]}))
    assert not _cipher_signature(row["issues"])
    assert [v["version"] for v in row["cipher_versions"]] == ["TLSv1.2"]


def test_weak_version_is_reported_once_when_enumeration_and_legacy_probe_agree():
    row = _from_pulse(_row({"complete": True, "versions": [{"version": "TLS 1.0", "accepted": True}]},
                           accepts_weak_protocols=["TLSv1.0", "TLSv1.1"], negotiated_protocol="TLSv1_0"))
    weak = sorted(i["version"] for i in row["issues"] if i["kind"] == "weak_protocol")
    assert weak == ["TLSv1.0", "TLSv1.1"]


# --- no enumeration: the real Pulse artifact behaves as before ---------------


def test_real_corpus_pulse_artifact_has_no_invented_grades():
    artifact = json.loads((CORPUS / "pulse" / "tcp.json").read_text(encoding="utf-8"))
    rows = findings_from_pulse_tls(artifact, now=NOW, expiring_soon_days=30, max_targets=100)
    assert len(rows) == 3
    for r in rows:
        assert "enumeration_complete" not in r
        assert all(v["ciphers"] == [] and v["least_strength"] is None for v in r["cipher_versions"])
        assert not any(i["kind"] in {"weak_cipher_grade", "weak_cipher_name"} for i in r["issues"])
    legacy = next(r for r in rows if r["accepts_weak_protocols"])
    assert sorted((i["kind"], i["version"], i.get("requires_confirmation")) for i in legacy["issues"]
                  if i["kind"] == "weak_protocol") == [
        ("weak_protocol", "TLSv1.0", True), ("weak_protocol", "TLSv1.1", True)]
    assert legacy["cipher_versions"] == [{"version": "TLSv1.2", "ciphers": [], "least_strength": None}]


# --- the top-up: ports Pulse did not probe -----------------------------------


def _write_pulse_tls(tmp_path: Path, rows: list[dict[str, Any]]) -> Path:
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    (tmp_path / "pulse").mkdir()
    (tmp_path / "pulse" / "tls.json").write_text(json.dumps({"tls": rows}), encoding="utf-8")
    return nmap_dir


def _fake_probe(calls: list[list[str]]):
    def fake(open_ports, **kwargs):
        calls.append(list(open_ports))
        rows = []
        for entry in open_ports:
            host, _, port = entry.partition("/")[0].rpartition(":")
            rows.append({"host": host, "port": port, "cert": None, "cipher_versions": [], "issues": [],
                         "source": "pulse-tls-probe"})
        return rows

    return fake


def test_probe_tops_up_open_tls_ports_pulse_has_no_row_for(tmp_path: Path):
    nmap_dir = _write_pulse_tls(tmp_path, [{"ip": "10.0.0.1", "port": 443, "self_signed": False}])
    calls: list[list[str]] = []
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints", side_effect=_fake_probe(calls)) as probe:
        result = check_tls_posture(nmap_dir, cfg, tmp_path, now=NOW,
                                   open_ports=["10.0.0.1:443/tcp", "10.0.0.1:9443/tcp", "10.0.0.1:22/tcp",
                                               "10.0.0.2:4443/tcp", "10.0.0.2:53/udp"])
    probe.assert_called_once()
    assert calls == [["10.0.0.1:9443", "10.0.0.2:4443"]]  # 443 is Pulse's, 22 is not a TLS port
    assert result["source"] == "pulse-tls"
    assert [(f["host"], f["port"], f["source"]) for f in result["findings"]] == [
        ("10.0.0.1", "443", "pulse-tls"), ("10.0.0.1", "9443", "pulse-tls-probe"),
        ("10.0.0.2", "4443", "pulse-tls-probe")]
    assert result["checked_count"] == 3
    assert result["targets_considered"] == 3
    assert result["truncated"] is False
    assert json.loads((tmp_path / "tls_probe.json").read_text())["checked_count"] == 2
    assert json.loads((tmp_path / "tls_posture.json").read_text())["checked_count"] == 3


def test_top_up_is_off_without_probe_fallback_or_open_ports(tmp_path: Path):
    nmap_dir = _write_pulse_tls(tmp_path, [{"ip": "10.0.0.1", "port": 443}])
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints") as probe:
        off = check_tls_posture(nmap_dir, TlsPostureConfig(enabled=True, probe_fallback=False), tmp_path,
                                now=NOW, open_ports=["10.0.0.1:9443/tcp"])
        none = check_tls_posture(nmap_dir, TlsPostureConfig(enabled=True, probe_fallback=True), tmp_path,
                                 now=NOW, open_ports=None)
    probe.assert_not_called()
    assert off["checked_count"] == none["checked_count"] == 1


def test_top_up_respects_max_targets_across_both_sources(tmp_path: Path):
    nmap_dir = _write_pulse_tls(tmp_path, [{"ip": "10.0.0.1", "port": 443}])
    calls: list[list[str]] = []
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True, max_targets=3)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints", side_effect=_fake_probe(calls)):
        result = check_tls_posture(nmap_dir, cfg, tmp_path, now=NOW,
                                   open_ports=[f"10.0.0.{n}:9443/tcp" for n in range(1, 6)])
    assert calls == [["10.0.0.1:9443", "10.0.0.2:9443"]]  # 3 - 1 Pulse row
    assert result["checked_count"] == 3
    assert result["targets_considered"] == 3
    assert result["truncated"] is True


def test_full_pulse_cap_leaves_no_budget_for_the_probe(tmp_path: Path):
    nmap_dir = _write_pulse_tls(tmp_path, [{"ip": "10.0.0.1", "port": 443}])
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True, max_targets=1)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints") as probe:
        result = check_tls_posture(nmap_dir, cfg, tmp_path, now=NOW, open_ports=["10.0.0.1:9443/tcp"])
    probe.assert_not_called()
    assert result["checked_count"] == 1
    assert result["truncated"] is True


def test_corpus_style_gap_is_the_9443_listener(tmp_path: Path):
    """Pulse v1.3.0 probes 443/8443 only (measured live on the corpus stand with extra
    ``openssl s_server`` listeners on 443, 8443, 465, 636, 993 and 9443; the measurement is in
    ADR 0002, section "TLS (#545)", not in these fixtures). Here the stand's Pulse rows are the
    fixture, and the open 9443 plus 465/636/993 are what the scanner reports as open; of those
    only 9443 is in the default probe_tls_ports."""
    artifact = json.loads((CORPUS / "pulse" / "tcp.json").read_text(encoding="utf-8"))
    nmap_dir = _write_pulse_tls(tmp_path, artifact["tls"])
    calls: list[list[str]] = []
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    open_ports = ["172.29.41.20:443/tcp", "172.29.41.30:9443/tcp", "172.29.41.30:465/tcp",
                  "172.29.41.30:636/tcp", "172.29.41.30:993/tcp"]
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints", side_effect=_fake_probe(calls)):
        result = check_tls_posture(nmap_dir, cfg, tmp_path, now=NOW, open_ports=open_ports)
    assert calls == [["172.29.41.30:9443"]]
    assert result["checked_count"] == 4


# --- review fixes ------------------------------------------------------------


def _suite_row(*suites: Any, version: str = "TLSv1.2", complete: bool = True, **extra: Any) -> dict[str, Any]:
    return _row({"complete": complete, "versions": [{"version": version, "ciphers": list(suites)}]}, **extra)


@pytest.mark.parametrize("bits", [float("inf"), float("-inf"), float("nan"), 1e999, 10**400, "2048", [], {}])
def test_absurd_kex_bits_do_not_take_the_stage_down(bits):
    good = {"ip": "10.0.0.1", "port": 443, "negotiated_protocol": "TLSv1_2"}
    bad = _suite_row({"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "kex_bits": bits}, accepts_weak_protocols=["TLSv1.0"])
    rows = findings_from_pulse_tls({"tls": [good, bad]}, now=NOW, expiring_soon_days=30, max_targets=10)
    assert [r["host"] for r in rows] == ["10.0.0.1", "10.0.0.9"]
    assert any(i["kind"] == "weak_protocol" for i in rows[1]["issues"])  # the row's other findings survive
    # the suite itself is kept, its exchange simply unmeasured (not dropped by an exception handler)
    assert [c["name"] for c in rows[1]["cipher_versions"][0]["ciphers"]] == ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"]


def test_a_row_whose_enumeration_raises_is_isolated():
    ok = _suite_row({"name": "TLS_RSA_WITH_RC4_128_SHA", "kex_bits": 2048})
    ok["ip"] = "10.0.0.1"
    broken = _suite_row({"name": "TLS_RSA_WITH_RC4_128_SHA"}, accepts_weak_protocols=["TLSv1.1"])
    real = __import__("scanner.pipeline.tls_posture", fromlist=["x"]).parse_enumeration

    def flaky(row):
        if row["ip"] == "10.0.0.9":
            raise RuntimeError("boom")
        return real(row)

    with patch("scanner.pipeline.tls_posture.parse_enumeration", side_effect=flaky):
        rows = findings_from_pulse_tls({"tls": [ok, broken]}, now=NOW, expiring_soon_days=30, max_targets=10)
    assert {i["kind"] for i in rows[0]["issues"]} >= {"weak_cipher_grade"}
    assert [(i["kind"], i["version"]) for i in rows[1]["issues"] if i["kind"] == "weak_protocol"] == [
        ("weak_protocol", "TLSv1.1")]
    assert rows[1]["cipher_versions"] == [{"version": "TLSv1.2", "ciphers": [], "least_strength": None}]


def test_non_iana_name_with_a_code_is_named_by_the_code_and_without_one_is_dropped():
    named = _from_pulse(_suite_row({"code": "0x0005", "name": "RC4-SHA"}))
    assert [c["name"] for c in named["cipher_versions"][0]["ciphers"]] == ["TLS_RSA_WITH_RC4_128_SHA"]
    nameless = _from_pulse(_suite_row({"name": "RC4-SHA"}, {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}))
    assert [c["name"] for c in nameless["cipher_versions"][0]["ciphers"]] == ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]


def test_unknown_exchange_is_flagged_as_an_upper_bound_and_cannot_raise_a_kex_finding():
    unknown = _from_pulse(_suite_row({"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
                                     {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256"},
                                     {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kex_bits": 4096}))
    by_name = {c["name"]: c for c in unknown["cipher_versions"][0]["ciphers"]}
    assert by_name["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"] == {
        "name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "grade": "B", "grade_upper_bound": True}
    assert by_name["TLS_RSA_WITH_AES_128_GCM_SHA256"]["grade_upper_bound"] is True
    # 4096 is not a curve size: ignored, and then the letter is an upper bound again
    assert by_name["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]["grade_upper_bound"] is True
    assert not _cipher_signature(unknown["issues"])  # a 1024-bit DH is invisible without kex_bits

    known = _from_pulse(_suite_row({"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "kex_bits": 1024},
                                   {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "kex_bits": 512},
                                   {"name": "TLS_AES_128_GCM_SHA256"}))
    (suite,) = [c for c in known["cipher_versions"][0]["ciphers"] if "DHE" in c["name"]]
    assert suite == {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "grade": "D"}  # worst of the duplicates
    assert ("weak_cipher_grade", "TLSv1.2", "D", None) in _cipher_signature(known["issues"])
    tls13 = next(c for c in known["cipher_versions"][0]["ciphers"] if c["name"] == "TLS_AES_128_GCM_SHA256")
    assert "grade_upper_bound" not in tls13


def test_accepted_false_with_a_suite_list_is_still_not_accepted():
    row = _from_pulse(_row({"complete": True, "versions": [
        {"version": "SSLv3", "accepted": False, "ciphers": [{"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kex_bits": 2048}]}]}))
    assert not [i for i in row["issues"] if i["kind"] == "weak_protocol"]
    assert not _cipher_signature(row["issues"])
    assert row["cipher_versions"] == [{"version": "TLSv1.2", "ciphers": [], "least_strength": None}]


def test_duplicate_suites_collapse_to_the_worst_grade_within_and_across_entries():
    dup = {"name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"}
    row = _from_pulse(_row({"complete": True, "versions": [
        {"version": "TLSv1.2", "ciphers": [{**dup, "kex_bits": 4096}, {**dup, "kex_bits": 512}, {**dup, "kex_bits": 2048}]},
        {"version": "TLS 1.2", "ciphers": [{**dup, "kex_bits": 4096}, {"name": "TLS_NEW_WITH_THING"}]},
    ]}))
    (v,) = row["cipher_versions"]
    assert {c["name"]: c["grade"] for c in v["ciphers"]} == {dup["name"]: "D", "TLS_NEW_WITH_THING": None}
    assert v["least_strength"] == "D"


def test_a_known_grade_replaces_an_unknown_one_for_the_same_name():
    row = _from_pulse(_suite_row({"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kex_group": "nonsense"},
                                 {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kex_bits": 256}))
    assert row["cipher_versions"][0]["ciphers"] == [
        {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "grade": "A"}]


@pytest.mark.parametrize("code", ["5", "0005", "771", "C02F", "c02f", " 5 ", "0x", "0x12345", "x0005", 0x10000, -5])
def test_only_0x_hex_strings_and_in_range_ints_name_a_suite(code):
    row = _from_pulse(_suite_row({"code": code}))
    assert not [c for v in row["cipher_versions"] for c in v["ciphers"]]


def test_decimal_version_strings_are_not_read_but_ints_and_0x_hex_are():
    from scanner.pipeline.tls_enumeration import normalize_version

    assert normalize_version("771") is None
    assert normalize_version(771) == "TLSv1.2"
    assert normalize_version("0x0303") == "TLSv1.2"


def test_ipv6_open_port_is_covered_in_any_spelling_and_gap_is_passed_without_brackets(tmp_path: Path):
    nmap_dir = _write_pulse_tls(tmp_path, [{"ip": "0:0:0:0:0:0:0:1", "port": 443}, {"ip": "2001:db8::5", "port": 443}])
    calls: list[list[str]] = []
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints", side_effect=_fake_probe(calls)):
        result = check_tls_posture(
            nmap_dir, cfg, tmp_path, now=NOW,
            open_ports=["[::1]:443/tcp", "[2001:0db8:0:0:0:0:0:5]:443/tcp", "[::1]:9443/tcp"],
        )
    assert calls == [["::1:9443"]]
    assert result["checked_count"] == 3


def test_merged_rows_are_ordered_by_host_then_numeric_port(tmp_path: Path):
    nmap_dir = _write_pulse_tls(tmp_path, [{"ip": "10.0.0.2", "port": 443}, {"ip": "10.0.0.1", "port": 8443}])
    calls: list[list[str]] = []
    cfg = TlsPostureConfig(enabled=True, probe_fallback=True)
    with patch("scanner.pipeline.tls_posture.probe_tls_endpoints", side_effect=_fake_probe(calls)):
        result = check_tls_posture(
            nmap_dir, cfg, tmp_path, now=NOW,
            open_ports=["10.0.0.1:10443/tcp", "10.0.0.1:9443/tcp", "10.0.0.2:4443/tcp"],
        )
    assert [(f["host"], f["port"], f["source"]) for f in result["findings"]] == [
        ("10.0.0.1", "8443", "pulse-tls"), ("10.0.0.1", "9443", "pulse-tls-probe"),
        ("10.0.0.1", "10443", "pulse-tls-probe"), ("10.0.0.2", "443", "pulse-tls"),
        ("10.0.0.2", "4443", "pulse-tls-probe")]


def test_a_suite_that_raises_while_being_read_is_skipped_alone():
    real = __import__("scanner.pipeline.tls_enumeration", fromlist=["x"]).grade_cipher_suite_detail

    def flaky(name, **kw):
        if "RC4" in name:
            raise RuntimeError("boom")
        return real(name, **kw)

    with patch("scanner.pipeline.tls_enumeration.grade_cipher_suite_detail", side_effect=flaky):
        row = _from_pulse(_suite_row({"name": "TLS_RSA_WITH_RC4_128_SHA"},
                                     {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kex_bits": 256}))
    assert [c["name"] for c in row["cipher_versions"][0]["ciphers"]] == ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]


@pytest.mark.parametrize("complete", [False, True])
def test_raw_selection_evidence_is_preserved_without_claiming_completed_handshake(complete):
    row = _from_pulse(_row({"complete": complete, "evidence": "server_hello_selection", "versions": [
        {"version": "SSLv3", "accepted": True, "ciphers": [{"code": "0x0005", "name": "TLS_RSA_WITH_RC4_128_SHA"}]}]}))
    assert row["enumeration_evidence"] == "server_hello_selection"
    assert row["enumeration_complete"] is complete
    assert all(issue.get("requires_confirmation") for issue in row["issues"] if issue["kind"] in CIPHER_KINDS)
    assert {issue["kind"] for issue in row["issues"]} >= {"weak_protocol", "weak_cipher_name"}
    assert row["cipher_versions"][0]["ciphers"][0]["grade_upper_bound"] is True


def test_recorded_raw_engine_tls13_result_grades_observed_suites():
    # Recorded from GenDec raw enumerator against a local OpenSSL TLS1.3 server.
    payload = json.loads((Path(__file__).parent / "fixtures/pulse_tls/raw_tls13.json").read_text())
    row = _from_pulse(payload["tls"][0])
    assert row["enumeration_evidence"] == "server_hello_selection"
    version = next(v for v in row["cipher_versions"] if v["version"] == "TLSv1.3")
    assert {s["name"] for s in version["ciphers"]} == {
        "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}
    assert version["server_preference"] is True
    assert {s["grade"] for s in version["ciphers"]} == {"A"}
