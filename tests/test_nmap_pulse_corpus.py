"""Nmap/Pulse golden corpus (#541, ADR 0002): gap numbers pinned, offline.

The fixtures in ``tests/fixtures/nmap_pulse_corpus`` were recorded on a compose
stand with Nmap 7.93 and Pulse 1.3.0 BEFORE any Pulse or adapter change. The
expected numbers below are the starting gap. When a later change legitimately
closes part of it, the test goes red on purpose: re-record (``record.sh``) if the
inputs changed, then update the numbers in the same commit as
``docs/pulse-backend.md`` so the gap table stays a history, not a guess.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from scanner.pipeline.pulse_corpus import SCHEMA, compare_corpus, format_table

CORPUS = Path(__file__).parent / "fixtures" / "nmap_pulse_corpus"

# Gap before any Pulse/adapter change. Keep in step with docs/pulse-backend.md.
EXPECTED_SUMMARY = {
    "endpoints": {"nmap": 19, "pulse": 19, "both": 19, "only_nmap": 0, "only_pulse": 0},
    "service": {"match": 18, "mismatch": 1},
    "product": {"nmap_has_product": 18, "match": 14, "mismatch": 1, "missing_in_pulse": 3},
    "version": {"exact": 11, "base_only": 3, "mismatch": 0, "missing_in_pulse": 3, "not_in_nmap": 2},
    "cpe": {"endpoints_nmap": 17, "endpoints_pulse": 0},
    "tls": {
        "nmap_endpoints": 4,
        "pulse_endpoints": 3,
        "both": 3,
        "protocol_sets_equal": 2,
        "weak_protocol_verdict_agrees": 3,
        "nmap_weak_protocol_endpoints": 1,
        "pulse_weak_protocol_endpoints": 1,
        "nmap_cipher_suites_enumerated": 122,
        "pulse_cipher_suites_enumerated": 0,
        "cert_cn_match": 3,
    },
    "scripts": {
        "nmap_port_script_outputs": 157,
        "nmap_distinct_script_ids": 40,
        "nmap_flagged_vulnerable": 16,
        "pulse_findings": 13,
        "pulse_findings_by_class": {"exposure": 6, "tls": 4, "version_cve": 3},
        "pulse_scripts_run_findings": 13,
        "cve_both": 3,
        "cve_only_nmap": 425,
        "cve_only_pulse": 0,
    },
    "os": {"hosts_nmap": 14, "hosts_pulse": 14, "hosts_with_both": 14, "family_agree": 14, "family_disagree": 0},
    "shadow_endpoints_jaccard": 1.0,
}


@pytest.fixture()
def corpus_copy(tmp_path: Path) -> Path:
    """A scratch copy to corrupt; the checked-in fixtures are never touched."""
    dest = tmp_path / "corpus"
    shutil.copytree(CORPUS / "nmap", dest / "nmap")
    shutil.copytree(CORPUS / "pulse", dest / "pulse")
    return dest


def test_gap_numbers_are_pinned():
    report = compare_corpus(CORPUS)
    assert report["schema"] == SCHEMA
    assert report["summary"] == EXPECTED_SUMMARY


def test_report_names_every_endpoint_and_renders():
    report = compare_corpus(CORPUS)
    endpoints = {row["endpoint"] for row in report["endpoints"]}
    assert len(endpoints) == 19
    # The weak endpoint must be in the TLS rows, with the protocols Nmap enumerated.
    legacy = next(r for r in report["tls"] if r["endpoint"] == "172.29.41.21:443")
    assert {"TLSv1.0", "TLSv1.1"} <= set(legacy["nmap_protocols"])
    assert "scripts.cve_only_nmap" in format_table(report)


def test_stand_is_pinned_and_stubs_are_declared():
    meta =json.loads((CORPUS / "stand-meta.json").read_text(encoding="utf-8"))
    for name, svc in meta["services"].items():
        ref = svc["build_base"] or svc["image"]
        if not ref.startswith("shapo-corpus/"):
            assert "@sha256:" in ref, f"{name} is not pinned by digest: {ref}"
    assert meta["stub_services"] == ["iis-stub (172.29.41.23)", "rdp-stub (172.29.41.24)"]


# --- the test must go red when the corpus or the comparison is spoiled -------


def test_dropping_a_pulse_endpoint_is_noticed(corpus_copy: Path):
    path = corpus_copy / "pulse" / "tcp.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["open"] = [r for r in payload["open"] if not (r["ip"] == "172.29.41.42" and r["port"] == 21)]
    path.write_text(json.dumps(payload), encoding="utf-8")
    summary = compare_corpus(corpus_copy)["summary"]
    assert summary != EXPECTED_SUMMARY
    assert summary["endpoints"]["only_nmap"] == 1


def test_changing_a_pulse_version_is_noticed(corpus_copy: Path):
    path = corpus_copy / "pulse" / "tcp.json"
    path.write_text(path.read_text(encoding="utf-8").replace('"version": "7.2.5"', '"version": "7.0.0"'), encoding="utf-8")
    summary = compare_corpus(corpus_copy)["summary"]
    assert summary["version"]["mismatch"] == 1
    assert summary["version"]["exact"] == EXPECTED_SUMMARY["version"]["exact"] - 1


def test_stripping_nmap_script_output_is_noticed(corpus_copy: Path):
    path = corpus_copy / "nmap" / "tcp.xml"
    text = path.read_text(encoding="utf-8")
    assert 'id="ssl-enum-ciphers"' in text
    path.write_text(text.replace('id="ssl-enum-ciphers"', 'id="ssl-enum-ciphers-x"'), encoding="utf-8")
    summary = compare_corpus(corpus_copy)["summary"]
    assert summary["tls"]["nmap_cipher_suites_enumerated"] == 0
    assert summary["tls"] != EXPECTED_SUMMARY["tls"]


def test_empty_corpus_does_not_pass(tmp_path: Path):
    (tmp_path / "nmap").mkdir()
    (tmp_path / "pulse").mkdir()
    summary = compare_corpus(tmp_path)["summary"]
    assert summary["endpoints"]["nmap"] == 0
    assert summary != EXPECTED_SUMMARY
