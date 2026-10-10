"""Nmap/Pulse golden corpus (#541, ADR 0002): gap numbers pinned, offline.

The fixtures in ``tests/fixtures/nmap_pulse_corpus`` were recorded on a compose
stand with Nmap 7.93 and Pulse 1.3.0 BEFORE any Pulse or adapter change. The
expected numbers below are the starting gap. When a later change legitimately
closes part of it, the test goes red on purpose: re-record (``record.sh``) if the
inputs changed, then update the numbers in the same commit as
``docs/pulse-backend.md`` so the gap table stays a history, not a guess.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
from pathlib import Path
from xml.sax.saxutils import quoteattr

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pulse_corpus import SCHEMA, compare_corpus, format_table  # noqa: E402

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
        "pulse_plugin_findings": 5,
        "cve_both": 3,
        "cve_only_nmap": 425,
        "cve_only_pulse": 0,
    },
    "os": {"hosts_nmap": 14, "hosts_pulse": 14, "hosts_with_both": 14, "family_agree": 14, "family_disagree": 0},
    # Shapoclyack's Rhai plugins (#544) against the NSE scripts that ran on the same stand.
    "plugins": {
        "files": 6,
        "errors": 0,
        "findings_by_plugin": {
            "shapo_cleartext_services": 1,
            "shapo_ftp_anonymous": 1,
            "shapo_remote_admin_exposure": 1,
            "shapo_smb_exposure": 2,
        },
        "plugin_only": ["shapo_cleartext_services", "shapo_remote_admin_exposure", "shapo_smb_exposure"],
        "nse": {
            "ssh2-enum-algos": {
                "endpoints": 4, "plugin": "shapo_ssh_algorithms",
                "covers": "weak algorithms only, not the full lists", "verdict_agrees": 4,
            },
            "ssh-hostkey": {
                "endpoints": 4, "plugin": None,
                "not_covered": "key fingerprints need the key exchange: binary packets",
            },
            "ftp-anon": {
                "endpoints": 1, "plugin": "shapo_ftp_anonymous",
                "covers": "login accepted or not; no directory listing (needs a data connection)",
                "verdict_agrees": 1,
            },
            "ftp-syst": {"endpoints": 1, "plugin": None, "not_covered": "informational (SYST reply); not a finding"},
            "smb2-security-mode": {
                "endpoints": 1, "plugin": None,
                "not_covered": "SMB2 negotiate starts with 0xFE: a byte the sandbox cannot send",
            },
            "smb-protocols": {
                "endpoints": 1, "plugin": None, "not_covered": "SMB negotiate: a byte the sandbox cannot send",
            },
            "rdp-enum-encryption": {
                "endpoints": 1, "plugin": None,
                "not_covered": "X.224 request carries 0xE0: a byte the sandbox cannot send",
            },
        },
    },
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
    meta = json.loads((CORPUS / "stand-meta.json").read_text(encoding="utf-8"))
    compose = yaml.safe_load((CORPUS / "stand" / "docker-compose.yml").read_text(encoding="utf-8"))

    def pins(services: dict) -> dict:
        out = {}
        for name, svc in services.items():
            build = svc.get("build") or {}
            base = (build.get("args") or {}).get("BASE")
            out[name] = (svc.get("image"), base)
        return out

    # What compose says, with the registry placeholder resolved the way
    # record.sh normalises the meta.
    from_compose = {
        name: tuple(ref.replace("${MIRROR:-docker.io/library}", "docker.io/library") if ref else ref for ref in pair)
        for name, pair in pins(compose["services"]).items()
    }
    from_meta = {n: (s["image"], s["build_base"]) for n, s in meta["services"].items()}
    assert from_meta == from_compose, "stand-meta.json and docker-compose.yml disagree: re-run record.sh"

    for name, (image, base) in from_compose.items():
        for ref in (image, base):
            if ref and not ref.startswith("shapo-corpus/"):
                assert re.search(r"@sha256:[0-9a-f]{64}$", ref), f"{name} is not pinned by digest: {ref}"
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


def _plugin_run(corpus: Path) -> dict:
    return json.loads((corpus / "pulse" / "tcp-plugins.json").read_text(encoding="utf-8"))


def test_the_plugin_run_was_recorded_with_the_plugins_that_ship():
    """A plugin edited after the recording would leave the corpus describing code that is gone."""
    from scanner.pipeline import pulse_plugins

    recorded = dict(
        reversed(line.split())
        for line in (CORPUS / "pulse" / "plugins.sha256").read_text(encoding="utf-8").splitlines()
    )
    shipped = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in pulse_plugins.PLUGINS_DIR.glob("*.rhai")}
    assert recorded == shipped, (
        "a plugin changed since pulse/tcp-plugins.json was recorded: "
        "RECORD_PARTS=pulse PULSE_BIN=<linux pulse> tests/fixtures/nmap_pulse_corpus/record.sh"
    )


def test_every_shipped_plugin_is_accounted_for_against_nse():
    from pulse_corpus import NSE_PLUGIN_MAP, PLUGIN_ONLY

    from scanner.pipeline import pulse_plugins

    shipped = {p.stem for p in pulse_plugins.PLUGINS_DIR.glob("*.rhai")}
    mapped = {m["plugin"] for m in NSE_PLUGIN_MAP.values() if m["plugin"]}
    assert shipped == mapped | set(PLUGIN_ONLY)
    for script_id, mapping in NSE_PLUGIN_MAP.items():
        assert bool(mapping["plugin"]) != bool(mapping.get("why")), script_id  # a plugin, or the reason there is none


def test_dropping_a_plugin_finding_is_noticed(corpus_copy: Path):
    path = corpus_copy / "pulse" / "tcp-plugins.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["cves"] = [c for c in payload["cves"] if c.get("cve_id") != "SCRIPT-SHAPO_FTP_ANONYMOUS"]
    payload["findings"] = payload["cves"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    summary = compare_corpus(corpus_copy)["summary"]
    assert summary["scripts"]["pulse_plugin_findings"] == 4
    assert summary["plugins"]["nse"]["ftp-anon"]["verdict_agrees"] == 0  # Nmap allows it, the plugin no longer says so


def test_a_weak_algorithm_nmap_lists_and_the_plugin_misses_is_a_disagreement(corpus_copy: Path):
    path = corpus_copy / "nmap" / "tcp.xml"
    text = path.read_text(encoding="utf-8")
    assert 'id="ssh2-enum-algos"' in text
    # Put a name the plugin calls weak into one endpoint's algorithm list.
    marked = text.replace('id="ssh2-enum-algos" output="', 'id="ssh2-enum-algos" output="\n      3des-cbc', 1)
    path.write_text(marked, encoding="utf-8")
    assert compare_corpus(corpus_copy)["summary"]["plugins"]["nse"]["ssh2-enum-algos"]["verdict_agrees"] == 3


def test_a_plugin_error_in_the_recorded_run_is_counted(corpus_copy: Path):
    stderr = corpus_copy / "pulse" / "tcp-plugins.stderr"
    stderr.write_text("  warn  plugin error \u2014 shapo_ssh_algorithms: Runtime error: boom\n", encoding="utf-8")
    assert compare_corpus(corpus_copy)["summary"]["plugins"]["errors"] == 1


def test_empty_corpus_does_not_pass(tmp_path: Path):
    (tmp_path / "nmap").mkdir()
    (tmp_path / "pulse").mkdir()
    summary = compare_corpus(tmp_path)["summary"]
    assert summary["endpoints"]["nmap"] == 0
    assert summary != EXPECTED_SUMMARY


# --- synthetic mini corpora: each branch must give a match AND a mismatch ----

CERT = "Subject: commonName={cn}\nIssuer: commonName={cn}\n"
ENUM = "\n  {v}: \n    ciphers: \n      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A\n  least strength: A"


def _nmap_host(addr: str, port: int, *, product: str, version: str, tls: tuple[str, ...] = (), cn: str = "") -> str:
    scripts = ""
    if tls:
        enum = "".join(ENUM.format(v=v) for v in tls).strip()
        scripts = (
            f'<script id="ssl-enum-ciphers" output={quoteattr(enum)}/>'
            f'<script id="ssl-cert" output={quoteattr(CERT.format(cn=cn))}/>'
        )
    return (
        f'<host><address addr="{addr}" addrtype="ipv4"/><ports><port protocol="tcp" portid="{port}">'
        f'<state state="open"/><service name="ssh" product="{product}" version="{version}"/>{scripts}'
        "</port></ports></host>"
    )


def _mini(tmp_path: Path, nmap_hosts: list[str], pulse: dict) -> Path:
    (tmp_path / "nmap").mkdir()
    (tmp_path / "pulse").mkdir()
    (tmp_path / "nmap" / "tcp.xml").write_text(f"<nmaprun>{''.join(nmap_hosts)}</nmaprun>", encoding="utf-8")
    (tmp_path / "pulse" / "tcp.json").write_text(json.dumps(pulse), encoding="utf-8")
    return tmp_path


def _open(ip: str, port: int, product: str, version: str, cpe: list[str] | None = None) -> dict:
    return {
        "ip": ip,
        "port": port,
        "protocol": "tcp",
        "service": "ssh",
        "product": product,
        "version": version,
        "cpe": cpe or [],
    }


def test_product_case_cpe_and_version_branches(tmp_path: Path):
    nmap = [
        _nmap_host("10.9.0.1", 22, product="OpenSSH", version="8.2p1 Ubuntu 4"),
        _nmap_host("10.9.0.2", 22, product="OpenSSH", version="9.2"),
    ]
    pulse = {
        "open": [
            # lower-case product, distribution revision dropped, CPE filled in
            _open("10.9.0.1", 22, "openssh", "8.2p1", ["cpe:/a:openbsd:openssh:8.2p1"]),
            # different product, different version, no CPE
            _open("10.9.0.2", 22, "Dropbear", "2022.83"),
        ]
    }
    s = compare_corpus(_mini(tmp_path, nmap, pulse))["summary"]
    assert s["product"] == {"nmap_has_product": 2, "match": 1, "mismatch": 1, "missing_in_pulse": 0}
    assert s["version"]["base_only"] == 1
    assert s["version"]["mismatch"] == 1
    assert s["cpe"]["endpoints_pulse"] == 1


def test_tls_weak_verdict_and_certificate_branches(tmp_path: Path):
    nmap = [
        # legacy server: Nmap enumerates TLSv1.0 and TLSv1.2
        _nmap_host("10.9.0.1", 443, product="nginx", version="1", tls=("TLSv1.0", "TLSv1.2"), cn="a.test"),
        # modern server: TLSv1.2 only
        _nmap_host("10.9.0.2", 443, product="nginx", version="1", tls=("TLSv1.2",), cn="b.test"),
    ]
    pulse = {
        "open": [_open("10.9.0.1", 443, "nginx", "1"), _open("10.9.0.2", 443, "nginx", "1")],
        "tls": [
            # agrees: weak protocol seen, same certificate name
            {
                "ip": "10.9.0.1",
                "port": 443,
                "negotiated_protocol": "TLSv1_2",
                "accepts_weak_protocols": ["TLSv1.0"],
                "subject_cn": "a.test",
            },
            # disagrees: Pulse says a weak protocol is accepted, Nmap does not; other certificate name
            {
                "ip": "10.9.0.2",
                "port": 443,
                "negotiated_protocol": "TLSv1_2",
                "accepts_weak_protocols": ["TLSv1.1"],
                "subject_cn": "other.test",
            },
        ],
    }
    tls = compare_corpus(_mini(tmp_path, nmap, pulse))["summary"]["tls"]
    assert tls["both"] == 2
    assert tls["weak_protocol_verdict_agrees"] == 1
    assert tls["protocol_sets_equal"] == 1
    assert tls["cert_cn_match"] == 1
    assert tls["nmap_weak_protocol_endpoints"] == 1
    assert tls["pulse_weak_protocol_endpoints"] == 2
