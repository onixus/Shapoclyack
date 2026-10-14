"""Nmap/Pulse golden corpus (#541, ADR 0002): gap numbers pinned, offline.

The fixtures in ``tests/fixtures/nmap_pulse_corpus`` were recorded on a compose
stand with Nmap 7.93 and Pulse 1.3.0 BEFORE any Pulse or adapter change. The
expected numbers below are the historical starting gap. New source capabilities
are accounted for separately and cannot change this recording. A new measurement
needs a real stand run (``record.sh``) and corresponding documentation; it must
never be inferred from a newer plugin registry.
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

# Gap as recorded on 2026-10-10 with the adapter's pinned inputs (--services-db,
# --probe-db). Before probes.json (#546) product was 14 match / 1 mismatch /
# 3 missing_in_pulse. Keep in step with docs/pulse-backend.md.
def _vuln(endpoints: int, flagged: int, destination: str, *, vuln: bool = True, **extra) -> dict:
    return {"vuln": vuln, "endpoints": endpoints, "flagged": flagged, "destination": destination, **extra}


EXPECTED_VULN_SCRIPTS = {
    "vulners": _vuln(10, 9, "version_match"),
    "http-vuln-cve2011-3192": _vuln(4, 4, "refused"),
    "http-slowloris-check": _vuln(1, 1, "refused"),
    "http-trace": _vuln(2, 0, "plugin", plugin_flags=1),
    "http-litespeed-sourcecode-download": _vuln(1, 1, "refused"),
    "http-phpmyadmin-dir-traversal": _vuln(1, 1, "refused"),
    "http-majordomo2-dir-traversal": _vuln(1, 0, "nuclei_web"),
    "http-vuln-cve2017-1001000": _vuln(1, 0, "refused"),
    "http-csrf": _vuln(7, 0, "refused"),
    "http-dombased-xss": _vuln(7, 0, "refused"),
    "http-stored-xss": _vuln(7, 0, "refused"),
    "ssl-ccs-injection": _vuln(1, 0, "tls"),
    "smb-vuln-ms10-054": _vuln(1, 0, "refused"),
    "smb-vuln-ms10-061": _vuln(1, 0, "gap"),
    "samba-vuln-cve-2012-1182": _vuln(1, 0, "version_match"),
    "smb-vuln-ms17-010": _vuln(0, 0, "gap"),
    "smb2-security-mode": _vuln(1, 0, "nuclei_network", vuln=False),
    "smb-protocols": _vuln(1, 0, "gap", vuln=False),
    "rdp-enum-encryption": _vuln(1, 0, "gap", vuln=False),
    "http-methods": _vuln(2, 0, "plugin", vuln=False, plugin_flags=1),
    "http-malware-host": _vuln(1, 0, "refused", vuln=False),
}

EXPECTED_SUMMARY = {
    "endpoints": {"nmap": 19, "pulse": 19, "both": 19, "only_nmap": 0, "only_pulse": 0},
    "service": {"match": 18, "mismatch": 1},
    "product": {"nmap_has_product": 18, "match": 14, "mismatch": 2, "missing_in_pulse": 2},
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
        "pulse_plugin_findings": 6,
        "cve_both": 3,
        "cve_only_nmap": 425,
        "cve_only_pulse": 0,
    },
    "os": {"hosts_nmap": 14, "hosts_pulse": 14, "hosts_with_both": 14, "family_agree": 14, "family_disagree": 0},
    # Shapoclyack's Rhai plugins (#544) against the NSE scripts that ran on the same stand.
    "plugins": {
        "files": 7,
        "errors": 0,
        "findings_by_plugin": {
            "shapo_cleartext_services": 1,
            "shapo_ftp_anonymous": 1,
            "shapo_http_trace": 1,
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
                "endpoints": 1, "plugin": None, "nuclei": "smb-signing-not-required",
                "not_covered": "SMB2 negotiate starts with 0xFE: a byte the sandbox cannot send",
            },
            "smb-protocols": {
                "endpoints": 1, "plugin": None, "not_covered": "SMB negotiate: a byte the sandbox cannot send",
            },
            "rdp-enum-encryption": {
                "endpoints": 1, "plugin": None,
                "not_covered": "X.224 request carries 0xE0: a byte the sandbox cannot send",
            },
            # Nmap says TRACE on Apache :80 and :443; the plugin has no TLS, so it reports :80 only.
            "http-trace": {
                "endpoints": 2, "plugin": "shapo_http_trace",
                "covers": "TRACE echo over plain HTTP only; HTTPS is out of the sandbox's reach",
                "verdict_agrees": 1,
            },
        },
    },
    # Nmap's `vuln` category against where each script goes now (#547, docs/nse-vuln-coverage.md).
    "nse_vuln": {
        "vuln_scripts": 16,
        "vuln_scripts_printed": 15,
        "vuln_outputs": 46,
        "vuln_flagged_by_nmap": 16,
        "by_destination": {"nuclei_web": 1, "plugin": 1, "tls": 1, "version_match": 2, "gap": 2, "refused": 9},
        "scripts": EXPECTED_VULN_SCRIPTS,
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


def test_recorded_plugin_sources_have_not_changed():
    """Historical sources stay byte-identical; new sources do not claim recorded acceptance."""
    from pulse_corpus import RECORDED_NSE_PLUGIN_MAP, RECORDED_PLUGIN_ONLY

    from scanner.pipeline import pulse_plugins

    recorded = dict(
        reversed(line.split())
        for line in (CORPUS / "pulse" / "plugins.sha256").read_text(encoding="utf-8").splitlines()
    )
    historical = {m["plugin"] for m in RECORDED_NSE_PLUGIN_MAP.values() if m["plugin"]} | set(RECORDED_PLUGIN_ONLY)
    assert set(recorded) == {f"{name}.rhai" for name in historical}
    shipped = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in pulse_plugins.PLUGINS_DIR.glob("*.rhai")}
    assert recorded.items() <= shipped.items(), (
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
    assert summary["scripts"]["pulse_plugin_findings"] == 5
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


# --- NSE vuln -> destination (#547) ---------------------------------------


def test_every_destination_in_the_vuln_map_is_one_the_report_knows_and_points_at_something_real():
    from pulse_corpus import NSE_VULN_MAP, VULN_DESTINATIONS

    from scanner.pipeline import pulse_plugins
    from scanner.pipeline.nuclei_network import NETWORK_RULES

    shipped = {p.stem for p in pulse_plugins.PLUGINS_DIR.glob("*.rhai")}
    network_nse = {script for rule in NETWORK_RULES for script in rule.nse}
    network_ids = {template for rule in NETWORK_RULES for template in rule.template_ids}
    for script_id, mapping in NSE_VULN_MAP.items():
        assert mapping["destination"] in VULN_DESTINATIONS, script_id
        assert mapping["categories"], script_id
        if mapping["destination"] == "plugin":
            assert mapping["ref"] in shipped, script_id
        if mapping["destination"] == "nuclei_network":
            assert script_id in network_nse and mapping["ref"] in network_ids, script_id
        if mapping["destination"] in ("refused", "gap"):
            assert mapping.get("why"), f"{script_id}: a refusal or a gap states its reason"
    # The other direction: nothing the network pass claims to answer is missing from the report.
    assert network_nse <= set(NSE_VULN_MAP)


def test_a_plugin_that_stops_reporting_trace_is_a_disagreement_in_the_vuln_section(corpus_copy: Path):
    path = corpus_copy / "pulse" / "tcp-plugins.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["cves"] = [c for c in payload["cves"] if c.get("cve_id") != "SCRIPT-SHAPO_HTTP_TRACE"]
    payload["findings"] = payload["cves"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    summary = compare_corpus(corpus_copy)["summary"]
    assert summary["nse_vuln"]["scripts"]["http-trace"]["plugin_flags"] == 0
    assert summary["plugins"]["nse"]["http-trace"]["verdict_agrees"] == 0


def test_a_vuln_script_that_printed_nothing_is_not_counted_as_an_output(corpus_copy: Path):
    path = corpus_copy / "nmap" / "tcp.xml"
    text = path.read_text(encoding="utf-8")
    assert 'id="http-slowloris-check"' in text
    path.write_text(re.sub(r'(id="http-slowloris-check" output=")[^"]*"', r'\1"', text, count=1), encoding="utf-8")
    summary = compare_corpus(corpus_copy)["summary"]["nse_vuln"]
    assert summary["scripts"]["http-slowloris-check"]["endpoints"] == 0
    assert summary["vuln_outputs"] == 45


# --- CVE by version: what retro_match says on the corpus with the shipped seed (#547) ----


def test_retro_match_on_the_corpus_with_the_shipped_seed_is_a_handful_of_findings_not_nmap_s_428():
    """The docs call ``retro_match`` the primary CVE-by-version source; this is what that is worth
    until the real NVD dataset is harvested (``scripts/fetch-nvd-cpe.py --full``, off by default).

    Nmap's ``vulners`` named 428 CVE ids on this stand; the seed holds 23 CVEs of 8 products, so
    only the endpoints whose product it knows can match. No advisory provider is given, so a
    Debian/Ubuntu backport cannot turn a match into ``fixed``: this counts range hits.
    """
    from api.services import retro_match as rm
    from api.services.cpe_ranges import load_dataset
    from scanner.pipeline.pulse_probe import parse_pulse_json

    root = Path(__file__).resolve().parents[1]
    dataset = load_dataset(root / "scanner" / "data" / "nvd-cpe" / "nvd-cpe-ranges.json")
    services, _, _ = parse_pulse_json(json.loads((CORPUS / "pulse" / "tcp.json").read_text(encoding="utf-8")))
    outcomes = {
        f"{s.ip}:{s.port}": rm.match(
            rm.Fingerprint(
                product=s.product, version=s.version, banner=s.banner, cpe=tuple(s.cpe), service=s.service,
                distro=s.distro, distro_revision=s.distro_revision,
            ),
            dataset,
            lookup=lambda *args, **kwargs: None,
        )
        for s in services
    }
    vulnerable = {ep: sorted(m.cve for m in o.matches if m.verdict == "vulnerable") for ep, o in outcomes.items()}
    vulnerable = {ep: cves for ep, cves in vulnerable.items() if cves}
    assert len(outcomes) == 18
    assert sum(1 for o in outcomes.values() if o.matches) == 6
    assert vulnerable == {
        "172.29.41.21:80": ["CVE-2021-23017", "CVE-2022-41741"],
        "172.29.41.21:443": ["CVE-2021-23017", "CVE-2022-41741"],
        "172.29.41.42:21": ["CVE-2021-30047"],
    }


# --- the doc and the map are written apart, so one checks the other (#547 review) ----

_DOC_LABELS = {
    "version matching": "version_match", "refused": "refused", "Rhai plugin": "plugin",
    "Nuclei web": "nuclei_web", "Nuclei network": "nuclei_network", "TLS": "tls", "gap": "gap",
}


def _doc_rows() -> dict[str, tuple[int, str]]:
    """``{script: (n, destination code)}`` from the two script tables of docs/nse-vuln-coverage.md."""
    text = (Path(__file__).resolve().parents[1] / "docs" / "nse-vuln-coverage.md").read_text(encoding="utf-8")
    rows: dict[str, tuple[int, str]] = {}
    for line in text.split("## The Nuclei network pass")[0].splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        match = re.fullmatch(r"`([a-z0-9-]+)`", cells[0]) if cells else None
        if not match or len(cells) < 4 or not cells[1].isdigit():
            continue
        label = next((c for c in cells[2:4] if c in _DOC_LABELS), None)
        assert label, f"{match.group(1)}: no destination label in {cells[2:4]}"
        rows[match.group(1)] = (int(cells[1]), _DOC_LABELS[label])
    return rows


def test_the_doc_table_and_the_map_say_the_same_thing_per_script():
    from pulse_corpus import NSE_VULN_MAP

    doc = _doc_rows()
    summary = compare_corpus(CORPUS)["summary"]["nse_vuln"]["scripts"]
    assert set(doc) == set(NSE_VULN_MAP)
    for script_id, mapping in NSE_VULN_MAP.items():
        assert doc[script_id][1] == mapping["destination"], script_id
        assert doc[script_id][0] == summary[script_id]["endpoints"], script_id


def test_a_doc_row_whose_destination_changed_is_noticed():
    doc = _doc_rows()
    assert doc["http-slowloris-check"][1] == "refused"
    assert doc["smb2-security-mode"][1] == "nuclei_network"


def test_every_template_id_the_map_and_the_table_name_exists_in_the_pinned_templates_when_they_are_here():
    """Offline the ids can only be checked for shape; with a templates checkout they are looked up.

    ``OCTO_NUCLEI_TEMPLATES_DIR`` (or the image's ``/usr/share/nuclei-templates``) is the v9.9.4 pin.
    """
    import os

    from pulse_corpus import NSE_VULN_MAP

    from scanner.pipeline.config_schema import NUCLEI_TEMPLATE_ID_RE
    from scanner.pipeline.nuclei_network import NETWORK_RULES
    from scanner.pipeline.nuclei_scan import index_template_ids

    ids = {t for rule in NETWORK_RULES for t in rule.template_ids}
    ids |= {m["ref"] for m in NSE_VULN_MAP.values() if m["destination"] == "nuclei_web"}
    assert ids and all(NUCLEI_TEMPLATE_ID_RE.fullmatch(i) for i in ids)
    root = Path(os.environ.get("OCTO_NUCLEI_TEMPLATES_DIR") or "/usr/share/nuclei-templates")
    if not root.is_dir():
        pytest.skip("no nuclei-templates checkout (OCTO_NUCLEI_TEMPLATES_DIR)")
    found = index_template_ids(sorted(ids), [root])
    assert set(found) == ids, f"not in the pinned templates: {sorted(ids - set(found))}"


def test_new_plugins_are_explicitly_unrecorded_source_capabilities():
    from pulse_corpus import NSE_PLUGIN_MAP, PLUGIN_ONLY
    from scanner.pipeline import pulse_plugins

    recorded = {line.split()[1].removesuffix(".rhai") for line in (CORPUS / "pulse" / "plugins.sha256").read_text().splitlines()}
    shipped = {p.stem for p in pulse_plugins.PLUGINS_DIR.glob("*.rhai")}
    unrecorded = shipped - recorded
    assert len(unrecorded) == 9
    accounted = {m["plugin"] for m in NSE_PLUGIN_MAP.values() if m["plugin"]} | set(PLUGIN_ONLY)
    assert unrecorded <= accounted
    # A newly shipped but undeclared plugin must break the complete accounting gate.
    assert shipped | {"shapo_unaccounted"} != accounted
    # Editing a historical source must still break the recording provenance gate.
    hashes = dict(reversed(line.split()) for line in (CORPUS / "pulse" / "plugins.sha256").read_text().splitlines())
    current = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in pulse_plugins.PLUGINS_DIR.glob("*.rhai")}
    current[next(iter(hashes))] = "0" * 64
    assert not hashes.items() <= current.items()
