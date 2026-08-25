"""Zone hygiene for the org's own domains (org_profile M2, #182)."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import pytest

from scanner.pipeline import dns_hygiene
from scanner.pipeline.config_schema import DnsHygieneConfig
from scanner.pipeline.dns_hygiene import (
    _classify_caa,
    _classify_ns,
    _classify_soa,
    _count_axfr_records,
    _parse_caa,
    _parse_soa,
    _probe_axfr,
    check_dns_hygiene,
)

#: One line of a real dnsx -axfr answer. No test may let this reach a log.
ZONE_LINE = json.dumps(
    {
        "host": "example.com",
        "axfr": [
            "internal-db.example.com. 300 IN A 10.0.0.7",
            "vpn.example.com. 300 IN A 198.51.100.9",
        ],
    }
)


def _patch_dnsx(
    monkeypatch,
    *,
    ns: dict | None = None,
    soa: dict | None = None,
    caa: dict | None = None,
    addresses: dict | None = None,
) -> None:
    """Answer every dnsx wrapper from canned records.

    Same convention as ``test_domain_monitor.py``: the module attribute is
    replaced and the fake repeats the keyword-only signature exactly, so a
    changed signature fails the test instead of silently passing.
    """

    def fake_ns(domains, output_dir, *, timeout, retries):
        return dict(ns or {})

    def fake_soa(domains, output_dir, *, timeout, retries):
        return dict(soa or {})

    def fake_caa(domains, output_dir, *, timeout, retries):
        return dict(caa or {})

    def fake_a_aaaa(names, output_dir, *, kind, timeout, retries):
        return {name: dict((addresses or {}).get(name, {})) for name in names}

    monkeypatch.setattr(dns_hygiene, "_run_dnsx_ns", fake_ns)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_soa", fake_soa)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_caa", fake_caa)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_a_aaaa", fake_a_aaaa)


def _kinds(result: dict) -> set[str]:
    return {finding["kind"] for finding in result["findings"]}


def test_dns_hygiene_disabled(tmp_path: Path):
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=False), tmp_path)
    assert result["skipped_reason"] == "dns_hygiene.disabled"
    assert (tmp_path / "dns_hygiene.json").exists()
    assert (tmp_path / "dns_hygiene_findings.txt").exists()


def test_dns_hygiene_no_domains(tmp_path: Path):
    result = check_dns_hygiene([], DnsHygieneConfig(enabled=True), tmp_path)
    assert result["skipped_reason"] == "no_domains"
    assert (tmp_path / "dns_hygiene.json").exists()


def test_dns_hygiene_truncates_at_max_domains(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch)
    result = check_dns_hygiene(
        ["a.example", "b.example"],
        DnsHygieneConfig(enabled=True, max_domains=1),
        tmp_path,
    )
    assert result["truncated"] is True
    assert result["seed_domains"] == ["a.example"]
    assert set(result["domains"]) == {"a.example"}


def test_ns_set_is_capped_per_domain(tmp_path: Path, monkeypatch):
    many = [f"ns{index}.provider.example" for index in range(dns_hygiene.MAX_NS_PER_DOMAIN + 5)]
    _patch_dnsx(monkeypatch, ns={"example.com": {"ns": many}})
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    record = result["domains"]["example.com"]
    assert len(record["nameservers"]) == dns_hygiene.MAX_NS_PER_DOMAIN
    assert record["nameservers_truncated"] is True
    assert result["truncated"] is True


def test_ns_single_point_and_lame_delegation():
    _, findings = _classify_ns("example.com", ["ns1.example.com"], {"ns1.example.com": ["1.1.1.1"]})
    assert [f["kind"] for f in findings] == ["ns_single_point"]
    assert findings[0]["reason"] == "single_ns"

    _, findings = _classify_ns(
        "example.com",
        ["ns1.a.example", "ns2.b.example"],
        {"ns1.a.example": ["203.0.113.1"], "ns2.b.example": []},
    )
    kinds = {f["kind"] for f in findings}
    assert "ns_lame_delegation" in kinds
    assert "ns_single_point" not in kinds


def test_ns_diverse_set_has_no_finding():
    block, findings = _classify_ns(
        "example.com",
        ["ns1.a.example", "ns2.b.example"],
        {"ns1.a.example": ["203.0.113.1"], "ns2.b.example": ["198.51.100.1"]},
    )
    assert findings == []
    # The source is named, and it is not ASN: this stage performs no ASN lookup.
    assert block["source"] == "ns_parent_domain_and_ip_prefix"


def test_soa_missing_and_timer_range():
    assert [f["kind"] for f in _classify_soa("example.com", None, [])] == ["soa_missing"]

    sane = {"mname": "ns1.example.com", "timers": {"refresh": 7200, "expire": 1_209_600}}
    assert _classify_soa("example.com", sane, ["ns1.example.com"]) == []

    broken = {"mname": "ns9.other.example", "timers": {"expire": 600}}
    kinds = {f["kind"] for f in _classify_soa("example.com", broken, ["ns1.example.com"])}
    assert kinds == {"soa_mname_not_in_ns", "soa_timers_out_of_range"}


def test_parse_soa_accepts_object_and_string():
    parsed = _parse_soa({"soa": [{"ns": "NS1.Example.com.", "refresh": 7200, "serial": 5}]})
    assert parsed == {"mname": "ns1.example.com", "serial": 5, "timers": {"refresh": 7200}}
    assert _parse_soa({"soa": ["ns1.example.com."]}) == {"mname": "ns1.example.com", "timers": {}}
    assert _parse_soa({}) is None


def test_caa_missing_and_wildcard_unrestricted():
    assert [f["kind"] for f in _classify_caa("example.com", _parse_caa({}))] == ["caa_missing"]

    only_issue = _parse_caa({"caa": ['0 issue "letsencrypt.org"']})
    assert only_issue["issuers"] == ["letsencrypt.org"]
    assert [f["kind"] for f in _classify_caa("example.com", only_issue)] == [
        "caa_wildcard_unrestricted"
    ]

    narrow = _parse_caa({"caa": ['0 issue "letsencrypt.org"', '0 issuewild ";"']})
    assert _classify_caa("example.com", narrow) == []


def test_dnssec_source_is_the_rdap_flag(tmp_path: Path, monkeypatch):
    (tmp_path / "ownership.json").write_text(
        json.dumps({"domains": {"example.com": {"dnssec": False}}}), encoding="utf-8"
    )
    _patch_dnsx(monkeypatch, ns={"example.com": {"ns": ["ns1.a.example", "ns2.b.example"]}})
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    dnssec = result["domains"]["example.com"]["dnssec"]
    assert dnssec == {
        "status": "absent",
        "delegation_signed": False,
        "source": "rdap_registry",
        "reason": None,
    }
    assert "dnssec_absent" in _kinds(result)


def test_dnssec_is_not_checked_without_ownership(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch, ns={"example.com": {"ns": ["ns1.a.example", "ns2.b.example"]}})
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    dnssec = result["domains"]["example.com"]["dnssec"]
    # No data must never turn into "ok" and never into a finding either.
    assert dnssec["status"] == "not_checked"
    assert dnssec["reason"] == "no_rdap_secure_dns"
    assert "dnssec_absent" not in _kinds(result)


def test_wildcard_needs_every_probe_to_resolve(tmp_path: Path, monkeypatch):
    resolved: dict[str, dict] = {}

    def fake_a_aaaa(names, output_dir, *, kind, timeout, retries):
        if kind != "wildcard":
            return {}
        # Only the first probe label answers -- that is a name collision, not
        # a wildcard, and must not be reported as one.
        return {sorted(names)[0]: {"a": ["203.0.113.5"]}} if not resolved else resolved

    _patch_dnsx(monkeypatch)
    monkeypatch.setattr(dns_hygiene, "_run_dnsx_a_aaaa", fake_a_aaaa)
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    assert result["domains"]["example.com"]["wildcard"]["present"] is False
    assert "wildcard_a_record" not in _kinds(result)

    def fake_all(names, output_dir, *, kind, timeout, retries):
        return {name: {"a": ["203.0.113.5"]} for name in names} if kind == "wildcard" else {}

    monkeypatch.setattr(dns_hygiene, "_run_dnsx_a_aaaa", fake_all)
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    assert result["domains"]["example.com"]["wildcard"]["present"] is True
    assert "wildcard_a_record" in _kinds(result)


def test_axfr_is_off_by_default(tmp_path: Path, monkeypatch):
    config = DnsHygieneConfig(enabled=True)
    assert config.axfr_probe is False

    def explode(*args, **kwargs):
        raise AssertionError("AXFR must not run unless axfr_probe is enabled")

    _patch_dnsx(
        monkeypatch,
        ns={"example.com": {"ns": ["ns1.a.example", "ns2.b.example"]}},
        addresses={"ns1.a.example": {"a": ["93.184.216.34"]}, "ns2.b.example": {"a": ["8.8.8.8"]}},
    )
    monkeypatch.setattr(dns_hygiene, "_probe_axfr", explode)

    result = check_dns_hygiene(["example.com"], config, tmp_path)
    axfr = result["domains"]["example.com"]["axfr"]
    assert axfr == {"status": "disabled", "reason": "axfr_probe.disabled", "nameservers": []}
    assert result["axfr_probe"] is False


def test_axfr_refuses_a_nameserver_on_a_private_address(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("no zone transfer may be attempted against a private address")

    monkeypatch.setattr(subprocess, "run", explode)

    probe = _probe_axfr("example.com", "ns1.example.com", ["10.0.0.5"], timeout=5)
    assert probe["status"] == "refused"
    assert probe["reason"] == "ns_address_not_public"
    assert probe["records"] == 0


@pytest.mark.parametrize("address", ["127.0.0.1", "169.254.169.254", "::1", "192.168.1.1"])
def test_axfr_refuses_every_non_public_address_class(monkeypatch, address: str):
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: pytest.fail("private nameserver was dialled")
    )
    assert _probe_axfr("example.com", "ns.example.com", [address], timeout=5)["status"] == "refused"


def test_axfr_probes_a_public_nameserver(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout=ZONE_LINE, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    probe = _probe_axfr("example.com", "ns1.example.com", ["93.184.216.34"], timeout=5)
    assert probe["status"] == "open"
    assert probe["records"] == 2
    # Dialled by validated IP literal, not by the name: the address that was
    # checked is the address that is used.
    assert "93.184.216.34:53" in calls[0]


def test_axfr_never_writes_the_zone_to_the_log_or_the_artifact(
    tmp_path: Path, monkeypatch, caplog
):
    def fake_run(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=ZONE_LINE, stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    _patch_dnsx(
        monkeypatch,
        ns={"example.com": {"ns": ["ns1.a.example"]}},
        addresses={"ns1.a.example": {"a": ["93.184.216.34"]}},
    )

    with caplog.at_level(logging.DEBUG):
        result = check_dns_hygiene(
            ["example.com"],
            DnsHygieneConfig(enabled=True, axfr_probe=True),
            tmp_path,
        )

    logged = "\n".join(record.getMessage() for record in caplog.records)
    artifact = (tmp_path / "dns_hygiene.json").read_text(encoding="utf-8")
    for secret in ("internal-db.example.com", "10.0.0.7", "vpn.example.com", "198.51.100.9"):
        assert secret not in logged
        assert secret not in artifact
    # The fact and the count survive; the zone does not.
    assert "zone transfer succeeded for example.com" in logged
    probe = result["domains"]["example.com"]["axfr"]["nameservers"][0]
    assert probe == {"nameserver": "ns1.a.example", "status": "open", "reason": None, "records": 2}
    assert "axfr_open" in _kinds(result)


def test_axfr_closed_nameserver_is_not_a_finding(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, stdout="", stderr=""),
    )
    _patch_dnsx(
        monkeypatch,
        ns={"example.com": {"ns": ["ns1.a.example"]}},
        addresses={"ns1.a.example": {"a": ["93.184.216.34"]}},
    )
    result = check_dns_hygiene(
        ["example.com"], DnsHygieneConfig(enabled=True, axfr_probe=True), tmp_path
    )
    assert result["domains"]["example.com"]["axfr"]["nameservers"][0]["status"] == "closed"
    assert "axfr_open" not in _kinds(result)


def test_count_axfr_records_across_dnsx_shapes():
    assert _count_axfr_records("") == 0
    assert _count_axfr_records(json.dumps({"host": "x", "axfr": ["a", "b", "c"]})) == 3
    assert _count_axfr_records(json.dumps({"host": "x", "all": {"records": ["a"]}})) == 1
    assert _count_axfr_records("not json\nalso not json") == 2


def test_domain_with_no_dns_answer_is_not_checked(tmp_path: Path, monkeypatch):
    _patch_dnsx(monkeypatch)
    result = check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path)
    record = result["domains"]["example.com"]
    assert record["status"] == "not_checked"
    assert record["reason"] == "no_dns_answer"
