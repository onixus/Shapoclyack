from __future__ import annotations

import ipaddress
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from scanner import exit_codes
from scanner import main as scanner_main
from scanner.pipeline import dnsx as dnsx_module
from scanner.pipeline import domain_monitor, scan_scope, takeover
from scanner.pipeline.config_schema import ControlsConfig, DomainMonitorConfig
from scanner.pipeline.controls import evaluate_controls
from tests.mtls_pki import CA
from scanner.pipeline.domain_monitor import (
    _classify_dangling_cname,
    _classify_typosquat,
    _generate_typosquat_candidates,
    _split_domain,
    monitor_domains,
)

#: What every stage call below passes as ``resolvers`` and every dnsx fake
#: asserts it received, so a stage that drops the argument fails here.
RESOLVERS = ["192.0.2.53:53"]


@pytest.fixture(autouse=True)
def _takeover_probes_stay_on_loopback(monkeypatch):
    """No test in this module may send the takeover confirmation off the machine.

    A record fake that hands back a routable address with HTTP confirmation on
    would otherwise dial it for real -- it did, to 1.2.3.4, before the test
    that does so was told to switch confirmation off.
    """
    real = takeover.confirm_over_http

    def loopback_only(probes, **kwargs):
        for probe in probes:
            assert ipaddress.ip_address(probe.address).is_loopback, (
                f"takeover probe to {probe.address} would leave the machine"
            )
        return real(probes, **kwargs)

    monkeypatch.setattr(takeover, "confirm_over_http", loopback_only)


def test_domain_monitor_disabled(tmp_path: Path):
    result = monitor_domains(
        ["example.com"], [], DomainMonitorConfig(enabled=False), tmp_path, resolvers=RESOLVERS
    )
    assert result["skipped_reason"] == "domain_monitor.disabled"
    assert (tmp_path / "domain_monitor.json").exists()


def test_domain_monitor_no_domains(tmp_path: Path):
    result = monitor_domains(
        [], [], DomainMonitorConfig(enabled=True), tmp_path, resolvers=RESOLVERS
    )
    assert result["skipped_reason"] == "no_domains"


def test_typosquat_finding_present(tmp_path: Path, monkeypatch):
    candidates = _generate_typosquat_candidates("example.com", max_candidates=50)
    assert candidates
    picked = candidates[0]

    def fake_a_aaaa(domains, output_dir, *, timeout, retries, resolvers):
        assert resolvers == RESOLVERS
        return {picked.lower(): {"a": ["1.2.3.4"], "aaaa": []}}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", fake_a_aaaa)

    result = monitor_domains(
        ["example.com"],
        [],
        DomainMonitorConfig(enabled=True, dangling_cname_enabled=False, max_candidates=50),
        tmp_path,
        resolvers=RESOLVERS,
    )
    findings = result["typosquat"]["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["kind"] == "typosquat_registered"
    assert finding["seed"] == "example.com"
    assert finding["candidate"] == picked
    assert finding["a"] == ["1.2.3.4"]


def test_typosquat_no_finding_when_not_resolved(tmp_path: Path, monkeypatch):
    def fake_a_aaaa(domains, output_dir, *, timeout, retries, resolvers):
        assert resolvers == RESOLVERS
        return {}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", fake_a_aaaa)

    result = monitor_domains(
        ["example.com"],
        [],
        DomainMonitorConfig(enabled=True, dangling_cname_enabled=False, max_candidates=20),
        tmp_path,
        resolvers=RESOLVERS,
    )
    assert result["typosquat"]["findings"] == []


def test_dangling_cname_finding_present(tmp_path: Path, monkeypatch):
    def fake_cname(fqdns, output_dir, *, timeout, retries, resolvers):
        assert resolvers == RESOLVERS
        return {
            "staging.example.com": {
                "cname": ["abandoned.github.io"],
                "a": [],
                "aaaa": [],
                "status": {"A": "NOERROR", "AAAA": "NOERROR"},
            }
        }

    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        [],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, typosquat_enabled=False),
        tmp_path,
        resolvers=RESOLVERS,
    )
    findings = result["dangling_cname"]["findings"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding["kind"] == "subdomain_takeover"
    assert finding["confidence"] == "heuristic"
    assert finding["fqdn"] == "staging.example.com"
    assert finding["cname_target"] == "abandoned.github.io"
    assert finding["matched_suffix"] == "github.io"


def test_dangling_cname_no_finding_when_a_present(tmp_path: Path, monkeypatch):
    def fake_cname(fqdns, output_dir, *, timeout, retries, resolvers):
        assert resolvers == RESOLVERS
        return {
            "staging.example.com": {
                "cname": ["abandoned.github.io"],
                "a": ["1.2.3.4"],
                "aaaa": [],
                "status": {"A": "NOERROR", "AAAA": "NOERROR"},
            }
        }

    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        [],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, typosquat_enabled=False, takeover_http_confirm=False),
        tmp_path,
        resolvers=RESOLVERS,
    )
    assert result["dangling_cname"]["findings"] == []
    [unconfirmed] = result["dangling_cname"]["not_reported"]
    assert unconfirmed["reason"] == "http_confirm_disabled"


def test_dangling_cname_no_finding_when_no_suffix_match(tmp_path: Path, monkeypatch):
    def fake_cname(fqdns, output_dir, *, timeout, retries, resolvers):
        assert resolvers == RESOLVERS
        return {
            "staging.example.com": {
                "cname": ["internal-lb.example-corp.net"],
                "a": [],
                "aaaa": [],
                "status": {"A": "NOERROR", "AAAA": "NOERROR"},
            }
        }

    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        [],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, typosquat_enabled=False),
        tmp_path,
        resolvers=RESOLVERS,
    )
    assert result["dangling_cname"]["findings"] == []


def test_generate_typosquat_candidates_spans_classes_and_caps():
    candidates = _generate_typosquat_candidates("example.com", max_candidates=12)
    assert 0 < len(candidates) <= 12
    assert "example.com" not in candidates

    # Confirm round-robin fairness: candidates from at least 3 different
    # generator classes appear (omission drops a char; keyboard-adjacent
    # substitutes a char but keeps the same length; TLD swap keeps "example").
    has_shorter = any(len(c.split(".")[0]) < len("example") for c in candidates)
    has_tld_swap = any(c.startswith("example.") and c != "example.com" for c in candidates)
    has_same_length_diff_label = any(
        len(c.split(".")[0]) == len("example") and c.split(".")[0] != "example" for c in candidates
    )
    assert sum([has_shorter, has_tld_swap, has_same_length_diff_label]) >= 3


def test_generate_typosquat_candidates_truncates_with_small_cap():
    candidates = _generate_typosquat_candidates("example.com", max_candidates=6)
    assert len(candidates) <= 6
    assert len(candidates) > 0


def test_generate_typosquat_candidates_dedup_no_original():
    candidates = _generate_typosquat_candidates("example.com", max_candidates=500)
    lowered = [c.lower() for c in candidates]
    assert len(lowered) == len(set(lowered))
    assert "example.com" not in lowered


def test_persisted_files_reflect_both_findings(tmp_path: Path, monkeypatch):
    candidates = _generate_typosquat_candidates("example.com", max_candidates=50)
    picked = candidates[0]

    def fake_a_aaaa(domains, output_dir, *, timeout, retries, resolvers):
        assert resolvers == RESOLVERS
        return {picked.lower(): {"a": ["1.2.3.4"], "aaaa": []}}

    def fake_cname(fqdns, output_dir, *, timeout, retries, resolvers):
        assert resolvers == RESOLVERS
        return {
            "staging.example.com": {
                "cname": ["abandoned.github.io"],
                "a": [],
                "aaaa": [],
                "status": {"A": "NOERROR", "AAAA": "NOERROR"},
            }
        }

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", fake_a_aaaa)
    monkeypatch.setattr(domain_monitor, "_run_dnsx_cname", fake_cname)

    result = monitor_domains(
        ["example.com"],
        ["staging.example.com"],
        DomainMonitorConfig(enabled=True, max_candidates=50),
        tmp_path,
        resolvers=RESOLVERS,
    )

    saved = json.loads((tmp_path / "domain_monitor.json").read_text(encoding="utf-8"))
    assert saved["typosquat"]["findings"] == result["typosquat"]["findings"]
    assert saved["dangling_cname"]["findings"] == result["dangling_cname"]["findings"]

    lines = (tmp_path / "domain_monitor_findings.txt").read_text(encoding="utf-8").splitlines()
    assert any(line.startswith(f"typosquat:example.com:{picked}:") for line in lines)
    assert any(
        line == "subdomain_takeover:heuristic:staging.example.com:abandoned.github.io"
        for line in lines
    )


def test_classify_helpers_return_none_when_appropriate():
    assert _classify_typosquat("example.com", "examp1e.com", {"a": [], "aaaa": []}) is None
    assert (
        _classify_dangling_cname(
            "host.example.com",
            {"cname": [], "a": [], "aaaa": [], "status": {"A": "NOERROR", "AAAA": "NOERROR"}},
            takeover.load_catalogue(),
        )
        is None
    )


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("bbc.co.uk", ("bbc", "co.uk")),
        ("example.com.ru", ("example", "com.ru")),
        ("shop.example.com.ru", ("example", "com.ru")),
        ("x.github.io", ("x", "github.io")),
        ("example.com", ("example", "com")),
    ],
)
def test_split_domain_is_registrable_label_and_public_suffix(domain, expected):
    assert _split_domain(domain) == expected


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("co.uk", ("co", "uk")),
        ("github.io", ("github", "io")),
        ("localhost", ("localhost", "")),
        ("192.0.2.1", ("192.0.2", "1")),
    ],
)
def test_split_domain_without_registrable_domain_splits_at_last_dot(domain, expected):
    assert _split_domain(domain) == expected


def _suffix_after_first_label(candidate: str) -> tuple[str, str]:
    label, _, suffix = candidate.partition(".")
    return label, suffix


def test_typosquat_candidates_keep_a_multi_label_suffix_whole():
    candidates = _generate_typosquat_candidates("bbc.co.uk", max_candidates=500)

    assert "bbcc.co.uk" in candidates  # doubling
    assert "vbc.co.uk" in candidates  # keyboard-adjacent
    assert "bbc.com" in candidates  # co.uk swapped as a unit
    assert "bbc.uk" in candidates  # the suffix's own TLD
    assert "bbc.co" in candidates
    assert "bbc.co.com" not in candidates
    swaps = {"uk", "com", "net", "org", "co", "io", "info", "biz", "cc", "xyz"}
    for candidate in candidates:
        label, suffix = _suffix_after_first_label(candidate)
        # Only the label is ever mutated; the suffix is kept or swapped whole.
        assert suffix == "co.uk" or (label == "bbc" and suffix in swaps), candidate


def test_typosquat_candidates_for_a_subdomain_seed_mutate_the_registrable_label():
    candidates = _generate_typosquat_candidates("shop.example.com.ru", max_candidates=500)

    assert "exmaple.com.ru" in candidates
    assert "example.ru" in candidates
    assert "example.com" in candidates
    assert not [c for c in candidates if "shop" in c]


def test_typosquat_candidates_under_a_private_suffix():
    candidates = _generate_typosquat_candidates("x.github.io", max_candidates=500)

    assert "z.github.io" in candidates
    assert "x.io" in candidates
    assert "x.com" in candidates
    assert "xgithub.io" not in candidates
    assert "x.github.com" not in candidates


def test_typosquat_candidates_never_include_the_seeds_own_registrable_domain():
    # Transposing the two b's of "bbc" gives "bbc" back.
    candidates = _generate_typosquat_candidates("www.bbc.co.uk", max_candidates=500)

    assert "bbc.co.uk" not in candidates


def test_org_registrable_domain_is_not_reported_as_its_own_typosquat(tmp_path: Path, monkeypatch):
    def resolve_everything(domains, output_dir, *, timeout, retries, resolvers):
        return {d.lower(): {"a": ["192.0.2.10"], "aaaa": []} for d in domains}

    monkeypatch.setattr(domain_monitor, "_run_dnsx_a_aaaa", resolve_everything)

    result = monitor_domains(
        ["www.bbc.co.uk"],
        [],
        DomainMonitorConfig(enabled=True, dangling_cname_enabled=False, max_candidates=500),
        tmp_path,
        resolvers=RESOLVERS,
    )
    reported = {finding["candidate"] for finding in result["typosquat"]["findings"]}
    assert reported
    assert "bbc.co.uk" not in reported
    assert "bbc.com" in reported


# --- subdomain takeover: catalogue, NXDOMAIN, HTTP confirmation -------------
#
# These drive ``monitor_domains`` with only ``run_command`` replaced, so the
# argv the stage builds is the one the fake answers -- the shapes of a real
# dnsx 1.2.3 run, not whatever a wrapper fake chooses to return.


class Dnsx123:
    """``run_command`` for the stage's dnsx runs, answering as dnsx 1.2.3 does.

    Measured on 2026-10-06 against a stub resolver in the aio image:

    - an A or AAAA query returns the whole CNAME chain, its addresses and an
      rcode, and writes a row even for NXDOMAIN, SERVFAIL and REFUSED;
    - a query that times out writes no row;
    - with several record types in one run, ``status_code`` is the rcode of
      the *last* type asked (A, AAAA, CNAME, ..., TXT in that order);
    - ``-cname`` alone returns the first hop only and never an address;
    - ``cname`` and ``all`` keep the answer section's order.

    A ``zone`` entry: ``cname`` (the chain in resolution order), ``a``,
    ``aaaa``, ``txt``, ``status`` (default NOERROR), ``status_a`` /
    ``status_aaaa`` / ``status_txt`` per type, ``drop`` (a list of types that
    time out, or True for all), ``wire_order`` (the chain's hops in the order
    the answer section lists them). ``by_run`` overrides entries for one run,
    keyed by its output file stem (``nxdomain_recheck``). A name missing from
    the zone does not exist.
    """

    _TYPE_ORDER = ("-a", "-aaaa", "-cname", "-txt")

    def __init__(self, zone: dict[str, dict], by_run: dict[str, dict[str, dict]] | None = None) -> None:
        self.zone = zone
        self.by_run = by_run or {}
        self.argvs: list[list[str]] = []

    def __call__(self, command, timeout, retries):  # noqa: ANN001
        self.argvs.append(list(command))
        assert command[command.index("-r") + 1] == RESOLVERS[0]
        names = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").split()
        out = Path(command[command.index("-o") + 1])
        zone = {**self.zone, **self.by_run.get(out.name.removesuffix("_records.jsonl"), {})}
        asked = [flag for flag in self._TYPE_ORDER if flag in command]
        rows = []
        for name in names:
            entry = zone.get(name, {"status": "NXDOMAIN"})
            drop = entry.get("drop") or []
            answered = [t for t in asked if not (drop is True or t.lstrip("-") in drop)]
            if not answered:
                continue
            chain = list(entry.get("cname", []))
            last = answered[-1].lstrip("-")
            row: dict = {"host": name, "status_code": entry.get(f"status_{last}", entry.get("status", "NOERROR"))}
            if any(t in answered for t in ("-a", "-aaaa")):
                if chain:
                    hops = list(zip([name, *chain[:-1]], chain, strict=True))
                    order = entry.get("wire_order")
                    if order:
                        hops = sorted(hops, key=lambda hop: order.index(hop[1]))
                    row["cname"] = [target for _, target in hops]
                    row["all"] = [f"{owner}.\t60\tIN\tCNAME\t{target}." for owner, target in hops]
                if "-a" in answered and entry.get("a"):
                    row["a"] = list(entry["a"])
                if "-aaaa" in answered and entry.get("aaaa"):
                    row["aaaa"] = list(entry["aaaa"])
            elif "-cname" in answered and chain:
                row["cname"] = chain[:1]
            if "-txt" in answered and entry.get("txt"):
                row["txt"] = list(entry["txt"])
            rows.append(row)
        out.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def lookups(self) -> list[tuple[str, list[str]]]:
        """(output file, record-type flags) of every run, in order."""
        result = []
        for argv in self.argvs:
            flags = [arg for arg in argv if arg in ("-a", "-aaaa", "-cname", "-txt", "-resp")]
            result.append((Path(argv[argv.index("-o") + 1]).name, flags))
        return result

    def asked(self, run: str) -> list[str]:
        """The names one run was asked about (by output file stem)."""
        for argv in self.argvs:
            if Path(argv[argv.index("-o") + 1]).name == f"{run}_records.jsonl":
                return Path(argv[argv.index("-l") + 1]).read_text(encoding="utf-8").split()
        return []


def _takeover_block(
    tmp_path: Path,
    monkeypatch,
    zone: dict[str, dict],
    fqdns: list[str],
    **config: object,
) -> tuple[dict, Dnsx123]:
    address_allowed = config.pop("address_allowed", None)
    by_run = config.pop("by_run", None)
    fake = Dnsx123(zone, by_run)
    monkeypatch.setattr(domain_monitor, "run_command", fake)
    monkeypatch.setattr(dnsx_module, "run_command", fake)
    kwargs = {} if address_allowed is None else {"address_allowed": address_allowed}
    result = monitor_domains(
        [],
        fqdns,
        DomainMonitorConfig(enabled=True, typosquat_enabled=False, **config),
        tmp_path,
        resolvers=RESOLVERS,
        **kwargs,
    )
    return result["dangling_cname"], fake


def test_the_chain_lookup_asks_for_addresses_and_never_for_cname_records(tmp_path, monkeypatch):
    """``-cname`` alone never returns an address, so "no A/AAAA" held for every
    name and every pattern match was reported; beside ``-a`` it hides NXDOMAIN."""
    zone = {"www.example.com": {"cname": ["org.github.io"], "a": ["185.199.108.153"]}}

    _, fake = _takeover_block(
        tmp_path, monkeypatch, zone, ["www.example.com"], takeover_http_confirm=False
    )

    # One record type per run: with both, dnsx reports the rcode of the last only.
    assert fake.lookups()[:2] == [
        ("cname_records.jsonl", ["-a"]),
        ("cname_aaaa_records.jsonl", ["-aaaa"]),
    ]


def test_a_resolving_cname_into_a_claimable_service_is_not_reported_unconfirmed(
    tmp_path, monkeypatch
):
    """A live GitHub Pages site resolves like an abandoned one; without the
    provider's page there is nothing to report, only something to list."""
    zone = {"www.example.com": {"cname": ["org.github.io"], "a": ["185.199.108.153"]}}

    block, _ = _takeover_block(
        tmp_path, monkeypatch, zone, ["www.example.com"], takeover_http_confirm=False
    )

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["service"] == "github_pages"
    assert listed["reason"] == "http_confirm_disabled"
    assert listed["evidence"]["addresses"] == ["185.199.108.153"]


@pytest.mark.parametrize(
    "target",
    [
        "d111111abcdef8.cloudfront.net",
        "example.global.ssl.fastly.net",
        "example.wpengine.com",
        "example.unbouncepages.com",
        "example.zendesk.com",
    ],
)
def test_a_service_that_cannot_be_taken_over_is_not_reported(tmp_path, monkeypatch, target):
    """Five of the fourteen suffixes the stage used to flag belong to services
    that do not allow a takeover; a chain into them is listed, not reported."""
    zone = {"help.example.com": {"cname": [target]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["help.example.com"])

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "service_not_vulnerable"
    assert listed["evidence"]["service_status"] == "not_vulnerable"


def test_a_suffix_matches_only_at_a_label_boundary(tmp_path, monkeypatch):
    zone = {"x.example.com": {"cname": ["pages.evilgithub.io"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["x.example.com"])

    assert block["findings"] == []
    assert block["not_reported"] == []


def test_an_s3_website_endpoint_is_recognised(tmp_path, monkeypatch):
    """The old "s3-website" suffix could never end a real name."""
    target = "assets.example.com.s3-website-eu-west-1.amazonaws.com"
    zone = {"assets.example.com": {"cname": [target]}}

    block, _ = _takeover_block(
        tmp_path, monkeypatch, zone, ["assets.example.com"], takeover_http_confirm=False
    )

    [finding] = block["findings"]
    assert finding["kind"] == "subdomain_takeover"
    assert finding["service"] == "aws_s3"
    assert finding["confidence"] == "heuristic"
    assert finding["cname_target"] == target


def test_heuristic_finding_is_kept_when_http_confirmation_is_off(tmp_path, monkeypatch):
    """The check the stage always made -- claimable service, no address -- still
    reports, with the fields an old reader of the section looks for."""
    zone = {"staging.example.com": {"cname": ["abandoned.github.io"]}}

    block, _ = _takeover_block(
        tmp_path, monkeypatch, zone, ["staging.example.com"], takeover_http_confirm=False
    )

    [finding] = block["findings"]
    assert finding["kind"] == "subdomain_takeover"
    assert finding["confidence"] == "heuristic"
    # GitHub Pages is an edge case (a verified domain cannot be claimed): low.
    assert finding["severity"] == "low"
    assert "Edge case:" in finding["detail"]
    assert finding["fqdn"] == "staging.example.com"
    assert finding["cname_target"] == "abandoned.github.io"
    assert finding["matched_suffix"] == "github.io"
    assert finding["evidence"]["check"] == "cname_pattern"
    assert finding["evidence"]["unconfirmed_reason"] == "no_address"
    assert block["http_probed"] == 0


def test_nxdomain_of_a_claimable_resource_name_is_a_confirmed_takeover(tmp_path, monkeypatch):
    zone = {
        "app.example.com": {
            "cname": ["legacy-app.trafficmanager.net", "old-app.azurewebsites.net"],
            "status": "NXDOMAIN",
        }
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    [finding] = block["findings"]
    assert finding["kind"] == "subdomain_takeover"
    assert finding["confidence"] == "confirmed"
    assert finding["severity"] == "high"
    # NXDOMAIN is about the end of the chain, not the first hop that matched.
    assert finding["cname_target"] == "old-app.azurewebsites.net"
    assert finding["service"] == "azure_app_service"
    evidence = finding["evidence"]
    assert evidence["check"] == "dns_nxdomain"
    assert evidence["nxdomain_names"] == ["old-app.azurewebsites.net"]
    assert evidence["cname_chain"] == ["legacy-app.trafficmanager.net", "old-app.azurewebsites.net"]


def test_an_existing_resource_of_an_nxdomain_service_is_not_reported(tmp_path, monkeypatch):
    zone = {"app.example.com": {"cname": ["live-app.azurewebsites.net"], "a": ["20.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "target_exists"


def test_a_cname_into_an_unregistered_domain_names_what_returned_nxdomain(tmp_path, monkeypatch):
    zone = {
        "promo.example.com": {"cname": ["www.promo-campaign-2019.com"], "status": "NXDOMAIN"},
    }

    block, fake = _takeover_block(tmp_path, monkeypatch, zone, ["promo.example.com"])

    [finding] = block["findings"]
    assert finding["kind"] == "dangling_cname_nxdomain"
    assert finding["severity"] == "high"
    assert finding["cname_target"] == "www.promo-campaign-2019.com"
    evidence = finding["evidence"]
    assert evidence["registrable_domain"] == "promo-campaign-2019.com"
    assert evidence["nxdomain_names"] == ["www.promo-campaign-2019.com", "promo-campaign-2019.com"]
    assert evidence["check"] == "dns_nxdomain"
    # The registrable domain is asked about, and both NXDOMAINs asked again.
    assert fake.asked("registrable") == ["promo-campaign-2019.com"]
    assert fake.asked("nxdomain_recheck") == ["promo-campaign-2019.com", "promo.example.com"]


def test_a_dangling_name_inside_a_registered_domain_is_not_reported(tmp_path, monkeypatch):
    """Only the owner of partner-corp.com can recreate that name."""
    zone = {
        "old.example.com": {"cname": ["gone.partner-corp.com"], "status": "NXDOMAIN"},
        "partner-corp.com": {"status": "NOERROR"},
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["old.example.com"])

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "registrable_domain_exists"
    assert listed["evidence"]["registrable_domain"] == "partner-corp.com"


def test_nxdomain_into_a_service_that_cannot_be_taken_over_is_not_reported(tmp_path, monkeypatch):
    """cloudfront.net is a private PSL suffix: without the catalogue the
    distribution name would be its own "registrable domain", and unregistered."""
    zone = {"cdn.example.com": {"cname": ["d2deleted00000.cloudfront.net"], "status": "NXDOMAIN"}}

    block, fake = _takeover_block(tmp_path, monkeypatch, zone, ["cdn.example.com"])

    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "service_not_vulnerable"
    assert [name for name, _ in fake.lookups()] == ["cname_records.jsonl", "cname_aaaa_records.jsonl"]


# --- the HTTP confirmation, against a provider stand-in on 127.0.0.1 ---------


class _Provider:
    """A provider's front end: one canned answer per Host header."""

    def __init__(self) -> None:
        self.pages: dict[str, tuple[int, dict[str, str], str]] = {}
        self.requests: list[tuple[str, str]] = []
        self.delay = 0.0
        #: Seconds between body bytes; 0 sends the body at once.
        self.drip = 0.0
        #: Hosts whose body never ends: the page, then filler until the client hangs up.
        self.endless: set[str] = set()
        #: Body bytes written per host, as the server saw them leave.
        self.sent: dict[str, int] = {}
        self.in_flight = 0
        self.max_in_flight = 0
        self.lock = threading.Lock()
        self.port = 0
        self.sni: list[str | None] = []


def _handler(provider: _Provider) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            host = self.headers.get("Host", "")
            with provider.lock:
                provider.requests.append((host, self.path))
                provider.in_flight += 1
                provider.max_in_flight = max(provider.max_in_flight, provider.in_flight)
            try:
                time.sleep(provider.delay)
                status, headers, body = provider.pages.get(host, (200, {}, "a live site"))
                payload = body.encode("utf-8")
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                if host in provider.endless:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    chunk = payload + b"x" * 8192
                    deadline = time.monotonic() + 20
                    while time.monotonic() < deadline:
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        provider.sent[host] = provider.sent.get(host, 0) + len(chunk)
                        chunk = b"x" * 8192
                        time.sleep(0.001)
                    return
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if not provider.drip:
                    self.wfile.write(payload)
                    return
                for index in range(len(payload)):
                    self.wfile.write(payload[index : index + 1])
                    self.wfile.flush()
                    time.sleep(provider.drip)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the client gave up on a dripping body, as it should
            finally:
                with provider.lock:
                    provider.in_flight -= 1

        def log_message(self, *args):  # noqa: ANN002
            pass

    return Handler


def _serve(provider: _Provider, tls_context: ssl.SSLContext | None = None):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(provider))
    # The HTTPS attempt against the plain server is expected to fail; keep it quiet.
    server.handle_error = lambda request, client_address: None
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    provider.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def provider():
    """Plain HTTP; the HTTPS attempt at the same port fails its handshake."""
    stand_in = _Provider()
    server, thread = _serve(stand_in)
    yield stand_in
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture
def tls_provider(tmp_path):
    stand_in = _Provider()
    cert_path, key_path = CA().server("127.0.0.1").write(tmp_path, "provider")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)

    def record_sni(_sock, server_name, _context):  # noqa: ANN001
        stand_in.sni.append(server_name)

    context.sni_callback = record_sni
    server, thread = _serve(stand_in, tls_context=context)
    yield stand_in
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _ports(monkeypatch, https: int, http: int) -> None:
    """Point the confirmation at the stand-in provider on 127.0.0.1.

    The stage never dials a loopback answer in production -- that is what a
    sinkholing resolver returns -- so these tests take 127.0.0.0/8 off the
    sinkhole list; ``test_a_sinkhole_answer_is_never_sent_the_request`` runs
    with the real one. raising=False so the same test can run against a build
    without these names and fail on its assertions rather than on this line.
    """
    monkeypatch.setattr(
        domain_monitor, "_TAKEOVER_HTTP_PORTS", (("https", https), ("http", http)), raising=False
    )
    monkeypatch.setattr(
        domain_monitor,
        "_SINKHOLE_NETWORKS",
        tuple(
            ipaddress.ip_network(network) for network in ("0.0.0.0/8", "::/128", "::1/128")
        ),
        raising=False,
    )


GITHUB_UNCLAIMED = (404, {"Content-Type": "text/html"}, "<p>There isn't a GitHub Pages site here.</p>")


def test_the_provider_page_confirms_the_takeover(tmp_path, monkeypatch, provider):
    provider.pages["docs.example.com"] = GITHUB_UNCLAIMED
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["docs.example.com"])

    [finding] = block["findings"]
    assert finding["kind"] == "subdomain_takeover"
    assert finding["confidence"] == "confirmed"
    # Confirmed, but GitHub Pages is an edge case: medium, and the detail says why.
    assert finding["severity"] == "medium"
    service = takeover.load_catalogue().match("example-org.github.io")[0]
    assert finding["detail"].endswith(f"Edge case: {service.note}")
    assert finding["service"] == "github_pages"
    evidence = finding["evidence"]
    assert evidence["check"] == "http_fingerprint"
    assert evidence["fingerprint_id"] == "github_pages.no_site"
    assert evidence["http_status"] == 404
    assert evidence["http_scheme"] == "http"
    assert evidence["address"] == "127.0.0.1"
    assert [attempt["scheme"] for attempt in evidence["attempts"]] == ["https", "http"]
    assert evidence["attempts"][0]["error"] is not None
    # Asked for the org's own name, at the address its lookup returned.
    assert provider.requests == [("docs.example.com", "/")]


def test_a_live_resource_without_the_fingerprint_is_not_reported(tmp_path, monkeypatch, provider):
    provider.pages["www.example.com"] = (200, {}, "<h1>Our docs</h1>")
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"www.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["www.example.com"])

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "fingerprint_not_matched"
    assert listed["evidence"]["http_status"] == 200


def test_confirmation_over_https_sends_the_org_name_as_sni_and_host(
    tmp_path, monkeypatch, tls_provider
):
    """Providers route HTTPS by SNI: a request naming the IP would get their
    default site, not the answer for the org's name."""
    tls_provider.pages["shop.example.com"] = (
        200,
        {},
        "<title>Store</title>Sorry, this shop is currently unavailable.",
    )
    _ports(monkeypatch, tls_provider.port, _closed_port())
    zone = {"shop.example.com": {"cname": ["shops.myshopify.com"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["shop.example.com"])

    [finding] = block["findings"]
    assert finding["confidence"] == "confirmed"
    assert finding["evidence"]["http_scheme"] == "https"
    assert finding["evidence"]["fingerprint_id"] == "shopify.shop_unavailable"
    assert tls_provider.sni == ["shop.example.com"]
    assert tls_provider.requests == [("shop.example.com", "/")]


def test_no_answer_is_inconclusive_and_not_a_finding(tmp_path, monkeypatch):
    port = _closed_port()
    _ports(monkeypatch, port, port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["docs.example.com"])

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "http_inconclusive"
    assert [attempt["error"] is not None for attempt in listed["evidence"]["attempts"]] == [
        True,
        True,
    ]


def test_a_redirect_is_not_followed(tmp_path, monkeypatch, provider):
    provider.pages["docs.example.com"] = (302, {"Location": "/elsewhere"}, "")
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["docs.example.com"])

    assert provider.requests == [("docs.example.com", "/")]
    assert block["not_reported"][0]["evidence"]["http_status"] == 302


def test_only_the_head_of_the_body_is_read(tmp_path, monkeypatch, provider):
    """Error pages carry their marker near the top; a marker past the cap is
    in a large live page, and the rest of that page is never downloaded."""
    filler = "x" * (takeover.BODY_MAX_BYTES + 1024)
    provider.pages["docs.example.com"] = (404, {}, filler + "There isn't a GitHub Pages site here.")
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["docs.example.com"])

    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "fingerprint_not_matched"


def test_a_dripping_body_is_cut_off_by_the_deadline(tmp_path, monkeypatch, provider):
    """httpx's timeout is per read; a byte every half second never trips it."""
    provider.pages["docs.example.com"] = GITHUB_UNCLAIMED
    provider.drip = 0.5
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    started = time.monotonic()
    block, _ = _takeover_block(
        tmp_path, monkeypatch, zone, ["docs.example.com"], takeover_http_timeout_seconds=2
    )

    # The 44-byte body would take 22 s to arrive; the deadline is 2 s per attempt.
    assert time.monotonic() - started < 10
    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "http_inconclusive"
    assert listed["evidence"]["attempts"][1]["error"] == "TimeoutError"


def test_an_address_the_scope_denies_is_never_contacted(tmp_path, monkeypatch, provider):
    provider.pages["docs.example.com"] = GITHUB_UNCLAIMED
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(
        tmp_path,
        monkeypatch,
        zone,
        ["docs.example.com"],
        address_allowed=lambda address: address != "127.0.0.1",
    )

    assert provider.requests == []
    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "address_refused_by_scope"


def test_confirmation_off_sends_nothing(tmp_path, monkeypatch, provider):
    provider.pages["docs.example.com"] = GITHUB_UNCLAIMED
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(
        tmp_path, monkeypatch, zone, ["docs.example.com"], takeover_http_confirm=False
    )

    assert provider.requests == []
    assert block["http_confirm"] is False
    assert block["not_reported"][0]["reason"] == "http_confirm_disabled"


def test_confirmation_requests_are_bounded_by_the_pool(tmp_path, monkeypatch, provider):
    provider.delay = 0.2
    _ports(monkeypatch, provider.port, provider.port)
    names = [f"site{i}.example.com" for i in range(6)]
    zone = {
        name: {"cname": [f"org{i}.github.io"], "a": ["127.0.0.1"]} for i, name in enumerate(names)
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, names, takeover_http_concurrency=2)

    assert block["http_probed"] == 6
    assert len(provider.requests) == 6
    assert 1 <= provider.max_in_flight <= 2


def test_the_http_target_cap_is_reported_as_truncation(tmp_path, monkeypatch, provider):
    _ports(monkeypatch, provider.port, provider.port)
    names = [f"site{i}.example.com" for i in range(3)]
    zone = {
        name: {"cname": [f"org{i}.github.io"], "a": ["127.0.0.1"]} for i, name in enumerate(names)
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, names, takeover_http_max_targets=2)

    assert block["truncated"] is True
    assert block["http_probed"] == 2
    assert len(provider.requests) == 2
    reasons = sorted(entry["reason"] for entry in block["not_reported"])
    assert reasons == ["fingerprint_not_matched", "fingerprint_not_matched", "http_target_cap"]


def test_a_confirmed_takeover_fails_the_dns_structure_control(tmp_path, monkeypatch, provider):
    """The finding carries its severity, so the controls matrix stops reading
    every takeover as the "medium" it used to default to."""
    provider.pages["docs.example.com"] = (404, {}, "<h1>project not found</h1>")
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["na-west1.surge.sh"], "a": ["127.0.0.1"]}}

    _takeover_block(tmp_path, monkeypatch, zone, ["docs.example.com"])

    controls = evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]
    dns = {control["control"]: control for control in controls}["dns_structure"]
    assert dns["status"] == "fail"
    assert dns["findings_by_severity"]["high"] == 1
    assert dns["top_findings"][0]["id"] == "subdomain_takeover"


# --- DNS answers a verdict cannot rest on -----------------------------------


def test_an_address_from_either_query_means_the_name_resolves(tmp_path, monkeypatch):
    """Measured live: ``-a -aaaa`` reported this name NXDOMAIN with an A record,
    because the AAAA query ran last. Some servers do answer AAAA that way."""
    zone = {
        "app.example.com": {
            "cname": ["live-app.azurewebsites.net"],
            "a": ["20.0.0.1"],
            "status_a": "NOERROR",
            "status_aaaa": "NXDOMAIN",
        }
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "target_exists"
    assert listed["evidence"]["dns_status_by_type"] == {"A": "NOERROR", "AAAA": "NXDOMAIN"}


def test_nxdomain_needs_both_record_types(tmp_path, monkeypatch):
    """The reverse: an A NXDOMAIN that ``-a -aaaa`` hid behind the AAAA NOERROR."""
    zone = {
        "app.example.com": {
            "cname": ["gone-app.azurewebsites.net"],
            "status_a": "NXDOMAIN",
            "status_aaaa": "NOERROR",
        }
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "dns_inconclusive"
    assert block["dns_unanswered"] == ["app.example.com"]


@pytest.mark.parametrize("rcode", ["SERVFAIL", "REFUSED"])
@pytest.mark.parametrize(
    "target",
    ["org.github.io", "gone-app.azurewebsites.net", "gone.retired-partner.com"],
)
def test_an_error_answer_decides_nothing_for_any_service(tmp_path, monkeypatch, rcode, target):
    """dnsx writes a row with the partial chain on SERVFAIL and REFUSED."""
    zone = {"app.example.com": {"cname": [target], "status": rcode}}

    block, fake = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "dns_inconclusive"
    assert fake.asked("registrable") == []
    assert fake.asked("nxdomain_recheck") == []


def test_a_timed_out_query_type_makes_the_name_inconclusive(tmp_path, monkeypatch):
    zone = {
        "app.example.com": {
            "cname": ["gone-app.azurewebsites.net"],
            "status": "NXDOMAIN",
            "drop": ["a"],
        }
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "dns_inconclusive"


def test_names_dnsx_wrote_no_row_for_are_listed_and_the_control_is_not_ok(tmp_path, monkeypatch):
    """A dead resolver: dnsx exits 0 and writes nothing. That is not a clean bill."""
    zone = {"app.example.com": {"drop": True}, "docs.example.com": {"drop": True}}
    fake = Dnsx123(zone)
    monkeypatch.setattr(domain_monitor, "run_command", fake)
    monkeypatch.setattr(dnsx_module, "run_command", fake)

    result = monitor_domains(
        ["example.com"],
        ["app.example.com", "docs.example.com"],
        DomainMonitorConfig(enabled=True, typosquat_enabled=False),
        tmp_path,
        resolvers=RESOLVERS,
    )

    block = result["dangling_cname"]
    assert [entry["reason"] for entry in block["not_reported"]] == ["dns_no_answer", "dns_no_answer"]
    assert block["dns_unanswered"] == ["app.example.com", "docs.example.com"]
    controls = evaluate_controls(tmp_path, ControlsConfig(enabled=True))["controls"]
    dns = {control["control"]: control for control in controls}["dns_structure"]
    assert dns["status"] == "not_checked"
    assert "2 in-scope name(s) got no usable DNS answer" in dns["why"]


def test_the_chain_is_walked_not_read_in_answer_order(tmp_path, monkeypatch):
    """Live dnsx keeps the answer section's order; a reversed answer used to
    make the first hop look like the name that does not exist."""
    zone = {
        "app.example.com": {
            "cname": ["a.trafficmanager.net", "b.azurewebsites.net", "c.cloudapp.net"],
            "wire_order": ["c.cloudapp.net", "b.azurewebsites.net", "a.trafficmanager.net"],
            "status": "NXDOMAIN",
        }
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    [finding] = block["findings"]
    assert finding["cname_target"] == "c.cloudapp.net"
    assert finding["evidence"]["cname_chain"] == [
        "a.trafficmanager.net",
        "b.azurewebsites.net",
        "c.cloudapp.net",
    ]


# --- NXDOMAIN confirmations: asked twice, and only where it means "free" -----


def test_an_nxdomain_that_does_not_repeat_is_not_confirmed(tmp_path, monkeypatch):
    zone = {"app.example.com": {"cname": ["old-app.azurewebsites.net"], "status": "NXDOMAIN"}}
    flapped = {"app.example.com": {"cname": ["old-app.azurewebsites.net"], "a": ["20.0.0.1"]}}

    block, fake = _takeover_block(
        tmp_path, monkeypatch, zone, ["app.example.com"], by_run={"nxdomain_recheck": flapped}
    )

    assert fake.asked("nxdomain_recheck") == ["app.example.com"]
    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "nxdomain_not_repeated"
    assert listed["evidence"]["recheck"] == {"app.example.com": "NOERROR"}


def test_an_app_service_name_with_a_verification_record_is_not_a_takeover(tmp_path, monkeypatch):
    zone = {
        "app.example.com": {"cname": ["old-app.azurewebsites.net"], "status": "NXDOMAIN"},
        "asuid.app.example.com": {"txt": ["0123456789ABCDEF"]},
    }

    block, fake = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    assert fake.asked("asuid") == ["asuid.app.example.com"]
    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "domain_verified"


def test_an_app_service_name_without_one_is_confirmed_high(tmp_path, monkeypatch):
    zone = {"app.example.com": {"cname": ["old-app.azurewebsites.net"], "status": "NXDOMAIN"}}

    block, fake = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    [finding] = block["findings"]
    assert (finding["confidence"], finding["severity"]) == ("confirmed", "high")
    assert finding["evidence"]["recheck"] == {"app.example.com": "NXDOMAIN"}
    assert fake.asked("asuid") == ["asuid.app.example.com"]


def test_an_unanswered_verification_lookup_decides_nothing(tmp_path, monkeypatch):
    zone = {
        "app.example.com": {"cname": ["old-app.azurewebsites.net"], "status": "NXDOMAIN"},
        "asuid.app.example.com": {"status": "SERVFAIL"},
    }

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["app.example.com"])

    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "dns_inconclusive"


@pytest.mark.parametrize(
    "target",
    [
        "abc123defg.execute-api.us-east-1.amazonaws.com",
        "happy-river-0a1b2c3.azurestaticapps.net",
        "abcdefghijk.lambda-url.us-east-1.on.aws",
    ],
)
def test_nxdomain_at_an_unknown_hosting_platform_is_low(tmp_path, monkeypatch, target):
    """Under a private PSL suffix the "registrable domain" is the platform's
    tenant name; nobody can register it, and whether the platform lets a
    stranger re-create it is unknown -- so neither "free to register" nor high."""
    zone = {"api.example.com": {"cname": [target], "status": "NXDOMAIN"}}

    block, fake = _takeover_block(tmp_path, monkeypatch, zone, ["api.example.com"])

    [finding] = block["findings"]
    assert finding["kind"] == "dangling_cname"
    assert (finding["confidence"], finding["severity"]) == ("heuristic", "low")
    assert "provider we don't know" in finding["detail"]
    assert "check whether the name can be re-created" in finding["detail"]
    assert fake.asked("registrable") == []


@pytest.mark.parametrize(
    "target",
    ["vpn01.corp.local", "portal.internal", "nas.home.arpa", "srv.corp", "files.lan", "x.test"],
)
def test_a_name_nobody_can_register_is_not_reported_as_unregistered(tmp_path, monkeypatch, target):
    zone = {"intra.example.com": {"cname": [target], "status": "NXDOMAIN"}}

    block, fake = _takeover_block(tmp_path, monkeypatch, zone, ["intra.example.com"])

    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "target_not_registrable"
    assert fake.asked("registrable") == []


def test_a_target_that_is_its_own_registrable_domain_is_still_asked_about(tmp_path, monkeypatch):
    """No shortcut from "the chain's end is NXDOMAIN" to "the domain is free"."""
    zone = {"promo.example.com": {"cname": ["promo-campaign-2019.com"], "status": "NXDOMAIN"}}
    answered = {"promo-campaign-2019.com": {"status": "NOERROR"}}

    block, fake = _takeover_block(
        tmp_path, monkeypatch, zone, ["promo.example.com"], by_run={"registrable": answered}
    )

    assert fake.asked("registrable") == ["promo-campaign-2019.com"]
    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == "registrable_domain_exists"


@pytest.mark.parametrize(
    ("answer", "reason"),
    [({"drop": True}, "dns_no_answer"), ({"status": "SERVFAIL"}, "dns_inconclusive")],
)
def test_an_unusable_answer_about_the_registrable_domain_decides_nothing(
    tmp_path, monkeypatch, answer, reason
):
    zone = {"promo.example.com": {"cname": ["www.promo-campaign-2019.com"], "status": "NXDOMAIN"}}

    block, fake = _takeover_block(
        tmp_path,
        monkeypatch,
        zone,
        ["promo.example.com"],
        by_run={"registrable": {"promo-campaign-2019.com": answer}},
    )

    assert block["findings"] == []
    assert block["not_reported"][0]["reason"] == reason
    assert fake.asked("nxdomain_recheck") == []


def test_an_unregistered_domain_that_reappears_on_the_second_ask_is_not_reported(
    tmp_path, monkeypatch
):
    zone = {"promo.example.com": {"cname": ["www.promo-campaign-2019.com"], "status": "NXDOMAIN"}}
    reappeared = {"promo-campaign-2019.com": {"status": "NOERROR"}}

    block, _ = _takeover_block(
        tmp_path,
        monkeypatch,
        zone,
        ["promo.example.com"],
        by_run={"nxdomain_recheck": reappeared},
    )

    assert block["findings"] == []
    [listed] = block["not_reported"]
    assert listed["reason"] == "nxdomain_not_repeated"
    assert listed["evidence"]["recheck"] == {
        "promo.example.com": "NXDOMAIN",
        "promo-campaign-2019.com": "NOERROR",
    }


# --- what the confirmation request may and may not do ------------------------


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "127.53.0.1", "::1", "::"])
def test_a_sinkhole_answer_is_never_sent_the_request(tmp_path, monkeypatch, provider, address):
    """A filtering resolver answers 0.0.0.0 or loopback for what it blocks; the
    GET would land on the sensor itself and say nothing about the provider."""
    provider.pages["docs.example.com"] = GITHUB_UNCLAIMED
    monkeypatch.setattr(
        domain_monitor, "_TAKEOVER_HTTP_PORTS", (("https", provider.port), ("http", provider.port))
    )
    family = "aaaa" if ":" in address else "a"
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], family: [address]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["docs.example.com"])

    assert provider.requests == []
    assert block["not_reported"][0]["reason"] == "sinkholed"


def test_the_environment_proxy_is_not_used(tmp_path, monkeypatch, provider):
    """The request is pinned to the address just resolved; a proxy would resolve
    the name again, and here it would also be a dead end."""
    provider.pages["docs.example.com"] = GITHUB_UNCLAIMED
    _ports(monkeypatch, provider.port, provider.port)
    dead_proxy = f"http://127.0.0.1:{_closed_port()}"
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(variable, dead_proxy)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    block, _ = _takeover_block(tmp_path, monkeypatch, zone, ["docs.example.com"])

    [finding] = block["findings"]
    assert finding["confidence"] == "confirmed"
    assert provider.requests == [("docs.example.com", "/")]


def test_an_endless_body_is_cut_at_the_cap_not_at_the_deadline(tmp_path, monkeypatch, provider):
    """The page marker comes first; reading on past 64 KiB would run into the
    deadline and lose the confirmation."""
    provider.pages["docs.example.com"] = GITHUB_UNCLAIMED
    provider.endless.add("docs.example.com")
    _ports(monkeypatch, provider.port, provider.port)
    zone = {"docs.example.com": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}

    started = time.monotonic()
    block, _ = _takeover_block(
        tmp_path, monkeypatch, zone, ["docs.example.com"], takeover_http_timeout_seconds=2
    )

    assert time.monotonic() - started < 2
    [finding] = block["findings"]
    assert finding["evidence"]["fingerprint_id"] == "github_pages.no_site"


def _pipeline_config(tmp_path: Path) -> Path:
    raw = yaml.safe_load(Path("scanner/config/default.yaml").read_text(encoding="utf-8"))
    raw["runtime"]["output_dir"] = str(tmp_path / "output")
    raw["runtime"]["state_dir"] = str(tmp_path / "state")
    raw["runtime"]["logs_dir"] = str(tmp_path / "output" / "logs")
    raw["dns"]["resolvers"] = ["192.0.2.53"]
    raw["discovery"]["domain_monitor"]["enabled"] = True
    raw["discovery"]["domain_monitor"]["typosquat_enabled"] = False
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return config_path


def test_the_pipeline_never_sends_the_request_to_an_address_the_scope_denies(
    tmp_path, monkeypatch, provider
):
    """End to end through scanner.main: the deny-only scope filter reaches the
    stage, and its refusal lands in the denials artifact with the others."""
    provider.pages["docs.customer.example"] = GITHUB_UNCLAIMED
    _ports(monkeypatch, provider.port, provider.port)
    fake = Dnsx123(
        {"docs.customer.example": {"cname": ["example-org.github.io"], "a": ["127.0.0.1"]}}
    )
    monkeypatch.setattr(domain_monitor, "run_command", fake)
    monkeypatch.setattr(dnsx_module, "run_command", fake)
    # The scan targets themselves are not under test: none, so the run ends at
    # its own "no targets" gate right after writing the denials.
    monkeypatch.setattr(scanner_main, "resolve_fqdns", lambda *args, **kwargs: [])
    monkeypatch.setattr(scanner_main, "run_discovery_stage", lambda **kwargs: [])
    document = {
        "version": scan_scope.DOCUMENT_VERSION,
        "tenant_id": "acme",
        "approved": True,
        "entries": [
            {"effect": "allow", "kind": "domain", "value": "customer.example"},
            {"effect": "deny", "kind": "cidr", "value": "127.0.0.1/32"},
        ],
    }
    scope_file = tmp_path / "scan_scope.json"
    scope_file.write_text(json.dumps(document), encoding="utf-8")
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("docs.customer.example\n", encoding="utf-8")
    ranges_file = tmp_path / "ranges.txt"
    ranges_file.write_text("\n", encoding="utf-8")
    monkeypatch.setattr(
        "sys.argv",
        [
            "scanner.main",
            "--config", str(_pipeline_config(tmp_path)),
            "--ranges", str(ranges_file),
            "--domains", str(domains_file),
            "--run-id", "20261006T120000Z",
            "--skip-nse",
            "--scan-scope", str(scope_file),
        ],
    )

    assert scanner_main._run_pipeline(scanner_main.parse_args()) == exit_codes.INPUT_ERROR

    run_dir = tmp_path / "output" / "runs" / "20261006T120000Z"
    block = json.loads((run_dir / "domain_monitor.json").read_text(encoding="utf-8"))["dangling_cname"]
    assert provider.requests == []
    assert block["not_reported"][0]["reason"] == "address_refused_by_scope"
    denials = json.loads((run_dir / scan_scope.DENIED_ARTIFACT).read_text(encoding="utf-8"))
    assert "resolved -> 127.0.0.1 (denied by 127.0.0.1/32)" in denials["denied"]
