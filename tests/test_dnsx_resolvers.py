"""Every dnsx run names its resolvers with ``-r``.

dnsx v1.2.3 without ``-r`` asks only its eight built-in public resolvers and
never the system one. On the kind stand, the ``resolve`` stage's own command
sent ``kubernetes.default.svc.cluster.local`` to 8.8.8.8 and 1.0.0.1 and got
nothing back; with ``-r 10.96.0.10`` the name resolved. So each test below
pins the whole argv of one dnsx call site, for the system resolver (the
default, ``dns.resolvers: []``) and for a configured list.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from scanner.pipeline import dns_resolvers, dnsx, domain_monitor, hostnames, resolve
from scanner.pipeline.config_schema import (
    DiscoveryConfig,
    DnsHygieneConfig,
    DomainMonitorConfig,
    HostnameResolveConfig,
    MailPostureConfig,
)
from scanner.pipeline.dns_hygiene import check_dns_hygiene
from scanner.pipeline.domain_monitor import monitor_domains
from scanner.pipeline.hostnames import enrich_discovery_hostnames
from scanner.pipeline.mail_posture import check_mail_posture
from scanner.pipeline.resolve import resolve_fqdns

REPO = Path(__file__).resolve().parents[1]

#: ``(dns.resolvers, the -r value dnsx must get)``. The first is the config
#: default, which means the resolv.conf below.
CASES = pytest.mark.parametrize(
    ("resolvers", "r_value"),
    [
        pytest.param([], "10.96.0.10:53", id="system"),
        pytest.param(
            ["10.20.0.53", "2001:db8::53", "[2001:db8::54]:5353", "10.20.0.54:5353"],
            # Order kept, IPv6 bracketed, every port explicit: dnsx appends
            # ":53" only to an entry with no colon in it.
            "10.20.0.53:53,[2001:db8::53]:53,[2001:db8::54]:5353,10.20.0.54:5353",
            id="configured",
        ),
    ],
)


@pytest.fixture(autouse=True)
def _kind_resolv_conf(tmp_path: Path, monkeypatch) -> None:
    """The pod's resolv.conf on the kind stand, so no test reads the host's."""
    path = tmp_path / "resolv.conf"
    path.write_text(
        "search default.svc.cluster.local svc.cluster.local cluster.local\n"
        "nameserver 10.96.0.10\n"
        "options ndots:5\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dns_resolvers, "RESOLV_CONF", path)


class _Dnsx:
    """Stands in for ``run_command``: records each argv, answers from canned JSONL.

    ``answers`` is keyed by the name of the ``-o`` file.
    """

    def __init__(self, answers: dict[str, list[dict]] | None = None) -> None:
        self.argvs: list[list[str]] = []
        self.answers = answers or {}

    def __call__(self, command, *, timeout, retries):
        self.argvs.append(list(command))
        out = Path(command[command.index("-o") + 1])
        lines = self.answers.get(out.name, [])
        out.write_text("".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8")


def _argv(targets: Path, flags: list[str], r_value: str, out: Path) -> list[str]:
    return [
        "dnsx",
        "-l", str(targets),
        *flags,
        "-r", r_value,
        "-json",
        "-silent",
        "-disable-update-check",
        "-o", str(out),
    ]  # fmt: skip


@CASES
def test_resolve_stage(tmp_path: Path, monkeypatch, resolvers, r_value):
    fake = _Dnsx(
        {"dnsx_records.jsonl": [{"host": "kubernetes.default.svc.cluster.local", "a": ["10.96.0.1"]}]}
    )
    monkeypatch.setattr(resolve, "run_command", fake)

    ips = resolve_fqdns(
        ["kubernetes.default.svc.cluster.local"], tmp_path, 5, 1, resolvers=resolvers
    )

    assert fake.argvs == [
        [
            "dnsx",
            "-l", str(tmp_path / "normalized" / "fqdn_targets.txt"),
            "-a",
            "-aaaa",
            "-r", r_value,
            "-json",
            "-silent",
            "-disable-update-check",
            "-o", str(tmp_path / "dnsx_records.jsonl"),
        ]
    ]  # fmt: skip
    assert ips == ["10.96.0.1"]


def test_resolve_stage_called_without_resolvers_still_names_the_system_one(
    tmp_path: Path, monkeypatch
):
    fake = _Dnsx()
    monkeypatch.setattr(resolve, "run_command", fake)

    resolve_fqdns(["kubernetes.default.svc.cluster.local"], tmp_path, 5, 1)

    [argv] = fake.argvs
    assert argv[argv.index("-r") + 1] == "10.96.0.10:53"


@CASES
def test_ptr_lookup(tmp_path: Path, monkeypatch, resolvers, r_value):
    fake = _Dnsx(
        {"ptr.records.jsonl": [{"host": "10.96.0.1", "ptr": ["kubernetes.default.svc.cluster.local."]}]}
    )
    monkeypatch.setattr(hostnames, "run_command", fake)

    result = enrich_discovery_hostnames(
        ["10.96.0.1"],
        tmp_path,
        DiscoveryConfig(hostnames=HostnameResolveConfig(forward=False, reverse=True)),
        timeout=5,
        retries=1,
        resolvers=resolvers,
    )

    batch = tmp_path / "discover"
    assert fake.argvs == [
        _argv(batch / "ptr.targets.txt", ["-ptr"], r_value, batch / "ptr.records.jsonl")
    ]
    assert result["10.96.0.1"]["reverse"] == ["kubernetes.default.svc.cluster.local"]


@CASES
def test_domain_monitor_typosquat_and_dangling_cname(tmp_path: Path, monkeypatch, resolvers, r_value):
    fake = _Dnsx()
    monkeypatch.setattr(domain_monitor, "run_command", fake)

    monitor_domains(
        ["example.com"],
        ["www.example.com"],
        DomainMonitorConfig(enabled=True, max_candidates=3),
        tmp_path,
        resolvers=resolvers,
    )

    batch = tmp_path / "domain_monitor"
    assert fake.argvs == [
        _argv(batch / "typosquat_targets.txt", ["-a", "-aaaa"], r_value, batch / "typosquat_records.jsonl"),
        _argv(batch / "cname_targets.txt", ["-cname", "-resp"], r_value, batch / "cname_records.jsonl"),
    ]


@CASES
def test_dns_hygiene_every_lookup(tmp_path: Path, monkeypatch, resolvers, r_value):
    # An NS answer, so the nameserver-address batch runs too.
    fake = _Dnsx({"ns_records.jsonl": [{"host": "example.com", "ns": ["ns1.example.net"]}]})
    monkeypatch.setattr(dnsx, "run_command", fake)

    check_dns_hygiene(["example.com"], DnsHygieneConfig(enabled=True), tmp_path, resolvers=resolvers)

    batch = tmp_path / "dns_hygiene"
    assert fake.argvs == [
        _argv(batch / "ns_targets.txt", ["-ns"], r_value, batch / "ns_records.jsonl"),
        _argv(batch / "soa_targets.txt", ["-soa"], r_value, batch / "soa_records.jsonl"),
        _argv(batch / "caa_targets.txt", ["-caa"], r_value, batch / "caa_records.jsonl"),
        _argv(
            batch / "ns_addresses_targets.txt",
            ["-a", "-aaaa"],
            r_value,
            batch / "ns_addresses_records.jsonl",
        ),
        _argv(batch / "wildcard_targets.txt", ["-a", "-aaaa"], r_value, batch / "wildcard_records.jsonl"),
    ]


@CASES
def test_mail_posture_every_lookup(tmp_path: Path, monkeypatch, resolvers, r_value):
    # An SPF include, so the include walk runs its own batch too.
    fake = _Dnsx(
        {"policy_records.jsonl": [{"host": "example.com", "txt": ["v=spf1 include:_spf.example.net -all"]}]}
    )
    monkeypatch.setattr(dnsx, "run_command", fake)

    check_mail_posture(
        ["example.com"],
        MailPostureConfig(enabled=True, mta_sts_http=False, dkim_selectors=["s1"]),
        tmp_path,
        resolvers=resolvers,
    )

    batch = tmp_path / "mail_posture"
    assert fake.argvs == [
        _argv(batch / "mx_targets.txt", ["-mx"], r_value, batch / "mx_records.jsonl"),
        _argv(batch / "policy_targets.txt", ["-txt"], r_value, batch / "policy_records.jsonl"),
        _argv(batch / "dkim_targets.txt", ["-txt"], r_value, batch / "dkim_records.jsonl"),
        _argv(batch / "spf_include_targets.txt", ["-txt"], r_value, batch / "spf_include_records.jsonl"),
    ]


def test_dnsx_query_without_any_nameserver_asks_loopback_not_the_public_list(
    tmp_path: Path, monkeypatch
):
    """No ``nameserver`` line still yields ``-r``: leaving it out means dnsx's public eight."""
    monkeypatch.setattr(dns_resolvers, "RESOLV_CONF", tmp_path / "missing")
    fake = _Dnsx()
    monkeypatch.setattr(dnsx, "run_command", fake)

    dnsx.query(
        ["example.com"],
        tmp_path,
        stage="s",
        kind="ns",
        flags=["-ns"],
        timeout=5,
        retries=0,
        resolvers=[],
    )

    batch = tmp_path / "s"
    assert fake.argvs == [
        _argv(batch / "ns_targets.txt", ["-ns"], "127.0.0.1:53", batch / "ns_records.jsonl")
    ]


@pytest.mark.parametrize(
    "stage",
    [
        "resolve_fqdns",
        "enrich_discovery_hostnames",
        "monitor_domains",
        "check_dns_hygiene",
        "check_mail_posture",
    ],
)
def test_the_pipeline_hands_every_dnsx_stage_the_configured_resolvers(stage: str):
    """``scanner/main.py`` must pass ``config.dns.resolvers`` to each dnsx stage.

    Leaving it out would still use the system resolvers, not the public ones,
    but ``dns.resolvers`` would then do nothing for that stage, and no run
    would show it.
    """
    tree = ast.parse((REPO / "scanner" / "main.py").read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == stage
    ]
    assert len(calls) == 1, f"expected exactly one {stage} call in scanner/main.py"
    passed = {kw.arg: ast.unparse(kw.value) for kw in calls[0].keywords}
    assert passed.get("resolvers") == "config.dns.resolvers"


def test_no_dnsx_command_in_the_scanner_goes_without_resolvers():
    """A dnsx argv written as a list literal must splat ``dnsx_resolver_args``.

    Catches the next call site, which the tests above cannot know about.
    """
    checked: list[str] = []
    missing: list[str] = []
    for path in sorted((REPO / "scanner").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (
                isinstance(node, ast.List)
                and node.elts
                and isinstance(node.elts[0], ast.Constant)
                and node.elts[0].value == "dnsx"
            ):
                continue
            where = f"{path.relative_to(REPO)}:{node.lineno}"
            checked.append(where)
            if not any(
                isinstance(elt, ast.Starred)
                and isinstance(elt.value, ast.Call)
                and isinstance(elt.value.func, ast.Name)
                and elt.value.func.id == "dnsx_resolver_args"
                for elt in node.elts
            ):
                missing.append(where)
    # resolve, hostnames, domain_monitor (two) and dnsx.query at the least.
    assert len(checked) >= 5, checked
    assert missing == []
