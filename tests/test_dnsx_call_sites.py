"""Every dnsx run the scanner starts carries ``-r``.

dnsx 1.2.3 without ``-r`` never reads ``/etc/resolv.conf``: it asks 1.1.1.1,
8.8.8.8, 9.9.9.9, 208.67.222.222 and four more public resolvers directly
(``dnsx.DefaultResolvers``, upstream ``libs/dnsx/dnsx.go``). On a kind cluster
that gives a run of name targets zero records and exit code 0; internal names
never resolve anywhere; and every target name goes to those operators.

The stage tests elsewhere replace the dnsx wrappers wholesale, so none of them
sees an argv. These drive each stage through its real wrappers with only
``run_command`` replaced, and then the pipeline itself, so a new call site
that builds its own argv -- or a stage that stops passing the setting along --
fails here. The AXFR probe is the one dnsx run without ``-r``: it names the
zone's nameserver with ``-resolver`` and is covered in ``test_dns_hygiene.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from scanner import main as scanner_main
from scanner.pipeline import dns_hygiene, dnsx, domain_monitor, hostnames, mail_posture, resolve
from scanner.pipeline.config_schema import (
    DnsHygieneConfig,
    DomainMonitorConfig,
    MailPostureConfig,
)
from scanner.pipeline.errors import StageFailureError

CONFIGURED = ["192.0.2.53", "[2001:db8::53]:5353"]
CONFIGURED_FLAG = "192.0.2.53:53,[2001:db8::53]:5353"
SYSTEM_FLAG = "10.96.0.10:53"

#: What the fake dnsx answers, by the stem of the ``-o`` file each call site
#: writes. Enough for every stage to reach its next lookup: an SPF include to
#: walk, an alive address to PTR.
ANSWERS = {
    "dnsx_records": [{"host": "www.customer.example", "a": ["203.0.113.10"]}],
    "policy_records": [
        {"host": "customer.example", "txt": ["v=spf1 include:_spf.mail.example -all"]}
    ],
}


class FakeDnsx:
    """Stands in for ``utils.run_command`` in every module that starts dnsx."""

    def __init__(self) -> None:
        self.argvs: list[list[str]] = []

    def __call__(self, command, timeout, retries):  # noqa: ANN001
        assert command[0] == "dnsx", command
        self.argvs.append(list(command))
        out = Path(command[command.index("-o") + 1])
        rows = ANSWERS.get(out.name.removesuffix(".jsonl"), [])
        out.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def install(self, monkeypatch) -> FakeDnsx:
        for module in (dnsx, resolve, hostnames, domain_monitor):
            monkeypatch.setattr(module, "run_command", self)
        return self

    def resolver_flags(self) -> list[str]:
        flags = []
        for argv in self.argvs:
            assert argv.count("-r") == 1, argv
            flags.append(argv[argv.index("-r") + 1])
        return flags

    def outputs(self) -> list[str]:
        return [Path(argv[argv.index("-o") + 1]).name for argv in self.argvs]


@pytest.fixture
def system_resolv_conf(tmp_path: Path, monkeypatch) -> Path:
    path = tmp_path / "resolv.conf"
    path.write_text(
        "search network-scan.svc.cluster.local svc.cluster.local\n"
        "nameserver 10.96.0.10\n"
        "options ndots:5\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(dnsx, "RESOLV_CONF", path)
    return path


def _run_every_stage(tmp_path: Path, resolvers: list[str]) -> None:
    out = tmp_path / "out"
    out.mkdir()
    resolve.resolve_fqdns(["www.customer.example"], out, 30, 0, resolvers=resolvers)
    hostnames.reverse_map_from_ptr(
        ["203.0.113.10"], out, timeout=30, retries=0, resolvers=resolvers
    )
    domain_monitor.monitor_domains(
        ["customer.example"],
        ["www.customer.example"],
        DomainMonitorConfig(enabled=True, max_candidates=5),
        out,
        resolvers=resolvers,
    )
    dns_hygiene.check_dns_hygiene(
        ["customer.example"], DnsHygieneConfig(enabled=True), out, resolvers=resolvers
    )
    mail_posture.check_mail_posture(
        ["customer.example"],
        MailPostureConfig(enabled=True, mta_sts_http=False),
        out,
        resolvers=resolvers,
    )


EVERY_RUN = [
    # resolve
    "dnsx_records.jsonl",
    # discover-hostnames
    "ptr.records.jsonl",
    # domain_monitor
    "typosquat_records.jsonl",
    "cname_records.jsonl",
    # dns_hygiene (no NS came back, so no ns_addresses batch)
    "ns_records.jsonl",
    "soa_records.jsonl",
    "caa_records.jsonl",
    "wildcard_records.jsonl",
    # mail_posture, including the SPF include walk
    "mx_records.jsonl",
    "policy_records.jsonl",
    "dkim_records.jsonl",
    "spf_include_records.jsonl",
]


def test_every_call_site_passes_the_configured_resolvers(
    tmp_path: Path, monkeypatch, system_resolv_conf
):
    fake = FakeDnsx().install(monkeypatch)

    _run_every_stage(tmp_path, CONFIGURED)

    assert fake.outputs() == EVERY_RUN
    # The system resolver is in the fixture on purpose: configured wins.
    assert fake.resolver_flags() == [CONFIGURED_FLAG] * len(EVERY_RUN)


def test_every_call_site_falls_back_to_resolv_conf_not_to_dnsx_defaults(
    tmp_path: Path, monkeypatch, system_resolv_conf
):
    fake = FakeDnsx().install(monkeypatch)

    _run_every_stage(tmp_path, [])

    assert fake.outputs() == EVERY_RUN
    assert fake.resolver_flags() == [SYSTEM_FLAG] * len(EVERY_RUN)


def test_without_resolv_conf_every_call_site_asks_the_local_resolver(
    tmp_path: Path, monkeypatch
):
    """libc's answer to a missing resolv.conf, never dnsx's public list."""
    monkeypatch.setattr(dnsx, "RESOLV_CONF", tmp_path / "missing")
    fake = FakeDnsx().install(monkeypatch)

    _run_every_stage(tmp_path, [])

    assert fake.outputs() == EVERY_RUN
    assert fake.resolver_flags() == [dnsx.LOCAL_RESOLVER] * len(EVERY_RUN)


# --- the setting reaches the stages through the pipeline -------------------


class _StopBeforePorts(Exception):
    pass


def test_the_pipeline_hands_dns_resolvers_to_every_dnsx_stage(tmp_path: Path, monkeypatch):
    raw = yaml.safe_load(Path("scanner/config/default.yaml").read_text(encoding="utf-8"))
    assert raw["dns"]["resolvers"] == []  # shipped default: the system's
    raw["runtime"]["output_dir"] = str(tmp_path / "output")
    raw["runtime"]["state_dir"] = str(tmp_path / "state")
    raw["runtime"]["logs_dir"] = str(tmp_path / "output" / "logs")
    raw["dns"]["resolvers"] = CONFIGURED
    # "custom" keeps hostnames.reverse as the file says; the balanced preset
    # that "auto" picks turns the PTR pass off.
    raw["discovery"]["profile"] = "custom"
    raw["discovery"]["hostnames"]["reverse"] = True
    raw["discovery"]["domain_monitor"]["enabled"] = True
    raw["discovery"]["domain_monitor"]["max_candidates"] = 5
    raw["org_profile"]["dns_hygiene"]["enabled"] = True
    raw["org_profile"]["mail_posture"]["enabled"] = True
    raw["org_profile"]["mail_posture"]["mta_sts_http"] = False
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    domains_file = tmp_path / "domains.txt"
    domains_file.write_text("www.customer.example\n", encoding="utf-8")

    fake = FakeDnsx().install(monkeypatch)
    # Discovery would probe the network; say the resolved address is alive so
    # discover-hostnames has something to PTR, and stop at the port scan.
    monkeypatch.setattr(scanner_main, "run_discovery_stage", lambda **kwargs: ["203.0.113.10"])

    def _stop(**kwargs):
        raise _StopBeforePorts

    monkeypatch.setattr(scanner_main, "run_batches_parallel", _stop)
    monkeypatch.setattr(
        "sys.argv",
        [
            "scanner.main",
            "--config",
            str(config_path),
            "--domains",
            str(domains_file),
            "--run-id",
            "20260925T120000Z",
            "--skip-nse",
        ],
    )

    with pytest.raises(StageFailureError) as stopped:
        scanner_main._run_pipeline(scanner_main.parse_args())
    assert isinstance(stopped.value.__cause__, _StopBeforePorts)

    assert fake.outputs() == [
        "dnsx_records.jsonl",
        "typosquat_records.jsonl",
        "cname_records.jsonl",
        "ns_records.jsonl",
        "soa_records.jsonl",
        "caa_records.jsonl",
        "wildcard_records.jsonl",
        "mx_records.jsonl",
        "policy_records.jsonl",
        "dkim_records.jsonl",
        "spf_include_records.jsonl",
        "ptr.records.jsonl",
    ]
    assert fake.resolver_flags() == [CONFIGURED_FLAG] * len(fake.argvs)


def test_resolve_says_so_when_no_resolver_answered(tmp_path: Path, monkeypatch, caplog):
    """dnsx exits 0 with no output at all when no resolver answered (an
    NXDOMAIN still gets a line), so the run log is the only place it shows."""
    monkeypatch.setattr(resolve, "run_command", FakeDnsx())
    monkeypatch.setitem(ANSWERS, "dnsx_records", [])

    assert resolve.resolve_fqdns(["a.corp.example"], tmp_path, 30, 0, resolvers=CONFIGURED) == []
    assert "no resolver answered for any of 1 name(s)" in caplog.text


def test_resolve_stays_quiet_when_the_resolver_answered_nxdomain(tmp_path: Path, monkeypatch, caplog):
    """An NXDOMAIN is an answer: dnsx 1.2.3 writes a line for it."""
    monkeypatch.setattr(resolve, "run_command", FakeDnsx())
    monkeypatch.setitem(
        ANSWERS,
        "dnsx_records",
        [{"host": "gone.corp.example", "status_code": "NXDOMAIN", "status_code_raw": 3}],
    )

    assert resolve.resolve_fqdns(["gone.corp.example"], tmp_path, 30, 0, resolvers=CONFIGURED) == []
    assert "no resolver answered" not in caplog.text
