"""L2 discovery through Pulse (#542).

``tests/fixtures/l2_discovery`` holds a real Pulse 1.3.0 run on one Docker
bridge (addresses rewritten to 10.0.0.x): live hosts 10.0.0.1, .10 (an ``nmbd``
named L2NBHOST in workgroup L2WG), .11 (an ``avahi-daemon``) and .12, plus the
kernel's ``/proc/net/arp`` and ``/proc/net/route`` taken right after it.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scanner.pipeline import l2_discovery
from scanner.pipeline.config_schema import L2DiscoveryConfig
from scanner.pipeline.l2_discovery import (
    interface_networks,
    mcast_solicit,
    mdns_names,
    merge_l2_names,
    nbstat_names,
    neighbour_macs,
    parse_pulse_l2,
    run_l2_discovery,
    select_l2_networks,
    valid_hostname,
)

FIXTURES = Path(__file__).parent / "fixtures" / "l2_discovery"
NAMES_JSON = (FIXTURES / "pulse-l2-names.json").read_text(encoding="utf-8")
ARP_ONLY_JSON = (FIXTURES / "pulse-l2-arp-only.json").read_text(encoding="utf-8")
SCOPE = ["10.0.0.0/24"]


@pytest.fixture(autouse=True)
def kernel(tmp_path: Path, monkeypatch):
    """Point every /proc read at a scratch copy of the recorded kernel state."""
    proc = tmp_path / "kernel"
    (proc / "neigh" / "default").mkdir(parents=True)
    (proc / "neigh" / "default" / "mcast_solicit").write_text("3\n", encoding="utf-8")
    arp, route = proc / "arp", proc / "route"
    arp.write_text((FIXTURES / "proc-net-arp.txt").read_text(encoding="utf-8"), encoding="utf-8")
    route.write_text((FIXTURES / "proc-net-route.txt").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(l2_discovery, "NEIGH_SYSCTL_DIR", proc / "neigh")
    monkeypatch.setattr(l2_discovery, "PROC_NET_ARP", arp)
    monkeypatch.setattr(l2_discovery, "PROC_NET_ROUTE", route)
    monkeypatch.setattr(l2_discovery, "resolve_pulse_bin", lambda configured="": "/usr/local/bin/pulse")
    monkeypatch.setattr(l2_discovery, "_pulse_available", lambda path: True)
    real_which = l2_discovery.shutil.which
    which_calls: list[tuple[str, str | None]] = []

    def which(cmd, mode=1, path=None):
        which_calls.append((cmd, path))
        return "/usr/sbin/ip" if cmd == "ip" else real_which(cmd, mode, path)

    monkeypatch.setattr(l2_discovery.shutil, "which", which)
    return SimpleNamespace(root=proc, arp=arp, route=route, which_calls=which_calls)


def _pulse(monkeypatch, stdout: str = NAMES_JSON, returncode: int = 0):
    """Replace the Pulse run; returns the list of (command, kwargs) it was called with."""
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(l2_discovery, "run_command", fake_run)
    return calls


def _cfg(**overrides: Any) -> L2DiscoveryConfig:
    return L2DiscoveryConfig(enabled=True, max_hosts=300, **overrides)


def _flag(command: list[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def test_select_l2_networks_never_widens_scope_and_caps_work():
    cfg = L2DiscoveryConfig(
        enabled=True,
        networks=["10.0.0.0/24", "10.0.1.0/24", "192.0.2.0/24"],
        max_hosts=300,
    )
    selected, skipped = select_l2_networks(["10.0.0.0/23"], cfg)
    assert [str(network) for network in selected] == ["10.0.0.0/24"]
    reasons = {row["network"]: row["reason"] for row in skipped}
    assert reasons["10.0.1.0/24"].startswith("host_cap_exceeded")
    assert reasons["192.0.2.0/24"] == "outside_scan_scope"


def test_recorded_run_gives_alive_hosts_macs_and_netbios_name(tmp_path: Path, monkeypatch):
    _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path)

    assert result["alive_hosts"] == ["10.0.0.1", "10.0.0.10", "10.0.0.11", "10.0.0.12"]
    assert result["hosts"] == [
        {"host": "10.0.0.1", "mac": "9E:60:52:AF:EA:F8", "vendor": None},
        {"host": "10.0.0.10", "mac": "EA:65:0D:AA:FB:A2", "vendor": None},
        {"host": "10.0.0.11", "mac": "BE:5F:0A:F9:01:E5", "vendor": None},
        {"host": "10.0.0.12", "mac": "1A:3D:C6:22:F9:81", "vendor": None},
    ]
    # NBSTAT: the machine name, not the workgroup (group) nor __MSBROWSE__;
    # the mDNS banner lists service types only.
    assert result["names_by_host"] == {"10.0.0.10": ["l2nbhost"]}
    evidence = {(row["host"], row["script_id"]): row for row in result["name_evidence"]}
    assert set(evidence) == {("10.0.0.10", "pulse:netbios-ns"), ("10.0.0.11", "pulse:mdns")}
    assert evidence[("10.0.0.11", "pulse:mdns")]["names"] == []
    assert "L2NBHOST" in evidence[("10.0.0.10", "pulse:netbios-ns")]["output"]
    assert result["skipped_reason"] is None
    assert (tmp_path / "discover" / "l2-pulse.json").read_text(encoding="utf-8").strip() == NAMES_JSON.strip()
    assert (tmp_path / "discover" / "l2-alive.txt").read_text(encoding="utf-8").split() == result["alive_hosts"]


def test_artifact_keeps_every_key_and_adds_the_engine_ones(tmp_path: Path, monkeypatch):
    _pulse(monkeypatch)
    run_l2_discovery(SCOPE, _cfg(max_rate=100), tmp_path)
    artifact = json.loads((tmp_path / "l2_discovery.json").read_text(encoding="utf-8"))
    assert set(artifact) == {
        "enabled", "networks", "alive_hosts", "hosts", "names_by_host", "name_evidence",
        "skipped_networks", "skipped_reason", "engine", "pulse_rate", "rate_divisor",
    }  # fmt: skip
    assert artifact["engine"] == "pulse"
    assert (artifact["pulse_rate"], artifact["rate_divisor"]) == (20, 5)
    assert artifact["networks"] == SCOPE


def test_alive_host_without_a_complete_neighbour_entry_has_no_mac(tmp_path: Path, monkeypatch, kernel):
    lines = kernel.arp.read_text(encoding="utf-8").splitlines()
    # 10.0.0.12 answered Pulse, but its entry went incomplete before we read it.
    kernel.arp.write_text(
        "\n".join(
            line.replace("0x2         1a:3d:c6:22:f9:81", "0x0         00:00:00:00:00:00") if "10.0.0.12" in line else line
            for line in lines
        )
        + "\n",
        encoding="utf-8",
    )
    _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path)
    macs = {row["host"]: row["mac"] for row in result["hosts"]}
    assert macs["10.0.0.12"] is None
    assert macs["10.0.0.1"] == "9E:60:52:AF:EA:F8"


def test_neighbour_macs_takes_only_complete_entries_of_the_device(kernel):
    assert set(neighbour_macs()) == {"10.0.0.1", "10.0.0.10", "10.0.0.11", "10.0.0.12"}
    assert neighbour_macs("eth0") == neighbour_macs()
    assert neighbour_macs("eth1") == {}
    # Each half of "complete" counts on its own: a flag-less entry with a stale
    # MAC and a complete flag over the zero MAC are both not evidence.
    with kernel.arp.open("a", encoding="utf-8") as handle:
        handle.write("10.0.0.20     0x1         0x0         de:ad:be:ef:00:01     *        eth0\n")
        handle.write("10.0.0.21     0x1         0x2         00:00:00:00:00:00     *        eth0\n")
    assert "10.0.0.20" not in neighbour_macs() and "10.0.0.21" not in neighbour_macs()
    kernel.arp.unlink()
    assert neighbour_macs() == {}


def test_pulse_rows_outside_the_selected_networks_are_dropped():
    payload = json.loads(NAMES_JSON)
    payload["results"].append(
        {"ip": "192.0.2.77", "host": "192.0.2.77", "port": 137, "protocol": "udp", "state": "open",
         "banner": "x"}
    )  # fmt: skip
    hosts, names, evidence = parse_pulse_l2(payload, SCOPE)
    assert [row["host"] for row in hosts] == ["10.0.0.1", "10.0.0.10", "10.0.0.11", "10.0.0.12"]
    assert all(row["host"].startswith("10.0.0.") for row in evidence)
    assert "192.0.2.77" not in names


def test_run_drops_a_pulse_row_for_an_address_outside_scope(tmp_path: Path, monkeypatch):
    _pulse(monkeypatch, ARP_ONLY_JSON.replace("10.0.0.12", "192.0.2.12"))
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path)
    assert result["alive_hosts"] == ["10.0.0.1", "10.0.0.10", "10.0.0.11"]


def test_nbstat_names_skip_group_names_and_the_browser_marker():
    banner = next(
        row["banner"] for row in json.loads(NAMES_JSON)["results"] if row["port"] == 137 and row["banner"]
    )
    assert nbstat_names(banner) == ["l2nbhost"]
    assert nbstat_names("no name table here") == []


def _nbstat_banner(*entries: tuple[str, str]) -> str:
    """A banner shaped like Pulse's: echoed wildcard name, 12-byte header, 18-byte entries."""
    header = "\ufffd" * 3 + "." * 9 + " CK" + "A" * 30 + "." + "..!......\ufffd" + "."
    return header + "".join(f"{name:<15}.{flags}" for name, flags in entries)


def test_nbstat_marker_is_never_a_name_even_when_registered_unique():
    banner = _nbstat_banner(
        ("PLC01", ".."), ("..__MSBROWSE__", ".."), ("\ufffd.WORKGRP", "\ufffd."), ("LAB-PC", "..")
    )
    assert nbstat_names(banner) == ["plc01", "lab-pc"]


def test_mdns_service_types_are_not_names_but_a_local_host_is():
    banner = next(
        row["banner"] for row in json.loads(NAMES_JSON)["results"] if row["port"] == 5353 and row["banner"]
    )
    assert mdns_names(banner) == []
    assert mdns_names("..\t_services._dns-sd._udp.local.....myhost.local..\n_ssh._tcp") == ["myhost.local"]


def test_command_is_one_bounded_pulse_run(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    run_l2_discovery(SCOPE, _cfg(max_rate=100), tmp_path)

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[0] == "/usr/local/bin/pulse"
    assert Path(_flag(command, "--targets-file")).read_text(encoding="utf-8").split() == SCOPE
    assert _flag(command, "--discover-method") == "arp" and "-D" in command
    assert _flag(command, "--max-hosts") == "300"
    assert _flag(command, "--rate") == "20"  # 100 pps / (3 requests + 1 datagram + 1 measured extra)
    assert _flag(command, "-p") == "137,5353" and "-b" in command
    assert {"--all", "-q"} <= set(command) and _flag(command, "--protocol") == "udp"
    assert "--services-db" in command
    env = kwargs["env"]
    assert env["HOME"] != str(Path.home()) and "SHODAN_API_KEY" not in env
    assert kwargs["timeout"] == 120 and kwargs["check"] is False


@pytest.mark.parametrize(
    ("solicit", "max_rate", "expected"),
    [("3", "100", "20"), ("5", "100", "14"), ("0", "100", "50"), ("3", "7", "1")],
)
def test_rate_is_the_packet_ceiling_divided_by_the_arp_retries(
    tmp_path: Path, monkeypatch, kernel, solicit, max_rate, expected
):
    (kernel.root / "neigh" / "default" / "mcast_solicit").write_text(solicit, encoding="utf-8")
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(max_rate=int(max_rate), timeout_seconds=3600), tmp_path)
    assert _flag(calls[0][0], "--rate") == expected
    assert result["rate_divisor"] == int(solicit) + 2  # + the name probe of a live host


def test_the_rate_divisor_does_not_depend_on_name_probes(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    for cfg, excluded in (
        (_cfg(netbios=False, mdns=False), []),
        (_cfg(), [137, 5353]),
        (_cfg(mdns=False), []),
        (_cfg(), []),
    ):
        result = run_l2_discovery(SCOPE, cfg, tmp_path, exclude_ports=excluded)
        assert (result["rate_divisor"], _flag(calls[-1][0], "--rate")) == (5, "200")


def test_unreadable_mcast_solicit_assumes_the_linux_default(tmp_path: Path, monkeypatch, kernel):
    (kernel.root / "neigh" / "default" / "mcast_solicit").unlink()
    calls = _pulse(monkeypatch)
    run_l2_discovery(SCOPE, _cfg(max_rate=100), tmp_path)
    assert _flag(calls[0][0], "--rate") == "20"


def test_rate_below_one_candidate_per_second_skips_the_stage(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(max_rate=3), tmp_path)  # 3 // 4 == 0, and --rate 0 is unlimited
    assert calls == []
    assert result["skipped_reason"] == "rate_cap_unenforceable:3"
    assert result["alive_hosts"] == [] and result["pulse_rate"] is None


def test_policy_excluded_name_ports_are_dropped(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    cfg = _cfg()

    run_l2_discovery(SCOPE, cfg, tmp_path, exclude_ports=[137])
    assert _flag(calls[-1][0], "-p") == "5353" and "-b" in calls[-1][0]

    run_l2_discovery(SCOPE, cfg, tmp_path, exclude_ports=[5353])
    assert _flag(calls[-1][0], "-p") == "137"

    result = run_l2_discovery(SCOPE, cfg, tmp_path, exclude_ports=[137, 5353])
    assert _flag(calls[-1][0], "-p") == "9" and "-b" not in calls[-1][0]
    assert result["alive_hosts"] == ["10.0.0.1", "10.0.0.10", "10.0.0.11", "10.0.0.12"]
    assert result["name_evidence"] and result["skipped_reason"] is None  # the recorded run carries banners

    run_l2_discovery(SCOPE, _cfg(netbios=False, mdns=False), tmp_path)
    assert _flag(calls[-1][0], "-p") == "9"
    run_l2_discovery(SCOPE, _cfg(mdns=False), tmp_path)
    assert _flag(calls[-1][0], "-p") == "137"


def test_excluding_the_arp_trigger_port_switches_the_stage_off(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path, exclude_ports=[9])
    assert calls == []
    assert result["skipped_reason"] == "arp.trigger_port_excluded:9"


def test_rate_zero_is_never_passed(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    for max_rate in (1, 3, 4, 5, 100, 100_000):
        run_l2_discovery(SCOPE, _cfg(max_rate=max_rate, timeout_seconds=3600), tmp_path)
    assert all(_flag(command, "--rate") != "0" for command, _ in calls)


def test_no_live_host_is_empty_stdout_not_a_failure(tmp_path: Path, monkeypatch):
    _pulse(monkeypatch, stdout="")
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path)
    assert result["skipped_reason"] is None
    assert result["alive_hosts"] == [] and result["hosts"] == []
    assert not (tmp_path / "discover" / "l2-pulse.json").exists()


def test_failures_are_recorded_not_raised(tmp_path: Path, monkeypatch):
    _pulse(monkeypatch, stdout=NAMES_JSON, returncode=2)
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path)
    assert result["skipped_reason"] == "arp.failed:2" and result["alive_hosts"] == []

    _pulse(monkeypatch, stdout="Error: cannot open raw socket")
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path)
    assert result["skipped_reason"] == "arp.failed:invalid_json"

    _pulse(monkeypatch, stdout="[1, 2]")
    assert run_l2_discovery(SCOPE, _cfg(), tmp_path)["skipped_reason"] == "arp.failed:invalid_json"

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout") or 1)

    monkeypatch.setattr(l2_discovery, "run_command", timeout)
    result = run_l2_discovery(SCOPE, _cfg(), tmp_path)
    assert result["skipped_reason"] == "arp.failed:TimeoutExpired"
    assert json.loads((tmp_path / "l2_discovery.json").read_text(encoding="utf-8"))["alive_hosts"] == []


def test_without_pulse_warns_and_points_to_doc(tmp_path: Path, monkeypatch, caplog):
    monkeypatch.setattr(l2_discovery, "_pulse_available", lambda path: False)
    calls = _pulse(monkeypatch)
    with caplog.at_level("WARNING", logger="shapoclyack.l2-discovery"):
        result = run_l2_discovery(SCOPE, _cfg(), tmp_path)

    assert calls == []
    assert result["skipped_reason"] == "pulse.unavailable"
    assert "docs/pulse-backend.md" in caplog.text


def test_disabled_stage_does_nothing(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, L2DiscoveryConfig(enabled=False), tmp_path)
    assert calls == [] and result["skipped_reason"] == "l2.disabled"


def test_interface_keeps_only_networks_routed_on_link_through_it(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    cfg = L2DiscoveryConfig(
        enabled=True, interface="eth0", networks=["10.0.0.0/24", "10.0.1.0/24"], max_hosts=600
    )
    result = run_l2_discovery(["10.0.0.0/23"], cfg, tmp_path)

    assert result["networks"] == ["10.0.0.0/24"]
    assert Path(_flag(calls[0][0], "--targets-file")).read_text(encoding="utf-8").split() == ["10.0.0.0/24"]
    assert {"network": "10.0.1.0/24", "reason": "not_on_interface:eth0"} in result["skipped_networks"]
    assert result["alive_hosts"]


def test_interface_that_reaches_no_selected_network_runs_nothing(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(interface="eth1"), tmp_path)
    assert calls == []
    assert result["skipped_reason"] == "no_in_scope_local_networks"
    assert result["skipped_networks"] == [{"network": "10.0.0.0/24", "reason": "not_on_interface:eth1"}]


def test_interface_with_an_unreadable_route_table_is_unverifiable(tmp_path: Path, monkeypatch, kernel):
    kernel.route.unlink()
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(interface="eth0"), tmp_path)
    assert calls == []
    assert result["skipped_reason"] == "interface.unverifiable"
    # Without an interface the route table is not consulted at all.
    assert run_l2_discovery(SCOPE, _cfg(), tmp_path / "again")["alive_hosts"]


def test_mac_lookup_is_limited_to_the_configured_interface(tmp_path: Path, monkeypatch, kernel):
    kernel.arp.write_text(
        kernel.arp.read_text(encoding="utf-8").replace("be:5f:0a:f9:01:e5     *        eth0", "be:5f:0a:f9:01:e5     *        eth1"),
        encoding="utf-8",
    )
    _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(interface="eth0"), tmp_path)
    macs = {row["host"]: row["mac"] for row in result["hosts"]}
    assert macs["10.0.0.11"] is None and macs["10.0.0.10"] == "EA:65:0D:AA:FB:A2"


def test_merge_l2_names_preserves_dns_provenance():
    merged = merge_l2_names(
        {"10.0.0.5": {"forward": ["plc.example"], "reverse": [], "names": ["plc.example"]}},
        {"10.0.0.5": ["PLC-01", "panel.local"]},
    )
    assert merged["10.0.0.5"]["forward"] == ["plc.example"]
    assert merged["10.0.0.5"]["l2"] == ["plc-01", "panel.local"]
    assert merged["10.0.0.5"]["names"] == ["plc.example", "plc-01", "panel.local"]


def test_without_iproute2_pulse_is_not_run_because_it_would_report_nothing(
    tmp_path: Path, monkeypatch, kernel, caplog
):
    # Pulse's ARP method shells out to `ip -4 neigh`; without it: 0 live, empty stdout, rc 0.
    monkeypatch.setattr(l2_discovery.shutil, "which", lambda cmd, mode=1, path=None: None)
    calls = _pulse(monkeypatch, stdout="")
    with caplog.at_level("WARNING", logger="shapoclyack.l2-discovery"):
        result = run_l2_discovery(SCOPE, _cfg(), tmp_path)
    assert calls == []
    assert result["skipped_reason"] == "pulse.arp_needs_iproute2"
    assert "docs/pulse-backend.md#l2-discovery" in caplog.text


def test_iproute2_is_looked_up_on_the_path_pulse_will_get(tmp_path: Path, monkeypatch, kernel):
    monkeypatch.setenv("PATH", "/opt/pulse-path")
    _pulse(monkeypatch)
    run_l2_discovery(SCOPE, _cfg(), tmp_path)
    assert ("ip", "/opt/pulse-path") in kernel.which_calls


def test_without_an_interface_the_rate_divisor_uses_the_largest_retry_count(
    tmp_path: Path, monkeypatch, kernel
):
    neigh = kernel.root / "neigh"
    for name, value in (("eth1", "6"), ("lo", "9")):  # lo never ARPs
        (neigh / name).mkdir()
        (neigh / name / "mcast_solicit").write_text(value, encoding="utf-8")
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(max_rate=700), tmp_path)
    assert result["rate_divisor"] == 8 and _flag(calls[0][0], "--rate") == "87"

    # With an interface only its own value counts (default=3 in the fixture, eth0=2).
    (neigh / "eth0").mkdir()
    (neigh / "eth0" / "mcast_solicit").write_text("2", encoding="utf-8")
    result = run_l2_discovery(SCOPE, _cfg(max_rate=700, interface="eth0"), tmp_path)
    assert result["rate_divisor"] == 4


# --- names: hostile and truncated banners ---------------------------------

def test_nbstat_statistics_block_after_the_names_is_not_a_name():
    # The 46-byte statistics block starts with the adapter's MAC: VMware
    # 00:50:56 and KVM 52:54:00 have bytes below 0x80 and read as text.
    names = (("WINBOX", ".."), ("WINBOX", ".."), ("WINBOX", ".."), ("WORKGRP", "\ufffd."))
    for stats in (".PVxyz" + " " * 9 + "." * 31, "RT.xyz" + " " * 9 + "." * 31):
        assert nbstat_names(_nbstat_banner(*names) + stats) == ["winbox"]


def test_nbstat_names_that_are_not_netbios_names_are_dropped():
    banner = _nbstat_banner(
        ("<script>alert", ".."), ("ab\ufffdcd", ".."), ("a.b", ".."), ("-lead", ".."),
        ("two words", ".."), ("../../etc", ".."), ("OK_1-x", ".."),
    )  # fmt: skip
    assert nbstat_names(banner) == ["ok_1-x"]


def test_mdns_hostile_banner_yields_only_valid_host_names():
    banner = "<script>alert(1)</script>.local\x00evil'name\"x.local\x01../../etc.local ok-1.local"
    names = mdns_names(banner)
    assert names == ["x.local", "etc.local", "ok-1.local"]
    assert all(valid_hostname(name) for name in names)
    assert not any(c in name for name in names for c in "<>()/'\" ")


def test_mdns_names_over_the_hostname_limits_are_dropped():
    assert mdns_names("..." + "a." * 130 + "local") == []  # 265 characters
    assert mdns_names("." + "x" * 64 + ".local") == []  # label over 63
    assert mdns_names("." + "x" * 63 + ".local") == ["x" * 63 + ".local"]
    assert not valid_hostname("") and not valid_hostname("a..b") and not valid_hostname("a b.local")


def test_mdns_parsing_is_linear_on_a_hostile_banner():
    started = time.monotonic()
    assert mdns_names("a." * 50_000) == []  # 100 KB
    mdns_names("local." * 8_000)  # a name check at every "local" is quadratic without the cut
    assert time.monotonic() - started < 1.0


@pytest.mark.parametrize(
    ("banner", "expected"),
    [
        ("._ssh._tcp.local.myhost.local", ["myhost.local"]),
        ("..print-1._ipp._tcp.local.host2.local", ["host2.local"]),
        ("a.local.local", ["a.local"]),  # never "local.local"
    ],
)
def test_an_earlier_local_ends_the_previous_name(banner, expected):
    assert mdns_names(banner) == expected


def test_mdns_local_name_after_a_service_type_in_one_run_is_found():
    # Length bytes print as dots, so a type and a host name can share a run.
    assert mdns_names("_ssh._tcp...myhost.local") == ["myhost.local"]


def test_evidence_output_is_cut_at_4096_and_only_udp_rows_count():
    long_banner = "x" * 10_000
    nbstat = next(
        row["banner"] for row in json.loads(NAMES_JSON)["results"] if row["port"] == 137 and row["banner"]
    )
    payload = {
        "results": [
            {"ip": "10.0.0.5", "port": 5353, "protocol": "udp", "banner": long_banner},
            {"ip": "10.0.0.6", "port": 137, "protocol": "tcp", "banner": nbstat},
            {"ip": "10.0.0.7", "port": 80, "protocol": "udp", "banner": nbstat},
        ]
    }
    hosts, names, evidence = parse_pulse_l2(payload, SCOPE)
    assert [row["host"] for row in hosts] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]
    assert [(row["host"], len(row["output"])) for row in evidence] == [("10.0.0.5", 4096)]
    assert names == {}


def test_mcast_solicit_ignores_an_interface_that_is_a_path(kernel):
    (kernel.root / "x").mkdir()
    (kernel.root / "x" / "mcast_solicit").write_text("9", encoding="utf-8")
    assert mcast_solicit("../x") == 3
    (kernel.root / "neigh" / "eth7").mkdir()
    (kernel.root / "neigh" / "eth7" / "mcast_solicit").write_text("9", encoding="utf-8")
    assert mcast_solicit("eth7") == 9


# --- interface: which route the kernel really takes ------------------------

def _route(iface: str, net: str, *, gateway: str = "0.0.0.0", flags: int = 1, metric: int = 0) -> str:
    network = ipaddress.ip_network(net)

    def hexed(address: ipaddress.IPv4Address) -> str:
        return address.packed[::-1].hex().upper()

    return (
        f"{iface}\t{hexed(network.network_address)}\t{hexed(ipaddress.IPv4Address(gateway))}\t{flags:04X}"
        f"\t0\t0\t{metric}\t{hexed(network.netmask)}\t0\t0\t0"
    )


def _set_routes(kernel, *lines: str) -> None:
    kernel.route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        + "\n".join(lines)
        + "\n",
        encoding="utf-8",
    )


def _nets(values) -> list[str]:
    return [str(n) for n in values]


def test_interface_networks_reads_the_recorded_table():
    assert _nets(interface_networks("eth0")) == ["10.0.0.0/24"]
    assert interface_networks("eth1") == []


def test_route_through_a_gateway_is_not_on_link(kernel):
    _set_routes(kernel, _route("eth0", "10.0.0.0/24", gateway="10.0.0.1", flags=3))
    assert interface_networks("eth0") == []


def test_route_that_is_down_and_the_default_route_are_not_on_link(kernel):
    _set_routes(kernel, _route("eth0", "10.0.0.0/24", flags=0), _route("eth0", "0.0.0.0/0"))
    assert interface_networks("eth0") == []


def test_a_down_rival_route_does_not_take_the_network_away(kernel):
    _set_routes(kernel, _route("eth0", "10.0.0.0/24"), _route("eth1", "10.0.0.128/25", flags=0))
    assert _nets(interface_networks("eth0")) == ["10.0.0.0/24"]


def test_more_specific_route_of_another_interface_takes_its_part(tmp_path: Path, monkeypatch, kernel):
    _set_routes(kernel, _route("eth0", "10.0.0.0/24"), _route("eth1", "10.0.0.128/25"))
    assert _nets(interface_networks("eth0")) == ["10.0.0.0/25"]

    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(interface="eth0"), tmp_path)
    assert result["networks"] == ["10.0.0.0/25"]
    assert {"network": "10.0.0.128/25", "reason": "not_on_interface:eth0"} in result["skipped_networks"]
    assert Path(_flag(calls[0][0], "--targets-file")).read_text(encoding="utf-8").split() == ["10.0.0.0/25"]


def test_more_specific_route_through_a_gateway_on_our_own_interface_takes_its_part(kernel):
    _set_routes(kernel, _route("eth0", "10.0.0.0/24"), _route("eth0", "10.0.0.128/25", gateway="10.0.0.1", flags=3))
    assert _nets(interface_networks("eth0")) == ["10.0.0.0/25"]


def test_equal_route_wins_only_with_a_strictly_smaller_metric(tmp_path: Path, monkeypatch, kernel):
    _set_routes(kernel, _route("eth0", "10.0.0.0/24", metric=100), _route("wlan0", "10.0.0.0/24", metric=50))
    assert interface_networks("eth0") == []
    calls = _pulse(monkeypatch)
    result = run_l2_discovery(SCOPE, _cfg(interface="eth0"), tmp_path)
    assert calls == [] and result["skipped_reason"] == "no_in_scope_local_networks"
    assert result["skipped_networks"] == [{"network": "10.0.0.0/24", "reason": "not_on_interface:eth0"}]

    _set_routes(kernel, _route("eth0", "10.0.0.0/24", metric=100), _route("wlan0", "10.0.0.0/24", metric=100))
    assert interface_networks("eth0") == [], "a tie is not ours"

    _set_routes(kernel, _route("eth0", "10.0.0.0/24", metric=50), _route("wlan0", "10.0.0.0/24", metric=100))
    assert _nets(interface_networks("eth0")) == ["10.0.0.0/24"]


def test_less_specific_route_of_another_interface_changes_nothing(kernel):
    _set_routes(kernel, _route("eth0", "10.0.0.0/24"), _route("eth1", "10.0.0.0/16"), _route("eth1", "0.0.0.0/0"))
    assert _nets(interface_networks("eth0")) == ["10.0.0.0/24"]


# --- time budget -----------------------------------------------------------

def test_sweep_that_cannot_finish_inside_the_timeout_is_not_started(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    # 254 candidates at 7 // 4 = 1 per second, plus 3 s of ARP retries.
    result = run_l2_discovery(SCOPE, _cfg(max_rate=7, timeout_seconds=120), tmp_path)
    assert calls == []
    assert result["skipped_reason"] == "timeout_unreachable:257s"
    assert result["pulse_rate"] == 1 and result["alive_hosts"] == []


def test_timeout_estimate_counts_the_arp_retry_tail(tmp_path: Path, monkeypatch):
    calls = _pulse(monkeypatch)
    assert run_l2_discovery(SCOPE, _cfg(max_rate=7, timeout_seconds=257), tmp_path)["skipped_reason"] is None
    assert len(calls) == 1
    assert run_l2_discovery(SCOPE, _cfg(max_rate=7, timeout_seconds=256), tmp_path)["skipped_reason"] == (
        "timeout_unreachable:257s"
    )
    assert len(calls) == 1
