from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from scanner.pipeline.config_schema import L2DiscoveryConfig
from scanner.pipeline.l2_discovery import (
    merge_l2_names,
    parse_arp_xml,
    parse_name_xml,
    run_l2_discovery,
    select_l2_networks,
)

ARP_XML = """<?xml version='1.0'?>
<nmaprun>
  <host><status state='up'/><address addr='10.0.0.5' addrtype='ipv4'/>
    <address addr='AA:BB:CC:DD:EE:FF' addrtype='mac' vendor='PLC Corp'/></host>
  <host><status state='up'/><address addr='10.0.1.5' addrtype='ipv4'/></host>
</nmaprun>
"""

NAME_XML = """<?xml version='1.0'?>
<nmaprun><host><status state='up'/><address addr='10.0.0.5' addrtype='ipv4'/>
<ports>
  <port protocol='udp' portid='137'><script id='nbstat' output='NetBIOS name: PLC-01'/></port>
  <port protocol='udp' portid='5353'><script id='dns-service-discovery' output='panel-01.local.'/></port>
</ports></host></nmaprun>
"""


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


def test_parse_l2_xml_is_scope_bound_and_extracts_names():
    rows = parse_arp_xml(ARP_XML, ["10.0.0.0/24"])
    assert rows == [
        {
            "host": "10.0.0.5",
            "mac": "AA:BB:CC:DD:EE:FF",
            "vendor": "PLC Corp",
        }
    ]
    names, evidence = parse_name_xml(NAME_XML, ["10.0.0.0/24"])
    assert names["10.0.0.5"] == ["plc-01", "panel-01.local"]
    assert {row["script_id"] for row in evidence} == {"nbstat", "dns-service-discovery"}


def test_run_l2_discovery_uses_arp_then_name_probes(tmp_path: Path, monkeypatch):
    commands: list[list[str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        out = Path(command[command.index("-oX") + 1])
        out.write_text(NAME_XML if "-sU" in command else ARP_XML, encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanner.pipeline.l2_discovery.shutil.which", lambda name: "/usr/bin/nmap")
    monkeypatch.setattr("scanner.pipeline.l2_discovery.run_command", fake_run)
    result = run_l2_discovery(
        ["10.0.0.0/24"],
        L2DiscoveryConfig(enabled=True, max_hosts=300),
        tmp_path,
    )

    assert result["alive_hosts"] == ["10.0.0.5"]
    assert result["names_by_host"]["10.0.0.5"] == ["plc-01", "panel-01.local"]
    assert "-PR" in commands[0]
    assert "nbstat,dns-service-discovery" in commands[1]
    assert (tmp_path / "l2_discovery.json").exists()


def test_merge_l2_names_preserves_dns_provenance():
    merged = merge_l2_names(
        {"10.0.0.5": {"forward": ["plc.example"], "reverse": [], "names": ["plc.example"]}},
        {"10.0.0.5": ["PLC-01", "panel.local"]},
    )
    assert merged["10.0.0.5"]["forward"] == ["plc.example"]
    assert merged["10.0.0.5"]["l2"] == ["plc-01", "panel.local"]
    assert merged["10.0.0.5"]["names"] == ["plc.example", "plc-01", "panel.local"]
