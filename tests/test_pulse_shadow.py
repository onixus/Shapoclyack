"""Offline tests for Pulse vs Nmap shadow diff."""

from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.pulse_shadow import compare_pulse_nmap, write_pulse_nmap_diff


def _write_nmap_xml(path: Path, host: str, ports: list[tuple[str, str]]) -> None:
    """ports: list of (portid, service_name)."""
    port_xml = []
    for portid, svc in ports:
        port_xml.append(
            f"""
    <port protocol="tcp" portid="{portid}">
      <state state="open"/>
      <service name="{svc}"/>
    </port>"""
        )
    body = f"""<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="{host}" addrtype="ipv4"/>
    <ports>
      {"".join(port_xml)}
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="90"/>
    </os>
  </host>
</nmaprun>
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def test_compare_endpoints_jaccard(tmp_path: Path):
    # Pulse: 22,80
    (tmp_path / "services.json").write_text(
        json.dumps(
            [
                {"schema_version": "octo.service.v1", "ip": "10.0.0.1", "port": 22, "protocol": "tcp", "service": "ssh"},
                {"schema_version": "octo.service.v1", "ip": "10.0.0.1", "port": 80, "protocol": "tcp", "service": "http"},
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "os.json").write_text(
        json.dumps(
            [
                {
                    "schema_version": "octo.os.v1",
                    "ip": "10.0.0.1",
                    "family": "Linux",
                    "detail": "Linux 3.x",
                    "confidence": 70,
                    "source": "sinfp",
                }
            ]
        ),
        encoding="utf-8",
    )
    # Nmap: 22,443 (overlap 22 only)
    nmap_dir = tmp_path / "nmap" / "tcp"
    _write_nmap_xml(nmap_dir / "h.xml", "10.0.0.1", [("22", "ssh"), ("443", "https")])

    diff = compare_pulse_nmap(tmp_path, tmp_path / "nmap")
    ep = diff["endpoints"]
    assert ep["pulse_count"] == 2
    assert ep["nmap_count"] == 2
    assert ep["both_count"] == 1
    assert ep["only_pulse_count"] == 1
    assert ep["only_nmap_count"] == 1
    assert "10.0.0.1:80/tcp" in ep["only_pulse_sample"]
    assert "10.0.0.1:443/tcp" in ep["only_nmap_sample"]
    assert ep["jaccard"] == 0.3333 or abs(ep["jaccard"] - 1 / 3) < 0.01

    os_ = diff["os"]
    assert os_["pulse_hosts"] == 1
    assert os_["nmap_hosts"] == 1
    assert os_["family_agree"] == 1


def test_write_diff_file(tmp_path: Path):
    (tmp_path / "services.json").write_text("[]", encoding="utf-8")
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    path = write_pulse_nmap_diff(tmp_path, nmap_dir, extra={"backend": "hybrid"})
    assert path.exists()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema"] == "octo.pulse_nmap_diff.v1"
    assert data["meta"]["backend"] == "hybrid"
