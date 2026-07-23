from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.asn_enrich import (
    AsnDatabase,
    attach_asn_to_records,
    enrich_hosts_asn,
)
from scanner.pipeline.report import build_reports


def test_asn_private_and_empty():
    db = AsnDatabase.load(None)
    # Private/loopback IPs carry no ASN and never hit a reader.
    assert db.lookup("10.0.0.5") == {"asn": "", "asn_org": ""}
    assert db.lookup("127.0.0.1") == {"asn": "", "asn_org": ""}
    # Public IP with no database stays empty (fail-soft).
    assert db.lookup("8.8.8.8") == {"asn": "", "asn_org": ""}


def test_asn_json_overlay_lookup(tmp_path: Path):
    overlay = tmp_path / "asn.json"
    overlay.write_text(
        json.dumps(
            {
                "entries": {
                    "1.1.1.1": {"asn": "AS13335", "asn_org": "Cloudflare, Inc."},
                    "8.8.8.8": {"asn": "AS15169", "org": "Google LLC"},
                }
            }
        ),
        encoding="utf-8",
    )
    db = AsnDatabase.load(overlay)
    assert db.lookup("1.1.1.1") == {"asn": "AS13335", "asn_org": "Cloudflare, Inc."}
    # `org` is accepted as an alias for `asn_org`.
    assert db.lookup("8.8.8.8")["asn_org"] == "Google LLC"
    assert db.lookup("9.9.9.9") == {"asn": "", "asn_org": ""}

    asn_map = enrich_hosts_asn(["1.1.1.1", "9.9.9.9"], db)
    records = [{"host": "1.1.1.1"}, {"host": "9.9.9.9"}]
    attach_asn_to_records(records, asn_map)
    assert records[0]["asn"] == "AS13335"
    assert records[0]["asn_org"] == "Cloudflare, Inc."
    assert records[1]["asn"] is None
    assert records[1]["asn_org"] is None
    db.close()


def test_build_reports_attaches_asn_to_alive_hosts(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    (nmap_dir / "host.xml").write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    asn = tmp_path / "asn.json"
    asn.write_text(
        json.dumps({"entries": {"1.1.1.1": {"asn": "AS13335", "asn_org": "Cloudflare, Inc."}}}),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    out.mkdir()

    build_reports(
        output_dir=out,
        total_targets=1,
        alive_hosts=["1.1.1.1"],
        open_ports=["1.1.1.1:443"],
        nmap_dir=nmap_dir,
        markdown_summary=False,
        html_summary=False,
        csv_export=False,
        json_export=False,
        cvss4_enabled=False,
        geoip_enabled=False,
        asn_enabled=True,
        asn_database=asn,
    )

    alive = json.loads((out / "alive_hosts.json").read_text(encoding="utf-8"))
    assert alive[0]["asn"] == "AS13335"
    assert alive[0]["asn_org"] == "Cloudflare, Inc."


def test_build_reports_asn_disabled_leaves_fields_absent_or_none(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    (nmap_dir / "host.xml").write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.1.1.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    out = tmp_path / "out"
    out.mkdir()
    build_reports(
        output_dir=out,
        total_targets=1,
        alive_hosts=["1.1.1.1"],
        open_ports=["1.1.1.1:443"],
        nmap_dir=nmap_dir,
        markdown_summary=False,
        html_summary=False,
        csv_export=False,
        json_export=False,
        cvss4_enabled=False,
        geoip_enabled=False,
        asn_enabled=False,
    )
    alive = json.loads((out / "alive_hosts.json").read_text(encoding="utf-8"))
    # asn_map stays empty when disabled, so per-host asn/asn_org are None.
    assert alive[0]["asn"] is None
    assert alive[0]["asn_org"] is None
