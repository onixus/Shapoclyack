from __future__ import annotations

import json
from pathlib import Path

from scanner.pipeline.cvss4 import Cvss4Database, enrich_vulnerabilities, score_to_severity
from scanner.pipeline.geoip import GeoIpDatabase, attach_geo_to_records, enrich_hosts_geo
from scanner.pipeline.report import build_reports


def test_score_to_severity_bands():
    assert score_to_severity(9.3) == "critical"
    assert score_to_severity(7.1) == "high"
    assert score_to_severity(4.2) == "medium"
    assert score_to_severity(1.0) == "low"
    assert score_to_severity(None) == "unknown"


def test_cvss4_load_wrapped_and_enrich(tmp_path: Path):
    db_path = tmp_path / "cvss4.json"
    db_path.write_text(
        json.dumps(
            {
                "version": "4.0",
                "entries": {
                    "CVE-2021-44228": {
                        "score": 10.0,
                        "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                        "severity": "critical",
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    db = Cvss4Database.load(db_path)
    assert len(db) == 1
    vulns = [
        {
            "host": "1.1.1.1",
            "port": "443",
            "cve": "CVE-2021-44228",
            "cvss": 9.8,
            "severity": "critical",
            "script_id": "vulners",
        },
        {
            "host": "1.1.1.1",
            "port": "80",
            "cve": "CVE-1999-0001",
            "cvss": 5.0,
            "severity": "medium",
            "script_id": "vulners",
        },
    ]
    enrich_vulnerabilities(vulns, db)
    assert vulns[0]["cvss4"] == 10.0
    assert vulns[0]["cvss4_severity"] == "critical"
    assert vulns[0]["severity"] == "critical"
    assert vulns[1]["cvss4"] is None


def test_geoip_json_overlay_lookup(tmp_path: Path):
    overlay = tmp_path / "geo.json"
    overlay.write_text(
        json.dumps(
            {
                "entries": {
                    "8.8.8.8": {"country": "United States", "city": "Mountain View", "country_iso": "US"}
                }
            }
        ),
        encoding="utf-8",
    )
    db = GeoIpDatabase.load(overlay)
    hit = db.lookup("8.8.8.8")
    assert hit["country"] == "United States"
    assert hit["city"] == "Mountain View"
    assert hit["country_iso"] == "US"
    assert db.lookup("9.9.9.9")["country"] == ""

    geo_map = enrich_hosts_geo(["8.8.8.8", "9.9.9.9"], db)
    records = [{"host": "8.8.8.8"}, {"host": "9.9.9.9"}]
    attach_geo_to_records(records, geo_map)
    assert records[0]["city"] == "Mountain View"
    assert records[1]["city"] is None
    db.close()


def test_build_reports_attaches_cvss4_and_geo(tmp_path: Path):
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    (nmap_dir / "host.xml").write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="vulners" output="CVE-2021-44228 9.8 https://example"/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )
    cvss4 = tmp_path / "cvss4.json"
    cvss4.write_text(
        json.dumps(
            {
                "entries": {
                    "CVE-2021-44228": {"score": 10.0, "vector": "CVSS:4.0/AV:N", "severity": "critical"}
                }
            }
        ),
        encoding="utf-8",
    )
    geo = tmp_path / "geo.json"
    geo.write_text(
        json.dumps(
            {"entries": {"8.8.8.8": {"country": "United States", "city": "Mountain View", "country_iso": "US"}}}
        ),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    out.mkdir()

    build_reports(
        output_dir=out,
        total_targets=1,
        alive_hosts=["8.8.8.8"],
        open_ports=["8.8.8.8:443"],
        nmap_dir=nmap_dir,
        markdown_summary=True,
        html_summary=False,
        csv_export=True,
        json_export=False,
        cvss4_enabled=True,
        cvss4_database=cvss4,
        geoip_enabled=True,
        geoip_database=geo,
    )

    vulns = json.loads((out / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert vulns[0]["cvss4"] == 10.0
    assert vulns[0]["country"] == "United States"
    assert vulns[0]["city"] == "Mountain View"
    assert (out / "geoip.json").exists()
    alive = json.loads((out / "alive_hosts.json").read_text(encoding="utf-8"))
    assert alive[0]["city"] == "Mountain View"
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "CVSS4" in md
    assert "Mountain View" in md
