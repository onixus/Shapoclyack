from __future__ import annotations

import json
from pathlib import Path

import pytest

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
                        "published": "2021-12-10",
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
    assert vulns[0]["cve_published"] == "2021-12-10"
    assert vulns[1]["cvss4"] is None


def test_geoip_private_ip_labeled():
    db = GeoIpDatabase.load(None)
    hit = db.lookup("172.19.0.2")
    assert hit["country"] == "Private"
    assert hit["city"] == "LAN"
    assert db.lookup("127.0.0.1")["city"] == "localhost"
    # Public IP with empty DB stays empty
    assert db.lookup("8.8.8.8")["country"] == ""


def test_geoip_private_ip_has_no_coordinates():
    """A private address has no position on the planet, and inventing one would
    plot lab hosts on the Geo Map as if they had been geolocated."""
    db = GeoIpDatabase.load(None)
    hit = db.lookup("172.19.0.2")
    assert hit["latitude"] is None
    assert hit["longitude"] is None


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


def test_geoip_overlay_coordinates(tmp_path: Path):
    overlay = tmp_path / "geo.json"
    overlay.write_text(
        json.dumps(
            {
                # Short `lat`/`lon` aliases: the overlay is hand-written in labs.
                "8.8.8.8": {"country": "Nowhere", "lat": 0, "lon": 0},
                "9.9.9.9": {"country": "Bad", "latitude": 900, "longitude": "north"},
            }
        ),
        encoding="utf-8",
    )
    db = GeoIpDatabase.load(overlay)
    try:
        # 0/0 is Null Island, a real coordinate — not a missing one.
        assert db.lookup("8.8.8.8")["latitude"] == 0
        assert db.lookup("8.8.8.8")["longitude"] == 0
        # Out of range and non-numeric are both dropped, not plotted off-map.
        assert db.lookup("9.9.9.9")["latitude"] is None
        assert db.lookup("9.9.9.9")["longitude"] is None
    finally:
        db.close()


def test_geoip_overlay_rejects_boolean_coordinates(tmp_path: Path):
    """`float(True)` is 1.0, so a `true` in a hand-written overlay would
    otherwise pass every range check and plot a fabricated position."""
    overlay = tmp_path / "geo.json"
    overlay.write_text(
        json.dumps({"8.8.8.8": {"country": "Nowhere", "latitude": True, "longitude": False}}),
        encoding="utf-8",
    )
    db = GeoIpDatabase.load(overlay)
    try:
        assert db.lookup("8.8.8.8")["latitude"] is None
        assert db.lookup("8.8.8.8")["longitude"] is None
    finally:
        db.close()


def test_geoip_overlay_cannot_give_a_private_address_a_position(tmp_path: Path):
    """The overlay is hand-written for labs, so it is exactly where a 10.x entry
    with coordinates would come from — and a lab host must not appear on the
    world map as a geolocated one."""
    overlay = tmp_path / "geo.json"
    overlay.write_text(
        json.dumps(
            {"10.0.0.7": {"country": "Lab", "city": "Rack 3", "latitude": 48.85, "longitude": 2.35}}
        ),
        encoding="utf-8",
    )
    db = GeoIpDatabase.load(overlay)
    try:
        hit = db.lookup("10.0.0.7")
        # The operator's labels survive; the position does not.
        assert hit["city"] == "Rack 3"
        assert hit["latitude"] is None
        assert hit["longitude"] is None
    finally:
        db.close()


class _CountryEditionReader:
    """Stands in for a GeoLite2-Country database.

    ``geoip2``'s Reader raises when a City query is made against a Country
    database rather than degrading, and there is no Country-edition fixture in
    the repository to exercise that against — a stub is the honest way to test
    the branch without shipping a second binary.
    """

    class _Response:
        class country:  # noqa: N801 - mirrors geoip2's attribute shape
            name = "Germany"
            iso_code = "DE"

    def __init__(self) -> None:
        self.city_calls = 0

    def city(self, ip):  # noqa: ARG002
        self.city_calls += 1
        raise TypeError("The city method cannot be used with the GeoIP2-Country database")

    def country(self, ip):  # noqa: ARG002
        return self._Response()


def test_geoip_country_edition_database_still_resolves_the_country():
    """Before this fell back, a Country-edition install resolved *nothing*:
    every public host came back empty, which the Geo Map would read as an estate
    with no location at all rather than a coarser one."""
    reader = _CountryEditionReader()
    db = GeoIpDatabase(reader=reader)
    hit = db.lookup("81.2.69.142")
    assert hit["country"] == "Germany"
    assert hit["country_iso"] == "DE"
    # No city and no coordinates to be had from this edition — the map places
    # such a host at the country centroid and says so.
    assert hit["city"] == ""
    assert hit["latitude"] is None

    # The working method is remembered, so the fallback costs one exception per
    # process rather than one per host.
    db.lookup("81.2.69.143")
    assert reader.city_calls == 1


def test_geoip_mmdb_fixture_lookup():
    """Exercise real MaxMind GeoIP2 City .mmdb reader path (test fixture)."""
    mmdb = Path(__file__).resolve().parent / "data" / "geoip" / "GeoIP2-City-Test.mmdb"
    assert mmdb.is_file(), f"missing test MMDB fixture: {mmdb}"
    db = GeoIpDatabase.load(mmdb)
    try:
        hit = db.lookup("81.2.69.142")
        assert hit["country_iso"] == "GB"
        assert hit["country"] == "United Kingdom"
        assert hit["city"] == "London"
        # Coordinates from the record's `location`, which is what the Geo Map plots.
        assert hit["latitude"] == pytest.approx(51.51, abs=0.1)
        assert hit["longitude"] == pytest.approx(-0.09, abs=0.1)
        missing = db.lookup("1.1.1.1")
        assert missing["country"] == ""
        assert missing["city"] == ""
        assert missing["latitude"] is None
    finally:
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


def test_build_reports_geoip_mmdb_fixture(tmp_path: Path):
    mmdb = Path(__file__).resolve().parent / "data" / "geoip" / "GeoIP2-City-Test.mmdb"
    nmap_dir = tmp_path / "nmap"
    nmap_dir.mkdir()
    (nmap_dir / "host.xml").write_text(
        """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="81.2.69.142" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
        <script id="vulners" output="CVE-2014-0160 7.5 https://example"/>
      </port>
    </ports>
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
        alive_hosts=["81.2.69.142"],
        open_ports=["81.2.69.142:80"],
        nmap_dir=nmap_dir,
        markdown_summary=False,
        html_summary=False,
        csv_export=False,
        json_export=False,
        cvss4_enabled=False,
        geoip_enabled=True,
        geoip_database=mmdb,
    )
    vulns = json.loads((out / "vulnerabilities.json").read_text(encoding="utf-8"))
    assert vulns[0]["country_iso"] == "GB"
    assert vulns[0]["city"] == "London"
    geo = json.loads((out / "geoip.json").read_text(encoding="utf-8"))
    assert geo["81.2.69.142"]["country"] == "United Kingdom"
    assert geo["81.2.69.142"]["latitude"] == pytest.approx(51.51, abs=0.1)
    alive = json.loads((out / "alive_hosts.json").read_text(encoding="utf-8"))
    assert alive[0]["longitude"] == pytest.approx(-0.09, abs=0.1)
