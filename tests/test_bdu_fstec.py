"""BDU FSTEC is identity/provenance enrichment, not a guessed detector."""
from __future__ import annotations

import json
import zipfile

from api.services import bdu_fstec


XML = """<?xml version="1.0" encoding="utf-8"?>
<vulnerabilities>
  <vul>
    <identifier>BDU:2024-00001</identifier>
    <name>First issue</name>
    <severity>Критический</severity>
    <cvss><vector score="9.7">CVSS:3.1/AV:N/AC:L</vector></cvss>
    <identifiers>
      <identifier type="CVE">CVE-2024-1111</identifier>
    </identifiers>
    <publication_date>01.01.2024</publication_date>
    <last_upd_date>15.02.2024</last_upd_date>
  </vul>
  <vul>
    <identifier>BDU:2025-00002</identifier>
    <name>Two identities</name>
    <identifiers>
      <identifier type="CVE">CVE-2025-2222</identifier>
      <identifier type="CVE">CVE-2025-3333</identifier>
    </identifiers>
    <publication_date>2025-03-01</publication_date>
  </vul>
  <vul>
    <identifier>BDU:2026-00003</identifier>
    <name>BDU only</name>
    <publication_date>02.04.2026</publication_date>
  </vul>
</vulnerabilities>
"""


def _zip(tmp_path):
    path = tmp_path / "vulxml.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("vulxml.xml", XML)
    return path


def test_official_shape_builds_cve_identity_and_keeps_bdu_only(tmp_path):
    source = _zip(tmp_path)
    overlay = bdu_fstec.build_overlay(
        source,
        origin_url="https://bdu.fstec.ru/files/documents/vulxml.zip",
    )
    assert overlay["source"] == "bdu-fstec"
    assert len(overlay["source_sha256"]) == 64
    assert overlay["updated"] == "02.04.2026"
    assert overlay["entries"]["CVE-2024-1111"][0]["bdu_id"] == "BDU:2024-00001"
    assert overlay["entries"]["CVE-2024-1111"][0]["cvss"] == 9.7
    assert set(overlay["entries"]) == {
        "CVE-2024-1111",
        "CVE-2025-2222",
        "CVE-2025-3333",
    }
    assert [row["bdu_id"] for row in overlay["bdu_only"]] == ["BDU:2026-00003"]


def test_lookup_hot_reloads_and_never_promotes_bdu_only(tmp_path, monkeypatch):
    database = tmp_path / "bdu.json"
    monkeypatch.setenv(bdu_fstec.DATABASE_ENV, str(database))
    monkeypatch.setenv("OCTO_ENRICHMENT_RELOAD_SECONDS", "0")
    bdu_fstec.reset_cache()

    first = bdu_fstec.build_overlay(_zip(tmp_path))
    database.write_text(json.dumps(first), encoding="utf-8")
    hit = bdu_fstec.lookup("cve-2024-1111")
    assert hit["bdu_ids"] == ["BDU:2024-00001"]
    assert hit["source"] == "bdu-fstec"
    assert bdu_fstec.lookup("BDU:2026-00003")["bdu_ids"] == []

    first["entries"]["CVE-2024-1111"].append(
        {
            "bdu_id": "BDU:2024-99999",
            "name": "Second BDU id",
            "severity": "",
            "cvss": None,
            "publication_date": None,
            "updated": None,
        }
    )
    database.write_text(json.dumps(first) + " ", encoding="utf-8")
    assert bdu_fstec.lookup("CVE-2024-1111")["bdu_ids"] == [
        "BDU:2024-00001",
        "BDU:2024-99999",
    ]


def test_bad_archive_is_refused(tmp_path):
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("one.xml", XML)
        archive.writestr("two.xml", XML)
    try:
        bdu_fstec.build_overlay(path)
    except ValueError as exc:
        assert "exactly one XML" in str(exc)
    else:
        raise AssertionError("ambiguous BDU archive accepted")
