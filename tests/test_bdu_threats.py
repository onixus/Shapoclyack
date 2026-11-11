"""Tests for FSTEC Threat Bank (БДУ УБИ) parser."""

import json
import zipfile
from pathlib import Path

import pytest

from api.services import bdu_threats


_MINIMAL_SHARED_STRINGS = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="6" uniqueCount="6">
    <si><t>Идентификатор УБИ</t></si>
    <si><t>Наименование УБИ</t></si>
    <si><t>Описание</t></si>
    <si><t>Источник</t></si>
    <si><t>Объект</t></si>
    <si><t>Угроза отказа в обслуживании</t></si>
</sst>
"""

_MINIMAL_SHEET1 = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
    <sheetData>
        <row r="1">
            <c r="A1" t="s"><v>0</v></c>
            <c r="B1" t="s"><v>1</v></c>
            <c r="C1" t="s"><v>2</v></c>
            <c r="D1" t="s"><v>3</v></c>
            <c r="E1" t="s"><v>4</v></c>
            <c r="F1"><v>1</v></c>
            <c r="G1"><v>1</v></c>
            <c r="H1"><v>1</v></c>
            <c r="I1"><v>45000</v></c>
            <c r="J1"><v>45000</v></c>
        </row>
        <row r="2">
            <c r="A2"><v>15</v></c>
            <c r="B2" t="s"><v>5</v></c>
            <c r="C2"><v>Описание угрозы</v></c>
            <c r="D2"><v>Внешний нарушитель</v></c>
            <c r="E2"><v>Серверные службы</v></c>
            <c r="F2"><v>0</v></c>
            <c r="G2"><v>0</v></c>
            <c r="H2"><v>1</v></c>
            <c r="I2"><v>45000</v></c>
            <c r="J2"><v>45000</v></c>
        </row>
    </sheetData>
</worksheet>
"""


def _create_mock_xlsx(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("xl/sharedStrings.xml", _MINIMAL_SHARED_STRINGS)
        z.writestr("xl/worksheets/sheet1.xml", _MINIMAL_SHEET1)


def test_parse_threats_xlsx(tmp_path):
    xlsx_path = tmp_path / "thrlist.xlsx"
    _create_mock_xlsx(xlsx_path)

    overlay = bdu_threats.build_overlay(xlsx_path)
    assert overlay["source"] == "bdu-threats-fstec"
    assert "УБИ.015" in overlay["threats"]
    threat = overlay["threats"]["УБИ.015"]
    assert threat["name"] == "Угроза отказа в обслуживании"
    assert threat["impact_availability"] is True
    assert threat["impact_confidentiality"] is False
    assert threat["impact_integrity"] is False


def test_bdu_threats_lookup(tmp_path, monkeypatch):
    xlsx_path = tmp_path / "thrlist.xlsx"
    _create_mock_xlsx(xlsx_path)
    json_path = tmp_path / "threats-overlay.json"

    overlay = bdu_threats.build_overlay(xlsx_path)
    json_path.write_text(json.dumps(overlay), encoding="utf-8")

    monkeypatch.setenv(bdu_threats.DATABASE_ENV, str(json_path))
    bdu_threats.reset_cache()

    hit = bdu_threats.lookup_threat("15")
    assert hit is not None
    assert hit["ubi_id"] == "УБИ.015"

    hit2 = bdu_threats.lookup_threat("УБИ.015")
    assert hit2 is not None
    assert hit2["name"] == "Угроза отказа в обслуживании"

    assert bdu_threats.lookup_threat("УБИ.999") is None


def test_lookup_normalizes_ubi_forms_and_hides_archived(tmp_path, monkeypatch):
    payload = {
        "version": 1,
        "threats": {
            "УБИ.001": {"ubi_id": "УБИ.001", "name": "live", "status": "Опубликована"},
            "УБИ.002": {"ubi_id": "УБИ.002", "name": "old", "status": "Архивная"},
        },
    }
    path = tmp_path / "threats-overlay.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv(bdu_threats.DATABASE_ENV, str(path))
    bdu_threats.reset_cache()
    assert bdu_threats.lookup_threat("УБИ.1")["name"] == "live"
    assert bdu_threats.lookup_threat("уби.1")["name"] == "live"
    assert bdu_threats.lookup_threat("UBI.001")["name"] == "live"
    assert bdu_threats.lookup_threat("УБИ.002") is None
    assert [row["ubi_id"] for row in bdu_threats.list_threats()] == ["УБИ.001"]


def test_bad_zip_and_oversized_member_are_value_errors(tmp_path, monkeypatch):
    bad = tmp_path / "bad.xlsx"
    bad.write_bytes(b"not a zip")
    with bad.open("rb") as stream:
        with pytest.raises(ValueError, match="invalid thrlist"):
            bdu_threats.parse_xlsx(stream)
    xlsx = tmp_path / "thrlist.xlsx"
    _create_mock_xlsx(xlsx)
    monkeypatch.setattr(bdu_threats, "MAX_MEMBER_BYTES", 10)
    with xlsx.open("rb") as stream:
        with pytest.raises(ValueError, match="expands"):
            bdu_threats.parse_xlsx(stream)


def test_overlay_size_is_checked_before_hashing(tmp_path, monkeypatch):
    path = tmp_path / "huge.xlsx"
    path.write_bytes(b"x" * 32)
    monkeypatch.setattr(bdu_threats, "MAX_XLSX_BYTES", 8)

    def hashed(_path):
        raise AssertionError("hashed before the size check")

    monkeypatch.setattr(bdu_threats, "_sha256", hashed)
    with pytest.raises(ValueError, match="exceeds"):
        bdu_threats.build_overlay(path)
