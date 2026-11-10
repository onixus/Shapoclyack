"""FSTEC Threat Bank (БДУ УБИ — thrlist.xlsx) parser and enrichment overlay.

Parses official thrlist.xlsx published at https://bdu.fstec.ru/files/documents/thrlist.xlsx
without relying on external dependencies (using zipfile and xml.etree.ElementTree).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO
import xml.etree.ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

DEFAULT_DATABASE = Path("scanner/data/bdu/threats-overlay.json")
DATABASE_ENV = "OCTO_BDU_THREATS_DATABASE"
SOURCE_URL = "https://bdu.fstec.ru/files/documents/thrlist.xlsx"
SOURCE_URL_ENV = "BDU_THREATS_URL"

_UBI_RE = re.compile(r"^УБИ\.(\d+)$", re.IGNORECASE)
MAX_XLSX_BYTES = 100 * 1024 * 1024

_lock = threading.Lock()
_cache_fingerprint: tuple[str, int, int] | None = None
_cache: dict[str, Any] = {}
_checked_at: float | None = None


def _clean_str(val: str | None) -> str:
    if not val:
        return ""
    # Remove Excel control code artifacts like _x000D_
    return val.replace("_x000D_", "").strip()


def parse_xlsx(stream: BinaryIO) -> tuple[dict[str, dict[str, Any]], str | None]:
    """Parse thrlist.xlsx spreadsheet and extract UBI threat definitions."""
    with zipfile.ZipFile(stream) as archive:
        if "xl/sharedStrings.xml" not in archive.namelist() or "xl/worksheets/sheet1.xml" not in archive.namelist():
            raise ValueError("invalid thrlist.xlsx: missing worksheets or shared strings")

        # 1. Parse shared strings safely
        shared_strings: list[str] = []
        with archive.open("xl/sharedStrings.xml") as ss_file:
            try:
                ss_tree = SafeET.parse(ss_file)
            except (ET.ParseError, DefusedXmlException) as exc:
                raise ValueError(f"invalid sharedStrings XML in thrlist.xlsx: {exc}") from exc

            for si in ss_tree.iter():
                if si.tag.endswith("}si"):
                    texts = [elem.text or "" for elem in si.iter() if elem.tag.endswith("}t")]
                    shared_strings.append("".join(texts))

        # 2. Parse sheet1.xml
        with archive.open("xl/worksheets/sheet1.xml") as sheet_file:
            try:
                sheet_tree = SafeET.parse(sheet_file)
            except (ET.ParseError, DefusedXmlException) as exc:
                raise ValueError(f"invalid sheet1.xml in thrlist.xlsx: {exc}") from exc

            rows: list[dict[str, str]] = []
            for row_node in sheet_tree.iter():
                if not row_node.tag.endswith("}row"):
                    continue
                row_cells: dict[str, str] = {}
                for c in row_node.iter():
                    if not c.tag.endswith("}c"):
                        continue
                    r_ref = c.attrib.get("r", "")
                    col_letter = "".join(filter(str.isalpha, r_ref))
                    cell_type = c.attrib.get("t")
                    v_elem = None
                    for ch in c:
                        if ch.tag.endswith("}v"):
                            v_elem = ch.text
                    val = v_elem or ""
                    if cell_type == "s" and v_elem is not None:
                        try:
                            val = shared_strings[int(v_elem)]
                        except (IndexError, ValueError):
                            val = ""
                    row_cells[col_letter] = _clean_str(val)
                if row_cells:
                    rows.append(row_cells)

    # First row is super-header, second row is column headers:
    # A: Идентификатор УБИ
    # B: Наименование УБИ
    # C: Описание
    # D: Источник угрозы
    # E: Объект воздействия
    # F: Нарушение конфиденциальности
    # G: Нарушение целостности
    # H: Нарушение доступности
    # I: Дата включения угрозы
    # J: Дата последнего изменения
    threats: dict[str, dict[str, Any]] = {}
    newest_date: str | None = None

    for row in rows:
        raw_id = row.get("A", "").strip()
        if not raw_id or not raw_id.isdigit():
            continue
        ubi_id = f"УБИ.{int(raw_id):03d}"
        name = row.get("B", "")
        description = row.get("C", "")
        source = row.get("D", "")
        target_object = row.get("E", "")
        confidentiality = row.get("F", "") == "1"
        integrity = row.get("G", "") == "1"
        availability = row.get("H", "") == "1"
        
        # Excel date offset (days since 1899-12-30)
        updated = row.get("J") or row.get("I")
        updated_iso: str | None = None
        if updated and updated.isdigit():
            try:
                days = int(updated)
                epoch = datetime(1899, 12, 30, tzinfo=timezone.utc)
                parsed_dt = epoch.fromtimestamp(epoch.timestamp() + days * 86400, tz=timezone.utc)
                updated_iso = parsed_dt.strftime("%Y-%m-%d")
                if not newest_date or updated_iso > newest_date:
                    newest_date = updated_iso
            except (ValueError, OverflowError):
                pass

        threats[ubi_id] = {
            "ubi_id": ubi_id,
            "name": name,
            "description": description,
            "threat_source": source,
            "target_object": target_object,
            "impact_confidentiality": confidentiality,
            "impact_integrity": integrity,
            "impact_availability": availability,
            "updated": updated_iso,
        }

    return threats, newest_date


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_overlay(source: Path, *, origin_url: str | None = None) -> dict[str, Any]:
    """Parse official thrlist.xlsx into structured JSON overlay."""
    source = Path(source)
    source_sha256 = _sha256(source)
    if source.stat().st_size > MAX_XLSX_BYTES:
        raise ValueError(f"threats XLSX exceeds {MAX_XLSX_BYTES} bytes; refusing")

    with source.open("rb") as stream:
        threats, updated = parse_xlsx(stream)

    if not threats:
        raise ValueError("thrlist.xlsx contains no usable threat records")

    return {
        "version": 1,
        "source": "bdu-threats-fstec",
        "updated": updated,
        "origin_url": origin_url,
        "source_sha256": source_sha256,
        "threats": threats,
    }


def database_path() -> Path:
    return Path(os.environ.get(DATABASE_ENV) or DEFAULT_DATABASE)


def reset_cache() -> None:
    global _cache_fingerprint, _cache, _checked_at
    with _lock:
        _cache_fingerprint = None
        _cache = {}
        _checked_at = None


def _load() -> dict[str, Any]:
    global _cache_fingerprint, _cache, _checked_at
    now = time.monotonic()
    checked = _checked_at
    if checked is not None and now - checked < 60.0:
        return _cache
    path = database_path()
    try:
        stat = path.stat()
        fingerprint = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        fingerprint = (str(path), 0, 0)
    with _lock:
        if fingerprint == _cache_fingerprint:
            _checked_at = now
            return _cache
    payload: dict[str, Any] = {}
    if fingerprint[1]:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("version") == 1 and isinstance(raw.get("threats"), dict):
                payload = raw
        except (OSError, ValueError, RecursionError):
            payload = {}
    with _lock:
        _cache_fingerprint = fingerprint
        _cache = payload
        _checked_at = now
        return _cache


def lookup_threat(ubi_id: str) -> dict[str, Any] | None:
    """Look up one threat by UBI.NNN or NNN."""
    val = ubi_id.strip().upper()
    if val.isdigit():
        val = f"УБИ.{int(val):03d}"
    data = _load()
    threats = data.get("threats") or {}
    return threats.get(val)


def list_threats() -> list[dict[str, Any]]:
    data = _load()
    threats = data.get("threats") or {}
    return sorted(threats.values(), key=lambda t: t.get("ubi_id", ""))
