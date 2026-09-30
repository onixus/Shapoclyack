"""FSTEC BDU CVE identity overlay and official XML dump parser (#356).

The database is used as enrichment for findings another detector already
observed. A BDU-only record is preserved in provenance, but is not turned into
a finding: affected-version ranges in the public dump are not a machine-safe
package/CPE constraint and guessing there would create false evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import xml.etree.ElementTree as ET
import zipfile

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO

DEFAULT_DATABASE = Path("scanner/data/bdu/bdu-overlay.json")
DATABASE_ENV = "OCTO_BDU_FSTEC_DATABASE"
SOURCE_URL = "https://bdu.fstec.ru/files/documents/vulxml.zip"
SOURCE_URL_ENV = "BDU_FSTEC_URL"

_CVE_RE = re.compile(r"^CVE-\\d{4}-\\d{4,}$", re.IGNORECASE)
_BDU_RE = re.compile(r"^BDU:\\d{4}-\\d{5,}$", re.IGNORECASE)
MAX_XML_BYTES = 1024 * 1024 * 1024

_lock = threading.Lock()
_cache_fingerprint: tuple[str, int, int] | None = None
_cache: dict[str, Any] = {}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _text(node: ET.Element, name: str) -> str:
    for child in node:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _date_key(value: str | None) -> tuple[int, int, int]:
    text = str(value or "").strip()
    for fmt in ("%d.%m.%Y", "%Y-%m-%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(text[:19] if "T" in fmt else text[:10], fmt)
            return parsed.year, parsed.month, parsed.day
        except ValueError:
            continue
    return 0, 0, 0


def _all_cves(node: ET.Element) -> list[str]:
    found: set[str] = set()
    for child in node.iter():
        if _local(child.tag) != "identifier":
            continue
        value = (child.text or "").strip().upper()
        if _CVE_RE.fullmatch(value):
            found.add(value)
    return sorted(found)


def _bdu_id(node: ET.Element) -> str:
    for child in node:
        if _local(child.tag) == "identifier":
            value = (child.text or "").strip().upper()
            return value if _BDU_RE.fullmatch(value) else ""
    return ""


def _cvss(node: ET.Element) -> float | None:
    for child in node.iter():
        if _local(child.tag) != "vector":
            continue
        try:
            return float(child.attrib.get("score", ""))
        except (TypeError, ValueError):
            return None
    return None


def _record(node: ET.Element) -> dict[str, Any] | None:
    bdu_id = _bdu_id(node)
    if not bdu_id:
        return None
    updated = _text(node, "last_upd_date") or _text(node, "publication_date")
    return {
        "bdu_id": bdu_id,
        "name": _text(node, "name"),
        "severity": _text(node, "severity"),
        "cvss": _cvss(node),
        "publication_date": _text(node, "publication_date") or None,
        "updated": updated or None,
        "cves": _all_cves(node),
    }


def parse_xml(
    stream: BinaryIO,
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]], str | None]:
    """Stream the official XML and keep CVE-linked plus BDU-only records."""
    entries: dict[str, list[dict[str, Any]]] = {}
    bdu_only: list[dict[str, Any]] = []
    newest: str | None = None
    newest_key = (0, 0, 0)
    for _event, node in SafeET.iterparse(stream, events=("end",)):
        if _local(node.tag) != "vul":
            continue
        record = _record(node)
        node.clear()
        if record is None:
            continue
        updated = record.get("updated")
        key = _date_key(updated if isinstance(updated, str) else None)
        if key > newest_key:
            newest_key, newest = key, str(updated)
        public = {key: value for key, value in record.items() if key != "cves"}
        cves = record["cves"]
        if cves:
            for cve in cves:
                entries.setdefault(cve, []).append(public)
        else:
            bdu_only.append(public)
    for records in entries.values():
        records.sort(key=lambda item: item["bdu_id"])
    bdu_only.sort(key=lambda item: item["bdu_id"])
    return entries, bdu_only, newest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_overlay(source: Path, *, origin_url: str | None = None) -> dict[str, Any]:
    """Parse an official ZIP dump or an XML fixture into a compact overlay."""
    source = Path(source)
    source_sha256 = _sha256(source)
    if zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as archive:
            candidates = [
                info
                for info in archive.infolist()
                if not info.is_dir() and info.filename.lower().endswith(".xml")
            ]
            if len(candidates) != 1:
                raise ValueError(
                    f"expected exactly one XML member in {source.name}, got {len(candidates)}"
                )
            member = candidates[0]
            if member.file_size <= 0 or member.file_size > MAX_XML_BYTES:
                raise ValueError(f"BDU XML expands to {member.file_size} bytes; refusing")
            with archive.open(member) as stream:
                try:
                    entries, bdu_only, updated = parse_xml(stream)
                except (ET.ParseError, DefusedXmlException) as exc:
                    raise ValueError(f"invalid BDU XML: {exc}") from exc
    else:
        if source.stat().st_size > MAX_XML_BYTES:
            raise ValueError(f"BDU XML exceeds {MAX_XML_BYTES} bytes; refusing")
        with source.open("rb") as stream:
            try:
                entries, bdu_only, updated = parse_xml(stream)
            except (ET.ParseError, DefusedXmlException) as exc:
                raise ValueError(f"invalid BDU XML: {exc}") from exc
    if not entries and not bdu_only:
        raise ValueError("BDU dump contains no usable vulnerability records")
    return {
        "version": 1,
        "source": "bdu-fstec",
        "updated": updated,
        "origin_url": origin_url,
        "source_sha256": source_sha256,
        "entries": entries,
        "bdu_only": bdu_only,
    }


def database_path() -> Path:
    return Path(os.environ.get(DATABASE_ENV) or DEFAULT_DATABASE)


def reset_cache() -> None:
    global _cache_fingerprint, _cache
    with _lock:
        _cache_fingerprint = None
        _cache = {}


def _load() -> dict[str, Any]:
    global _cache_fingerprint, _cache
    path = database_path()
    try:
        stat = path.stat()
        fingerprint = (str(path), stat.st_mtime_ns, stat.st_size)
    except OSError:
        fingerprint = (str(path), 0, 0)
    with _lock:
        if fingerprint == _cache_fingerprint:
            return _cache
        payload: dict[str, Any] = {}
        if fingerprint[1]:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                if (
                    isinstance(raw, dict)
                    and raw.get("version") == 1
                    and isinstance(raw.get("entries"), dict)
                ):
                    payload = raw
            except (OSError, ValueError, RecursionError):
                payload = {}
        _cache_fingerprint = fingerprint
        _cache = payload
        return _cache


def snapshot() -> dict[str, Any]:
    """The currently loaded overlay object, for one internally consistent pass."""
    return _load()


def lookup(
    cve: str | None,
    *,
    dataset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """BDU identity for one CVE together with dataset provenance."""
    value = str(cve or "").strip().upper()
    if not _CVE_RE.fullmatch(value):
        return {"bdu_ids": [], "source": None, "updated": None, "source_sha256": None}
    payload = _load() if dataset is None else dataset
    raw = (payload.get("entries") or {}).get(value, [])
    records = raw if isinstance(raw, list) else []
    ids = sorted(
        {
            str(item.get("bdu_id"))
            for item in records
            if isinstance(item, dict)
            and _BDU_RE.fullmatch(str(item.get("bdu_id") or ""))
        }
    )
    return {
        "bdu_ids": ids,
        "source": payload.get("source") if ids else None,
        "updated": payload.get("updated") if ids else None,
        "source_sha256": payload.get("source_sha256") if ids else None,
    }


def dataset_info(dataset: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = _load() if dataset is None else dataset
    entries = payload.get("entries") if isinstance(payload.get("entries"), dict) else {}
    bdu_only = payload.get("bdu_only") if isinstance(payload.get("bdu_only"), list) else []
    return {
        "source": payload.get("source") or None,
        "updated": payload.get("updated") or None,
        "source_sha256": payload.get("source_sha256") or None,
        "origin_url": payload.get("origin_url") or None,
        "cve_entries": len(entries),
        "bdu_only_entries": len(bdu_only),
        "present": bool(payload),
    }
