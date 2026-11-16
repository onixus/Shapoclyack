"""Tests for business PDF report generation."""

from __future__ import annotations

import json
import re
import zlib
from pathlib import Path

from scanner.pipeline import pdf_report
from scanner.pipeline.pdf_report import write_business_pdf

#: The same Latin+Cyrillic DejaVu subset the report-factory tests use.
_FONT_FIXTURES = Path(__file__).parent / "fixtures" / "fonts"

#: Titles from ``scanner.pipeline.controls.CONTROL_DEFINITIONS``. A core-font
#: summary.pdf used to print every Cyrillic letter in this column as ``?``.
_CONTROL_TITLES = (
    "DNS структура",
    "TLS сертификаты",
    "Почтовая защита",
    "Технологии сайта",
    "Открытые сервисы",
    "Утечки учетных данных",
)


def _seed_run(tmp_path: Path) -> Path:
    (tmp_path / "summary.json").write_text(
        json.dumps(
            {
                "total_targets": 10,
                "alive_hosts": 2,
                "alive_hosts_with_names": 1,
                "open_host_port_pairs": 4,
                "nmap_open_services": 3,
                "os_detected_hosts": 1,
                "potential_vulnerabilities": 2,
                "vulnerable_hosts": 1,
                "vulnerabilities_by_severity": {
                    "critical": 1,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "unknown": 0,
                },
                "top_services": [["ssh", 1], ["http", 2]],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "vulnerabilities.json").write_text(
        json.dumps(
            [
                {
                    "host": "10.0.0.5",
                    "port": "22",
                    "script_id": "vulners",
                    "cve": "CVE-2016-10012",
                    "cvss": 9.8,
                    "severity": "critical",
                },
                {
                    "host": "10.0.0.5",
                    "port": "80",
                    "script_id": "http-csrf",
                    "cve": "CVE-2018-15473",
                    "cvss": 5.3,
                    "severity": "medium",
                },
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "diff.json").write_text(
        json.dumps(
            {
                "counts": {
                    "hosts_added": 1,
                    "hosts_removed": 0,
                    "ports_added": 2,
                    "ports_removed": 0,
                    "vulns_added": 1,
                    "vulns_removed": 0,
                },
                "vulnerabilities": {
                    "added": [
                        {
                            "host": "10.0.0.5",
                            "port": "22",
                            "cve": "CVE-2016-10012",
                            "severity": "critical",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "run_meta.json").write_text(
        json.dumps({"run_id": "pdf-run-1", "mode": "balanced"}),
        encoding="utf-8",
    )
    return tmp_path


def test_write_business_pdf_creates_valid_pdf(tmp_path: Path):
    out_dir = _seed_run(tmp_path)
    path = write_business_pdf(
        out_dir,
        run_id="pdf-run-1",
        title="Shapoclyack Security Scan Report",
        org_name="Acme Security",
        max_vulnerabilities=10,
    )
    assert path == out_dir / "summary.pdf"
    assert path.exists()
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 500


def test_write_business_pdf_works_with_empty_artifacts(tmp_path: Path):
    path = write_business_pdf(tmp_path, run_id="empty")
    assert path.exists()
    assert path.read_bytes().startswith(b"%PDF")


def _seed_controls(tmp_path: Path) -> None:
    (tmp_path / "controls.json").write_text(
        json.dumps(
            {
                "overall_verdict": "fail",
                "overall_risk": "high",
                "controls": [
                    {
                        "title": title,
                        "status": "not_checked",
                        "risk_level": "unassessed",
                        "why": "checked",
                    }
                    for title in _CONTROL_TITLES
                ],
            }
        ),
        encoding="utf-8",
    )


def _pdf_streams(out: bytes) -> list[bytes]:
    streams = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", out, re.DOTALL):
        raw = match.group(1)
        try:
            streams.append(zlib.decompress(raw))
        except zlib.error:
            streams.append(raw)
    return streams


def _tounicode_points(out: bytes) -> set[int]:
    """Unicode scalars the embedded face's ToUnicode map can produce.

    fpdf2 records only the glyphs it drew. A summary that still ran titles
    through the Latin-1 replacement keeps the font name and drops these points.
    """

    points: set[int] = set()

    def take(hex_text: bytes) -> None:
        raw = bytes.fromhex(hex_text.decode())
        if len(raw) % 2:
            return
        points.update(int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2))

    for stream in _pdf_streams(out):
        if b"beginbfchar" not in stream and b"beginbfrange" not in stream:
            continue
        for block in re.findall(rb"beginbfchar(.*?)endbfchar", stream, re.DOTALL):
            for _src, dest in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", block):
                take(dest)
        for block in re.findall(rb"beginbfrange(.*?)endbfrange", stream, re.DOTALL):
            for start, end, dest in re.findall(
                rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>",
                block,
            ):
                span = int(end, 16) - int(start, 16)
                if not 0 <= span <= 0x1000 or len(dest) < 4:
                    continue
                # dest may be several UTF-16 units; a bfrange walks the first one.
                first = int(dest[:4], 16)
                points.update(range(first, first + span + 1))
            for _start, _end, array in re.findall(
                rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*\[(.*?)\]",
                block,
                re.DOTALL,
            ):
                for dest in re.findall(rb"<([0-9A-Fa-f]+)>", array):
                    take(dest)
    return points


def test_summary_pdf_keeps_cyrillic_control_titles(tmp_path: Path, monkeypatch):
    """«Утечки учетных данных» has to stay that, not become ``?????? ??????? ??????``."""
    monkeypatch.setattr(pdf_report, "_UNICODE_FONT_DIRS", (str(_FONT_FIXTURES),))
    _seed_controls(tmp_path)
    path = write_business_pdf(tmp_path, run_id="cyr", org_name="Организация")
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert b"DejaVu" in data
    assert b"DNS ?????????" not in data
    needed = {ord(ch) for title in _CONTROL_TITLES for ch in title if "\u0400" <= ch <= "\u04ff"}
    needed.add(ord("О"))
    missing = needed - _tounicode_points(data)
    assert not missing, "Cyrillic titles did not go through the TrueType face"


def test_summary_pdf_still_renders_without_a_unicode_face(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(pdf_report, "_UNICODE_FONT_DIRS", ())
    _seed_controls(tmp_path)
    path = write_business_pdf(tmp_path, run_id="core")
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert b"DejaVu" not in data
    replaced = "DNS структура".encode("latin-1", errors="replace")
    assert any(replaced in stream for stream in _pdf_streams(data))


def test_a_truncated_unicode_face_does_not_fail_summary_pdf(tmp_path: Path, monkeypatch):
    (tmp_path / "DejaVuSans.ttf").write_bytes(b"")
    monkeypatch.setattr(pdf_report, "_UNICODE_FONT_DIRS", (str(tmp_path),))
    out = tmp_path / "run"
    out.mkdir()
    path = write_business_pdf(out, run_id="bad-font")
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert b"DejaVu" not in data
