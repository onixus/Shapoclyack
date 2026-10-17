"""Rendering a report body to CSV or XLSX (#355).

Both are tables over the same body ``content.build`` produced -- like the other
renderers, nothing here queries anything. ``tables`` turns the body into named
tables once; CSV prints them one after another, separated by a blank row, and
XLSX gives each its own worksheet.

**Formula injection.** A report is opened in Excel by someone outside the
installation, and its cells carry text an attacker can influence (a finding
title read off a banner, an asset name from a DNS record). A cell starting with
``= + - @`` -- or a tab or carriage return, which Excel strips before deciding
-- is a formula to a spreadsheet, so ``cell`` puts an apostrophe in front of
it, the convention every spreadsheet reads back as literal text. The XLSX
writer never emits a formula element either, so the escape there is a second
lock rather than the only one.

The XLSX is written with ``zipfile`` and a handful of XML parts rather than a
spreadsheet library: the output is flat tables of strings and numbers, and a
library would be a new pinned dependency (and a hash-locked entry in every
requirements lock) for the sake of formatting this does not use.
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from collections.abc import Sequence
from typing import Any
from xml.sax.saxutils import escape as _xml_escape

# See the module docstring: the tab and carriage return are here because Excel
# strips them before deciding whether a cell is a formula.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

#: A table is ``(name, header, rows)``.
Table = tuple[str, list[str], list[list[Any]]]

_SEVERITIES = ("critical", "high", "medium", "low", "unknown")
_SLA_LABELS = {
    "within_sla": "Within SLA",
    "due_soon": "Due soon",
    "breached": "Past deadline",
    "no_sla": "No SLA",
}
# Characters XML 1.0 cannot carry at all; an escaped entity is still invalid.
_XML_ILLEGAL = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")
_SHEET_NAME_ILLEGAL = re.compile(r"[\[\]:*?/\\]")


def cell(value: Any) -> Any:
    """A value made safe to hand to a spreadsheet; numbers pass through."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (list, tuple)):
        value = ", ".join(str(item) for item in value)
    elif isinstance(value, dict):
        value = ", ".join(f"{key}={val}" for key, val in value.items())
    text = str(value)
    if text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def tables(body: dict[str, Any]) -> list[Table]:
    """The report body as flat tables, one per section that is present."""
    out: list[Table] = [
        (
            "Report",
            ["Field", "Value"],
            [
                ["Title", body.get("title")],
                ["Kind", body.get("kind")],
                ["Generated at", body.get("generated_at")],
                ["Period (days)", body.get("period_days")],
            ],
        )
    ]
    if body.get("kpis") is not None:
        out.append(("KPIs", ["Metric", "Value"], [[k, v] for k, v in body["kpis"].items()]))
    if body.get("severity") is not None:
        severity = body["severity"]
        out.append(
            (
                "Severity",
                ["Severity", "Open findings"],
                [[name, int(severity.get(name, 0))] for name in _SEVERITIES],
            )
        )
    if body.get("sla") is not None:
        sla = body["sla"]
        out.append(
            (
                "SLA",
                ["SLA status", "Findings"],
                [[label, int(sla.get(key, 0))] for key, label in _SLA_LABELS.items()],
            )
        )
    if body.get("trend") is not None:
        out.append(
            (
                "Trend",
                ["Recorded at", "Open", "Past deadline", "Estate risk"],
                [
                    [p.get("recorded_at"), p.get("open_total"), p.get("breached"), p.get("estate_risk")]
                    for p in body["trend"]
                ],
            )
        )
    if body.get("top_findings") is not None:
        out.append(
            (
                "Findings",
                [
                    "Vuln ID", "Title", "CVE", "Asset", "Port", "Severity", "Risk level",
                    "Score", "State", "SLA", "In KEV", "Due at", "Remediation",
                ],
                [
                    [
                        f.get("vuln_id"), f.get("title"), f.get("cve"), f.get("asset_id"),
                        f.get("port"), f.get("severity"), f.get("risk_level"),
                        f.get("contextual_score"), f.get("state"), f.get("sla"),
                        f.get("in_kev"), f.get("due_at"), f.get("remediation"),
                    ]
                    for f in body["top_findings"]
                ],
            )
        )
    if body.get("assets") is not None:
        out.append(("Assets", ["Metric", "Value"], [[k, v] for k, v in body["assets"].items()]))
    register = body.get("risk_acceptance")
    if register is not None:
        out.append(
            (
                "Risk acceptance",
                ["Finding", "Owner", "Requested by", "Approved by", "Self-approved", "Until", "Status"],
                [
                    [
                        e.get("cve") or e.get("title") or e.get("vuln_id"),
                        e.get("asset_owner") or e.get("assignee"),
                        e.get("requested_by"), e.get("approved_by"), e.get("self_approved"),
                        e.get("until"), e.get("status"),
                    ]
                    for e in register.get("entries") or []
                ],
            )
        )
    for framework in body.get("compliance") or []:
        controls = framework.get("controls") or []
        if controls:
            header = ["Control", "Title", "Status", "Failing findings"]
            rows: list[list[Any]] = [
                [c.get("control_id"), c.get("title"), c.get("status"), c.get("failing_count")]
                for c in controls
            ]
        else:
            header = ["Control", "Title", "Coverage score", "Not assessed"]
            rows = [
                [
                    "(summary)",
                    f"{framework.get('controls_passed', 0)}/"
                    f"{framework.get('controls_assessed', 0)} assessed controls passing",
                    framework.get("coverage_score"),
                    framework.get("controls_not_assessed", 0),
                ]
            ]
        name = f"{framework.get('name', 'Compliance')} {framework.get('version', '')}".strip()
        out.append((name, header, rows))
    return out


def render_csv(body: dict[str, Any]) -> bytes:
    """Every table in order: a one-cell heading row, the header, the rows, a blank row."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    for index, (name, header, rows) in enumerate(tables(body)):
        if index:
            writer.writerow([])
        writer.writerow([cell(name)])
        writer.writerow([cell(h) for h in header])
        for row in rows:
            writer.writerow([cell(v) for v in row])
    # BOM so Excel reads Cyrillic control titles as UTF-8 rather than cp1252.
    return b"\xef\xbb\xbf" + buffer.getvalue().encode("utf-8")


# ------------------------------------------------------------------------ XLSX


def _sheet_names(names: Sequence[str]) -> list[str]:
    """Names Excel accepts: <= 31 characters, none of ``[]:*?/\\``, unique."""
    used: set[str] = set()
    out: list[str] = []
    for raw in names:
        base = (_SHEET_NAME_ILLEGAL.sub(" ", raw).strip().strip("'") or "Sheet")[:31]
        name, n = base, 1
        while name.lower() in used:
            n += 1
            suffix = f" ({n})"
            name = base[: 31 - len(suffix)] + suffix
        used.add(name.lower())
        out.append(name)
    return out


def _column(index: int) -> str:
    letters = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        letters = chr(65 + rem) + letters
    return letters


def _row_xml(row_no: int, values: list[Any], style: int) -> str:
    cells = []
    for col, raw in enumerate(values):
        value = cell(raw)
        ref = f"{_column(col)}{row_no}"
        if isinstance(value, (int, float)):
            cells.append(f'<c r="{ref}" s="{style}"><v>{value!r}</v></c>')
        else:
            text = _xml_escape(_XML_ILLEGAL.sub("", str(value)))
            cells.append(
                f'<c r="{ref}" s="{style}" t="inlineStr"><is>'
                f'<t xml:space="preserve">{text}</t></is></c>'
            )
    return f'<row r="{row_no}">{"".join(cells)}</row>'


def _sheet_xml(header: list[str], rows: list[list[Any]]) -> str:
    body = [_row_xml(1, list(header), 1)]
    body += [_row_xml(i, r, 0) for i, r in enumerate(rows, start=2)]
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" '
        'activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>'
        f'<sheetData>{"".join(body)}</sheetData></worksheet>'
    )


def render_xlsx(body: dict[str, Any]) -> bytes:
    """One worksheet per table, a bold frozen header row, strings stored inline."""
    data = tables(body)
    names = _sheet_names([name for name, _, _ in data])
    ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rel_ns = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    pkg_rel = "http://schemas.openxmlformats.org/package/2006/relationships"
    head = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    sheet_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="{sheet_type}"/>'
        for i in range(1, len(data) + 1)
    )
    sheets = "".join(
        f'<sheet name="{_xml_escape(n, {chr(34): "&quot;"})}" sheetId="{i}" r:id="rId{i}"/>'
        for i, n in enumerate(names, start=1)
    )
    sheet_rels = "".join(
        f'<Relationship Id="rId{i}" Type="{rel_ns}/worksheet" Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, len(data) + 1)
    )
    parts = {
        "[Content_Types].xml": (
            f'{head}<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/'
            'vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            f"{overrides}</Types>"
        ),
        "_rels/.rels": (
            f'{head}<Relationships xmlns="{pkg_rel}"><Relationship Id="rId1" '
            f'Type="{rel_ns}/officeDocument" Target="xl/workbook.xml"/></Relationships>'
        ),
        "xl/workbook.xml": (
            f'{head}<workbook xmlns="{ns}" xmlns:r="{rel_ns}"><sheets>{sheets}</sheets></workbook>'
        ),
        "xl/_rels/workbook.xml.rels": (
            f'{head}<Relationships xmlns="{pkg_rel}">{sheet_rels}'
            f'<Relationship Id="rId{len(data) + 1}" Type="{rel_ns}/styles" Target="styles.xml"/>'
            "</Relationships>"
        ),
        "xl/styles.xml": (
            f'{head}<styleSheet xmlns="{ns}">'
            '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
            '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
            '<fills count="2"><fill><patternFill patternType="none"/></fill>'
            '<fill><patternFill patternType="gray125"/></fill></fills>'
            "<borders count=\"1\"><border><left/><right/><top/><bottom/><diagonal/></border></borders>"
            '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
            '<cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
            '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs>'
            "</styleSheet>"
        ),
    }
    for i, (_, header, rows) in enumerate(data, start=1):
        parts[f"xl/worksheets/sheet{i}.xml"] = _sheet_xml(header, rows)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, xml in parts.items():
            # Fixed timestamp: the same body renders to the same bytes, which is
            # what keeps a manifest hash meaningful across a re-render.
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, xml)
    return out.getvalue()
