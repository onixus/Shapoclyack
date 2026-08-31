"""Rendering a report body to PDF, HTML or JSON (Sprint 4).

Three renderers over the one body ``content.build`` produced. None of them
queries anything: a renderer that reached back into the database could produce
a PDF whose numbers disagree with the JSON export taken a second earlier, and
"the report says 41, the API says 40" is the kind of discrepancy that costs an
MSSP a customer call rather than a bug report.

The PDF keeps using ``fpdf2``'s core fonts, as ``scanner/pipeline/pdf_report``
does. That limits text to Latin-1 and is why every string goes through
``_safe``: a customer name with a character the core fonts lack must degrade to
a replacement character, not raise mid-render on the first of the month.

The HTML renderer emits a self-contained document with no external references —
no CDN, no webfont, no tracking pixel. It is emailed to people outside the
installation, and a report that phones home when opened is a report a security
team will not forward.
"""

from __future__ import annotations

import base64
import html
import io
import json
from datetime import datetime
from typing import Any

from fpdf import FPDF

from api.services.reports import branding as branding_service

FORMATS = ("pdf", "html", "json")

MEDIA_TYPES = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "json": "application/json",
}

_SEVERITIES = ("critical", "high", "medium", "low", "unknown")
_SLA_LABELS = {
    "on_track": "On track",
    "due_soon": "Due soon",
    "breached": "Breached",
    "accepted": "Accepted risk",
    "none": "No deadline",
}
_STATUS_LABELS = {"passed": "Pass", "failed": "Fail", "not_assessed": "Not assessed"}


def _safe(text: object) -> str:
    return str(text if text is not None else "").encode("latin-1", errors="replace").decode(
        "latin-1"
    )


def _hex_to_rgb(value: str | None, fallback: tuple[int, int, int]) -> tuple[int, int, int]:
    raw = (value or "").lstrip("#")
    if len(raw) == 3:
        raw = "".join(char * 2 for char in raw)
    if len(raw) != 6:
        return fallback
    try:
        return (int(raw[0:2], 16), int(raw[2:4], 16), int(raw[4:6], 16))
    except ValueError:
        return fallback


def _fmt_date(value: str | None) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return str(value)


# --------------------------------------------------------------------------- PDF


class _BrandedPDF(FPDF):
    def __init__(self, body: dict[str, Any]) -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        brand = body.get("branding") or {}
        self.org_name = str(brand.get("org_name") or "")
        self.footer_text = str(brand.get("footer_text") or "Confidential")
        self.primary = _hex_to_rgb(brand.get("primary_color"), (30, 58, 138))
        self.accent = _hex_to_rgb(brand.get("accent_color"), (59, 130, 246))
        self._logo = _decode_logo(brand.get("logo_png"))
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(left=15, top=16, right=15)

    def header(self) -> None:
        self.set_x(self.l_margin)
        if self._logo is not None:
            try:
                self.image(io.BytesIO(self._logo), x=self.l_margin, y=8, h=8)
                self.set_x(self.l_margin + 30)
            except Exception:  # noqa: BLE001 - a bad logo must not fail the report
                self._logo = None
                self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(*self.primary)
        self.cell(0, 6, _safe(self.org_name or "Security report"), align="L")
        self.ln(7)
        y = self.get_y()
        self.set_draw_color(*self.accent)
        self.set_line_width(0.4)
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 8, _safe(f"{self.footer_text}  |  Page {self.page_no()}"), align="C")


def _decode_logo(value: str | None) -> bytes | None:
    if not value:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except Exception:  # noqa: BLE001 - validated on write; never fail a render here
        return None


def _width(pdf: FPDF) -> float:
    return pdf.w - pdf.l_margin - pdf.r_margin


def _title(pdf: _BrandedPDF, text: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, _safe(text), new_x="LMARGIN", new_y="NEXT")
    y = pdf.get_y()
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(3)
    pdf.set_x(pdf.l_margin)


def _kv(pdf: _BrandedPDF, key: str, value: object) -> None:
    pdf.set_x(pdf.l_margin)
    key_w = 62.0
    y = pdf.get_y()
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(key_w, 6, _safe(key))
    pdf.set_xy(pdf.l_margin + key_w, y)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(_width(pdf) - key_w, 6, _safe(value))
    pdf.set_x(pdf.l_margin)


def _table(pdf: _BrandedPDF, headers: list[str], rows: list[list[str]], widths: list[float]) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_text_color(15, 23, 42)
    for header, width in zip(headers, widths, strict=True):
        pdf.cell(width, 7, _safe(header), border=1, fill=True)
    pdf.ln()
    pdf.set_font("Helvetica", "", 9)
    for row in rows:
        pdf.set_x(pdf.l_margin)
        for cell, width in zip(row, widths, strict=True):
            # Truncated rather than wrapped: a wrapped cell in fpdf's simple
            # cell layout desynchronises the row height from its neighbours.
            text = _safe(cell)
            limit = max(4, int(width / 1.8))
            pdf.cell(width, 6, text[:limit], border=1)
        pdf.ln()
    pdf.set_x(pdf.l_margin)


def render_pdf(body: dict[str, Any]) -> bytes:
    pdf = _BrandedPDF(body)
    pdf.add_page()
    width = _width(pdf)

    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(*pdf.primary)
    pdf.multi_cell(width, 9, _safe(body.get("title") or "Security report"))
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(
        width,
        6,
        _safe(
            "Vulnerability posture for the period ending "
            f"{_fmt_date(body.get('generated_at'))}."
        ),
    )
    pdf.ln(2)
    _kv(pdf, "Organisation", body.get("branding", {}).get("org_name") or body.get("tenant_id"))
    _kv(pdf, "Generated", _fmt_date(body.get("generated_at")))
    _kv(pdf, "Trend window", f"{body.get('period_days', 90)} days")

    sections = body.get("sections") or []
    if "kpis" in sections:
        kpis = body.get("kpis") or {}
        _title(pdf, "Executive summary")
        _kv(pdf, "Open findings", kpis.get("open_total", 0))
        _kv(pdf, "Estate risk (worst open)", kpis.get("estate_risk") or "none")
        _kv(pdf, "Past SLA deadline", kpis.get("breached", 0))
        _kv(pdf, "Untriaged", kpis.get("untriaged", 0))
        _kv(pdf, "Unassigned", kpis.get("unassigned", 0))
        _kv(pdf, "Closed to date", kpis.get("closed_total", 0))
        _kv(
            pdf,
            "Closures confirmed by re-scan",
            f"{kpis.get('machine_verified_closed', 0)} "
            f"({kpis.get('machine_verification_rate', 0.0)}%)",
        )

    if "severity" in sections:
        severity = body.get("severity") or {}
        _title(pdf, "Open findings by severity")
        _table(
            pdf,
            ["Severity", "Open"],
            [[name.capitalize(), str(int(severity.get(name, 0)))] for name in _SEVERITIES],
            [width / 2, width / 2],
        )

    if "sla" in sections:
        sla = body.get("sla") or {}
        _title(pdf, "Remediation against SLA")
        _table(
            pdf,
            ["SLA state", "Findings"],
            [[label, str(int(sla.get(key, 0)))] for key, label in _SLA_LABELS.items()],
            [width / 2, width / 2],
        )

    if "trend" in sections:
        trend = body.get("trend") or []
        _title(pdf, "Risk trend")
        if trend:
            step = max(1, len(trend) // 12)
            _table(
                pdf,
                ["Date", "Open", "Breached", "Estate risk"],
                [
                    [
                        _fmt_date(point.get("recorded_at"))[:10],
                        str(point.get("open_total", 0)),
                        str(point.get("breached", 0)),
                        str(point.get("estate_risk") or "-"),
                    ]
                    for point in trend[::step]
                ],
                [width * 0.3, width * 0.2, width * 0.2, width * 0.3],
            )
        else:
            _kv(pdf, "Snapshots", "none recorded in this window")

    if "top_findings" in sections:
        findings = body.get("top_findings") or []
        _title(pdf, "Highest-risk open findings")
        if findings:
            _table(
                pdf,
                ["Finding", "Asset", "Severity", "Score", "State"],
                [
                    [
                        str(item.get("cve") or item.get("title") or ""),
                        str(item.get("asset_id") or ""),
                        str(item.get("severity") or ""),
                        str(item.get("contextual_score") if item.get("contextual_score") is not None else "-"),
                        str(item.get("state") or ""),
                    ]
                    for item in findings
                ],
                [width * 0.34, width * 0.24, width * 0.14, width * 0.12, width * 0.16],
            )
        else:
            _kv(pdf, "Open findings", "none")

    if "assets" in sections:
        assets = body.get("assets") or {}
        _title(pdf, "Asset coverage")
        _kv(pdf, "Assets", assets.get("total", 0))
        _kv(pdf, "Active", assets.get("active", 0))
        _kv(pdf, "With an owner", f"{assets.get('with_owner', 0)} ({assets.get('owner_coverage_pct')}%)")
        _kv(pdf, "Without an owner", assets.get("without_owner", 0))
        _kv(pdf, "With a business service", assets.get("with_business_service", 0))

    if "compliance" in sections:
        for framework in body.get("compliance") or []:
            _title(pdf, f"{framework.get('name')} {framework.get('version')}")
            score = framework.get("coverage_score")
            _kv(
                pdf,
                "Assessed controls passing",
                f"{framework.get('controls_passed', 0)}/{framework.get('controls_assessed', 0)}"
                + (f" ({score}%)" if score is not None else ""),
            )
            _kv(pdf, "Not assessed", framework.get("controls_not_assessed", 0))
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(100, 116, 139)
            pdf.multi_cell(width, 4.5, _safe(framework.get("scope_note") or ""))
            pdf.ln(1)
            controls = framework.get("controls") or []
            if controls:
                _table(
                    pdf,
                    ["Control", "Title", "Status", "Failing"],
                    [
                        [
                            str(control.get("control_id")),
                            str(control.get("title")),
                            _STATUS_LABELS.get(str(control.get("status")), str(control.get("status"))),
                            str(control.get("failing_count", 0)),
                        ]
                        for control in controls
                    ],
                    [width * 0.14, width * 0.54, width * 0.18, width * 0.14],
                )

    return bytes(pdf.output())


# -------------------------------------------------------------------------- HTML


def _rows(pairs: list[tuple[str, Any]]) -> str:
    return "".join(
        f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
        for key, value in pairs
    )


def render_html(body: dict[str, Any]) -> str:
    brand = body.get("branding") or {}
    primary = html.escape(str(brand.get("primary_color") or branding_service.DEFAULT_PRIMARY))
    accent = html.escape(str(brand.get("accent_color") or branding_service.DEFAULT_ACCENT))
    sections = body.get("sections") or []
    parts: list[str] = []

    logo = brand.get("logo_png")
    header_logo = (
        f'<img class="logo" alt="" src="data:image/png;base64,{html.escape(str(logo))}">'
        if logo
        else ""
    )

    if "kpis" in sections:
        kpis = body.get("kpis") or {}
        parts.append(
            "<h2>Executive summary</h2><table>"
            + _rows(
                [
                    ("Open findings", kpis.get("open_total", 0)),
                    ("Estate risk (worst open)", kpis.get("estate_risk") or "none"),
                    ("Past SLA deadline", kpis.get("breached", 0)),
                    ("Untriaged", kpis.get("untriaged", 0)),
                    ("Unassigned", kpis.get("unassigned", 0)),
                    ("Closed to date", kpis.get("closed_total", 0)),
                    (
                        "Closures confirmed by re-scan",
                        f"{kpis.get('machine_verified_closed', 0)} "
                        f"({kpis.get('machine_verification_rate', 0.0)}%)",
                    ),
                ]
            )
            + "</table>"
        )
    if "severity" in sections:
        severity = body.get("severity") or {}
        parts.append(
            "<h2>Open findings by severity</h2><table>"
            + _rows([(name.capitalize(), int(severity.get(name, 0))) for name in _SEVERITIES])
            + "</table>"
        )
    if "sla" in sections:
        sla = body.get("sla") or {}
        parts.append(
            "<h2>Remediation against SLA</h2><table>"
            + _rows([(label, int(sla.get(key, 0))) for key, label in _SLA_LABELS.items()])
            + "</table>"
        )
    if "trend" in sections:
        trend = body.get("trend") or []
        rows = "".join(
            "<tr><td>{date}</td><td>{open_total}</td><td>{breached}</td><td>{risk}</td></tr>".format(
                date=html.escape(_fmt_date(point.get("recorded_at"))[:10]),
                open_total=int(point.get("open_total", 0)),
                breached=int(point.get("breached", 0)),
                risk=html.escape(str(point.get("estate_risk") or "-")),
            )
            for point in trend
        )
        parts.append(
            "<h2>Risk trend</h2><table><tr><th>Date</th><th>Open</th><th>Breached</th>"
            "<th>Estate risk</th></tr>" + (rows or "<tr><td colspan=4>No snapshots</td></tr>")
            + "</table>"
        )
    if "top_findings" in sections:
        rows = "".join(
            "<tr><td>{title}</td><td>{asset}</td><td>{sev}</td><td>{score}</td>"
            "<td>{state}</td></tr>".format(
                title=html.escape(str(item.get("cve") or item.get("title") or "")),
                asset=html.escape(str(item.get("asset_id") or "")),
                sev=html.escape(str(item.get("severity") or "")),
                score=html.escape(str(item.get("contextual_score") or "-")),
                state=html.escape(str(item.get("state") or "")),
            )
            for item in body.get("top_findings") or []
        )
        parts.append(
            "<h2>Highest-risk open findings</h2><table><tr><th>Finding</th><th>Asset</th>"
            "<th>Severity</th><th>Score</th><th>State</th></tr>"
            + (rows or "<tr><td colspan=5>No open findings</td></tr>")
            + "</table>"
        )
    if "assets" in sections:
        assets = body.get("assets") or {}
        parts.append(
            "<h2>Asset coverage</h2><table>"
            + _rows(
                [
                    ("Assets", assets.get("total", 0)),
                    ("Active", assets.get("active", 0)),
                    ("With an owner", assets.get("with_owner", 0)),
                    ("Without an owner", assets.get("without_owner", 0)),
                    ("Owner coverage", f"{assets.get('owner_coverage_pct')}%"),
                ]
            )
            + "</table>"
        )
    if "compliance" in sections:
        for framework in body.get("compliance") or []:
            score = framework.get("coverage_score")
            block = [
                f"<h2>{html.escape(str(framework.get('name')))} "
                f"{html.escape(str(framework.get('version')))}</h2>",
                f"<p class=note>{html.escape(str(framework.get('scope_note') or ''))}</p>",
                "<table>"
                + _rows(
                    [
                        (
                            "Assessed controls passing",
                            f"{framework.get('controls_passed', 0)}/"
                            f"{framework.get('controls_assessed', 0)}"
                            + (f" ({score}%)" if score is not None else ""),
                        ),
                        ("Not assessed", framework.get("controls_not_assessed", 0)),
                    ]
                )
                + "</table>",
            ]
            controls = framework.get("controls") or []
            if controls:
                rows = "".join(
                    "<tr><td>{cid}</td><td>{title}</td><td class='{cls}'>{status}</td>"
                    "<td>{failing}</td></tr>".format(
                        cid=html.escape(str(control.get("control_id"))),
                        title=html.escape(str(control.get("title"))),
                        cls=html.escape(str(control.get("status"))),
                        status=html.escape(
                            _STATUS_LABELS.get(
                                str(control.get("status")), str(control.get("status"))
                            )
                        ),
                        failing=int(control.get("failing_count", 0)),
                    )
                    for control in controls
                )
                block.append(
                    "<table><tr><th>Control</th><th>Title</th><th>Status</th>"
                    "<th>Failing</th></tr>" + rows + "</table>"
                )
            parts.append("".join(block))

    footer = html.escape(str(brand.get("footer_text") or "Confidential"))
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        f"<title>{html.escape(str(body.get('title') or 'Security report'))}</title>"
        "<style>"
        "body{font-family:system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif;"
        "color:#0f172a;margin:0;padding:32px;background:#fff;}"
        f"h1{{color:{primary};font-size:24px;margin:0 0 4px}}"
        f"header{{border-bottom:3px solid {accent};padding-bottom:12px;margin-bottom:24px}}"
        "h2{font-size:16px;margin:28px 0 8px}"
        "table{border-collapse:collapse;width:100%;margin-bottom:8px;font-size:13px}"
        "th,td{border:1px solid #e2e8f0;padding:6px 8px;text-align:left}"
        "th{background:#f1f5f9;font-weight:600}"
        ".note{color:#64748b;font-size:12px;margin:4px 0 10px}"
        ".failed{color:#b91c1c;font-weight:600}.passed{color:#15803d}"
        ".not_assessed{color:#64748b}"
        ".logo{max-height:40px;margin-bottom:8px;display:block}"
        "footer{margin-top:32px;border-top:1px solid #e2e8f0;padding-top:8px;"
        "color:#64748b;font-size:12px}"
        "</style></head><body><header>"
        + header_logo
        + f"<h1>{html.escape(str(body.get('title') or 'Security report'))}</h1>"
        f"<div class=note>Generated {html.escape(_fmt_date(body.get('generated_at')))}"
        f" &middot; trend window {int(body.get('period_days', 90))} days</div>"
        "</header>"
        + "".join(parts)
        + f"<footer>{footer}</footer></body></html>"
    )


# -------------------------------------------------------------------------- JSON


def render_json(body: dict[str, Any]) -> str:
    return json.dumps(body, indent=2, sort_keys=False, default=str)


def render(body: dict[str, Any], fmt: str) -> bytes:
    if fmt == "pdf":
        return render_pdf(body)
    if fmt == "html":
        return render_html(body).encode("utf-8")
    if fmt == "json":
        return render_json(body).encode("utf-8")
    raise ValueError(f"unknown report format {fmt!r}; expected one of {', '.join(FORMATS)}")
