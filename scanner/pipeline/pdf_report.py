"""Business-oriented PDF summary for Octo-man scan runs.

Reads artifacts already written by ``build_reports`` / report diff and produces
``summary.pdf``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fpdf import FPDF

from .report import SEVERITY_ORDER

_SEVERITY_LABELS = ("critical", "high", "medium", "low", "unknown")


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _safe(text: object) -> str:
    """FPDF core fonts are Latin-1; keep printable ASCII-friendly text."""
    raw = str(text if text is not None else "")
    return raw.encode("latin-1", errors="replace").decode("latin-1")


class _BusinessReportPDF(FPDF):
    def __init__(self, org_name: str = "") -> None:
        super().__init__(orientation="P", unit="mm", format="A4")
        self.org_name = org_name
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(left=15, top=16, right=15)

    def header(self) -> None:
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(30, 58, 138)
        label = "Octo-man"
        if self.org_name:
            label = f"{self.org_name}  |  {label}"
        self.cell(0, 6, _safe(label), align="L")
        self.ln(7)
        y = self.get_y()
        self.set_draw_color(59, 130, 246)
        self.set_line_width(0.4)
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_x(self.l_margin)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 116, 139)
        self.cell(
            0,
            8,
            _safe(f"Confidential  |  Page {self.page_no()}  |  Authorized use only"),
            align="C",
        )


def _content_width(pdf: FPDF) -> float:
    return pdf.w - pdf.l_margin - pdf.r_margin


def _reset(pdf: FPDF) -> None:
    pdf.set_x(pdf.l_margin)


def _section_title(pdf: FPDF, title: str) -> None:
    _reset(pdf)
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, _safe(title), new_x="LMARGIN", new_y="NEXT")
    y = pdf.get_y()
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(3)
    _reset(pdf)


def _kv_row(pdf: FPDF, key: str, value: object) -> None:
    _reset(pdf)
    key_w = 58.0
    val_w = _content_width(pdf) - key_w
    y = pdf.get_y()
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(key_w, 6, _safe(key))
    pdf.set_xy(pdf.l_margin + key_w, y)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(val_w, 6, _safe(value))
    _reset(pdf)


def write_business_pdf(
    output_dir: Path,
    *,
    run_id: str = "",
    title: str = "Octo-man Security Scan Report",
    org_name: str = "",
    max_vulnerabilities: int = 40,
) -> Path:
    """Write ``summary.pdf`` into ``output_dir`` from existing JSON artifacts."""
    output_dir = Path(output_dir)
    summary = _load_json(output_dir / "summary.json", {})
    if not isinstance(summary, dict):
        summary = {}
    vulnerabilities = _load_json(output_dir / "vulnerabilities.json", [])
    if not isinstance(vulnerabilities, list):
        vulnerabilities = []
    diff = _load_json(output_dir / "diff.json", None)
    if diff is not None and not isinstance(diff, dict):
        diff = None
    run_meta = _load_json(output_dir / "run_meta.json", {})
    if not isinstance(run_meta, dict):
        run_meta = {}

    resolved_run_id = run_id or str(run_meta.get("run_id") or output_dir.name)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pdf = _BusinessReportPDF(org_name=org_name)
    pdf.add_page()
    width = _content_width(pdf)

    _reset(pdf)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(30, 58, 138)
    pdf.multi_cell(width, 9, _safe(title))
    _reset(pdf)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(
        width,
        6,
        _safe(
            "Executive summary of network reconnaissance results. "
            "Figures below reflect the latest Octo-man pipeline run."
        ),
    )
    pdf.ln(2)
    _kv_row(pdf, "Run ID", resolved_run_id)
    _kv_row(pdf, "Generated", generated_at)
    mode = run_meta.get("mode") or run_meta.get("profile")
    if mode:
        _kv_row(pdf, "Profile", mode)

    _section_title(pdf, "1. Executive Summary")
    sev = summary.get("vulnerabilities_by_severity") or {}
    _kv_row(pdf, "Targets in scope", summary.get("total_targets", 0))
    _kv_row(pdf, "Alive hosts", summary.get("alive_hosts", 0))
    _kv_row(pdf, "Named hosts", summary.get("alive_hosts_with_names", 0))
    _kv_row(pdf, "Open host:port pairs", summary.get("open_host_port_pairs", 0))
    _kv_row(pdf, "Detected services", summary.get("nmap_open_services", 0))
    _kv_row(pdf, "Hosts with OS guess", summary.get("os_detected_hosts", 0))
    _kv_row(
        pdf,
        "Potential vulnerabilities",
        f"{summary.get('potential_vulnerabilities', 0)} "
        f"across {summary.get('vulnerable_hosts', 0)} hosts",
    )

    _section_title(pdf, "2. Severity Breakdown")
    col_w = width / 2
    _reset(pdf)
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(col_w, 7, "Severity", border=1, fill=True)
    pdf.cell(col_w, 7, "Count", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    for name in _SEVERITY_LABELS:
        _reset(pdf)
        pdf.cell(col_w, 7, _safe(name.capitalize()), border=1)
        pdf.cell(col_w, 7, str(int(sev.get(name, 0))), border=1, new_x="LMARGIN", new_y="NEXT")

    top_services = summary.get("top_services") or []
    _section_title(pdf, "3. Top Services")
    if top_services:
        _reset(pdf)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(col_w, 7, "Service", border=1, fill=True)
        pdf.cell(col_w, 7, "Open instances", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        for service, count in top_services[:12]:
            _reset(pdf)
            pdf.cell(col_w, 7, _safe(service or "unknown")[:40], border=1)
            pdf.cell(col_w, 7, str(count), border=1, new_x="LMARGIN", new_y="NEXT")
    else:
        _reset(pdf)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, "No service fingerprints available.", new_x="LMARGIN", new_y="NEXT")

    _section_title(pdf, "4. Priority Findings")
    ranked = sorted(
        vulnerabilities,
        key=lambda item: (
            -SEVERITY_ORDER.get(str(item.get("severity") or "unknown"), 0),
            -(float(item["cvss"]) if item.get("cvss") is not None else -1.0),
        ),
    )
    priority = [
        item
        for item in ranked
        if SEVERITY_ORDER.get(str(item.get("severity") or "unknown"), 0)
        >= SEVERITY_ORDER["medium"]
    ] or ranked
    shown = priority[: max(1, max_vulnerabilities)] if priority else []

    if shown:
        widths = [28.0, 38.0, 28.0, 16.0, width - 28.0 - 38.0 - 28.0 - 16.0]
        headers = ["Severity", "Location", "CVE", "CVSS", "Source"]
        _reset(pdf)
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(15, 23, 42)
        for w, header in zip(widths, headers, strict=True):
            pdf.cell(w, 7, header, border=1, fill=True)
        pdf.ln()
        pdf.set_font("Helvetica", "", 8)
        for item in shown:
            host = str(item.get("host") or "")
            port = str(item.get("port") or "")
            location = f"{host}:{port}" if port else host
            cve = str(item.get("cve") or "-")
            cvss = item.get("cvss")
            cvss_s = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "-"
            cells = [
                str(item.get("severity") or "unknown").upper()[:14],
                location[:22],
                cve[:16],
                cvss_s[:8],
                str(item.get("script_id") or "-")[:36],
            ]
            _reset(pdf)
            for w, cell in zip(widths, cells, strict=True):
                pdf.cell(w, 6, _safe(cell), border=1)
            pdf.ln()
        if len(priority) > len(shown):
            pdf.ln(1)
            _reset(pdf)
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(100, 116, 139)
            pdf.multi_cell(
                width,
                5,
                _safe(
                    f"Showing {len(shown)} of {len(priority)} medium+ findings "
                    f"({len(vulnerabilities)} total). See vulnerabilities.json for the full list."
                ),
            )
    else:
        _reset(pdf)
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, "No vulnerabilities recorded for this run.", new_x="LMARGIN", new_y="NEXT")

    if diff is not None:
        _section_title(pdf, "5. Changes Since Previous Run")
        counts = diff.get("counts") or {}
        _kv_row(
            pdf,
            "Hosts",
            f"+{counts.get('hosts_added', 0)} / -{counts.get('hosts_removed', 0)}",
        )
        _kv_row(
            pdf,
            "Ports",
            f"+{counts.get('ports_added', 0)} / -{counts.get('ports_removed', 0)}",
        )
        _kv_row(
            pdf,
            "Vulnerabilities",
            f"+{counts.get('vulns_added', 0)} / -{counts.get('vulns_removed', 0)}",
        )
        added = ((diff.get("vulnerabilities") or {}).get("added") or [])[:8]
        if added:
            pdf.ln(1)
            _reset(pdf)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, "Newly observed issues:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for item in added:
                host = item.get("host")
                port = item.get("port")
                location = f"{host}:{port}" if port else host
                label = item.get("cve") or item.get("script_id") or "finding"
                sev_name = str(item.get("severity") or "unknown").upper()
                _reset(pdf)
                pdf.multi_cell(width, 5, _safe(f"- [{sev_name}] {location} {label}"))

    _section_title(pdf, "Notes")
    _reset(pdf)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(
        width,
        5,
        _safe(
            "This report is generated automatically from Octo-man pipeline artifacts. "
            "CVE matches come from NSE scripts (vuln/vulners/vulscan) and may include "
            "version-based associations that require analyst validation. Use only on "
            "assets you are authorized to assess."
        ),
    )

    out_path = output_dir / "summary.pdf"
    pdf.output(str(out_path))
    logging.info("Wrote business PDF report: %s", out_path)
    return out_path
