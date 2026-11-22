"""Business-oriented PDF summary for Shapoclyack scan runs.

Reads artifacts already written by ``build_reports`` / report diff and produces
``summary.pdf``.

Text is set in DejaVu Sans when the host has it (the API and all-in-one images
install ``fonts-dejavu-core``) and in fpdf2's Latin-1 core fonts otherwise.
The lookup matches ``api.services.reports.render``: a missing or unreadable
face must not fail the report. Control titles in ``controls.py`` are Russian,
and a core-font ``summary.pdf`` used to print each of those letters as ``?``.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fpdf import FPDF

from .report import SEVERITY_ORDER

logger = logging.getLogger(__name__)

_SEVERITY_LABELS = ("critical", "high", "medium", "low", "unknown")
_SEVERITY_RU = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "unknown": "Не определён",
}
_STATUS_RU = {
    "pass": "Пройден",
    "passed": "Пройден",
    "fail": "Не пройден",
    "failed": "Не пройден",
    "not_checked": "Не проверялся",
    "not_assessed": "Не оценивался",
}
_RISK_RU = {
    "critical": "Критический",
    "high": "Высокий",
    "medium": "Средний",
    "low": "Низкий",
    "unassessed": "Не оценён",
    "not_checked": "Не проверялся",
}
_VERDICT_RU = {
    "pass": "Пройден",
    "fail": "Не пройден",
    "not_checked": "Не проверялся",
}
# The same names the console shows. Unknown English titles stay as written:
# inventing a label would hide which check fired.
_FINDING_TITLES = {
    "regreSSHion (OpenSSH signal handler race)": "Возможная уязвимость regreSSHion в OpenSSH",
    "EternalBlue-related NetBIOS/SMB exposure": "Доступен NetBIOS/SMB: проверьте защиту от EternalBlue",
    "BlueKeep (RDP RCE)": "Доступен RDP: проверьте защиту от BlueKeep",
    "MySQL auth bypass family (historical + exposure)": "Доступен MySQL: проверьте аутентификацию",
    "Elasticsearch groovy RCE class / exposure": "Доступен Elasticsearch: проверьте ограничения доступа",
    "rpcbind / RPC exposure": "Доступна служба RPC",
    "NFS export exposure": "Доступен NFS: проверьте общие каталоги",
    "EternalBlue (SMBv1 RCE)": "Доступен SMB: проверьте защиту от EternalBlue",
    "PostgreSQL COPY PROGRAM (misconfig RCE)": "Доступен PostgreSQL: проверьте права запуска команд",
    "VNC exposure": "Доступна служба удалённого рабочего стола VNC",
    "Java RMI exposure": "Доступен реестр удалённых вызовов Java RMI",
    "Telnet cleartext protocol": "Telnet передаёт данные без шифрования",
    "rexec/rlogin legacy exposure": "Доступны устаревшие службы rexec/rlogin",
    "Server accepts weak TLS protocol": "Сервер принимает устаревший протокол TLS",
    "TLS certificate self-signed (heuristic)": "Сертификат TLS самоподписанный",
}
_WHY = {
    "No domains checked for DNS hygiene": "Ни один домен не проверен на ошибки DNS.",
    "Credential leaks check was not configured or run":
        "Проверка утечек учётных данных не настроена или не запускалась.",
    "Mail authentication posture was not run": "Проверка защиты почты не выполнялась.",
    "Mail authentication posture skipped: mail_posture.disabled":
        "Проверка защиты почты пропущена: проверка отключена.",
}
_WHY_TEMPLATES = (
    (
        re.compile(r"^(\d+) high/critical TLS posture findings \(expired/weak/mismatch\)$"),
        lambda m: (
            f"Находок TLS высокой и критической серьёзности: {m.group(1)} "
            "(истёкший, слабый или несовпадающий сертификат)."
        ),
    ),
    (
        re.compile(r"^(\d+) endpoint banner\(s\) disclose product/version information$"),
        lambda m: f"Баннеров, раскрывающих продукт и версию: {m.group(1)}.",
    ),
    (
        re.compile(r"^(\d+) high/critical vulnerabilities found across open services$"),
        lambda m: f"Уязвимостей высокой и критической серьёзности в открытых сервисах: {m.group(1)}.",
    ),
)

#: Same directories as ``api.services.reports.render``. Module-level so a test
#: can point the lookup at the Cyrillic subset fixture or empty it. An
#: installation with none of them keeps the core fonts; that is a degraded
#: report, not a failed scan.
_UNICODE_FONT_DIRS: tuple[str, ...] = (
    "/usr/share/fonts/truetype/dejavu",
    "/usr/share/fonts/dejavu-sans-fonts",
    "/usr/share/fonts/dejavu",
    "/usr/share/fonts/TTF",
    "/usr/local/share/fonts",
)
_UNICODE_FONT_FAMILY = "DejaVu"
_UNICODE_FONT_FILES = {
    "": "DejaVuSans.ttf",
    "B": "DejaVuSans-Bold.ttf",
    "I": "DejaVuSans-Oblique.ttf",
}


def find_unicode_font() -> dict[str, Path] | None:
    """DejaVu Sans faces by fpdf style, or ``None``.

    Bold and oblique fall back to the regular file when only it is present
    (``fonts-dejavu-core`` ships no oblique): a heading set in regular weight
    is a cosmetic loss, a heading set in a font that raises is not a report.
    """

    for directory in _UNICODE_FONT_DIRS:
        regular = Path(directory) / _UNICODE_FONT_FILES[""]
        if not regular.is_file():
            continue
        faces = {"": regular}
        for style in ("B", "I"):
            candidate = Path(directory) / _UNICODE_FONT_FILES[style]
            faces[style] = candidate if candidate.is_file() else regular
        return faces
    return None


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
        # A zero-byte or truncated face is still ``is_file()``. Only parsing
        # can tell, and a bad file must not fail the scan report.
        faces = find_unicode_font()
        # Not ``font_family``: that name is FPDF's own, and ``set_font``
        # overwrites it with the face just selected. A later ``set_font``
        # that names Helvetica (the hostname legend) would then make every
        # following ``_font`` call draw in Helvetica while ``txt`` still
        # hands it Cyrillic — which is how a controls table used to abort
        # the report instead of writing summary.pdf.
        self._face = "Helvetica"
        self.unicode_text = False
        if faces is None:
            logger.warning(
                "no Unicode TrueType face found in %s; summary.pdf text outside "
                "Latin-1 is rendered as replacement characters",
                ", ".join(_UNICODE_FONT_DIRS),
            )
        else:
            try:
                for style, path in faces.items():
                    self.add_font(_UNICODE_FONT_FAMILY, style=style, fname=str(path))
            except Exception as exc:  # noqa: BLE001 - a bad font must not fail the report
                logger.warning(
                    "Unicode TrueType face at %s could not be loaded (%s); "
                    "summary.pdf text outside Latin-1 is rendered as replacement characters",
                    faces[""].parent,
                    exc,
                )
            else:
                self._face = _UNICODE_FONT_FAMILY
                self.unicode_text = True
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(left=15, top=16, right=15)

    def txt(self, value: object) -> str:
        """A string the current face can set: as-is with DejaVu, Latin-1 otherwise."""

        if self.unicode_text:
            return str(value if value is not None else "")
        return _safe(value)

    def header(self) -> None:
        self.set_x(self.l_margin)
        self.set_font(self._face, "B", 9)
        self.set_text_color(30, 58, 138)
        label = "Shapoclyack"
        if self.org_name:
            label = f"{self.org_name}  |  {label}"
        self.cell(0, 6, self.txt(label), align="L")
        self.ln(7)
        y = self.get_y()
        self.set_draw_color(59, 130, 246)
        self.set_line_width(0.4)
        self.line(self.l_margin, y, self.w - self.r_margin, y)
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-14)
        self.set_x(self.l_margin)
        self.set_font(self._face, "", 8)
        self.set_text_color(100, 116, 139)
        self.cell(
            0,
            8,
            self.txt(f"Confidential  |  Page {self.page_no()}  |  Authorized use only"),
            align="C",
        )


def _content_width(pdf: FPDF) -> float:
    return pdf.w - pdf.l_margin - pdf.r_margin


def _reset(pdf: FPDF) -> None:
    pdf.set_x(pdf.l_margin)


def _font(pdf: _BusinessReportPDF, style: str, size: float) -> None:
    pdf.set_font(pdf._face, style, size)


def _section_title(pdf: _BusinessReportPDF, title: str) -> None:
    _reset(pdf)
    pdf.ln(3)
    _font(pdf, "B", 13)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, pdf.txt(title), new_x="LMARGIN", new_y="NEXT")
    y = pdf.get_y()
    pdf.set_draw_color(226, 232, 240)
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(3)
    _reset(pdf)


def _kv_row(pdf: _BusinessReportPDF, key: str, value: object) -> None:
    _reset(pdf)
    key_w = 58.0
    val_w = _content_width(pdf) - key_w
    y = pdf.get_y()
    _font(pdf, "B", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(key_w, 6, pdf.txt(key))
    pdf.set_xy(pdf.l_margin + key_w, y)
    _font(pdf, "", 10)
    pdf.set_text_color(15, 23, 42)
    pdf.multi_cell(val_w, 6, pdf.txt(value))
    _reset(pdf)


def _finding_title(item: dict) -> str:
    title = str(item.get("title") or "").strip()
    if title in _FINDING_TITLES:
        return _FINDING_TITLES[title]
    if title:
        return title
    return str(item.get("script_id") or "-")


def _explain(text: object) -> str:
    raw = str(text or "")
    if not raw or any("\u0400" <= ch <= "\u04ff" for ch in raw):
        return raw
    known = _WHY.get(raw)
    if known:
        return known
    for pattern, render in _WHY_TEMPLATES:
        match = pattern.match(raw)
        if match:
            return render(match)
    return raw


def _row(pdf: _BusinessReportPDF, widths: list[float], cells: list[str], line_h: float = 4.0) -> None:
    """One table row that wraps instead of clipping.

    ``cell`` cuts a site name at the column edge, which is how the scanned
    name used to disappear and leave the address.
    """

    text = [pdf.txt(cell) for cell in cells]
    wrapped = [
        pdf.multi_cell(width, line_h, value, dry_run=True, output="LINES") or [""]
        for width, value in zip(widths, text, strict=True)
    ]
    row_h = line_h * max(len(lines) for lines in wrapped)
    if pdf.get_y() + row_h > pdf.page_break_trigger:
        pdf.add_page()
    y = pdf.get_y()
    x = pdf.l_margin
    for width, value in zip(widths, text, strict=True):
        pdf.set_xy(x, y)
        pdf.multi_cell(width, line_h, value, border=1)
        x += width
    pdf.set_xy(pdf.l_margin, y + row_h)


def _site_label(item: dict) -> str:
    """The scanned site, with the address in parentheses when it differs.

    The finding is about the name that was asked for. Printing the address in
    the column, and the name only in a footnote, is how a site scan used to
    read as a list of IPs.
    """

    host = str(item.get("host") or "")
    name = str(item.get("hostname") or "").strip()
    port = str(item.get("port") or "")
    site = name if name and name != host else host
    if port:
        site = f"{site}:{port}"
    if name and host and name != host:
        site = f"{site} ({host})"
    return site


def write_business_pdf(
    output_dir: Path,
    *,
    run_id: str = "",
    title: str = "Отчёт о проверке безопасности Shapoclyack",
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
    _font(pdf, "B", 18)
    pdf.set_text_color(30, 58, 138)
    pdf.multi_cell(width, 9, pdf.txt(title))
    _reset(pdf)
    _font(pdf, "", 11)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(
        width,
        6,
        pdf.txt(
            "Сводка результатов сетевой разведки. "
            "Цифры ниже относятся к последнему прогону Shapoclyack."
        ),
    )
    pdf.ln(2)
    _kv_row(pdf, "Прогон", resolved_run_id)
    _kv_row(pdf, "Сформирован", generated_at)
    mode = run_meta.get("mode") or run_meta.get("profile")
    if mode:
        _kv_row(pdf, "Профиль", mode)

    _section_title(pdf, "1. Краткие итоги")
    sev = summary.get("vulnerabilities_by_severity") or {}
    _kv_row(pdf, "Целей в области", summary.get("total_targets", 0))
    _kv_row(pdf, "Живых узлов", summary.get("alive_hosts", 0))
    _kv_row(pdf, "Узлов с именем", summary.get("alive_hosts_with_names", 0))
    _kv_row(pdf, "Открытых пар узел:порт", summary.get("open_host_port_pairs", 0))
    _kv_row(pdf, "Обнаружено служб", summary.get("nmap_open_services", 0))
    _kv_row(pdf, "Узлов с гипотезой ОС", summary.get("os_detected_hosts", 0))
    _kv_row(
        pdf,
        "Потенциальных уязвимостей",
        f"{summary.get('potential_vulnerabilities', 0)} "
        f"на {summary.get('vulnerable_hosts', 0)} узлах",
    )

    _section_title(pdf, "2. Разбивка по серьёзности")
    col_w = width / 2
    _reset(pdf)
    _font(pdf, "B", 10)
    pdf.set_fill_color(241, 245, 249)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(col_w, 7, pdf.txt("Серьёзность"), border=1, fill=True)
    pdf.cell(col_w, 7, pdf.txt("Количество"), border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    _font(pdf, "", 10)
    for name in _SEVERITY_LABELS:
        _reset(pdf)
        pdf.cell(col_w, 7, pdf.txt(_SEVERITY_RU.get(name, name)), border=1)
        pdf.cell(col_w, 7, str(int(sev.get(name, 0))), border=1, new_x="LMARGIN", new_y="NEXT")

    top_services = summary.get("top_services") or []
    _section_title(pdf, "3. Частые службы")
    if top_services:
        _reset(pdf)
        _font(pdf, "B", 10)
        pdf.set_fill_color(241, 245, 249)
        pdf.cell(col_w, 7, pdf.txt("Служба"), border=1, fill=True)
        pdf.cell(col_w, 7, pdf.txt("Открытых экземпляров"), border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
        _font(pdf, "", 10)
        for service, count in top_services[:12]:
            _reset(pdf)
            pdf.cell(col_w, 7, pdf.txt(service or "unknown")[:40], border=1)
            pdf.cell(col_w, 7, str(count), border=1, new_x="LMARGIN", new_y="NEXT")
    else:
        _reset(pdf)
        _font(pdf, "", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, pdf.txt("Отпечатков служб нет."), new_x="LMARGIN", new_y="NEXT")

    _section_title(pdf, "4. Приоритетные находки")
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
        # Site takes the room the address column used to waste: a name plus a
        # port does not fit in 38 mm, and clipping it is what dropped the site.
        widths = [28.0, 62.0, 28.0, 14.0, width - 28.0 - 62.0 - 28.0 - 14.0]
        headers = ["Серьёзность", "Сайт", "CVE", "CVSS", "Источник"]
        _reset(pdf)
        _font(pdf, "B", 9)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(15, 23, 42)
        for w, header in zip(widths, headers, strict=True):
            pdf.cell(w, 7, pdf.txt(header), border=1, fill=True)
        pdf.ln()
        _font(pdf, "", 8)
        for item in shown:
            cve = str(item.get("cve") or "-")
            cvss = item.get("cvss")
            cvss_s = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else "-"
            severity = str(item.get("severity") or "unknown")
            cells = [
                _SEVERITY_RU.get(severity, severity),
                _site_label(item),
                cve[:16],
                cvss_s[:8],
                _finding_title(item),
            ]
            _row(pdf, widths, cells)
        if len(priority) > len(shown):
            pdf.ln(1)
            _reset(pdf)
            _font(pdf, "I", 9)
            pdf.set_text_color(100, 116, 139)
            pdf.multi_cell(
                width,
                5,
                pdf.txt(
                    f"Показано {len(shown)} из {len(priority)} находок уровня «средний» и выше "
                    f"(всего {len(vulnerabilities)}). Полный список — в vulnerabilities.json."
                ),
            )
    else:
        _reset(pdf)
        _font(pdf, "", 10)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 6, pdf.txt("Для этого прогона уязвимости не записаны."), new_x="LMARGIN", new_y="NEXT")

    if diff is not None:
        _section_title(pdf, "5. Изменения с прошлого прогона")
        counts = diff.get("counts") or {}
        _kv_row(
            pdf,
            "Узлы",
            f"+{counts.get('hosts_added', 0)} / -{counts.get('hosts_removed', 0)}",
        )
        _kv_row(
            pdf,
            "Порты",
            f"+{counts.get('ports_added', 0)} / -{counts.get('ports_removed', 0)}",
        )
        _kv_row(
            pdf,
            "Уязвимости",
            f"+{counts.get('vulns_added', 0)} / -{counts.get('vulns_removed', 0)}",
        )
        added = ((diff.get("vulnerabilities") or {}).get("added") or [])[:8]
        if added:
            pdf.ln(1)
            _reset(pdf)
            _font(pdf, "B", 10)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, pdf.txt("Новые наблюдения:"), new_x="LMARGIN", new_y="NEXT")
            _font(pdf, "", 9)
            for item in added:
                location = _site_label(item)
                label = item.get("cve") or item.get("title") or item.get("script_id") or "находка"
                sev_name = _SEVERITY_RU.get(str(item.get("severity") or "unknown"), "Не определён")
                _reset(pdf)
                pdf.multi_cell(width, 5, pdf.txt(f"- [{sev_name}] {location} {label}"))

    controls_data = _load_json(output_dir / "controls.json", None)
    if isinstance(controls_data, dict) and controls_data.get("controls"):
        _section_title(pdf, "Матрица контролей")
        _kv_row(pdf, "Общий вывод", _VERDICT_RU.get(str(controls_data.get("overall_verdict") or "not_checked"), str(controls_data.get("overall_verdict") or "")))
        _kv_row(pdf, "Уровень риска NIST", _RISK_RU.get(str(controls_data.get("overall_risk") or "unassessed"), str(controls_data.get("overall_risk") or "")))
        pdf.ln(1)
        c_widths = [45.0, 28.0, 28.0, width - 45.0 - 28.0 - 28.0]
        c_headers = ["Контроль", "Статус", "Риск", "Оценка"]
        _reset(pdf)
        _font(pdf, "B", 9)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_text_color(15, 23, 42)
        for w, header in zip(c_widths, c_headers, strict=True):
            pdf.cell(w, 7, pdf.txt(header), border=1, fill=True)
        pdf.ln()
        _font(pdf, "", 8)
        for c in controls_data.get("controls") or []:
            c_cells = [
                str(c.get("title") or c.get("control") or ""),
                _STATUS_RU.get(str(c.get("status") or "not_checked"), str(c.get("status") or "")),
                _RISK_RU.get(str(c.get("risk_level") or "unassessed"), str(c.get("risk_level") or "")),
                _explain(c.get("why")),
            ]
            _row(pdf, c_widths, c_cells)

    _section_title(pdf, "Примечания")
    _reset(pdf)
    _font(pdf, "", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(
        width,
        5,
        pdf.txt(
            "Отчёт собран автоматически из артефактов прогона Shapoclyack. "
            "Совпадения CVE приходят из Pulse, шаблонов Nuclei и (для прогонов до удаления стадии Nmap) скриптов NSE "
            "и могут включать привязки по версии, которые должен подтвердить аналитик. "
            "Используйте только для активов, которые разрешено проверять."
        ),
    )

    out_path = output_dir / "summary.pdf"
    pdf.output(str(out_path))
    logger.info("Wrote business PDF report: %s", out_path)
    return out_path
