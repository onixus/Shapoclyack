"""CSV/XLSX report formats, the signed hash manifest and S3 delivery (#355).

The assertions that matter are the ways these go wrong in a customer's hands:
a finding title that Excel executes, a workbook Excel refuses to open, a
manifest that "verifies" after the report changed, an unsigned manifest
reported as valid, and a bucket a tenant admin picked that the platform's
credentials can write to.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import pytest

from api.services import artifact_store
from api.services.reports import delivery as report_delivery
from api.services.reports import manifest as report_manifest
from api.services.reports import render as renderer
from api.services.reports import spreadsheet, store
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_api_reports import _seed

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_HOSTILE = ["=HYPERLINK(\"http://evil\",\"x\")", "+1+1", "-2+3", "@SUM(A1)", "\t=1", "\r=1"]


def _body(title: str = "Exec") -> dict:
    return {
        "kind": "technical",
        "title": title,
        "generated_at": "2026-10-17T00:00:00Z",
        "period_days": 90,
        "sections": ["kpis", "top_findings"],
        "kpis": {"open_total": 2, "breached": 0},
        "top_findings": [
            {"vuln_id": "v1", "title": hostile, "cve": "CVE-2024-0001", "asset_id": "a",
             "severity": "high", "contextual_score": 7.5, "in_kev": True,
             "remediation": hostile}
            for hostile in _HOSTILE
        ],
        "compliance": [
            {"name": "Реестр", "version": "1", "controls": [
                {"control_id": "АУД.2", "title": "=cmd|' /C calc'!A0", "status": "failed",
                 "failing_count": 3}]}
        ],
    }


# ------------------------------------------------------------ formula injection


@pytest.mark.parametrize("value", _HOSTILE)
def test_cell_defuses_every_formula_prefix(value):
    assert spreadsheet.cell(value) == "'" + value


def test_cell_leaves_text_and_numbers_alone():
    assert spreadsheet.cell("plain") == "plain"
    assert spreadsheet.cell(-5) == -5
    assert spreadsheet.cell(7.5) == 7.5
    assert spreadsheet.cell(None) == ""
    assert spreadsheet.cell(["a", "=b"]) == "a, =b"


def test_csv_has_no_executable_cell():
    raw = renderer.render(_body(), "csv")
    assert raw.startswith(b"\xef\xbb\xbf")
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8-sig"))))
    cells = [c for row in rows for c in row]
    assert cells, "csv rendered nothing"
    assert not [c for c in cells if c.startswith(spreadsheet.FORMULA_PREFIXES)]
    # The hostile text is still there, as text.
    assert "'=HYPERLINK(\"http://evil\",\"x\")" in cells
    assert "АУД.2" in cells


def test_xlsx_is_a_workbook_with_no_formula_elements():
    raw = renderer.render(_body(), "xlsx")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.testzip() is None
        names = archive.namelist()
        assert "xl/workbook.xml" in names and "[Content_Types].xml" in names
        sheets = ElementTree.fromstring(archive.read("xl/workbook.xml")).findall(
            ".//m:sheet", _NS
        )
        assert [s.get("name") for s in sheets][:2] == ["Report", "KPIs"]
        findings = next(
            archive.read(f"xl/worksheets/sheet{i}.xml")
            for i, s in enumerate(sheets, start=1)
            if s.get("name") == "Findings"
        )
        root = ElementTree.fromstring(findings)
        assert root.findall(".//m:f", _NS) == []
        texts = [t.text or "" for t in root.findall(".//m:t", _NS)]
        assert not [t for t in texts if t.startswith(spreadsheet.FORMULA_PREFIXES)]
        assert "'=HYPERLINK(\"http://evil\",\"x\")" in texts
        # Numbers stay numbers (a score a reader can sort), not strings.
        assert any(c.find("m:v", _NS) is not None and c.get("t") is None
                   for c in root.findall(".//m:c", _NS))


def test_xlsx_sheet_names_are_legal_and_unique():
    names = spreadsheet._sheet_names(["A/B", "A/B", "x" * 80, "[bad]:name?"])
    assert len(set(n.lower() for n in names)) == 4
    assert all(len(n) <= 31 and not set("[]:*?/\\") & set(n) for n in names)


def test_same_body_renders_to_the_same_xlsx_bytes():
    assert renderer.render(_body(), "xlsx") == renderer.render(_body(), "xlsx")


def test_xlsx_opens_in_a_spreadsheet_library():
    openpyxl = pytest.importorskip("openpyxl")
    workbook = openpyxl.load_workbook(io.BytesIO(renderer.render(_body(), "xlsx")))
    assert "Findings" in workbook.sheetnames
    assert workbook["Findings"]["B2"].value.startswith("'")


# ------------------------------------------------------------------- manifest


def _signing_key() -> str:
    return base64.b64encode(bytes(range(32))).decode()


def _generate(settings, tenant_id, fmt="json"):
    report = store.generate(settings, tenant_id=tenant_id, kind="executive", fmt=fmt)
    assert report["status"] == "ready", report
    return report


@requires_postgres
def test_signed_manifest_verifies_then_fails_after_the_report_changes(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)

    ok = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert ok["status"] == "valid" and ok["signed"] and ok["signature_valid"]
    assert ok["key_matches_installation"] is True
    assert [f["status"] for f in ok["files"]] == ["ok"]

    key, _media, _name = store.resolve_report_object(settings, report["report_id"], tenant_id=tenant_id)
    artifact_store.get_store(settings).put_bytes(key, b'{"kpis": {"open_total": 0}}')
    bad = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert bad["status"] == "tampered"
    assert bad["files"][0]["status"] == "modified"


@requires_postgres
def test_a_rewritten_manifest_does_not_verify(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    key, _m, _n = store.resolve_report_object(settings, report["report_id"], tenant_id=tenant_id)
    mkey = report_manifest.manifest_key(key)
    backend = artifact_store.get_store(settings)

    # Swap in the hash of different content but keep the old signature.
    document = json.loads(backend.get_bytes(mkey))
    document["payload"]["files"][0]["sha256"] = "0" * 64
    backend.put_bytes(mkey, json.dumps(document).encode())
    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["status"] == "tampered"
    assert result["signature_valid"] is False


@requires_postgres
def test_without_a_key_the_manifest_is_unsigned_and_says_so(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.delenv("OCTO_EVIDENCE_SIGNING_KEY", raising=False)
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["status"] == "unsigned" and result["signed"] is False


@requires_postgres
def test_pinning_a_different_key_id_is_untrusted_not_tampered(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    result = store.verify_report(
        settings, report["report_id"], tenant_id=tenant_id, expected_key_id="f" * 64
    )
    assert result["status"] == "untrusted"


@requires_postgres
def test_verify_is_tenant_scoped_and_delete_removes_the_manifest(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    assert store.verify_report(settings, report["report_id"], tenant_id="someone-else") is None

    key, _m, _n = store.resolve_report_object(settings, report["report_id"], tenant_id=tenant_id)
    backend = artifact_store.get_store(settings)
    assert backend.exists(report_manifest.manifest_key(key))
    assert store.delete_report(settings, report["report_id"], tenant_id=tenant_id)
    assert not backend.exists(report_manifest.manifest_key(key))


@requires_postgres
def test_a_manifest_that_cannot_be_written_does_not_fail_the_report(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)

    def boom(*_a, **_k):
        raise RuntimeError("disk full")

    monkeypatch.setattr(report_manifest, "write", boom)
    report = _generate(settings, tenant_id)
    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["status"] == "missing"


@requires_postgres
def test_api_formats_manifest_and_verify(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    _seed(tmp_path)
    operator = auth_headers(client, "operator")
    viewer = auth_headers(client, "viewer")

    for fmt, expected in (("csv", "text/csv"), ("xlsx", "spreadsheetml.sheet")):
        made = client.post(
            "/api/reports/generate", headers=operator, json={"kind": "technical", "format": fmt}
        )
        assert made.status_code == 200, made.text
        download = client.get(f"/api/reports/{made.json()['report_id']}/download", headers=viewer)
        assert download.status_code == 200
        assert expected in download.headers["content-type"]
        assert download.content[:2] == (b"PK" if fmt == "xlsx" else b"\xef\xbb")

    rid = made.json()["report_id"]
    manifest = client.get(f"/api/reports/{rid}/manifest", headers=viewer)
    assert manifest.status_code == 200
    assert manifest.json()["payload"]["files"][0]["name"] == f"{rid}.xlsx"
    verdict = client.get(f"/api/reports/{rid}/verify", headers=viewer)
    assert verdict.status_code == 200 and verdict.json()["status"] == "valid"

    assert client.get("/api/reports/rpt_0000000000000000/verify", headers=viewer).status_code == 404
    assert client.get("/api/reports/rpt_0000000000000000/manifest", headers=viewer).status_code == 404
    assert client.get(f"/api/reports/{rid}/verify").status_code in (401, 403)


@requires_postgres
def test_schedule_rejects_unlisted_s3_bucket_and_accepts_listed(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    settings = make_settings(tmp_path, report_s3_buckets=("customer-reports",))
    template = store.create_template(settings, tenant_id=tenant_id, name="T")

    def make(target):
        return store.create_schedule(
            settings, tenant_id=tenant_id, template_id=template["template_id"],
            name="S", cron="0 6 1 * *", fmt="csv",
            recipients=[{"transport": "s3", "target": target}],
        )

    with pytest.raises(store.ReportError, match="OCTO_REPORT_S3_BUCKETS"):
        make("s3://other-bucket/x")
    assert make("s3://customer-reports/monthly")["recipients"][0]["transport"] == "s3"


# ------------------------------------------------------------------ S3 delivery


def test_s3_target_parsing(tmp_path):
    settings = make_settings(
        tmp_path, report_s3_buckets=("customer-reports", "shared"), artifact_s3_bucket="shared"
    )
    assert report_delivery.parse_s3_target("s3://customer-reports/a/b/", settings) == (
        "customer-reports", "a/b",
    )
    assert report_delivery.parse_s3_target("s3://customer-reports", settings)[1] == ""
    for bad in ("https://x/y", "s3://", "s3://UPPER/x", "s3://customer-reports/../x"):
        with pytest.raises(ValueError):
            report_delivery.parse_s3_target(bad, settings)
    with pytest.raises(ValueError, match="artifact store's own bucket"):
        report_delivery.parse_s3_target("s3://shared/x", settings)
    with pytest.raises(ValueError, match="not allowed"):
        report_delivery.parse_s3_target("s3://not-listed", settings)


def test_s3_delivery_writes_report_and_manifest_under_the_tenant(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, report_s3_buckets=("customer-reports",))
    written: list[tuple[str, str, bytes]] = []

    class FakeStore:
        def __init__(self, config):
            self.config = config

        def put_bytes(self, key, data, *, content_type=None):
            written.append((self.config.bucket + "/" + self.config.prefix, key, data))

    monkeypatch.setattr(report_delivery, "S3ArtifactStore", FakeStore)
    report = {"report_id": "rpt_1", "tenant_id": "acme", "format": "xlsx"}
    entries = report_delivery.deliver(
        settings,
        report=report,
        payload=b"PK",
        filename="rpt_1.xlsx",
        recipients=[
            {"transport": "s3", "target": "s3://customer-reports/monthly"},
            {"transport": "s3", "target": "s3://elsewhere/monthly"},
        ],
        extras={"rpt_1.manifest.json": b"{}"},
    )
    assert [e["status"] for e in entries] == ["delivered", "failed"]
    assert "not allowed" in entries[1]["error"]
    assert written == [
        ("customer-reports/monthly", "acme/rpt_1.xlsx", b"PK"),
        ("customer-reports/monthly", "acme/rpt_1.manifest.json", b"{}"),
    ]


def test_manifest_key_swaps_the_extension():
    assert report_manifest.manifest_key("reports/t/rpt_1.pdf") == "reports/t/rpt_1.manifest.json"
    assert Path(report_manifest.manifest_key("reports/t/rpt_1.xlsx")).name == "rpt_1.manifest.json"
