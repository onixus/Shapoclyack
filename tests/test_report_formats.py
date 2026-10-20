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
def test_a_report_resigned_with_someone_elses_key_is_not_valid(tmp_path, monkeypatch):
    """Whoever can write to the store can swap the report, make a key pair, and
    sign a matching manifest. The embedded key must not be what is trusted."""
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    key, _m, _n = store.resolve_report_object(settings, report["report_id"], tenant_id=tenant_id)
    backend = artifact_store.get_store(settings)
    forged = b'{"kpis": {"open_total": 0}}'
    backend.put_bytes(key, forged)

    attacker = base64.b64encode(bytes(range(1, 33))).decode()
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", attacker)
    backend.put_bytes(
        report_manifest.manifest_key(key),
        json.dumps(
            report_manifest.seal(
                report_manifest.build_payload(
                    report_id=report["report_id"], tenant_id=tenant_id,
                    generated_at=report["generated_at"], files={key.rsplit("/", 1)[-1]: forged},
                )
            )[0]
        ).encode(),
    )
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())

    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["signature_valid"] is True and result["files"][0]["status"] == "ok"
    assert result["status"] == "untrusted"
    assert result["key_matches_installation"] is False
    # Naming the attacker's key makes it a different word, never "valid".
    pinned = store.verify_report(
        settings, report["report_id"], tenant_id=tenant_id, expected_key_id=result["key_id"]
    )
    assert pinned["status"] == "valid_with_supplied_key"


@requires_postgres
def test_signed_manifest_with_no_installation_key_is_untrusted(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    monkeypatch.delenv("OCTO_EVIDENCE_SIGNING_KEY")
    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["status"] == "untrusted"


@requires_postgres
def test_a_rotated_key_needs_the_old_key_id_to_verify(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    old_id = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)["key_id"]
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", base64.b64encode(bytes(range(9, 41))).decode())
    assert store.verify_report(settings, report["report_id"], tenant_id=tenant_id)["status"] == "untrusted"
    assert store.verify_report(
        settings, report["report_id"], tenant_id=tenant_id, expected_key_id=old_id
    )["status"] == "valid_with_supplied_key"


@requires_postgres
def test_an_empty_or_foreign_manifest_is_tampered_and_beats_untrusted(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    first = _generate(settings, tenant_id)
    second = _generate(settings, tenant_id)
    backend = artifact_store.get_store(settings)
    key1, _m, _n = store.resolve_report_object(settings, first["report_id"], tenant_id=tenant_id)
    key2, _m, _n = store.resolve_report_object(settings, second["report_id"], tenant_id=tenant_id)

    # A validly signed manifest listing no files must not pass vacuously.
    empty = report_manifest.seal(
        report_manifest.build_payload(
            report_id=first["report_id"], tenant_id=tenant_id, generated_at=None, files={}
        )
    )[0]
    backend.put_bytes(report_manifest.manifest_key(key1), json.dumps(empty).encode())
    assert store.verify_report(settings, first["report_id"], tenant_id=tenant_id)["status"] == "tampered"

    # The other report's (genuine, signed) manifest dropped in place.
    backend.put_bytes(
        report_manifest.manifest_key(key1), backend.get_bytes(report_manifest.manifest_key(key2))
    )
    swapped = store.verify_report(settings, first["report_id"], tenant_id=tenant_id)
    assert swapped["status"] == "tampered"
    assert "different report" in swapped["detail"]

    # A changed file under a foreign signer reads as tampered, not untrusted.
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", base64.b64encode(bytes(range(9, 41))).decode())
    backend.put_bytes(key2, b"changed")
    assert store.verify_report(settings, second["report_id"], tenant_id=tenant_id)["status"] == "tampered"


def test_manifests_and_evidence_packages_are_not_interchangeable(monkeypatch, tmp_path):
    import importlib.util

    from api.services.compliance import evidence_package as evidence

    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    manifest, _ = report_manifest.seal(
        report_manifest.build_payload(
            report_id="rpt_0000000000000000", tenant_id="t", generated_at=None, files={"a": b"x"}
        )
    )
    package = evidence.sign_payload({"tenant_id": "t", "framework_id": "f"})

    with pytest.raises(evidence.InvalidEvidencePackage, match="kind"):
        evidence.verify(manifest)
    with pytest.raises(evidence.InvalidEvidencePackage, match="kind"):
        evidence.verify(package, expected_kind=report_manifest.KIND)
    assert evidence.verify(manifest, expected_kind=report_manifest.KIND)["kind"] == "report-manifest"
    assert evidence.verify(package)["framework_id"] == "f"

    spec = importlib.util.spec_from_file_location(
        "verify_script", Path(__file__).resolve().parent.parent / "scripts" / "verify-compliance-evidence.py"
    )
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    with pytest.raises(script.InvalidEvidencePackage, match="kind"):
        script.verify(manifest)
    with pytest.raises(script.InvalidEvidencePackage, match="kind"):
        script.verify(package, expected_kind=report_manifest.KIND)
    assert script.verify(manifest, expected_kind=report_manifest.KIND)["kind"] == "report-manifest"
    assert script.verify(package)["framework_id"] == "f"


def test_an_unusable_signing_key_is_warned_about(monkeypatch, caplog):
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", "not-a-key")
    with caplog.at_level("INFO", logger="shapoclyack.reports.manifest"):
        document, key_id = report_manifest.seal({"kind": "report-manifest", "files": []})
    assert key_id is None and document["signature"] is None
    assert [r.levelname for r in caplog.records] == ["WARNING"]
    caplog.clear()
    monkeypatch.delenv("OCTO_EVIDENCE_SIGNING_KEY")
    with caplog.at_level("INFO", logger="shapoclyack.reports.manifest"):
        report_manifest.seal({"kind": "report-manifest", "files": []})
    assert [r.levelname for r in caplog.records] == ["INFO"]


@requires_postgres
def test_without_a_key_the_manifest_is_unsigned_and_says_so(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.delenv("OCTO_EVIDENCE_SIGNING_KEY", raising=False)
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["status"] == "unsigned" and result["signed"] is False


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
    settings = make_settings(
        tmp_path, report_s3_buckets=("customer-reports",),
        artifact_s3_access_key_id="k", artifact_s3_secret_access_key="s",
    )
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
        tmp_path, report_s3_buckets=("customer-reports", "shared"), artifact_s3_bucket="shared",
        artifact_backend="s3",
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
    settings = make_settings(
        tmp_path, report_s3_buckets=("shared",),
        artifact_s3_access_key_id="k", artifact_s3_secret_access_key="s",
    )
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
            {"transport": "s3", "target": "s3://shared/monthly"},
            {"transport": "s3", "target": "s3://elsewhere/monthly"},
            # Tenant "acme" aiming at tenant "globex"'s area of the shared bucket.
            {"transport": "s3", "target": "s3://shared/globex"},
            {"transport": "s3", "target": "s3://shared"},
        ],
        extras={"rpt_1.manifest.json": b"{}"},
    )
    assert [e["status"] for e in entries] == ["delivered", "failed", "delivered", "delivered"]
    assert "not allowed" in entries[1]["error"]
    assert written == [
        ("shared/acme", "monthly/rpt_1.xlsx", b"PK"),
        ("shared/acme", "monthly/rpt_1.manifest.json", b"{}"),
        # The chosen folder is *inside* acme's own prefix, never beside it.
        ("shared/acme", "globex/rpt_1.xlsx", b"PK"),
        ("shared/acme", "globex/rpt_1.manifest.json", b"{}"),
        ("shared/acme", "rpt_1.xlsx", b"PK"),
        ("shared/acme", "rpt_1.manifest.json", b"{}"),
    ]
    assert not any(not prefix.startswith("shared/acme") for prefix, _k, _d in written)


def test_s3_delivery_without_a_manifest_is_refused(tmp_path, monkeypatch):
    settings = make_settings(
        tmp_path, report_s3_buckets=("shared",),
        artifact_s3_access_key_id="k", artifact_s3_secret_access_key="s",
    )
    written: list = []

    class FakeStore:
        def __init__(self, config):
            pass

        def put_bytes(self, key, data, *, content_type=None):
            written.append(key)

    monkeypatch.setattr(report_delivery, "S3ArtifactStore", FakeStore)
    entries = report_delivery.deliver(
        settings,
        report={"report_id": "rpt_1", "tenant_id": "acme", "format": "csv"},
        payload=b"x", filename="rpt_1.csv",
        recipients=[{"transport": "s3", "target": "s3://shared"}],
    )
    assert entries[0]["status"] == "failed"
    assert "no manifest" in entries[0]["error"]
    assert written == []


def test_s3_needs_explicit_credentials_on_a_local_artifact_backend(tmp_path):
    settings = make_settings(tmp_path, report_s3_buckets=("shared",))
    with pytest.raises(ValueError, match="OCTO_ARTIFACT_BACKEND=s3"):
        report_delivery.parse_s3_target("s3://shared", settings)
    entries = report_delivery.deliver(
        settings,
        report={"report_id": "rpt_1", "tenant_id": "acme", "format": "csv"},
        payload=b"x", filename="rpt_1.csv",
        recipients=[{"transport": "s3", "target": "s3://shared"}],
    )
    assert entries[0]["status"] == "failed"


@requires_postgres
def test_a_swapped_report_with_a_deleted_manifest_is_never_re_signed(tmp_path, monkeypatch):
    """Delete the manifest, swap the report, wait for the next delivery: the
    dispatcher must not sign the new bytes with the installation's key."""
    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)
    key, _m, _n = store.resolve_report_object(settings, report["report_id"], tenant_id=tenant_id)
    backend = artifact_store.get_store(settings)
    backend.put_bytes(key, b'{"kpis": {"open_total": 0}}')
    backend.delete(report_manifest.manifest_key(key))

    assert store.read_package_extras(settings, key) == {}
    assert not backend.exists(report_manifest.manifest_key(key))
    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["status"] == "missing"


@requires_postgres
def test_dispatcher_does_not_send_a_report_without_its_manifest_to_s3(tmp_path, monkeypatch):
    from api.services.reports import dispatcher as report_dispatcher

    configured_client(tmp_path, monkeypatch)
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    seeded, tenant_id = _seed(tmp_path)
    settings = make_settings(
        tmp_path, report_s3_buckets=("shared",),
        artifact_s3_access_key_id="k", artifact_s3_secret_access_key="s",
    )
    template = store.create_template(settings, tenant_id=tenant_id, name="T")
    store.create_schedule(
        settings, tenant_id=tenant_id, template_id=template["template_id"], name="S",
        cron="0 6 1 * *", fmt="json", recipients=[{"transport": "s3", "target": "s3://shared"}],
    )
    written: list = []

    class FakeStore:
        def __init__(self, config):
            pass

        def put_bytes(self, key, data, *, content_type=None):
            written.append(key)

    monkeypatch.setattr(report_delivery, "S3ArtifactStore", FakeStore)
    real_write = report_manifest.write
    monkeypatch.setattr(report_manifest, "write", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")))
    from datetime import UTC, datetime, timedelta

    report_dispatcher.ReportDispatcher(settings=settings).tick(
        now=datetime.now(UTC) + timedelta(days=40)
    )
    monkeypatch.setattr(report_manifest, "write", real_write)
    reports = store.list_reports(settings, tenant_id=tenant_id)
    assert reports and reports[0]["delivery"][0]["status"] == "failed"
    assert written == []


@requires_postgres
def test_an_unsigned_manifest_on_a_signing_installation_is_untrusted(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    monkeypatch.delenv("OCTO_EVIDENCE_SIGNING_KEY", raising=False)
    settings, tenant_id = _seed(tmp_path)
    report = _generate(settings, tenant_id)  # written unsigned: no key yet
    monkeypatch.setenv("OCTO_EVIDENCE_SIGNING_KEY", _signing_key())
    result = store.verify_report(settings, report["report_id"], tenant_id=tenant_id)
    assert result["status"] == "untrusted"
    assert "unsigned" in result["detail"]


def test_excel_reserved_sheet_name_is_renamed():
    names = spreadsheet._sheet_names(["History", "history", "Other"])
    assert "history" not in {n.lower() for n in names}
    assert len(set(n.lower() for n in names)) == 3


# ------------------------------------------------------- workbook well-formedness


def _all_parts_parse(raw: bytes) -> dict[str, ElementTree.Element]:
    """Every XML part of the archive, parsed -- what Excel does before it opens."""
    parsed = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.testzip() is None
        for name in archive.namelist():
            parsed[name] = ElementTree.fromstring(archive.read(name))
    return parsed


def test_hostile_sheet_names_still_give_a_well_formed_workbook():
    body = _body()
    body["compliance"] = [
        {"name": "FW\x01x\x0b" + "y" * 60, "version": "1:2/3", "controls": []},
        {"name": "FW\x01x\x0b" + "y" * 60, "version": "1:2/3", "controls": []},
        {"name": "[a]\ufffe'", "version": "", "controls": []},
    ]
    parts = _all_parts_parse(renderer.render(body, "xlsx"))
    assert {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels",
            "xl/styles.xml"} <= set(parts)
    names = [s.get("name") for s in parts["xl/workbook.xml"].findall(".//m:sheet", _NS)]
    assert len({n.lower() for n in names}) == len(names)
    for name in names:
        assert 0 < len(name) <= 31
        assert not set("[]:*?/\\") & set(name)
        assert all(ord(c) >= 32 for c in name)


def test_non_finite_numbers_and_huge_cells_do_not_corrupt_the_workbook():
    body = _body()
    body["top_findings"][0]["contextual_score"] = float("nan")
    body["top_findings"][1]["contextual_score"] = float("inf")
    body["top_findings"][2]["remediation"] = "x" * 40000
    raw = renderer.render(body, "xlsx")
    parts = _all_parts_parse(raw)
    xml = b"".join(
        zipfile.ZipFile(io.BytesIO(raw)).read(n) for n in parts if n.startswith("xl/worksheets/")
    ).decode()
    assert "<v>nan</v>" not in xml and "<v>inf</v>" not in xml
    for sheet in (p for n, p in parts.items() if n.startswith("xl/worksheets/")):
        for text in sheet.findall(".//m:t", _NS):
            assert len(text.text or "") <= spreadsheet.MAX_CELL_CHARS
    assert spreadsheet.cell("x" * 40000).endswith(spreadsheet.TRUNCATION_MARKER)
    assert len(spreadsheet.cell("=" + "x" * 40000)) == spreadsheet.MAX_CELL_CHARS
    assert spreadsheet.cell(float("nan")) == "" and spreadsheet.cell(float("-inf")) == ""
    cells = [c for row in csv.reader(io.StringIO(renderer.render(body, "csv").decode("utf-8-sig"))) for c in row]
    assert "nan" not in cells and "inf" not in cells
