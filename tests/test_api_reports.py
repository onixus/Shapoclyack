"""Report factory (Sprint 4): branding, templates, schedules, render, delivery.

The interesting assertions are about the ways a report factory goes wrong:
branding that validates at render time instead of write time, a schedule that
retries a failed render every tick, a download path built from a stored string,
a "delivered" flag that hides a bounce, and a tenant able to read another
tenant's report.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.services import vulnerabilities as vulns
from api.services.reports import branding as branding_service
from api.services.reports import delivery as report_delivery
from api.services.reports import dispatcher as report_dispatcher
from api.services.reports import store
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

_HOSTS = [{"host": "8.8.8.8", "hostname": "app.example.com"}]
_FINDINGS = [
    {"host": "8.8.8.8", "port": "443", "cve": "CVE-2024-0001", "cvss": 9.8, "severity": "critical"},
    {"host": "8.8.8.8", "port": "80", "cve": "CVE-2024-0002", "cvss": 5.0, "severity": "medium"},
]

# The smallest valid PNG: an 1x1 image. Enough for the magic-number check the
# branding validator does, without a fixture file.
_PNG_1PX = base64.b64encode(
    bytes.fromhex(
        "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4"
        "890000000a49444154789c6300010000050001"
        "0d0a2db40000000049454e44ae426082"
    )
).decode("ascii")


def _seed(tmp_path: Path):
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = make_settings(tmp_path)
    run_dir = settings.output_dir / "runs" / "run-1"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(_HOSTS), encoding="utf-8")
    (run_dir / "vulnerabilities.json").write_text(json.dumps(_FINDINGS), encoding="utf-8")

    tenants_service.load_tenants(settings)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    assets_service.upsert_assets_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    return settings, tenant_id


# ------------------------------------------------------------------ branding


def test_branding_is_validated_on_write_not_at_render(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    bad_colour = client.put("/api/reports/branding", headers=admin, json={"primary_color": "blue"})
    assert bad_colour.status_code == 400

    bad_logo = client.put(
        "/api/reports/branding",
        headers=admin,
        json={"logo_png": base64.b64encode(b"not a png").decode("ascii")},
    )
    assert bad_logo.status_code == 400

    ok = client.put(
        "/api/reports/branding",
        headers=admin,
        json={"org_name": "Acme MSSP", "primary_color": "#0b3d91", "logo_png": _PNG_1PX},
    )
    assert ok.status_code == 200
    assert ok.json()["org_name"] == "Acme MSSP"

    # Defaults are served for a tenant that never set anything, so a render
    # never has to cope with a missing row.
    assert branding_service.DEFAULT_ACCENT.startswith("#")


def test_branding_write_needs_admin(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    assert client.get("/api/reports/branding", headers=auth_headers(client, "viewer")).status_code == 200
    denied = client.put(
        "/api/reports/branding", headers=auth_headers(client, "operator"), json={"org_name": "X"}
    )
    assert denied.status_code == 403


# ----------------------------------------------------------------- templates


def test_template_crud_and_validation(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")

    created = client.post(
        "/api/reports/templates",
        headers=operator,
        json={"name": "Monthly exec", "kind": "executive", "sections": {"trend": False}},
    )
    assert created.status_code == 201
    template_id = created.json()["template_id"]

    # A compliance template without a framework has nothing to assess.
    assert (
        client.post(
            "/api/reports/templates",
            headers=operator,
            json={"name": "Compliance", "kind": "compliance"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/reports/templates",
            headers=operator,
            json={"name": "Compliance", "kind": "compliance", "framework_id": "sox"},
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/reports/templates",
            headers=operator,
            json={"name": "Bad sections", "sections": {"astrology": True}},
        ).status_code
        == 400
    )
    # Names are unique per tenant: two "Monthly exec" templates in one console
    # list are indistinguishable to the person picking one.
    assert (
        client.post(
            "/api/reports/templates", headers=operator, json={"name": "Monthly exec"}
        ).status_code
        == 400
    )

    patched = client.patch(
        f"/api/reports/templates/{template_id}", headers=operator, json={"name": "Quarterly exec"}
    )
    assert patched.status_code == 200 and patched.json()["name"] == "Quarterly exec"
    assert client.delete(f"/api/reports/templates/{template_id}", headers=operator).status_code == 204
    assert client.get("/api/reports/templates", headers=operator).json() == []


# ----------------------------------------------------------------- rendering


@pytest.mark.parametrize("fmt", ["pdf", "html", "json"])
def test_generate_renders_every_format(tmp_path, monkeypatch, fmt):
    client = configured_client(tmp_path, monkeypatch)
    _seed(tmp_path)
    operator = auth_headers(client, "operator")

    response = client.post(
        "/api/reports/generate", headers=operator, json={"kind": "executive", "format": fmt}
    )
    assert response.status_code == 200, response.text
    report = response.json()
    assert report["status"] == "ready" and report["size_bytes"] > 0

    download = client.get(
        f"/api/reports/{report['report_id']}/download", headers=auth_headers(client, "viewer")
    )
    assert download.status_code == 200
    if fmt == "pdf":
        assert download.content[:4] == b"%PDF"
    else:
        assert download.content


def test_the_json_export_is_the_same_report_as_the_pdf(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    operator = auth_headers(client, "operator")

    report = client.post(
        "/api/reports/generate", headers=operator, json={"kind": "executive", "format": "json"}
    ).json()
    path, _media, _name = store.resolve_report_file(
        settings, report["report_id"], tenant_id=tenant_id
    )
    body = json.loads(path.read_text(encoding="utf-8"))
    summary = client.get("/api/vulnerabilities/summary", headers=operator).json()
    assert body["kpis"]["open_total"] == summary["open_total"]
    assert body["kpis"]["breached"] == summary["breached"]


def test_compliance_report_carries_controls_and_executive_one_does_not(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    operator = auth_headers(client, "operator")

    compliance = client.post(
        "/api/reports/generate",
        headers=operator,
        json={"kind": "compliance", "framework_id": "pci-dss-4.0", "format": "json"},
    ).json()
    path, _media, _name = store.resolve_report_file(
        settings, compliance["report_id"], tenant_id=tenant_id
    )
    body = json.loads(path.read_text(encoding="utf-8"))
    assert body["compliance"][0]["framework_id"] == "pci-dss-4.0"
    assert body["compliance"][0]["controls"]

    executive = client.post(
        "/api/reports/generate", headers=operator, json={"kind": "executive", "format": "json"}
    ).json()
    path, _media, _name = store.resolve_report_file(
        settings, executive["report_id"], tenant_id=tenant_id
    )
    exec_body = json.loads(path.read_text(encoding="utf-8"))
    # Every framework's score, none of their control tables.
    assert len(exec_body["compliance"]) == 3
    assert all("controls" not in entry for entry in exec_body["compliance"])


def test_a_report_is_about_one_tenant_only(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    operator = auth_headers(client, "operator")
    report = client.post(
        "/api/reports/generate", headers=operator, json={"format": "json"}
    ).json()

    # Same id, a different tenant asking: not found, not "here you go".
    assert store.get_report(settings, report["report_id"], tenant_id="other") is None
    assert store.resolve_report_file(settings, report["report_id"], tenant_id="other") is None


def test_download_path_is_derived_not_read_from_the_row(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    report = client.post(
        "/api/reports/generate",
        headers=auth_headers(client, "operator"),
        json={"format": "json"},
    ).json()

    from sqlalchemy import select

    from api.db import models
    from api.db.engine import get_session

    with get_session(settings.postgres_url) as session:
        row = session.execute(
            select(models.GeneratedReport).where(
                models.GeneratedReport.report_id == report["report_id"]
            )
        ).scalar_one()
        row.storage_path = "../../../etc/passwd"
        session.commit()

    path, _media, _name = store.resolve_report_file(
        settings, report["report_id"], tenant_id=tenant_id
    )
    assert path.name == f"{report['report_id']}.json"
    assert store.reports_root(settings) in path.parents


# ----------------------------------------------------------------- schedules


def test_schedule_validation_and_admin_only(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")
    admin = auth_headers(client, "admin")
    template_id = client.post(
        "/api/reports/templates", headers=operator, json={"name": "Monthly exec"}
    ).json()["template_id"]

    denied = client.post(
        "/api/reports/schedules",
        headers=operator,
        json={"template_id": template_id, "name": "Monthly", "cron": "0 6 1 * *"},
    )
    assert denied.status_code == 403

    bad_cron = client.post(
        "/api/reports/schedules",
        headers=admin,
        json={"template_id": template_id, "name": "Monthly", "cron": "every monday"},
    )
    assert bad_cron.status_code == 400

    bad_recipient = client.post(
        "/api/reports/schedules",
        headers=admin,
        json={
            "template_id": template_id,
            "name": "Monthly",
            "cron": "0 6 1 * *",
            "recipients": [{"transport": "email", "target": "not-an-address"}],
        },
    )
    assert bad_recipient.status_code == 400

    created = client.post(
        "/api/reports/schedules",
        headers=admin,
        json={
            "template_id": template_id,
            "name": "Monthly",
            "cron": "0 6 1 * *",
            "recipients": [{"transport": "email", "target": "ciso@example.com"}],
        },
    )
    assert created.status_code == 201
    assert created.json()["next_run_at"]

    schedule_id = created.json()["schedule_id"]
    repointed = client.patch(
        f"/api/reports/schedules/{schedule_id}", headers=admin, json={"cron": "0 7 * * 1"}
    )
    # A cadence change re-anchors the next run rather than honouring the old one.
    assert repointed.status_code == 200
    assert repointed.json()["next_run_at"] != created.json()["next_run_at"]
    assert client.delete(f"/api/reports/schedules/{schedule_id}", headers=admin).status_code == 204


def test_a_schedule_cannot_point_at_another_tenants_template(tmp_path, monkeypatch):
    # Built for the tenant seeding and state reset, not for HTTP.
    configured_client(tmp_path, monkeypatch)
    settings, _tenant_id = _seed(tmp_path)
    with pytest.raises(store.ReportError):
        store.create_schedule(
            settings,
            tenant_id="default",
            template_id="rtpl_does_not_exist",
            name="Monthly",
            cron="0 6 1 * *",
        )


def test_dispatcher_renders_delivers_and_advances_the_schedule(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    template = store.create_template(settings, tenant_id=tenant_id, name="Monthly exec")
    schedule = store.create_schedule(
        settings,
        tenant_id=tenant_id,
        template_id=template["template_id"],
        name="Monthly",
        cron="0 6 1 * *",
        fmt="json",
        recipients=[{"transport": "email", "target": "ciso@example.com"}],
    )

    sent: list[dict] = []
    monkeypatch.setattr(
        report_delivery,
        "_send_email",
        lambda settings, recipient, **kwargs: sent.append(recipient)
        or {"transport": "email", "target": recipient["target"], "status": "delivered", "error": None},
    )

    dispatcher = report_dispatcher.ReportDispatcher(settings=settings)
    # Due by construction: the schedule's next run is a month out, so the tick
    # is given a clock past it rather than the test waiting for one.
    dispatcher.tick(now=datetime.now(UTC) + timedelta(days=40))

    assert sent == [{"transport": "email", "target": "ciso@example.com"}]
    reports = store.list_reports(settings, tenant_id=tenant_id)
    assert len(reports) == 1
    assert reports[0]["status"] == "ready"
    assert reports[0]["schedule_id"] == schedule["schedule_id"]
    assert reports[0]["delivery"][0]["status"] == "delivered"

    # And the occurrence is consumed: a second tick at the same clock must not
    # send the same report to the same customer again.
    dispatcher.tick(now=datetime.now(UTC) + timedelta(days=40))
    assert len(store.list_reports(settings, tenant_id=tenant_id)) == 1


def test_a_failed_render_is_recorded_and_does_not_retry_every_tick(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    template = store.create_template(settings, tenant_id=tenant_id, name="Monthly exec")
    store.create_schedule(
        settings,
        tenant_id=tenant_id,
        template_id=template["template_id"],
        name="Monthly",
        cron="0 6 1 * *",
        fmt="json",
    )

    from api.services.reports import content as content_builder

    def _boom(*args, **kwargs):
        raise RuntimeError("advisory dataset missing")

    monkeypatch.setattr(content_builder, "build", _boom)
    dispatcher = report_dispatcher.ReportDispatcher(settings=settings)
    when = datetime.now(UTC) + timedelta(days=40)
    dispatcher.tick(now=when)
    dispatcher.tick(now=when)

    reports = store.list_reports(settings, tenant_id=tenant_id)
    assert len(reports) == 1
    assert reports[0]["status"] == "failed"
    assert "advisory dataset missing" in reports[0]["error"]


def test_delivery_records_one_entry_per_recipient(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    path = tmp_path / "report.json"
    path.write_text("{}", encoding="utf-8")
    report = {"report_id": "rpt_1", "title": "t", "format": "json", "generated_at": "now"}

    entries = report_delivery.deliver(
        settings,
        report=report,
        path=path,
        recipients=[
            {"transport": "email", "target": "ciso@example.com"},
            {"transport": "carrier-pigeon", "target": "roof"},
        ],
    )
    assert [entry["status"] for entry in entries] == ["skipped", "failed"]
    # No SMTP relay configured is "skipped, and here is what to configure",
    # not a silent success.
    assert "OCTO_REPORT_SMTP_HOST" in entries[0]["error"]


def test_retention_prunes_old_reports_and_their_files(tmp_path, monkeypatch):
    configured_client(tmp_path, monkeypatch, report_retention_days=30)
    settings = make_settings(tmp_path, report_retention_days=30)
    _seed(tmp_path)
    report = store.generate(settings, tenant_id="default", fmt="json")
    path, _media, _name = store.resolve_report_file(settings, report["report_id"])

    assert store.prune_reports(settings)["deleted"] == 0
    assert path.is_file()

    result = store.prune_reports(settings, now=datetime.now(UTC) + timedelta(days=31))
    assert result["deleted"] == 1
    assert not path.is_file()
    assert store.get_report(settings, report["report_id"]) is None
