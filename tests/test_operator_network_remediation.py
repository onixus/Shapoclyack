"""Apache TRACE guidance needs reviewed process evidence, never a banner."""
from datetime import UTC, datetime, timedelta
import hashlib
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from api.db import models, tenant_scope
from api.db.engine import get_session
from api.services import assets, vulnerabilities
from api.services.local_operator import remediation
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_vuln_lifecycle import _write_run


def test_offline_vendor_record_is_pinned_and_not_an_apache_vulnerability_claim():
    guide = remediation.trace_guide()
    assert guide["directive"] == "TraceEnable off"
    assert guide["expected_trace_status"] == 405
    assert guide["vendor_url"] == "https://httpd.apache.org/docs/2.4/mod/core.html#traceenable"
    assert "policy choice" in guide["summary"]["en"]


@pytest.mark.parametrize("extra", [{"shell": "id"}, {"tenant_id": "other"},
    {"product": "nginx"}, {"version": "2.2.1"}, {"reviewed": False}, {"reviewed": 1}, {"reviewed": "true"},
    {"evidence_kind": "remote_banner"}, {"image_id": "httpd:latest"}])
def test_model_or_banner_cannot_supply_applicability(extra):
    data = {"finding_sha256": "a" * 64, "source_sha256": remediation.TRACE_GUIDE_SHA256,
        "product": "apache_httpd", "version": "2.4.65", "evidence_kind": "authenticated_process_inventory",
        "evidence_sha256": "b" * 64, "reviewed": True, **extra}
    with pytest.raises(ValidationError):
        remediation.ApplicabilityReview.model_validate(data)


def test_untrusted_detector_identity_cannot_reuse_trace_guidance():
    row = SimpleNamespace(source="scan", cve=None, script_id="pulse-plugin:shapo_http_trace", port="80",
        detectors=[{"detector": "pulse-plugin", "ref": "shapo_http_trace", "ruleset": "sha256:" + "0" * 64, "port": "80"}])
    assert not remediation._trace_identity(row)


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path, operator_enabled=True)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    headers = {role: auth_headers(client, role) for role in ("admin", "operator", "viewer")}
    plugin_sha = hashlib.sha256(remediation.TRACE_PLUGIN_FILE.read_bytes()).hexdigest()
    _write_run(settings.output_dir, "trace-run", [{"host": "127.0.0.1"}], [{
        "host": "127.0.0.1", "port": "80", "source": "pulse-plugin", "script_id": "pulse-plugin:shapo_http_trace",
        "ruleset_version": "sha256:" + plugin_sha, "severity": "low", "title": "HTTP TRACE enabled"}])
    assets.upsert_assets_from_run(settings, tenant_id="default", run_id="trace-run")
    vulnerabilities.register_findings_from_run(settings, tenant_id="default", run_id="trace-run")
    finding = vulnerabilities.list_vulnerabilities(settings, tenant_id="default")[0][0]
    return client, settings, headers, finding["vuln_id"]


def _get(env, role="viewer", **kwargs):
    client, settings, headers, vuln_id = env
    return client.get(f"/api/operator/remediation/findings/{vuln_id}", headers=headers[role],
        params={"tenant_id": "default", **kwargs})


def _review(env, role="admin", **kwargs):
    client, settings, headers, vuln_id = env
    current = _get(env).json()
    return client.post(f"/api/operator/remediation/findings/{vuln_id}/applicability-review?tenant_id=default",
        headers=headers[role], json={"finding_sha256": current["finding_sha256"], "source_sha256": current["guidance_sha256"],
            "product": "apache_httpd", "version": "2.4.65", "evidence_kind": "operator_verified_container",
            "evidence_sha256": "a" * 64, "image_id": "sha256:" + "b" * 64, "reviewed": True, **kwargs})


@requires_postgres
@pytest.mark.parametrize("language", ["ru", "en"])
def test_reviewed_configuration_card_is_not_package_patch_or_machine_closure(env, language):
    before = _get(env)
    assert before.status_code == 200, before.text
    assert before.json()["reason"] == "application_review_required", before.text
    assert before.json()["items"][0]["directive"] is None
    reviewed = _review(env)
    assert reviewed.status_code == 201, reviewed.text
    after = _get(env, language=language)
    assert after.status_code == 200, after.text
    card = after.json()["items"][0]
    assert card["kind"] == "configuration_hardening" and card["directive"] == "TraceEnable off"
    assert card["applicability"] == "administrator_reviewed"
    assert card["target_version"] is None and card["package"] is None and card["cve_ids"] == []
    assert card["upgrade_command"] is None
    assert card["verification"]["requires_confirmation"] is True
    client, settings, headers, vuln_id = env
    assert vulnerabilities.get_vulnerability(settings, tenant_id="default", vuln_id=vuln_id)["state"] == "OPEN"
    with tenant_scope.system("review evidence test"), get_session(settings.postgres_url) as db:
        event = db.scalar(select(models.VulnerabilityEvent).where(models.VulnerabilityEvent.actor == "admin"))
        assert event.detail[remediation.TRACE_REVIEW_KEY]["evidence_sha256"] == "a" * 64


@requires_postgres
@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_review_requires_current_administrator_not_read_or_scan_authority(env, role):
    response = _review(env, role=role)
    assert response.status_code == 403, response.text
    assert _get(env).json()["items"][0]["directive"] is None


@requires_postgres
@pytest.mark.parametrize("reviewed", [1, "true", False])
def test_review_marker_requires_explicit_json_true(env, reviewed):
    response = _review(env, reviewed=reviewed)
    assert response.status_code == 422, response.text
    assert _get(env).json()["items"][0]["directive"] is None


@requires_postgres
@pytest.mark.parametrize("field", ["finding_sha256", "source_sha256"])
def test_changed_review_binding_never_becomes_applicable(env, field):
    assert _review(env, **{field: "0" * 64}).status_code == 409
    assert _get(env).json()["items"][0]["directive"] is None


@requires_postgres
def test_current_sources_are_bound_and_reobservation_invalidates_old_applicability(env):
    assert _review(env).status_code == 201
    source = _get(env).json()["items"][0]["sources"][0]
    client, settings, headers, vuln_id = env
    url = f"/api/operator/remediation/findings/{vuln_id}/sources/{source['source_id']}"
    query = {"tenant_id": "default", "snapshot_id": source["snapshot_id"], "source_hash": source["source_hash"]}
    assert client.get(url, headers=headers["viewer"], params=query).status_code == 200
    with tenant_scope.system("changed finding"), get_session(settings.postgres_url) as db:
        db.get(models.Vulnerability, vuln_id).last_seen_run_id = "later-run"
    assert client.get(url, headers=headers["viewer"], params=query).status_code == 409
    assert _get(env).json()["items"][0]["directive"] is None


@requires_postgres
def test_foreign_tenant_cannot_read_or_attest_even_platform_admin(env):
    client, settings, headers, vuln_id = env
    assert client.post("/api/tenants", headers=headers["admin"], json={"tenant_id": "other", "name": "Other"}).status_code == 201
    assert _get(env, role="admin", tenant_id="other").status_code == 404
    response = client.post(f"/api/operator/remediation/findings/{vuln_id}/applicability-review?tenant_id=other",
        headers=headers["admin"], json={"finding_sha256": "a" * 64, "source_sha256": remediation.TRACE_GUIDE_SHA256,
            "product": "apache_httpd", "version": "2.4.65", "evidence_kind": "authenticated_process_inventory",
            "evidence_sha256": "b" * 64, "reviewed": True})
    assert response.status_code == 404, response.text


@requires_postgres
def test_stale_finding_and_raw_banner_do_not_offer_directive(env):
    assert _review(env).status_code == 201
    client, settings, headers, vuln_id = env
    with tenant_scope.system("stale finding"), get_session(settings.postgres_url) as db:
        row = db.get(models.Vulnerability, vuln_id)
        row.last_seen_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=8)
        row.title = "Apache/2.4.65 attacker-controlled banner"
    response = _get(env)
    assert response.json()["reason"] == "finding_stale"
    assert response.json()["items"][0]["directive"] is None
    assert "attacker-controlled" not in response.text
