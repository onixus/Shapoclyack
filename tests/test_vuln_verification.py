"""Tests for vulnerability automated verification scans and mechanical closure (Sprint 2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import vuln_states
from api.services import vulnerabilities as vulns_service
from tests.conftest import POSTGRES_URL, requires_postgres


def _settings(tmp_path: Path):
    from api.services import tenants as tenants_service
    from api.settings import Settings

    settings = Settings(
        output_dir=tmp_path / "output",
        state_dir=tmp_path / "state",
        postgres_url=POSTGRES_URL,
    )
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.state_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(settings)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(settings)
    return settings


def _seed(tmp_path: Path):
    from api.services import assets as assets_service
    from api.services import tenants as tenants_service

    settings = _settings(tmp_path)
    tenant_id = "test-tenant"
    with get_session(settings.postgres_url) as session:
        session.query(models.VulnerabilityEvent).delete()
        session.query(models.Vulnerability).delete()
        session.query(models.Asset).delete()
        session.commit()

    tenants_service.upsert_tenant(settings, tenant_id=tenant_id, name="Test Tenant")
    assets_service.upsert_asset(settings, tenant_id=tenant_id, asset_id="192.168.1.10")
    return settings, tenant_id


@requires_postgres
def test_trigger_verification_scan(tmp_path: Path):
    settings, tenant_id = _seed(tmp_path)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        v = models.Vulnerability(
            vuln_id="vln_test_verify",
            tenant_id=tenant_id,
            asset_id="192.168.1.10",
            finding_key="k1",
            cve="CVE-2026-1001",
            port="8080",
            severity="high",
            state=vuln_states.FIXING,
            state_changed_at=now,
            first_seen_at=now,
            last_seen_at=now,
            sla_started_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(v)
        session.commit()

    with patch("api.services.jobs.start_scan") as mock_start_scan:
        mock_job = MagicMock()
        mock_job.job_id = "job_verify_123"
        mock_start_scan.return_value = mock_job

        res = vulns_service.trigger_verification(
            settings,
            tenant_id=tenant_id,
            vuln_id="vln_test_verify",
            actor="test-operator",
        )

        assert res["state"] == vuln_states.VERIFYING
        assert res["verification_job_id"] == "job_verify_123"
        assert res["last_verified_at"] is not None


@requires_postgres
def test_mechanical_closure_on_successful_verification(tmp_path: Path):
    settings, tenant_id = _seed(tmp_path)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        v = models.Vulnerability(
            vuln_id="vln_test_closed",
            tenant_id=tenant_id,
            asset_id="192.168.1.10",
            finding_key="k_closed",
            cve="CVE-2026-1002",
            port="443",
            severity="critical",
            state=vuln_states.VERIFYING,
            state_changed_at=now,
            first_seen_at=now,
            last_seen_at=now,
            sla_started_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(v)
        session.commit()

    res = vulns_service.transition(
        settings,
        tenant_id=tenant_id,
        vuln_id="vln_test_closed",
        to_state=vuln_states.CLOSED,
        machine_verified=True,
        closure_reason="verified_remediated",
    )
    assert res is not None
    assert res["state"] == "CLOSED"
    assert res["machine_verified"] is True
    assert res["closure_reason"] == "verified_remediated"


@requires_postgres
def test_verification_failed_reopens_to_fixing(tmp_path: Path):
    settings, tenant_id = _seed(tmp_path)
    now = datetime.now(UTC)
    run_id = "20260831T120500Z"
    run_dir = settings.output_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    with get_session(settings.postgres_url) as session:
        v = models.Vulnerability(
            vuln_id="vln_test_fail",
            tenant_id=tenant_id,
            asset_id="192.168.1.10",
            finding_key="k_fail",
            cve="CVE-2026-9999",
            port="80",
            severity="high",
            state=vuln_states.VERIFYING,
            state_changed_at=now,
            first_seen_at=now,
            last_seen_at=now,
            sla_started_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(v)
        session.commit()

    finding_data = [
        {
            "host": "192.168.1.10",
            "cve": "CVE-2026-9999",
            "port": "80",
            "severity": "high",
            "cvss": 7.5,
        }
    ]
    (run_dir / "vulnerabilities.json").write_text(json.dumps(finding_data), encoding="utf-8")
    (run_dir / "fingerprint.json").write_text("[]", encoding="utf-8")

    with (
        patch("api.services.runs.get_run_dir", return_value=run_dir),
        patch("api.services.vulnerabilities._run_findings", return_value=finding_data),
    ):
        vulns_service.register_findings_from_run(settings, tenant_id=tenant_id, run_id=run_id)

    item = vulns_service.get_vulnerability(settings, tenant_id=tenant_id, vuln_id="vln_test_fail")
    assert item is not None
    assert item["state"] == vuln_states.FIXING
    assert item["last_seen_run_id"] == run_id
