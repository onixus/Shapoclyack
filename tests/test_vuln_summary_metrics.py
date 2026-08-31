"""Tests for machine verification metrics in vulnerability summary (Sprint 2)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

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


@requires_postgres
def test_summary_machine_verification_metrics(tmp_path: Path):
    settings = _settings(tmp_path)
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.query(models.VulnerabilityEvent).delete()
        session.query(models.Vulnerability).delete()
        session.query(models.Asset).delete()
        session.query(models.Tenant).delete()
        session.commit()

        tenant = models.Tenant(
            tenant_id="t-metrics",
            name="Metrics Tenant",
            status="active",
            created_at=now,
            updated_at=now,
        )
        session.add(tenant)
        session.commit()

        # 1 closed with machine verification
        v1 = models.Vulnerability(
            vuln_id="v_m1",
            tenant_id="t-metrics",
            asset_id="10.0.0.1",
            finding_key="k1",
            cve="CVE-2026-0001",
            severity="high",
            state=vuln_states.CLOSED,
            state_changed_at=now,
            first_seen_at=now,
            last_seen_at=now,
            sla_started_at=now,
            machine_verified=True,
            closure_reason="verified_remediated",
            created_at=now,
            updated_at=now,
        )
        # 1 closed manually
        v2 = models.Vulnerability(
            vuln_id="v_m2",
            tenant_id="t-metrics",
            asset_id="10.0.0.1",
            finding_key="k2",
            cve="CVE-2026-0002",
            severity="medium",
            state=vuln_states.CLOSED,
            state_changed_at=now,
            first_seen_at=now,
            last_seen_at=now,
            sla_started_at=now,
            machine_verified=False,
            closure_reason="manual",
            created_at=now,
            updated_at=now,
        )
        # 1 open
        v3 = models.Vulnerability(
            vuln_id="v_m3",
            tenant_id="t-metrics",
            asset_id="10.0.0.1",
            finding_key="k3",
            cve="CVE-2026-0003",
            severity="low",
            state=vuln_states.OPEN,
            state_changed_at=now,
            first_seen_at=now,
            last_seen_at=now,
            sla_started_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add_all([v1, v2, v3])
        session.commit()

    summary_data = vulns_service.summary(settings, tenant_id="t-metrics")
    assert summary_data["total"] == 3
    assert summary_data["open_total"] == 1
    assert summary_data["closed_total"] == 2
    assert summary_data["machine_verified_closed"] == 1
    assert summary_data["manual_closed"] == 1
    assert summary_data["machine_verification_rate"] == 50.0
