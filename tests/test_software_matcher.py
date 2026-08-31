"""Integration tests for software matcher, database persistence, and patch gaps (Sprint 3)."""

from datetime import UTC, datetime
from pathlib import Path

from api.db import models
from api.db.engine import get_session
from api.services import software_matcher
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
    from api.services import endpoint_inventory as endpoint_inventory_service
    from api.services import tenants as tenants_service

    settings = _settings(tmp_path)
    endpoint_inventory_service.configure(settings)
    endpoint_inventory_service.reset_for_tests()

    tenant_id = "test-tenant-sm"
    now = datetime.now(UTC)

    with get_session(settings.postgres_url) as session:
        session.query(models.EndpointSoftwareAdvisory).delete()
        session.query(models.VulnerabilityEvent).delete()
        session.query(models.Vulnerability).delete()
        session.query(models.Asset).delete()
        session.query(models.Tenant).delete()
        session.commit()

        tenant = models.Tenant(
            tenant_id=tenant_id,
            name="SM Tenant",
            status="active",
            created_at=now,
            updated_at=now,
        )
        session.add(tenant)
        session.commit()

    tenants_service.upsert_tenant(settings, tenant_id=tenant_id, name="SM Tenant")
    assets_service.upsert_asset(settings, tenant_id=tenant_id, asset_id="server-node-1")

    with get_session(settings.postgres_url) as session:
        device = models.EndpointDevice(
            device_id="dev-001",
            tenant_id=tenant_id,
            agent_id="agent-001",
            asset_id="server-node-1",
            hostname="web-prod-01",
            os_family="linux",
            os_name="Debian GNU/Linux 11 (bullseye)",
            os_version="11",
            os_arch="x86_64",
            agent_version="1.0.0",
            labels={"env": "prod"},
            reconciliation_status="linked",
            first_seen=now,
            last_seen=now,
            last_inventory_at=now,
            latest_snapshot_id="snap-001",
        )
        snapshot = models.EndpointInventorySnapshot(
            snapshot_id="snap-001",
            tenant_id=tenant_id,
            device_id="dev-001",
            schema_version=1,
            collected_at=now,
            received_at=now,
            payload_digest="digest-001",
            software_count=3,
        )
        item1 = models.EndpointSoftwareItem(
            snapshot_id="snap-001",
            tenant_id=tenant_id,
            device_id="dev-001",
            comparison_key="k1",
            name="openssl",
            version="1.1.1k-1+deb11u1",
            publisher="Debian",
            architecture="amd64",
            source="deb",
        )
        item2 = models.EndpointSoftwareItem(
            snapshot_id="snap-001",
            tenant_id=tenant_id,
            device_id="dev-001",
            comparison_key="k2",
            name="curl",
            version="7.74.0-1.3+deb11u1",
            publisher="Debian",
            architecture="amd64",
            source="deb",
        )
        item3 = models.EndpointSoftwareItem(
            snapshot_id="snap-001",
            tenant_id=tenant_id,
            device_id="dev-001",
            comparison_key="k3",
            name="bash",
            version="5.1-2+deb11u1",
            publisher="Debian",
            architecture="amd64",
            source="deb",
        )
        session.add_all([device, snapshot, item1, item2, item3])
        session.commit()

    return settings, tenant_id, "dev-001", "server-node-1"


@requires_postgres
def test_match_device_software_and_bridge_vulnerabilities(tmp_path: Path):
    settings, tenant_id, device_id, asset_id = _seed(tmp_path)

    advisories = software_matcher.match_device_software(
        settings, tenant_id=tenant_id, device_id=device_id
    )

    assert len(advisories) >= 2
    cves = [a["cve"] for a in advisories]
    assert "CVE-2023-0286" in cves  # openssl
    assert "CVE-2023-38545" in cves  # curl

    # Check database persistence of advisories
    stored = software_matcher.get_device_advisories(settings, tenant_id, device_id)
    assert len(stored) >= 2

    # Check that Vulnerability Center has tracked findings created for the asset
    with get_session(settings.postgres_url) as session:
        vulns = session.query(models.Vulnerability).filter_by(tenant_id=tenant_id, asset_id=asset_id).all()
        assert len(vulns) >= 2
        vuln_cves = [v.cve for v in vulns]
        assert "CVE-2023-0286" in vuln_cves
        assert "CVE-2023-38545" in vuln_cves


@requires_postgres
def test_compute_patch_gaps(tmp_path: Path):
    settings, tenant_id, device_id, _ = _seed(tmp_path)

    software_matcher.match_device_software(settings, tenant_id=tenant_id, device_id=device_id)

    gaps = software_matcher.compute_patch_gaps(settings, tenant_id=tenant_id, device_id=device_id)

    assert gaps["total_advisories"] >= 2
    assert gaps["vulnerable_package_count"] >= 2
    assert gaps["affected_device_count"] == 1
    assert len(gaps["remediations"]) >= 2
    assert any("apt-get --only-upgrade install" in r["upgrade_command"] for r in gaps["remediations"])
