"""MSSP per-tenant posture and exposure/KEV filters (#139)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from api.auth import get_settings
from api.db import models
from api.db.engine import get_session
from api.services import tenants as tenants_service
from scanner.pipeline.asset_identity import ip_identity_key
from tests.conftest import api_client, login, requires_postgres

pytestmark = requires_postgres


def _seed_tenant_asset(
    tenant_id: str,
    host_ip: str,
    *,
    owner_email: str | None = None,
    exposure_level: str | None = None,
    risk_level: str | None = "high",
    in_kev: bool = False,
) -> str:
    settings = get_settings()
    now = datetime.now(UTC).replace(tzinfo=None)
    asset_id = ip_identity_key(tenant_id, host_ip)
    with get_session(settings.postgres_url) as session:
        if session.get(models.Tenant, tenant_id) is None:
            session.add(
                models.Tenant(
                    tenant_id=tenant_id, name=tenant_id, status="active", created_at=now
                )
            )
        if session.get(models.Asset, asset_id) is None:
            session.add(
                models.Asset(
                    asset_id=asset_id,
                    tenant_id=tenant_id,
                    status="active",
                    first_seen=now,
                    last_seen=now,
                    owner_email=owner_email,
                    exposure_level=exposure_level,
                )
            )
        if risk_level is not None:
            vuln_id = f"vln-{uuid4().hex[:12]}"
            session.add(
                models.Vulnerability(
                    vuln_id=vuln_id,
                    tenant_id=tenant_id,
                    asset_id=asset_id,
                    finding_key=f"key-{vuln_id}",
                    cve="CVE-2024-13901",
                    title="seeded",
                    severity="critical",
                    risk_level=risk_level,
                    contextual_score=8.0,
                    in_kev=in_kev,
                    exploit_maturity="attacked" if in_kev else None,
                    state="OPEN",
                    state_changed_at=now,
                    first_seen_at=now,
                    last_seen_at=now,
                    sla_started_at=now,
                    created_at=now,
                    updated_at=now,
                )
            )
    return asset_id


def test_admin_compares_tenants_operator_cannot_see_others():
    other = f"ten_{uuid4().hex[:8]}"
    _seed_tenant_asset("default", f"10.139.0.{uuid4().hex[:2]}", risk_level="low")
    _seed_tenant_asset(
        other,
        "10.139.1.1",
        exposure_level="internet",
        risk_level="very_high",
        in_kev=True,
    )

    client = api_client()
    admin = {"Authorization": f"Bearer {login(client, 'admin')}"}
    operator = {"Authorization": f"Bearer {login(client, 'operator')}"}
    viewer = {"Authorization": f"Bearer {login(client, 'viewer')}"}

    assert client.get("/api/tenants/posture", headers=viewer).status_code == 403

    admin_rows = client.get("/api/tenants/posture", headers=admin).json()
    by_id = {row["tenant_id"]: row for row in admin_rows}
    assert other in by_id
    assert by_id[other]["estate_risk"] == "very_high"
    assert by_id[other]["open_total"] >= 1
    assert by_id[other]["in_kev_open"] >= 1
    assert by_id[other]["declared_internet_assets"] >= 1
    default_row = by_id.get("default")
    if default_row and default_row["estate_risk"] in {None, "low", "very_low", "moderate"}:
        assert admin_rows[0]["tenant_id"] == other

    op_rows = client.get("/api/tenants/posture", headers=operator).json()
    assert {row["tenant_id"] for row in op_rows} == {"default"}


def test_exposure_and_kev_filters():
    asset_id = _seed_tenant_asset(
        tenants_service.DEFAULT_TENANT_ID,
        f"10.139.2.{uuid4().hex[:2]}",
        exposure_level="internet",
        in_kev=True,
        risk_level="high",
    )
    client = api_client()
    viewer = {"Authorization": f"Bearer {login(client, 'viewer')}"}

    listed = client.get(
        "/api/assets", params={"exposure": "internet", "limit": 5000}, headers=viewer
    )
    assert listed.status_code == 200
    ids = {row["asset_id"] for row in listed.json()["items"]}
    assert asset_id in ids

    assert (
        client.get("/api/assets", params={"exposure": "outer-space"}, headers=viewer).status_code
        == 422
    )

    kev = client.get("/api/vulnerabilities", params={"in_kev": True, "open_only": True}, headers=viewer)
    assert kev.status_code == 200
    assert any(row["in_kev"] and row["asset_id"] == asset_id for row in kev.json()["items"])
