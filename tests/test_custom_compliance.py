"""W11 catalogue persistence, HTTP guards, assessment and PostgreSQL RLS."""
from datetime import UTC, datetime
import json

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from api.db import models
from api.db.compliance_models import ComplianceFrameworkDefinition as Definition
from api.db.engine import get_engine, get_session
from api.services import audit, tenants
from api.services.compliance import definitions, registry, service, signals
from api.services.tenant_purge import postgres as purge_pg
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_compliance_definitions import example

pytestmark = requires_postgres


@pytest.fixture
def setup(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    return client, settings, tenants.DEFAULT_TENANT_ID


def upload(client, role="admin", document=None):
    return client.post("/api/compliance/frameworks/import", headers=auth_headers(client, role),
                       json={"format": "json", "content": json.dumps(document or example())})


def test_import_replay_conflict_and_audit(setup):
    client, settings, tenant_id = setup
    created = upload(client)
    assert created.status_code == 201, created.text
    assert upload(client).status_code == 200
    assert upload(client, document=example() | {"name": "changed"}).status_code == 409
    with get_session(settings.postgres_url) as session:
        assert session.scalar(select(func.count()).select_from(Definition).where(
            Definition.tenant_id == tenant_id)) == 1
        assert session.scalar(select(func.count()).select_from(models.AuditEvent).where(
            models.AuditEvent.tenant_id == tenant_id,
            models.AuditEvent.action == "compliance.framework.import")) == 1
    fetched = client.get("/api/compliance/frameworks/custom-acme-v1/definition",
                         headers=auth_headers(client, "viewer"))
    assert fetched.status_code == 200
    assert fetched.json()["definition_sha256"] == created.json()["definition_sha256"]


@pytest.mark.parametrize("role", ["viewer", "operator"])
def test_import_is_admin_only(setup, role):
    client, _, _ = setup
    assert upload(client, role).status_code == 403


def test_custom_catalogue_uses_existing_assessment_and_report_fold(setup):
    client, settings, tenant_id = setup
    raw = example()
    raw["controls"][0]["signals"] = ["stale_asset"]
    assert upload(client, document=raw).status_code == 201
    viewer = auth_headers(client, "viewer")
    listed = client.get("/api/compliance/frameworks", headers=viewer)
    assert listed.status_code == 200
    assert "custom-acme-v1" in {row["framework_id"] for row in listed.json()}
    posture = client.get("/api/compliance/custom-acme-v1", headers=viewer)
    assert posture.status_code == 200, posture.text
    assert posture.json()["controls"][0]["status"] == "not_assessed"
    assert posture.json()["coverage_score"] is None
    assert "not a certification" in posture.json()["scope_note"]
    all_postures = service.assess_all(settings, tenant_id=tenant_id)
    assert "custom-acme-v1" in {row["framework_id"] for row in all_postures}
    assert registry.resolve_framework(settings, "custom-acme-v1", None) is None
    assert set(definitions.SIGNAL_SOURCES) == set(signals.SIGNALS)


def test_tenant_isolation_quota_and_batched_purge(setup, monkeypatch):
    client, settings, tenant_id = setup
    assert upload(client).status_code == 201
    other = "w11-other-tenant"
    with get_session(settings.postgres_url) as session:
        session.add(models.Tenant(tenant_id=other, name="Other", created_at=datetime.now(UTC).replace(tzinfo=None)))
    assert registry.get_definition(settings, tenant_id=other, framework_id="custom-acme-v1") is None
    created, fresh = registry.import_definition(settings, tenant_id=other, format="json",
        content=json.dumps(example() | {"name": "Other catalogue"}), audit=audit.system_context("test"))
    assert fresh and created["definition"]["name"] == "Other catalogue"
    monkeypatch.setattr(registry, "MAX_FRAMEWORKS_PER_TENANT", 1)
    assert upload(client, document=example() | {"framework_id": "custom-second"}).status_code == 409
    assert upload(client).status_code == 200  # Replay is not a new admission.
    assert "compliance_framework_definitions" in purge_pg.POSTGRES_TABLES
    with get_session(settings.postgres_url) as session:
        assert purge_pg.delete_batch(session, Definition.__tablename__, tenant_id, 1) == 1
    assert registry.get_definition(settings, tenant_id=other, framework_id="custom-acme-v1") is not None


def test_audit_failure_rolls_back_definition(setup, monkeypatch):
    _, settings, tenant_id = setup
    def fail(*args, **kwargs):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr(audit, "record", fail)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        registry.import_definition(settings, tenant_id=tenant_id, content=json.dumps(example()),
                                   format="json", audit=audit.system_context("test"))
    assert registry.get_definition(settings, tenant_id=tenant_id, framework_id="custom-acme-v1") is None


def test_rls_filters_unscoped_query_and_blocks_cross_tenant_write(setup):
    client, settings, tenant_id = setup
    assert upload(client).status_code == 201
    engine = get_engine(settings.postgres_url)
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL ROLE shapoclyack_tenant"))
        conn.execute(text("SELECT set_config('shapoclyack.tenant_id', :tenant, true)"), {"tenant": "other"})
        assert conn.execute(select(Definition.__table__)).all() == []
    with pytest.raises(DBAPIError):
        with engine.begin() as conn:
            conn.execute(text("SET LOCAL ROLE shapoclyack_tenant"))
            conn.execute(text("SELECT set_config('shapoclyack.tenant_id', :tenant, true)"), {"tenant": tenant_id})
            # No application tenant predicate: the database is the second fence.
            conn.execute(Definition.__table__.update().values(tenant_id="other"))


def test_stored_digest_mismatch_fails_closed(setup):
    client, settings, tenant_id = setup
    assert upload(client).status_code == 201
    with get_session(settings.postgres_url) as session:
        row = session.get(Definition, (tenant_id, "custom-acme-v1"))
        row.definition = row.definition | {"name": "tampered"}
    with pytest.raises(ValueError, match="digest mismatch"):
        registry.resolve_framework(settings, "custom-acme-v1", tenant_id)


def test_total_control_budget_is_bounded(setup, monkeypatch):
    client, _, _ = setup
    monkeypatch.setattr(registry, "MAX_CONTROLS_PER_TENANT", 1)
    assert upload(client).status_code == 201
    assert upload(client, document=example() | {"framework_id": "custom-second"}).status_code == 409
