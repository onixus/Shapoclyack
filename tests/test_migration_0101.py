"""Action claims migrate reversibly until durable effects exist."""
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from api.db import migrate
from tests.conftest import POSTGRES_URL, requires_postgres

pytestmark = requires_postgres


def test_operator_actions_upgrade_downgrade_and_refuse_evidence_loss(monkeypatch):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0101_" + uuid4().hex[:12]
    with admin.connect() as db:
        db.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    engine = create_engine(url)
    try:
        migrate.run_upgrade(url, revision="0100_asset_groups")
        assert "payload" not in {c["name"] for c in inspect(engine).get_columns("operator_executions")}
        migrate.run_upgrade(url, revision="0101_operator_actions")
        assert "payload" in {c["name"] for c in inspect(engine).get_columns("operator_executions")}
        assert any(c["column_names"] == ["proposal_id"] for c in inspect(engine).get_unique_constraints("operator_executions"))
        migrate._downgrade("0100_asset_groups")  # noqa: SLF001
        assert "payload" not in {c["name"] for c in inspect(engine).get_columns("operator_executions")}
        migrate.run_upgrade(url, revision="0101_operator_actions")
        with engine.begin() as db:
            db.execute(text("INSERT INTO tenants (tenant_id,name,created_at) VALUES ('migration','migration',CURRENT_TIMESTAMP)"))
            db.execute(text("INSERT INTO operator_sessions (session_id,tenant_id,username,created_at,updated_at) "
                            "VALUES ('migration','migration','operator',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
            db.execute(text("INSERT INTO operator_proposals (proposal_id,session_id,tenant_id,username,payload,status,created_at) "
                            "VALUES ('migration','migration','migration','operator','{}','unknown',CURRENT_TIMESTAMP)"))
        with pytest.raises(RuntimeError, match="exported and removed"):
            migrate._downgrade("0100_asset_groups")  # noqa: SLF001
        with engine.connect() as db:
            assert db.execute(text("SELECT status FROM operator_proposals WHERE proposal_id='migration'")).scalar_one() == "unknown"
        assert "payload" in {c["name"] for c in inspect(engine).get_columns("operator_executions")}
    finally:
        engine.dispose()
        with admin.connect() as db:
            db.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
