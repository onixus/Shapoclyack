"""Real branch upgrades preserve campaign and personal-operator history."""
from pathlib import Path
from uuid import uuid4

from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from api.db import migrate, models, tenant_scope
from tests.conftest import POSTGRES_URL, requires_postgres

HEAD = "0104_operator_campaigns_merge"
PARENTS = {"0103_operator_planner", "0101_remediation_campaigns"}


def test_single_merge_head_keeps_both_original_revision_lineages():
    scripts = ScriptDirectory.from_config(Config(str(Path(__file__).parents[1] / "api/db/alembic.ini")))
    assert scripts.get_heads() == [HEAD]
    assert set(scripts.get_revision(HEAD).down_revision) == PARENTS
    assert scripts.get_revision("0101_operator_actions").down_revision == "0100_asset_groups"
    assert scripts.get_revision("0101_remediation_campaigns").down_revision == "0100_asset_groups"


@requires_postgres
@pytest.mark.parametrize("starting_revision", [None, "0103_operator_planner", "0101_remediation_campaigns"])
def test_fresh_and_both_existing_branches_really_upgrade_without_data_loss(monkeypatch, starting_revision):
    admin = create_engine(POSTGRES_URL, isolation_level="AUTOCOMMIT")
    name = "mig0104_" + uuid4().hex[:12]
    with admin.connect() as db:
        db.execute(text(f'CREATE DATABASE "{name}"'))
    url = make_url(POSTGRES_URL).set(database=name).render_as_string(hide_password=False)
    monkeypatch.setenv("OCTO_POSTGRES_URL", url)
    engine = create_engine(url)
    try:
        if starting_revision:
            migrate.run_upgrade(url, revision=starting_revision)
            tables = set(inspect(engine).get_table_names())
            assert ("remediation_campaigns" in tables) == (starting_revision == "0101_remediation_campaigns")
            assert ("operator_embedding_indexes" in tables) == (starting_revision == "0103_operator_planner")
            with engine.begin() as db:
                db.execute(text("INSERT INTO tenants (tenant_id,name,created_at) VALUES ('preserve','preserve',CURRENT_TIMESTAMP)"))
                if starting_revision == "0103_operator_planner":
                    db.execute(text("INSERT INTO operator_sessions (session_id,tenant_id,username,created_at,updated_at) "
                                    "VALUES ('preserve','preserve','owner',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
                    db.execute(text("INSERT INTO operator_tasks (task_id,tenant_id,username,session_id,actor_token_version,kind,payload,"
                                    "run_id,language,idempotency_key,status,cancel_requested,created_at,updated_at) VALUES "
                                    "('preserve','preserve','owner','preserve',0,'plan_request','{\"request\":\"keep-private\"}',"
                                    "'run-private','ru','preserve','queued',false,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
                else:
                    db.execute(text("INSERT INTO remediation_campaigns (campaign_id,tenant_id,name,selection,status_changed_at,created_at,updated_at) "
                                    "VALUES ('preserve','preserve','Keep campaign','{\"finding_ids\":[\"keep\"]}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
        migrate.run_upgrade(url)  # Actual missing-parent DDL, never stamp.
        tables = set(inspect(engine).get_table_names())
        assert {"remediation_campaigns", "remediation_campaign_members", "remediation_campaign_events",
                "operator_proposals", "operator_executions", "operator_embedding_indexes", "operator_evidence_embeddings"} <= tables
        assert "payload" in {column["name"] for column in inspect(engine).get_columns("operator_tasks")}
        with engine.connect() as db:
            assert db.execute(text("SELECT version_num FROM alembic_version")).scalars().all() == [HEAD]
            assert tenant_scope.database_problems(db, models.Base.metadata) == []
        if starting_revision:
            with engine.connect() as db:
                if starting_revision == "0103_operator_planner":
                    row = db.execute(text("SELECT kind,payload,status FROM operator_tasks WHERE task_id='preserve'")).one()
                    assert tuple(row) == ("plan_request", {"request": "keep-private"}, "queued")
                else:
                    row = db.execute(text("SELECT name,selection FROM remediation_campaigns WHERE campaign_id='preserve'")).one()
                    assert tuple(row) == ("Keep campaign", {"finding_ids": ["keep"]})
        # A relative -1 is ambiguous at a merge. An explicit parent unmerges
        # this node into BOTH existing heads without deleting either schema.
        migrate._downgrade("0103_operator_planner")  # noqa: SLF001
        with engine.connect() as db:
            assert set(db.execute(text("SELECT version_num FROM alembic_version")).scalars()) == PARENTS
        assert set(inspect(engine).get_table_names()) == tables
        migrate.run_upgrade(url)
        with engine.connect() as db:
            assert db.execute(text("SELECT version_num FROM alembic_version")).scalars().all() == [HEAD]
            if starting_revision:
                table = "operator_tasks" if starting_revision == "0103_operator_planner" else "remediation_campaigns"
                assert db.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 1
    finally:
        engine.dispose()
        with admin.connect() as db:
            db.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        admin.dispose()
