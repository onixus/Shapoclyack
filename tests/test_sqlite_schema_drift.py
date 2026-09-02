"""The SQLite dev fallback keeps an existing file in step with the models.

``create_all`` only creates absent tables, so a dev database made before a
model gained a column failed the first query naming it (``no such column:
users.email`` on a ``scanner/state/octo_man.db`` from before OIDC). Postgres
has Alembic; SQLite gets the additive half of that here.
"""

from __future__ import annotations

from sqlalchemy import create_engine, inspect, text

from api.db import engine as db_engine


def test_an_old_sqlite_file_gains_the_columns_the_models_grew(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'old.db'}"
    old = create_engine(url, future=True)
    with old.begin() as conn:
        # The shape of `users` before migration 0026 added the OIDC columns,
        # with a row in it so a NOT NULL column cannot simply be bolted on.
        conn.execute(
            text(
                "CREATE TABLE users (username VARCHAR PRIMARY KEY, password_hash VARCHAR NOT NULL, "
                "role VARCHAR NOT NULL, created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO users (username, password_hash, role, created_at, updated_at) "
                "VALUES ('old', '$2b$x', 'viewer', '2026-01-01', '2026-01-01')"
            )
        )
    old.dispose()

    db_engine.reset_for_tests()
    try:
        engine = db_engine.get_engine(url)
        columns = {column["name"] for column in inspect(engine).get_columns("users")}
        assert {"email", "email_verified", "oidc_issuer", "oidc_subject", "disabled_at"} <= columns
        with engine.connect() as conn:
            # The query that used to fail, and the old row still there.
            rows = conn.execute(
                text("SELECT username, email, email_verified FROM users")
            ).all()
        assert rows[0][0] == "old"
        assert rows[0][1] is None
        # Every table now matches the models, not only the one we broke.
        inspector = inspect(engine)
        from api.db import models

        for table in models.Base.metadata.sorted_tables:
            present = {column["name"] for column in inspector.get_columns(table.name)}
            missing = {column.name for column in table.columns} - present
            assert not missing, (table.name, missing)
    finally:
        db_engine.reset_for_tests()


def test_boolean_defaults_are_added_as_integers_not_text(tmp_path) -> None:
    """``server_default="false"`` on a Boolean must not become ``DEFAULT 'false'``:
    SQLite would store the text, which reads back truthy."""
    url = f"sqlite:///{tmp_path / 'bool.db'}"
    old = create_engine(url, future=True)
    with old.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE vulnerabilities (vuln_id VARCHAR PRIMARY KEY, tenant_id VARCHAR NOT NULL, "
                "asset_id VARCHAR NOT NULL, severity VARCHAR NOT NULL, state VARCHAR NOT NULL, "
                "state_changed_at DATETIME NOT NULL, first_seen_at DATETIME NOT NULL, "
                "last_seen_at DATETIME NOT NULL, sla_started_at DATETIME NOT NULL, "
                "created_at DATETIME NOT NULL, updated_at DATETIME NOT NULL)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO vulnerabilities VALUES ('v1','t','a','high','OPEN','2026-01-01','2026-01-01',"
                "'2026-01-01','2026-01-01','2026-01-01','2026-01-01')"
            )
        )
    old.dispose()

    db_engine.reset_for_tests()
    try:
        engine = db_engine.get_engine(url)
        with engine.connect() as conn:
            value, kind = conn.execute(
                text("SELECT machine_verified, typeof(machine_verified) FROM vulnerabilities")
            ).one()
        assert (value, kind) == (0, "integer")
        from sqlalchemy.orm import Session

        from api.db import models

        with Session(engine) as session:
            row = session.get(models.Vulnerability, "v1")
            assert row is not None and row.machine_verified is False and row.in_kev is False
    finally:
        db_engine.reset_for_tests()


def test_a_fresh_sqlite_file_is_unchanged_by_the_repair(tmp_path) -> None:
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    db_engine.reset_for_tests()
    try:
        engine = db_engine.get_engine(url)
        assert "users" in inspect(engine).get_table_names()
    finally:
        db_engine.reset_for_tests()
