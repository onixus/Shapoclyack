"""The sizing harness against a real database: its guard and its purge (#337).

``scale_measure``'s writing commands VACUUM, seed tenants and — for ``api`` —
start an API in dev mode, which seeds the demo accounts. What keeps them off a
database somebody depends on is the SQL in ``foreign_tenants`` and the
``--i-own-database`` opt-in, so both are run here against a migrated Postgres
rather than monkeypatched away (review of #337, round 1).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import text

from api.db.engine import get_engine
from tests.conftest import POSTGRES_URL, make_settings, requires_postgres
from tests.fixtures import scale_measure, scale_seed

pytestmark = requires_postgres


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _current_database() -> str:
    with get_engine(POSTGRES_URL).connect() as conn:
        return str(conn.execute(text("SELECT current_database()")).scalar_one())


@pytest.fixture
def acme():
    """A production-shaped tenant: a row in ``tenants``, nothing scanned yet."""
    engine = get_engine(POSTGRES_URL)
    now = _now()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, status, created_at) "
                "VALUES ('acme-prod', 'Acme', 'active', :now) ON CONFLICT DO NOTHING"
            ),
            {"now": now},
        )
    yield engine, now
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM assets WHERE tenant_id = 'acme-prod'"))
        conn.execute(text("DELETE FROM tenants WHERE tenant_id = 'acme-prod'"))


def test_a_store_with_another_tenants_asset_is_refused(acme):
    engine, now = acme
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO assets (asset_id, tenant_id, status, first_seen, last_seen) "
                "VALUES ('acme-a1', 'acme-prod', 'active', :now, :now)"
            ),
            {"now": now},
        )
    assert "acme-prod" in scale_measure.foreign_tenants(POSTGRES_URL)


def test_a_production_install_before_its_first_scan_is_refused(acme):
    """Tenants (and users, schedules, sensors) but no assets yet: still somebody's."""
    assert "acme-prod" in scale_measure.foreign_tenants(POSTGRES_URL)


def test_the_default_tenant_is_refused_once_it_holds_work():
    """The API creates ``default`` on every start, so an empty one is the
    harness's too; a scan job in it is an operator's."""
    engine = get_engine(POSTGRES_URL)
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, created_at) VALUES ('default', 'Default', :now) "
                "ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"now": _now()},
        )
        conn.execute(
            text(
                "INSERT INTO jobs (job_id, tenant_id, command, scan_options, queued_at) "
                "VALUES ('sizing-guard-job', 'default', '[]', '{}', :now)"
            ),
            {"now": _now()},
        )
    try:
        assert "default (jobs)" in scale_measure.foreign_tenants(POSTGRES_URL)
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM jobs WHERE job_id = 'sizing-guard-job'"))


def test_console_accounts_not_seeded_by_dev_mode_are_refused():
    """An SSO-only or imported admin is a person, whatever the tenants hold."""
    engine = get_engine(POSTGRES_URL)
    now = _now()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, password_hash, role, created_at, updated_at, created_by) "
                "VALUES ('sizing-guard-admin', '', 'admin', :now, :now, 'import:OCTO_API_USERS')"
            ),
            {"now": now},
        )
    try:
        found = scale_measure.foreign_tenants(POSTGRES_URL)
        assert any(entry.startswith("users:") and "sizing-guard-admin" in entry for entry in found)
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM users WHERE username = 'sizing-guard-admin'"))


def test_the_harness_tenants_are_its_own():
    scale_seed._ensure_tenant(POSTGRES_URL, "sizing-guard")  # noqa: SLF001
    scale_seed.seed_postgres(POSTGRES_URL, scale_seed.SeedSpec(tenant_id="sizing-guard", assets=3))
    try:
        found = scale_measure.foreign_tenants(POSTGRES_URL)
        assert not any("sizing-guard" in entry for entry in found)
    finally:
        scale_measure.purge_harness_rows(POSTGRES_URL)


def test_writing_commands_need_the_database_named(monkeypatch, capsys, tmp_path):
    """The opt-in is bound to current_database(): a URL pasted from the wrong
    environment does not match the name the operator typed."""
    monkeypatch.setattr(scale_measure, "measure_postgres_tier", lambda *a, **k: {"measured": True})
    base = ["postgres", "--tiers", "10", "--work-dir", str(tmp_path / "w"), "--postgres-url", POSTGRES_URL]

    assert scale_measure.main(base) == 2
    assert "pass --i-own-database" in capsys.readouterr().err

    assert scale_measure.main([*base, "--i-own-database", "somebody-elses-db"]) == 2
    err = capsys.readouterr().err
    assert _current_database() in err and "somebody-elses-db" in err
    assert not (tmp_path / "w").exists()

    # The suite's database holds the tests' own tenants, so the data check is
    # waived here; the name still has to match.
    code = scale_measure.main(
        [*base, "--i-own-database", _current_database(), "--allow-shared-stores"]
    )
    assert code == 0
    assert '"measured": true' in capsys.readouterr().out


def test_purge_removes_every_harness_row_and_nothing_else():
    engine = get_engine(POSTGRES_URL)
    now = _now()
    scale_seed.seed_postgres(POSTGRES_URL, scale_seed.SeedSpec(tenant_id="sizing-purge", assets=5))
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, status, created_at) "
                "VALUES ('acme-keep', 'Acme', 'active', :now) ON CONFLICT DO NOTHING"
            ),
            {"now": now},
        )
        conn.execute(
            text(
                "INSERT INTO assets (asset_id, tenant_id, status, first_seen, last_seen) "
                "VALUES ('acme-keep-a1', 'acme-keep', 'active', :now, :now) ON CONFLICT DO NOTHING"
            ),
            {"now": now},
        )
    try:
        report = scale_measure.purge_harness_rows(POSTGRES_URL)
        assert report["tenants"] >= 1 and report["deleted"]["assets"] >= 5
        with engine.connect() as conn:
            for table in ("assets", "asset_identifiers", "tenants"):
                left = conn.execute(
                    text(f"SELECT count(*) FROM {table} WHERE tenant_id LIKE 'sizing-%'")
                ).scalar_one()
                assert left == 0, table
            kept = conn.execute(text("SELECT count(*) FROM assets WHERE tenant_id = 'acme-keep'")).scalar_one()
            assert kept == 1
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM assets WHERE tenant_id = 'acme-keep'"))
            conn.execute(text("DELETE FROM tenants WHERE tenant_id = 'acme-keep'"))


def test_purge_can_remove_the_dev_demo_accounts_and_only_those(tmp_path):
    from api.services import users

    engine = get_engine(POSTGRES_URL)
    now = _now()
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO users (username, password_hash, role, created_at, updated_at, created_by) "
                "VALUES ('sizing-demo-x', '', 'viewer', :now, :now, 'seed:dev'), "
                "('sizing-keep-x', '', 'viewer', :now, :now, 'import:OCTO_API_USERS') "
                "ON CONFLICT DO NOTHING"
            ),
            {"now": now},
        )
    try:
        report = scale_measure.purge_harness_rows(POSTGRES_URL, demo_accounts=True)
        assert report["demo_accounts"] >= 1
        with engine.connect() as conn:
            names = {row[0] for row in conn.execute(text("SELECT username FROM users"))}
        assert "sizing-demo-x" not in names and "sizing-keep-x" in names
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM users WHERE username IN ('sizing-demo-x', 'sizing-keep-x')"))
        # Put the suite's demo accounts back for the tests after this one.
        users._seed_dev_users(make_settings(tmp_path))  # noqa: SLF001
