"""``POST /api/assets/import`` — a CMDB/AD export into the registry (#350).

Each test pins one promise the importer makes and the obvious implementation
breaks: a dry run that writes, an empty cell that clears, an IP in one tenant
that lands on another tenant's asset, a CMDB value silently replacing an
operator's hand edit, a file that matches two assets merging them.
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path

import psycopg
import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError, OperationalError

from api.db import models
from api.db.engine import get_session, get_session_factory
from api.services import asset_import
from api.services import assets as assets_service
from api.services import quotas
from api.services import tenants as tenants_service
from scanner.pipeline.asset_identity import fqdn_identity_key, ip_identity_key
from tests.conftest import auth_headers, configured_client, login, make_settings, requires_postgres

pytestmark = requires_postgres

_URL = "/api/assets/import"
DEFAULT = "default"

_CSV = (
    "ip,fqdn,owner_email,team,criticality,environment,exposure,tag:cmdb_ci\n"
    "10.20.0.1,app1.corp.example,ada@example.com,payments,4,production,internet,CI0001\n"
    "10.20.0.2,,bob@example.com,ops,2,staging,internal,CI0002\n"
    ",db.corp.example,carol@example.com,dba,3,production,internal,CI0003\n"
)


def _client(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    return client, settings


def _import(client, headers, content, *, format="csv", dry_run=False, params=None, **extra):
    return client.post(
        _URL,
        headers=headers,
        params=params or {},
        json={"format": format, "content": content, "dry_run": dry_run, **extra},
    )


def _count(settings, model) -> int:
    with get_session(settings.postgres_url) as session:
        return session.execute(select(func.count()).select_from(model)).scalar_one()


def _asset(settings, asset_id: str) -> dict:
    with get_session(settings.postgres_url) as session:
        asset = session.get(models.Asset, asset_id)
        assert asset is not None, asset_id
        tags = session.execute(
            select(models.AssetTag).where(models.AssetTag.asset_id == asset_id)
        ).scalars().all()
        return {
            "tenant_id": asset.tenant_id,
            "owner_email": asset.owner_email,
            "business_unit": asset.business_unit,
            "business_service": asset.business_service,
            "asset_criticality": asset.asset_criticality,
            "environment": asset.environment,
            "exposure_level": asset.exposure_level,
            "context_source": asset.context_source,
            "last_scanned_at": asset.last_scanned_at,
            "tags": {tag.key: tag.value for tag in tags},
        }


def _audit_rows(settings) -> list[dict]:
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.AuditEvent).where(models.AuditEvent.action == "asset.import")
        ).scalars().all()
        return [{"tenant_id": row.tenant_id, "after": dict(row.after or {})} for row in rows]


def _statuses(report: dict) -> list[tuple[int, str, str | None]]:
    return [(row["row"], row["status"], row["code"]) for row in report["rows"]]


def test_a_dry_run_reports_the_plan_and_writes_nothing(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    before = {
        model: _count(settings, model)
        for model in (
            models.Asset,
            models.AssetIdentifier,
            models.AssetTag,
            models.AssetContextEvent,
            models.AuditEvent,
        )
    }

    # The default is a dry run: applying is the explicit act.
    response = client.post(
        _URL, headers=auth_headers(client, "admin"), json={"format": "csv", "content": _CSV}
    )

    assert response.status_code == 200, response.text
    report = response.json()
    assert report["dry_run"] is True
    assert report["counts"] == {"create": 3, "update": 0, "unchanged": 0, "conflict": 0, "invalid": 0}
    first = report["rows"][0]
    assert first["asset_id"] == ip_identity_key(DEFAULT, "10.20.0.1")
    assert first["changes"]["owner_email"] == {"old": None, "new": "ada@example.com"}
    assert first["changes"]["tag:cmdb_ci"] == {"old": None, "new": "CI0001"}
    assert first["identifiers_added"] == ["ip:10.20.0.1", "fqdn:app1.corp.example"]
    after = {model: _count(settings, model) for model in before}
    assert after == before


def test_an_apply_registers_assets_under_the_scan_identity_and_a_repeat_is_unchanged(
    tmp_path, monkeypatch
):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    applied = _import(client, admin, _CSV)

    assert applied.status_code == 200, applied.text
    assert applied.json()["counts"]["create"] == 3
    # The id a scan would have given the host, so the first scan that reaches
    # it lands on this row instead of opening a second one.
    ip_only = _asset(settings, ip_identity_key(DEFAULT, "10.20.0.2"))
    assert ip_only["owner_email"] == "bob@example.com"
    assert ip_only["asset_criticality"] == 2
    assert ip_only["context_source"] == "cmdb"
    assert ip_only["tags"] == {"cmdb_ci": "CI0002"}
    # Registered, not scanned: coverage stays unknown.
    assert ip_only["last_scanned_at"] is None
    name_only = _asset(settings, fqdn_identity_key(DEFAULT, "db.corp.example"))
    assert name_only["business_unit"] == "dba"
    with get_session(settings.postgres_url) as session:
        sources = set(
            session.execute(select(models.AssetContextEvent.source)).scalars().all()
        )
    assert sources == {"cmdb"}
    rows = _audit_rows(settings)
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == DEFAULT
    assert rows[0]["after"]["counts"]["create"] == 3
    assert len(rows[0]["after"]["created"]) == 3
    events_after_first = _count(settings, models.AssetContextEvent)

    again = _import(client, admin, _CSV)

    assert again.status_code == 200, again.text
    assert again.json()["counts"]["unchanged"] == 3
    assert _count(settings, models.Asset) == 3
    assert _count(settings, models.AssetContextEvent) == events_after_first


def test_a_row_finds_its_asset_by_a_registered_identifier_and_links_on_request(
    tmp_path, monkeypatch
):
    """The row finds the registered asset by IP and, asked to, links the FQDN.
    (The scan side of the same promise is
    ``test_the_first_scan_lands_on_the_imported_asset``.)"""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.30.0.9\n").status_code == 200

    response = _import(
        client, admin, "ip,fqdn,team\n10.30.0.9,web.corp.example,web\n", link_new_identifiers=True
    )

    report = response.json()
    assert _statuses(report) == [(1, "update", None)]
    assert report["rows"][0]["identifiers_added"] == ["fqdn:web.corp.example"]
    assert _count(settings, models.Asset) == 1
    # And the FQDN alone now finds it.
    by_name = _import(client, admin, "fqdn,team\nweb.corp.example,web\n").json()
    assert _statuses(by_name) == [(1, "unchanged", None)]


def test_absent_and_empty_cells_never_clear_a_field(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, _CSV).status_code == 200
    asset_id = ip_identity_key(DEFAULT, "10.20.0.1")

    # A narrower export: one column of context, and an empty owner cell.
    narrow = _import(client, admin, "ip,owner_email,service\n10.20.0.1,,checkout\n")
    # And a JSON exporter that writes null for whatever it does not know.
    nulls = _import(
        client,
        admin,
        json.dumps([{"ip": "10.20.0.1", "owner_email": None, "criticality": None, "tags": None}]),
        format="json",
    )

    assert narrow.json()["rows"][0]["changes"] == {
        "business_service": {"old": None, "new": "checkout"}
    }
    assert _statuses(nulls.json()) == [(1, "unchanged", None)]
    asset = _asset(settings, asset_id)
    assert asset["owner_email"] == "ada@example.com"
    assert asset["business_unit"] == "payments"
    assert asset["asset_criticality"] == 4
    assert asset["environment"] == "production"
    assert asset["tags"] == {"cmdb_ci": "CI0001"}
    assert asset["business_service"] == "checkout"


def test_the_same_ip_in_two_tenants_is_two_assets(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    tenants_service.create_tenant(tenant_id="globex", name="Globex")
    admin = auth_headers(client, "admin")

    first = _import(client, admin, "ip,team\n10.0.0.5,acme-ops\n", params={"tenant_id": DEFAULT})
    second = _import(client, admin, "ip,team\n10.0.0.5,globex-ops\n", params={"tenant_id": "globex"})

    # The second tenant does not "update" the first tenant's asset.
    assert _statuses(first.json()) == [(1, "create", None)]
    assert _statuses(second.json()) == [(1, "create", None)]
    mine = _asset(settings, ip_identity_key(DEFAULT, "10.0.0.5"))
    theirs = _asset(settings, ip_identity_key("globex", "10.0.0.5"))
    assert (mine["tenant_id"], mine["business_unit"]) == (DEFAULT, "acme-ops")
    assert (theirs["tenant_id"], theirs["business_unit"]) == ("globex", "globex-ops")
    # Each tenant's trail has its own row.
    assert sorted(row["tenant_id"] for row in _audit_rows(settings)) == [DEFAULT, "globex"]


def test_a_tenant_admin_imports_into_its_own_tenant_only(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    tenants_service.create_tenant(tenant_id="acme", name="Acme")
    tenants_service.create_tenant(tenant_id="globex", name="Globex")
    admin = auth_headers(client, "admin")
    password = "acme-boss-password-1234"
    assert client.post(
        "/api/users",
        headers=admin,
        json={"username": "acme-boss", "password": password, "role": "viewer"},
    ).status_code == 201
    assert client.put(
        "/api/tenants/acme/members/acme-boss", headers=admin, json={"role": "admin"}
    ).status_code == 200
    boss = {"Authorization": f"Bearer {login(client, 'acme-boss', password)}"}

    mine = _import(client, boss, "ip\n10.0.0.7\n", params={"tenant_id": "acme"})
    theirs = _import(client, boss, "ip\n10.0.0.7\n", params={"tenant_id": "globex"})

    assert mine.status_code == 200, mine.text
    assert theirs.status_code == 403
    assert _asset(settings, ip_identity_key("acme", "10.0.0.7"))["tenant_id"] == "acme"
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, ip_identity_key("globex", "10.0.0.7")) is None


def test_the_operator_and_viewer_cannot_import(tmp_path, monkeypatch):
    """``asset.import`` is the tenant admin's: an import spends the asset quota."""
    client, _ = _client(tmp_path, monkeypatch)
    for role in ("viewer", "operator"):
        refused = _import(client, auth_headers(client, role), "ip\n10.0.0.8\n", dry_run=True)
        assert refused.status_code == 403
        assert "asset.import" in refused.json()["detail"]


def test_conflicts_are_reported_and_never_merge_or_steal(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    seeded = _import(client, admin, "ip\n10.40.0.1\n10.40.0.2\n").json()
    first_id, second_id = (row["asset_id"] for row in seeded["rows"])
    assert _import(client, admin, "fqdn\nonly-name.corp.example\n").status_code == 200
    events_before = _count(settings, models.AssetContextEvent)

    content = (
        "asset_id,ip,fqdn,team\n"
        # The IP is one asset, the name another: an import never merges.
        ",10.40.0.1,only-name.corp.example,x\n"
        # Names the first asset, with the second asset's address.
        f"{first_id},10.40.0.2,,y\n"
        # Two rows for one asset: the second is not applied over the first.
        ",10.40.0.2,,a\n"
        ",10.40.0.2,,b\n"
        # An id that is not in this tenant.
        "deadbeef,,,z\n"
        # Not an address.
        ",10.40.0.300,,z\n"
    )
    report = _import(client, admin, content).json()

    assert _statuses(report) == [
        (1, "conflict", "ambiguous_match"),
        (2, "conflict", "identifier_owned_by_other_asset"),
        (3, "update", None),
        (4, "conflict", "duplicate_in_file"),
        (5, "invalid", "unknown_asset"),
        (6, "invalid", "invalid_value"),
    ]
    assert second_id in report["rows"][1]["message"]
    assert _count(settings, models.Asset) == 3
    assert _asset(settings, first_id)["business_unit"] is None
    assert _asset(settings, second_id)["business_unit"] == "a"
    # Only the one applied row wrote history.
    assert _count(settings, models.AssetContextEvent) == events_before + 1


def test_an_operators_hand_edit_wins_unless_the_import_says_otherwise(tmp_path, monkeypatch):
    """The precedence policy: a field an operator last set is not overwritten."""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip,owner,team\n10.50.0.1,cmdb@example.com,ops\n").status_code == 200
    asset_id = ip_identity_key(DEFAULT, "10.50.0.1")
    patched = client.patch(
        f"/api/assets/{asset_id}",
        headers=auth_headers(client, "operator"),
        json={"owner_email": "hand@example.com"},
    )
    assert patched.status_code == 200, patched.text

    # The CMDB still says cmdb@ for the owner and now says "platform" for the
    # team, which nobody touched by hand.
    sync = "ip,owner,team\n10.50.0.1,cmdb@example.com,platform\n"
    refused = _import(client, admin, sync).json()

    row = refused["rows"][0]
    assert (row["status"], row["code"]) == ("conflict", "operator_override")
    assert row["conflicting_fields"] == ["owner_email"]
    # Whole row or nothing: the unprotected team change was not applied either.
    assert _asset(settings, asset_id)["business_unit"] == "ops"
    assert _asset(settings, asset_id)["owner_email"] == "hand@example.com"

    forced = _import(client, admin, sync, overwrite_operator_edits=True).json()

    assert _statuses(forced) == [(1, "update", None)]
    asset = _asset(settings, asset_id)
    assert (asset["owner_email"], asset["business_unit"]) == ("cmdb@example.com", "platform")
    assert asset["context_source"] == "cmdb"
    # Overwritten by the CMDB, the field is the CMDB's again: the next sync
    # that disagrees updates it without the flag.
    later = _import(client, admin, "ip,owner\n10.50.0.1,next@example.com\n").json()
    assert _statuses(later) == [(1, "update", None)]


def test_a_value_with_no_history_on_a_hand_edited_asset_is_protected(tmp_path, monkeypatch):
    """Context set before #146 audited it has no event; it is not up for grabs."""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.60.0.1\n").status_code == 200
    asset_id = ip_identity_key(DEFAULT, "10.60.0.1")
    with get_session(settings.postgres_url) as session:
        asset = session.get(models.Asset, asset_id)
        asset.owner_email = "legacy@example.com"
        asset.context_source = None

    report = _import(client, admin, "ip,owner\n10.60.0.1,cmdb@example.com\n").json()

    assert _statuses(report) == [(1, "conflict", "operator_override")]


def test_csv_from_excel_bom_semicolons_and_formula_cells(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    content = (
        "﻿IP;Owner Email;Business Unit;Unknown Column\n"
        "10.70.0.1;ivanov@example.ru;Бухгалтерия;whatever\n"
        "10.70.0.2;ok@example.ru;=HYPERLINK(\"http://x\");\n"
    )

    report = _import(client, admin, content).json()

    assert report["ignored_columns"] == ["unknown_column"]
    assert _statuses(report) == [(1, "create", None), (2, "invalid", "invalid_value")]
    assert "formula" in report["rows"][1]["message"]
    assert _asset(settings, ip_identity_key(DEFAULT, "10.70.0.1"))["business_unit"] == "Бухгалтерия"
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, ip_identity_key(DEFAULT, "10.70.0.2")) is None


def test_a_file_decoded_in_the_wrong_charset_is_refused_whole(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    garbled = _import(client, admin, "ip,team\n10.80.0.1,��\n")
    unreadable = _import(client, admin, "{not json", format="json")
    no_rows = _import(client, admin, json.dumps({"hosts": []}), format="json")

    assert garbled.status_code == 422
    assert "U+FFFD" in garbled.json()["detail"]
    assert unreadable.status_code == 422
    assert no_rows.status_code == 422
    assert _count(settings, models.Asset) == 0


def test_the_size_and_row_ceilings(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    monkeypatch.setattr(asset_import, "MAX_ROWS", 3)
    rows = "ip\n" + "".join(f"10.90.0.{n}\n" for n in range(1, 5))

    too_many = _import(client, admin, rows)
    too_many_json = _import(
        client, admin, json.dumps([{"ip": f"10.90.1.{n}"} for n in range(1, 5)]), format="json"
    )
    monkeypatch.setattr(asset_import, "MAX_BYTES", 16)
    too_big = _import(client, admin, "ip\n10.90.0.1\n10.90.0.2\n")

    assert too_many.status_code == 413
    assert too_many_json.status_code == 413
    assert too_big.status_code == 413
    assert _count(settings, models.Asset) == 0


def test_the_asset_quota_refuses_new_assets_and_still_updates_known_ones(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.95.0.1\n").status_code == 200
    quotas.set_quota(settings, DEFAULT, max_assets=2, max_scans_per_month=None, updated_by="tests")

    report = _import(
        client, admin, "ip,team\n10.95.0.1,known\n10.95.0.2,new\n10.95.0.3,over\n"
    ).json()

    assert _statuses(report) == [
        (1, "update", None),
        (2, "create", None),
        (3, "conflict", "quota_exhausted"),
    ]
    assert _count(settings, models.Asset) == 2


def test_an_apply_retried_with_its_key_replays_instead_of_reapplying(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = {**auth_headers(client, "admin"), "Idempotency-Key": "cmdb-nightly-1"}

    first = _import(client, admin, _CSV)
    retry = _import(client, admin, _CSV)
    other = _import(client, admin, "ip\n10.99.0.1\n")

    assert first.status_code == 200
    assert retry.status_code == 200
    # The retry is the first answer — "create" three times — not a fresh run
    # that would report "unchanged".
    assert retry.json()["replayed"] is True
    assert retry.json()["counts"]["create"] == 3
    assert other.status_code == 409
    assert len(_audit_rows(settings)) == 1


# --- Concurrency: what the apply holds, and against whom (#502 review) -------


def _service_import(settings, content, **overrides):
    kwargs = {
        "tenant_id": DEFAULT,
        "content": content,
        "format": "csv",
        "dry_run": False,
        "context_source": "cmdb",
        "overwrite_operator_edits": False,
        "actor": "tests",
    }
    kwargs.update(overrides)
    return asset_import.run_import(settings, **kwargs)


def _in_thread(target) -> tuple[threading.Thread, dict]:
    out: dict = {}

    def run():
        try:
            out["result"] = target()
        except Exception as exc:  # noqa: BLE001 - the test asserts on it
            out["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, out


def _raw_session(settings):
    """A second connection, outside the import's transaction, that the test
    commits or rolls back itself."""
    return get_session_factory(settings.postgres_url)()


def _wait_for_lock_waiters(settings, count: int = 1, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with get_session(settings.postgres_url) as session:
            waiting = session.execute(
                text(
                    "SELECT count(*) FROM pg_stat_activity "
                    "WHERE datname = current_database() AND wait_event_type = 'Lock'"
                )
            ).scalar_one()
        if waiting >= count:
            return
        time.sleep(0.05)
    raise AssertionError(f"expected {count} backend(s) waiting on a lock")


def _pause_first_apply(monkeypatch) -> tuple[threading.Event, threading.Event]:
    """Stop the first apply after it planned — every lock it takes is held."""
    holding, release = threading.Event(), threading.Event()
    real_apply = asset_import._apply
    calls = []

    def paused(session, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            holding.set()
            assert release.wait(20), "the test never released the apply"
        return real_apply(session, **kwargs)

    monkeypatch.setattr(asset_import, "_apply", paused)
    return holding, release


def test_an_apply_in_flight_does_not_block_writers_that_reference_the_tenant(
    tmp_path, monkeypatch
):
    """A row lock on ``tenants`` conflicts with the FK check of every insert
    that references the tenant — new assets, jobs, findings, sensors. The
    import must serialise against other imports, not against the tenant."""
    client, settings = _client(tmp_path, monkeypatch)
    _service_import(settings, "ip\n10.110.0.1\n")
    holding, release = _pause_first_apply(monkeypatch)
    thread, out = _in_thread(lambda: _service_import(settings, "ip,team\n10.110.0.1,x\n"))
    try:
        assert holding.wait(15)
        scan = _raw_session(settings)
        try:
            scan.execute(text("SET LOCAL lock_timeout = '3s'"))
            scan.execute(
                text(
                    "INSERT INTO assets (asset_id, tenant_id, status, first_seen, last_seen) "
                    "VALUES ('scan-asset-1', :tenant, 'active', now(), now())"
                ),
                {"tenant": DEFAULT},
            )
            scan.commit()
        finally:
            scan.close()
    finally:
        release.set()
        thread.join(20)
    assert "error" not in out, out
    assert out["result"]["counts"]["update"] == 1


def test_an_apply_holds_its_asset_rows_and_a_second_import_waits_for_it(
    tmp_path, monkeypatch
):
    client, settings = _client(tmp_path, monkeypatch)
    _service_import(settings, "ip\n10.111.0.1\n")
    known = ip_identity_key(DEFAULT, "10.111.0.1")
    holding, release = _pause_first_apply(monkeypatch)
    content = "ip,team\n10.111.0.1,a\n10.111.0.2,a\n"
    first, first_out = _in_thread(lambda: _service_import(settings, content))
    second = None
    try:
        assert holding.wait(15)
        # The planned rows are locked until the commit: a writer cannot change
        # an asset between the plan that read it and the apply that writes it.
        probe = _raw_session(settings)
        try:
            with pytest.raises(OperationalError):
                probe.execute(
                    text("SELECT asset_id FROM assets WHERE asset_id = :id FOR UPDATE NOWAIT"),
                    {"id": known},
                )
        finally:
            probe.rollback()
            probe.close()
        # Same file again: it must plan after the first one commits, or both
        # plan "create" for 10.111.0.2 and the second dies on the primary key.
        second, second_out = _in_thread(lambda: _service_import(settings, content))
        time.sleep(0.5)
        assert second.is_alive(), "a second import of the tenant did not wait for the first"
    finally:
        release.set()
        first.join(20)
        if second is not None:
            second.join(20)
    assert "error" not in first_out, first_out
    assert first_out["result"]["counts"] == {
        "create": 1, "update": 1, "unchanged": 0, "conflict": 0, "invalid": 0,
    }
    assert "error" not in second_out, second_out
    assert second_out["result"]["counts"]["unchanged"] == 2


def test_an_apply_waiting_on_a_scan_does_not_deadlock_it(tmp_path, monkeypatch):
    """The scan updated a known asset, the import waits for that row, the scan
    then registers a new asset of the same tenant. With the tenant row locked
    by the import this was a deadlock, and the scan — whose asset upsert is
    best effort and never retried — could be the victim."""
    client, settings = _client(tmp_path, monkeypatch)
    _service_import(settings, "ip\n10.112.0.1\n")
    known = ip_identity_key(DEFAULT, "10.112.0.1")
    scan = _raw_session(settings)
    thread = None
    try:
        scan.execute(
            text("UPDATE assets SET last_seen = now() WHERE asset_id = :id"), {"id": known}
        )
        thread, out = _in_thread(lambda: _service_import(settings, "ip,team\n10.112.0.1,x\n"))
        _wait_for_lock_waiters(settings)
        scan.execute(
            text(
                "INSERT INTO assets (asset_id, tenant_id, status, first_seen, last_seen) "
                "VALUES ('scan-asset-2', :tenant, 'active', now(), now())"
            ),
            {"tenant": DEFAULT},
        )
        scan.commit()
    finally:
        scan.close()
        if thread is not None:
            thread.join(20)
    assert "error" not in out, out
    assert out["result"]["counts"]["update"] == 1
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, "scan-asset-2") is not None


def test_scan_ingest_locks_known_assets_in_id_order(tmp_path, monkeypatch):
    """The ingest and the import lock asset rows in one order, so neither can
    hold a row the other already waits behind. Here the run lists the larger
    id first; a row lock on the smaller one must stop the ingest *before* it
    takes the larger one."""
    client, settings = _client(tmp_path, monkeypatch)
    by_id = sorted(
        (ip_identity_key(DEFAULT, f"10.113.0.{n}"), f"10.113.0.{n}") for n in range(1, 4)
    )
    (low_id, low_ip), _, (high_id, high_ip) = by_id
    _service_import(settings, f"ip\n{low_ip}\n{high_ip}\n")
    _write_run(settings, "run-order", [{"host": high_ip}, {"host": low_ip}])
    holder = _raw_session(settings)
    thread = None
    try:
        holder.execute(
            text("SELECT asset_id FROM assets WHERE asset_id = :id FOR UPDATE"), {"id": low_id}
        )
        thread, out = _in_thread(
            lambda: assets_service.upsert_assets_from_run(
                settings, tenant_id=DEFAULT, run_id="run-order"
            )
        )
        _wait_for_lock_waiters(settings)
        probe = _raw_session(settings)
        try:
            probe.execute(
                text("SELECT asset_id FROM assets WHERE asset_id = :id FOR UPDATE NOWAIT"),
                {"id": high_id},
            )
        finally:
            probe.rollback()
            probe.close()
    finally:
        holder.rollback()
        holder.close()
        if thread is not None:
            thread.join(20)
    assert "error" not in out, out
    assert out["result"].assets_updated == 2


def test_a_deadlock_is_retried_and_a_persistent_one_is_409_not_500(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    real_plan = asset_import.plan
    failures = {"left": 1}

    def deadlocking(session, settings_, **kwargs):
        if failures["left"]:
            failures["left"] -= 1
            raise OperationalError("SELECT 1", {}, psycopg.errors.DeadlockDetected("deadlock"))
        return real_plan(session, settings_, **kwargs)

    monkeypatch.setattr(asset_import, "plan", deadlocking)

    retried = _import(client, admin, "ip\n10.114.0.1\n")

    assert retried.status_code == 200, retried.text
    assert retried.json()["counts"]["create"] == 1

    failures["left"] = 100
    keyed = {**admin, "Idempotency-Key": "deadlock-1"}
    refused = _import(client, keyed, "ip\n10.114.0.2\n")

    assert refused.status_code == 409, refused.text
    failures["left"] = 0
    # Nothing was applied, and the key was given back.
    assert _import(client, keyed, "ip\n10.114.0.2\n").json()["counts"]["create"] == 1


def test_an_identifier_registered_mid_import_is_409_and_nothing_applies(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = {**auth_headers(client, "admin"), "Idempotency-Key": "race-1"}
    racing_id = ip_identity_key(DEFAULT, "10.115.0.2")
    real_plan = asset_import.plan

    def plan_then_lose_the_race(session, settings_, **kwargs):
        result = real_plan(session, settings_, **kwargs)
        with get_session(settings.postgres_url) as other:
            # Bounded: an import that locked the tenant row would make this
            # insert wait on its own caller forever.
            other.execute(text("SET LOCAL lock_timeout = '5s'"))
            other.add(
                models.Asset(
                    asset_id=racing_id, tenant_id=DEFAULT, status="active",
                    first_seen=datetime(2026, 1, 1), last_seen=datetime(2026, 1, 1),
                )
            )
            other.flush()
            other.add(
                models.AssetIdentifier(
                    asset_id=racing_id, tenant_id=DEFAULT,
                    identifier_type="ip", identifier_value="10.115.0.2",
                )
            )
        return result

    monkeypatch.setattr(asset_import, "plan", plan_then_lose_the_race)
    raced = _import(client, admin, "ip,team\n10.115.0.1,a\n10.115.0.2,a\n")

    assert raced.status_code == 409, raced.text
    assert "registered" in raced.json()["detail"]
    with get_session(settings.postgres_url) as session:
        assert session.get(models.Asset, ip_identity_key(DEFAULT, "10.115.0.1")) is None
    monkeypatch.setattr(asset_import, "plan", real_plan)
    # The key went back with the 409: the same file under it is a fresh run.
    again = _import(client, admin, "ip,team\n10.115.0.1,a\n10.115.0.2,a\n")
    assert again.status_code == 200, again.text
    assert again.json()["replayed"] is False


def test_an_integrity_error_that_is_not_an_identity_race_is_not_a_409(tmp_path, monkeypatch):
    """409 tells the client "send it again"; a bug would fail the same way
    forever, so it must stay a 500."""
    client, settings = _client(tmp_path, monkeypatch)
    real_apply = asset_import._apply

    def broken_apply(session, **kwargs):
        real_apply(session, **kwargs)
        session.add(models.AssetTag(asset_id="no-such-asset", key="k", value="v"))

    monkeypatch.setattr(asset_import, "_apply", broken_apply)

    with pytest.raises(IntegrityError):
        _service_import(settings, "ip\n10.116.0.1\n")


# --- Identity and normalisation ----------------------------------------------


def _write_run(settings, run_id: str, hosts: list[dict]) -> None:
    run_dir = Path(settings.output_dir) / "runs" / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "alive_hosts.json").write_text(json.dumps(hosts))


def _identifiers(settings) -> set[tuple[str, str, str]]:
    with get_session(settings.postgres_url) as session:
        return {
            (row.asset_id, row.identifier_type, row.identifier_value)
            for row in session.execute(select(models.AssetIdentifier)).scalars()
        }


def test_the_first_scan_lands_on_the_imported_asset(tmp_path, monkeypatch):
    """Through the real scan ingest, with the spellings a CMDB writes: an
    IPv6 address not in canonical form and an FQDN upper-cased with the root
    dot. Normalised on the way in, they are the identifiers a scan reports."""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    imported = _import(client, admin, "ip,fqdn\n2001:DB8:0:0::1,\n,Web.Example.COM.\n")
    assert imported.status_code == 200, imported.text
    v6_id = ip_identity_key(DEFAULT, "2001:db8::1")
    web_id = fqdn_identity_key(DEFAULT, "web.example.com")
    assert [row["asset_id"] for row in imported.json()["rows"]] == [v6_id, web_id]

    _write_run(
        settings,
        "run-after-import",
        [{"host": "2001:db8::1"}, {"host": "10.117.0.2", "hostname": "web.example.com"}],
    )
    stats = assets_service.upsert_assets_from_run(
        settings, tenant_id=DEFAULT, run_id="run-after-import"
    )

    assert (stats.assets_created, stats.assets_updated) == (0, 2)
    assert _count(settings, models.Asset) == 2
    assert _identifiers(settings) == {
        (v6_id, "ip", "2001:db8::1"),
        (web_id, "fqdn", "web.example.com"),
        (web_id, "ip", "10.117.0.2"),
    }


def test_a_registered_ip_is_not_linked_to_a_new_name_without_the_flag(tmp_path, monkeypatch):
    """A VIP that yesterday's export paired with a.corp and today's with
    b.corp must not quietly make b.corp an identifier of a.corp's asset: the
    scan of b.corp would then land there. Linking is an explicit opt-in."""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip,fqdn\n10.118.0.1,a.corp.example\n").status_code == 200
    asset_id = ip_identity_key(DEFAULT, "10.118.0.1")
    before = _identifiers(settings)

    refused = _import(client, admin, "ip,fqdn,team\n10.118.0.1,b.corp.example,x\n").json()

    assert _statuses(refused) == [(1, "conflict", "new_identifier")]
    assert refused["rows"][0]["conflicting_fields"] == ["fqdn:b.corp.example"]
    assert _identifiers(settings) == before
    assert _asset(settings, asset_id)["business_unit"] is None

    linked = _import(
        client, admin, "ip,fqdn,team\n10.118.0.1,b.corp.example,x\n", link_new_identifiers=True
    ).json()

    assert _statuses(linked) == [(1, "update", None)]
    assert linked["rows"][0]["identifiers_added"] == ["fqdn:b.corp.example"]
    assert (asset_id, "fqdn", "b.corp.example") in _identifiers(settings)


def test_an_asset_under_its_scan_id_without_its_identifier_is_updated(tmp_path, monkeypatch):
    """The asset carries the id a scan would give the row's IP, but its
    identifier row is gone (an identity merge moved it). The import updates
    that asset — creating a second one under the same id cannot work."""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.119.0.1\n").status_code == 200
    asset_id = ip_identity_key(DEFAULT, "10.119.0.1")
    with get_session(settings.postgres_url) as session:
        session.execute(delete(models.AssetIdentifier))

    report = _import(client, admin, "ip,team\n10.119.0.1,ops\n")

    assert report.status_code == 200, report.text
    assert _statuses(report.json()) == [(1, "update", None)]
    assert _asset(settings, asset_id)["business_unit"] == "ops"
    # Its own identity key, so restoring the identifier is not a new link.
    assert _identifiers(settings) == {(asset_id, "ip", "10.119.0.1")}


def test_an_import_never_reads_another_tenants_asset(tmp_path, monkeypatch):
    """Called below the route, where no tenant scope narrows the session: the
    service's own ``tenant_id`` predicate is what keeps globex's asset out."""
    client, settings = _client(tmp_path, monkeypatch)
    tenants_service.create_tenant(tenant_id="globex", name="Globex")
    _service_import(settings, "ip,team\n10.120.0.1,globex-ops\n", tenant_id="globex")
    theirs = ip_identity_key("globex", "10.120.0.1")

    report = _service_import(settings, f"asset_id,team\n{theirs},mine\n")

    assert _statuses(report) == [(1, "invalid", "unknown_asset")]
    assert _asset(settings, theirs)["business_unit"] == "globex-ops"


# --- Precedence, per field ----------------------------------------------------


def _forget_history(settings, asset_id: str, **values) -> None:
    """The asset as a pre-#146 database left it: values, no events."""
    with get_session(settings.postgres_url) as session:
        asset = session.get(models.Asset, asset_id)
        for name, value in values.items():
            setattr(asset, name, value)
        session.execute(
            delete(models.AssetContextEvent).where(models.AssetContextEvent.asset_id == asset_id)
        )


def test_an_unrelated_import_does_not_unprotect_a_value_with_no_history(tmp_path, monkeypatch):
    """The asset-wide ``context_source`` is the import's own output: once any
    field of the asset was imported it says ``cmdb``, and the hand value next
    to it must not become the next import's to overwrite."""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.121.0.1\n").status_code == 200
    asset_id = ip_identity_key(DEFAULT, "10.121.0.1")
    _forget_history(settings, asset_id, business_unit="legacy-hand", context_source=None)

    # Fills a field that was empty: nobody's value is replaced.
    first = _import(client, admin, "ip,owner\n10.121.0.1,cmdb@example.com\n").json()
    second = _import(client, admin, "ip,team\n10.121.0.1,cmdb-team\n").json()

    assert _statuses(first) == [(1, "update", None)]
    assert _statuses(second) == [(1, "conflict", "operator_override")]
    assert second["rows"][0]["conflicting_fields"] == ["business_unit"]
    assert _asset(settings, asset_id)["business_unit"] == "legacy-hand"


def test_a_value_with_no_history_is_protected_whatever_the_asset_source_says(
    tmp_path, monkeypatch
):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.122.0.1\n").status_code == 200
    asset_id = ip_identity_key(DEFAULT, "10.122.0.1")
    _forget_history(settings, asset_id, owner_email="legacy@example.com", context_source="cmdb")

    report = _import(client, admin, "ip,owner\n10.122.0.1,cmdb@example.com\n").json()

    assert _statuses(report) == [(1, "conflict", "operator_override")]


# --- File hygiene -------------------------------------------------------------


def test_formula_tags_repeated_columns_and_nul_bytes(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    formula_tag = _import(client, admin, "ip,tag:ci\n10.123.0.1,=cmd|' /C calc'!A0\n").json()
    repeated = _import(client, admin, "ip,IP Address\n10.123.0.2,10.123.0.3\n")
    nul = _import(client, admin, "ip,team\n10.123.0.4,o\x00ps\n")

    assert _statuses(formula_tag) == [(1, "invalid", "invalid_value")]
    assert "formula" in formula_tag["rows"][0]["message"]
    assert repeated.status_code == 422
    assert "twice" in repeated.json()["detail"]
    assert nul.status_code == 422
    assert "NUL" in nul.json()["detail"]
    assert _count(settings, models.Asset) == 0


def test_an_apply_that_changed_nothing_gives_its_key_back(tmp_path, monkeypatch):
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.124.0.1\n").status_code == 200
    keyed = {**admin, "Idempotency-Key": "noop-1"}

    noop = _import(client, keyed, "ip\n10.124.0.1\n")
    different = _import(client, keyed, "ip\n10.124.0.2\n")

    assert noop.json()["counts"]["unchanged"] == 1
    # Not "409 key held for another request": the no-op stored nothing.
    assert different.status_code == 200, different.text
    assert different.json()["counts"]["create"] == 1
