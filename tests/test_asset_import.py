"""``POST /api/assets/import`` — a CMDB/AD export into the registry (#350).

Each test pins one promise the importer makes and the obvious implementation
breaks: a dry run that writes, an empty cell that clears, an IP in one tenant
that lands on another tenant's asset, a CMDB value silently replacing an
operator's hand edit, a file that matches two assets merging them.
"""

from __future__ import annotations

import json

from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_session
from api.services import asset_import
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


def test_a_scan_host_is_matched_by_its_identifier_not_duplicated(tmp_path, monkeypatch):
    """The row finds the asset the scan registered, by IP, and links the FQDN."""
    client, settings = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    assert _import(client, admin, "ip\n10.30.0.9\n").status_code == 200

    response = _import(client, admin, "ip,fqdn,team\n10.30.0.9,web.corp.example,web\n")

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
