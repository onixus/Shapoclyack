"""Data-subject requests for console accounts: export and erasure (#332).

The audit trail is append-only (#329) and names actors by username, so an
erasure cannot remove the name — it removes everything that ties the name to a
person, and keeps the name as a tombstone so it is never issued to somebody
else. These tests pin both halves: what goes (address, IdP identity, second
factor, sessions, memberships, the address on report schedules) and what stays
(the trail, pointing at the same pseudonym), plus the guard rails around it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import data_subject, legal_hold
from api.services import users as users_service
from tests.conftest import (
    auth_headers,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)
from tests.test_api_mfa import Clock, enrol

pytestmark = requires_postgres

EMAIL = "dana.scully@example.test"
PASSWORD = "dana-password-1234"


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = auth_headers(client, "admin")
    yield client, settings, admin
    # A hold left behind would make the next test's tenant reset fail.
    with get_session(settings.postgres_url) as session:
        session.query(models.TenantLegalHold).delete()


def _dana(client, admin) -> dict[str, str]:
    """An account with something in every section: an address, a membership in
    which it administers, a session, a sign-in, and a change of its own."""
    created = client.post(
        "/api/users",
        headers=admin,
        json={"username": "dana", "password": PASSWORD, "role": "viewer", "email": EMAIL},
    )
    assert created.status_code == 201, created.text
    granted = client.put(
        "/api/tenants/default/members/dana", headers=admin, json={"role": "admin"}
    )
    assert granted.status_code == 200, granted.text
    headers = bearer(login(client, "dana", PASSWORD))
    changed = client.put(
        "/api/tenants/default/retention",
        headers=headers,
        json={"overrides": {"runs": 60}, "note": "set by dana"},
    )
    assert changed.status_code == 200, changed.text
    return headers


def _schedule_with(settings, *recipients: str) -> None:
    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.ReportTemplate(
                template_id="tpl-1", tenant_id="default", name="Exec", created_at=now, updated_at=now
            )
        )
        session.flush()
        session.add(
            models.ReportSchedule(
                schedule_id="sch-1",
                tenant_id="default",
                template_id="tpl-1",
                name="Monthly",
                cron="0 6 1 * *",
                recipients=[{"transport": "email", "target": target} for target in recipients],
                created_at=now,
            )
        )


def _trail(settings, **where) -> list[models.AuditEvent]:
    with get_session(settings.postgres_url) as session:
        query = select(models.AuditEvent)
        for column, value in where.items():
            query = query.where(getattr(models.AuditEvent, column) == value)
        return list(session.execute(query.order_by(models.AuditEvent.id)).scalars())


# --------------------------------------------------------------------------- #
# Completeness: no column that can name an account is left undecided
# --------------------------------------------------------------------------- #


def _looks_like_a_person(name: str) -> bool:
    return (
        name in {"username", "actor", "assignee", "requested_by", "owner_id", "recipients"}
        or name.endswith("_by")
        or "email" in name
        or name.startswith("actor")
    )


def test_every_column_that_can_name_an_account_is_decided():
    """A ``*_by`` column added next year must be classified here or fail CI —
    otherwise the export silently misses it and erasure has no answer for it."""
    seen = set()
    for mapper in models.Base.registry.mappers:
        table = mapper.local_table
        for column in table.columns:
            key = (table.name, column.name)
            seen.add(key)
            if _looks_like_a_person(column.name):
                assert key in data_subject.SUBJECT_COLUMNS or key in data_subject.NOT_SUBJECT_COLUMNS, (
                    f"{table.name}.{column.name} can name a console account; classify it in "
                    "api/services/data_subject.py"
                )
    stale = (set(data_subject.SUBJECT_COLUMNS) | set(data_subject.NOT_SUBJECT_COLUMNS)) - seen
    assert not stale, f"classified columns that no longer exist: {sorted(stale)}"


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #


def test_the_export_holds_what_the_platform_has_about_the_account(env):
    client, settings, admin = env
    _dana(client, admin)
    _schedule_with(settings, EMAIL, "board@example.test")

    exported = client.get("/api/users/dana/export", headers=admin)
    assert exported.status_code == 200, exported.text
    document = exported.json()

    assert document["format"] == "shapoclyack.data-subject-export"
    assert document["subject"] == "dana"
    assert document["account"]["email"] == EMAIL
    assert document["account"]["password_set"] is True
    assert document["memberships"] == [
        {
            "tenant_id": "default",
            "role": "admin",
            "granted_at": document["memberships"][0]["granted_at"],
            "granted_by": "admin",
        }
    ]
    assert len(document["sessions"]) >= 1
    assert any(row["outcome"] == "success" for row in document["sign_in_history"])
    assert "client_ip" in document["sign_in_history"][0]
    actions = [row["action"] for row in document["administrative_activity"]]
    assert "retention_policy.update" in actions
    assert "user.create" in [row["action"] for row in document["changes_to_account"]]
    assert document["report_recipient_of"] == [
        {"tenant_id": "default", "schedule_id": "sch-1", "name": "Monthly"}
    ]
    assert {"table": "tenant_retention_policies", "column": "updated_by", "rows": 1} in document[
        "attributions"
    ]
    # Other people's data stays out of one person's copy (Art. 15(4)): the
    # trail rows come without their before/after documents. Secrets never.
    for row in document["administrative_activity"] + document["changes_to_account"]:
        assert "before" not in row and "after" not in row
    serialized = json.dumps(document)
    with get_session(settings.postgres_url) as session:
        stored = session.get(models.User, "dana")
        assert stored.password_hash not in serialized

    exported_rows = _trail(settings, action="user.export")
    assert [(row.actor, row.resource_id) for row in exported_rows] == [("admin", "dana")]


def test_only_a_platform_admin_exports(env):
    client, _settings, admin = env
    dana = _dana(client, admin)
    assert client.get("/api/users/admin/export", headers=dana).status_code == 403
    assert client.get("/api/users/nobody/export", headers=admin).status_code == 404


# --------------------------------------------------------------------------- #
# Erasure
# --------------------------------------------------------------------------- #


def test_erasure_leaves_a_pseudonym_the_trail_still_points_at(env):
    client, settings, admin = env
    dana = _dana(client, admin)
    _schedule_with(settings, EMAIL.upper(), "board@example.test")
    acted_before = len(_trail(settings, actor="dana"))
    assert acted_before >= 1

    erased = client.post("/api/users/dana/erase", headers=admin)
    assert erased.status_code == 200, erased.text
    removed = erased.json()["removed"]
    assert removed["email"] is True
    assert removed["memberships"] == ["default"]
    assert removed["sessions"] >= 1
    assert removed["report_recipients"] == 1

    with get_session(settings.postgres_url) as session:
        row = session.get(models.User, "dana")
        assert row.erased_at is not None
        assert row.disabled_at is not None
        assert (row.email, row.oidc_issuer, row.oidc_subject, row.mfa_secret) == (None,) * 4
        assert row.password_hash == ""
        assert row.role == "viewer"
        for model in (models.UserTenant, models.SessionFamily, models.WebAuthnCredential):
            assert session.query(model).filter_by(username="dana").count() == 0
        schedule = session.get(models.ReportSchedule, "sch-1")
        assert schedule.recipients == [{"transport": "email", "target": "board@example.test"}]

    # The trail is untouched and still names the same pseudonym ...
    assert len(_trail(settings, actor="dana")) == acted_before
    # ... and the erasure's own row carries no trace of what it erased.
    erase_rows = _trail(settings, action="user.erase")
    assert [(row.actor, row.resource_id) for row in erase_rows] == [("admin", "dana")]
    assert EMAIL.lower() not in json.dumps([row.before for row in erase_rows]).lower()
    # The tenant admin sees the member leave, in their own trail.
    revoked = _trail(settings, action="membership.revoke", tenant_id="default")
    assert [row.resource_id for row in revoked] == ["dana"]

    # Nobody can be dana again: not with the old token, the password, or anew.
    assert client.get("/api/auth/me", headers=dana).status_code == 401
    assert (
        client.post("/api/auth/login", json={"username": "dana", "password": PASSWORD}).status_code
        == 401
    )
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "dana", "password": "new-password-1234", "role": "admin"},
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/users/dana/password", headers=admin, json={"password": "new-password-1234"}
        ).status_code
        == 422
    )
    assert (
        client.put("/api/users/dana/disabled", headers=admin, json={"disabled": False}).status_code
        == 409
    )
    assert (
        client.put(
            "/api/tenants/default/members/dana", headers=admin, json={"role": "viewer"}
        ).status_code
        == 422
    )
    assert client.delete("/api/users/dana", headers=admin).status_code == 409

    again = client.post("/api/users/dana/erase", headers=admin)
    assert again.status_code == 200
    assert again.json()["already_erased"] is True
    assert len(_trail(settings, action="user.erase")) == 1

    listed = {user["username"]: user for user in client.get("/api/users", headers=admin).json()}
    assert listed["dana"]["erased_at"] is not None
    assert listed["dana"]["email"] is None


def test_nobody_erases_their_own_account(env):
    client, _settings, admin = env
    refused = client.post("/api/users/admin/erase", headers=admin)
    assert refused.status_code == 409
    assert "signed in as" in refused.json()["detail"]


def test_the_last_admin_with_a_password_cannot_be_erased(env):
    """The requester of an erasure is an admin, so this bites when that admin
    signs in through SSO: the account being erased is the last one that can
    still sign in with a password — the break-glass door."""
    _client, settings, _admin = env
    users_service.configure(settings)
    with pytest.raises(data_subject.ErasureRefused, match="last active admin"):
        data_subject.erase_user(settings, "admin", requested_by="sso-admin")
    with get_session(settings.postgres_url) as session:
        assert session.get(models.User, "admin").erased_at is None


def test_a_legal_hold_suspends_erasure(env):
    client, settings, admin = env
    _dana(client, admin)
    placed = client.put(
        "/api/tenants/default/legal-hold", headers=admin, json={"reason": "matter 2026-17"}
    )
    assert placed.status_code == 200
    refused = client.post("/api/users/dana/erase", headers=admin)
    assert refused.status_code == 409
    assert "legal hold" in refused.json()["detail"]
    with get_session(settings.postgres_url) as session:
        assert session.get(models.User, "dana").email == EMAIL

    # Acting in the held tenant is enough, membership or not: a revoked
    # membership does not take the account's actions out of the tenant's trail.
    assert client.delete("/api/tenants/default/members/dana", headers=admin).status_code == 204
    with pytest.raises(legal_hold.LegalHoldActive):
        data_subject.erase_user(settings, "dana", requested_by="admin")

    # Belonging once is enough too: a member whose grant was revoked before
    # they did anything is still named in the held tenant's trail.
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "eve", "password": "eve-password-1234", "role": "viewer"},
        ).status_code
        == 201
    )
    assert (
        client.put(
            "/api/tenants/default/members/eve", headers=admin, json={"role": "viewer"}
        ).status_code
        == 200
    )
    assert client.delete("/api/tenants/default/members/eve", headers=admin).status_code == 204
    assert client.post("/api/users/eve/erase", headers=admin).status_code == 409

    assert client.delete("/api/tenants/default/legal-hold", headers=admin).status_code == 204
    assert client.post("/api/users/dana/erase", headers=admin).status_code == 200
    assert client.post("/api/users/eve/erase", headers=admin).status_code == 200


def test_only_a_platform_admin_erases(env):
    client, _settings, admin = env
    dana = _dana(client, admin)
    assert client.post("/api/users/operator/erase", headers=dana).status_code == 403
    operator = auth_headers(client, "operator")
    assert client.post("/api/users/viewer/erase", headers=operator).status_code == 403
    assert client.post("/api/users/nobody/erase", headers=admin).status_code == 404


def test_erasure_needs_a_recent_second_factor(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("api.services.mfa._now", clock)
    client = configured_client(tmp_path, monkeypatch)
    headers = auth_headers(client, "admin")
    enrol(client, headers, clock)
    refused = client.post("/api/users/viewer/erase", headers=headers)
    assert refused.status_code == 403
    assert "multi-factor" in refused.json()["detail"]


def test_an_erased_account_is_not_linked_again_by_sso(env):
    """The address and the IdP subject are gone, and the name is taken: the
    person signing in again gets a *new* account, never the pseudonym back."""
    client, settings, admin = env
    _dana(client, admin)
    assert client.post("/api/users/dana/erase", headers=admin).status_code == 200
    with pytest.raises(users_service.SsoLinkError):
        users_service.link_or_provision_sso_user(
            settings,
            issuer="https://idp.example.test",
            subject="subject-dana",
            username="dana",
            email=EMAIL,
            email_verified=True,
            role="viewer",
            tenant_id="default",
            jit_enabled=True,
        )
