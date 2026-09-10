"""Agent identity binding, lifecycle state, and provisioning key expiry (#308).

Before this, an agent JWT was a bearer of its *tenant*, not of an agent: the
``agent_id`` in the token was never compared with the one in the body, the form
or the query string, so one compromised agent could act as every other agent in
the tenant. Deleting an agent was equally soft — the host kept its key and its
live JWT and re-registered on the next poll.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from api.settings import Settings
from tests.conftest import (
    approve_scan_scope_via_api,
    bearer,
    configured_client,
    login,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

# Agent mode with the legacy shared token *off*: these tests are about the
# per-agent JWT, and leaving the shared token configured would let a request
# authenticate through the branch that has no identity to bind.
SETTINGS = {"job_execution_mode": "agent", "agent_token": ""}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **{**SETTINGS, **overrides})


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def _mint_key(client: TestClient, admin: str, tenant_id: str = "default", label: str = "") -> dict:
    created = client.post(
        f"/api/tenants/{tenant_id}/provisioning-keys",
        headers=bearer(admin),
        json={"label": label},
    )
    assert created.status_code == 201, created.text
    return created.json()


def _agent_jwt(client: TestClient, provisioning_key: str, agent_id: str | None = None) -> dict:
    body: dict[str, object] = {"provisioning_key": provisioning_key}
    if agent_id:
        body["agent_id"] = agent_id
    exchanged = client.post("/api/auth/agent/token", json=body)
    assert exchanged.status_code == 200, exchanged.text
    return exchanged.json()


def _register(client: TestClient, token: str, hostname: str = "edge-1") -> dict:
    reg = client.post("/api/agent/register", headers=bearer(token), json={"hostname": hostname})
    assert reg.status_code == 200, reg.text
    return reg.json()


def _inventory_snapshot(agent_id: str, snapshot_id: str = "snap_agent_identity_01") -> dict:
    """The golden schema-v1 inventory body, re-stamped for one agent.

    Shared with tests/test_api_endpoint_inventory.py rather than hand-written
    here: the ingest route validates the whole contract, and a body assembled
    from memory fails on the fields this test is not about.
    """
    body = json.loads(
        (Path(__file__).parent / "fixtures" / "endpoint_inventory_v1_valid.json").read_text(
            encoding="utf-8"
        )
    )
    body["agent_id"] = agent_id
    body["snapshot_id"] = snapshot_id
    body["collected_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    return body


def _queue_job(client: TestClient, operator: str) -> str:
    job = client.post(
        "/api/jobs",
        headers=bearer(operator),
        json={"mode": "safe", "skip_nse": True, "ranges": "127.0.0.1\n", "ports": "80\n"},
    )
    assert job.status_code == 202, job.text
    return job.json()["job_id"]


# --------------------------------------------------------------------------
# 1. The agent_id in the token is the only agent that token may act as.
# --------------------------------------------------------------------------


def test_agent_token_may_not_act_as_another_agent(tmp_path, monkeypatch):
    """Two agents in one tenant, and neither may speak for the other.

    Same tenant on purpose: the cross-tenant check already existed and passed
    here, which is exactly why this was invisible — an MSSP customer's whole
    fleet shares one tenant.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    operator = login(client, "operator")
    key = _mint_key(client, admin)["key"]

    first = _agent_jwt(client, key, agent_id="agent_one")
    second = _agent_jwt(client, key, agent_id="agent_two")
    _register(client, first["access_token"], "one")
    _register(client, second["access_token"], "two")

    # Heartbeat as somebody else.
    beat = client.post(
        "/api/agent/heartbeat",
        headers=bearer(first["access_token"]),
        json={"agent_id": "agent_two", "status": "idle"},
    )
    assert beat.status_code == 403
    assert "bound to a different agent_id" in beat.json()["detail"]

    # Claim work as somebody else.
    _queue_job(client, operator)
    claimed = client.post(
        "/api/agent/jobs/claim?agent_id=agent_two",
        headers=bearer(first["access_token"]),
    )
    assert claimed.status_code == 403

    # Register as somebody else — which would otherwise rewrite that agent's
    # hostname, labels and version out from under it.
    reg = client.post(
        "/api/agent/register",
        headers=bearer(first["access_token"]),
        json={"agent_id": "agent_two", "hostname": "stolen"},
    )
    assert reg.status_code == 403
    assert client.get(
        "/api/agents/agent_two", headers=bearer(operator)
    ).json()["hostname"] == "two"


def test_registration_without_an_agent_id_uses_the_tokens_own(tmp_path, monkeypatch):
    """Omitting agent_id no longer mints a random id.

    The exchange already put one in the token; using it is what makes a
    restarted agent come back as itself instead of as a second row.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin)["key"]
    exchanged = _agent_jwt(client, key, agent_id="agent_fixed")

    info = _register(client, exchanged["access_token"])
    assert info["agent_id"] == "agent_fixed"
    again = _register(client, exchanged["access_token"], hostname="edge-1-restarted")
    assert again["agent_id"] == "agent_fixed"

    operator = login(client, "operator")
    listed = client.get("/api/agents", headers=bearer(operator)).json()
    assert listed["total"] == 1


def test_legacy_shared_token_agent_keeps_working_unbound(tmp_path, monkeypatch):
    """The documented boundary: OCTO_AGENT_TOKEN carries no identity.

    It is one credential for every agent in the ``default`` tenant by
    construction, so there is nothing to bind it to and it behaves exactly as
    before. Refusing it here would break every lab install without making the
    shared token any less shared.
    """
    client = configured_client(
        tmp_path, monkeypatch, job_execution_mode="agent", agent_token="legacy-shared"
    )
    headers = bearer("legacy-shared")
    first = client.post("/api/agent/register", headers=headers, json={"hostname": "one"})
    second = client.post("/api/agent/register", headers=headers, json={"hostname": "two"})
    assert first.status_code == 200 and second.status_code == 200

    # One shared credential acting as an agent it did not create: still allowed.
    beat = client.post(
        "/api/agent/heartbeat",
        headers=headers,
        json={"agent_id": second.json()["agent_id"], "status": "idle"},
    )
    assert beat.status_code == 200


# --------------------------------------------------------------------------
# 2. Lifecycle state: disabled / quarantined.
# --------------------------------------------------------------------------


def test_disabled_agent_is_refused_work_but_still_heartbeats(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    operator = login(client, "operator")
    key = _mint_key(client, admin)["key"]
    exchanged = _agent_jwt(client, key, agent_id="agent_one")
    agent_token = exchanged["access_token"]
    _register(client, agent_token)
    job_id = _queue_job(client, operator)

    patched = client.patch(
        "/api/agents/agent_one",
        headers=bearer(admin),
        json={"status": "disabled", "reason": "decommissioned rack"},
    )
    assert patched.status_code == 200
    assert patched.json()["lifecycle_status"] == "disabled"
    assert patched.json()["lifecycle_reason"] == "decommissioned rack"

    claimed = client.post("/api/agent/jobs/claim?agent_id=agent_one", headers=bearer(agent_token))
    assert claimed.status_code == 403
    assert "disabled by an operator" in claimed.json()["detail"]
    assert "decommissioned rack" in claimed.json()["detail"]

    results = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=bearer(agent_token),
        data={"agent_id": "agent_one", "exit_code": "0"},
    )
    assert results.status_code == 403

    # The heartbeat is answered, and it is what tells the agent why.
    beat = client.post(
        "/api/agent/heartbeat",
        headers=bearer(agent_token),
        json={"agent_id": "agent_one", "status": "idle"},
    )
    assert beat.status_code == 200
    assert beat.json()["lifecycle_status"] == "disabled"
    assert "decommissioned rack" in beat.json()["lifecycle_message"]


def test_a_disabled_agent_cannot_re_register_itself_back_into_service(tmp_path, monkeypatch):
    """Restarting is not an appeal. Only an operator moves it back to active."""
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin)["key"]
    agent_token = _agent_jwt(client, key, agent_id="agent_one")["access_token"]
    _register(client, agent_token)

    client.patch(
        "/api/agents/agent_one",
        headers=bearer(admin),
        json={"status": "quarantined", "reason": "credential leak"},
    )
    again = client.post(
        "/api/agent/register", headers=bearer(agent_token), json={"hostname": "edge-1"}
    )
    assert again.status_code == 403
    assert "quarantined by an operator" in again.json()["detail"]

    reactivated = client.patch(
        "/api/agents/agent_one", headers=bearer(admin), json={"status": "active"}
    )
    assert reactivated.status_code == 200
    # The reason explained a state it is no longer in, so it does not linger.
    assert reactivated.json()["lifecycle_reason"] is None
    assert reactivated.json()["lifecycle_message"] is None
    assert (
        client.post(
            "/api/agent/register", headers=bearer(agent_token), json={"hostname": "edge-1"}
        ).status_code
        == 200
    )


def test_changing_agent_state_needs_tenant_admin(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin)["key"]
    _register(client, _agent_jwt(client, key, agent_id="agent_one")["access_token"])

    for username in ("viewer", "operator"):
        refused = client.patch(
            "/api/agents/agent_one",
            headers=bearer(login(client, username)),
            json={"status": "disabled"},
        )
        assert refused.status_code == 403, username


def test_agent_state_of_another_tenant_reads_as_absent(tmp_path, monkeypatch):
    """404, not 403 — the same rule GET /api/agents/{id} has kept since #223."""
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    created = client.post(
        "/api/tenants", headers=bearer(admin), json={"name": "Acme", "tenant_id": "ten_acme"}
    )
    assert created.status_code == 201
    approve_scan_scope_via_api(client, "ten_acme", bearer(admin))
    key = _mint_key(client, admin, tenant_id="ten_acme")["key"]
    _register(client, _agent_jwt(client, key, agent_id="agent_acme")["access_token"])

    # The platform admin scoped to `default` sees an agent that is not there.
    refused = client.patch(
        "/api/agents/agent_acme?tenant_id=default",
        headers=bearer(admin),
        json={"status": "disabled"},
    )
    assert refused.status_code == 404


# --------------------------------------------------------------------------
# 3. Delete, and make it stick.
# --------------------------------------------------------------------------


def test_delete_without_revoke_leaves_the_key_and_the_agent_comes_back(tmp_path, monkeypatch):
    """The pause #308 is about, asserted rather than assumed.

    Deleting the row alone is not a revocation, and the response says so
    instead of implying the stronger outcome.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    operator = login(client, "operator")
    key = _mint_key(client, admin)["key"]
    agent_token = _agent_jwt(client, key, agent_id="agent_one")["access_token"]
    _register(client, agent_token)

    deleted = client.delete("/api/agents/agent_one", headers=bearer(operator))
    assert deleted.status_code == 200
    assert deleted.json()["key_revoked"] is False
    assert deleted.json()["provisioning_key_id"].startswith("pk_")

    back = client.post(
        "/api/agent/register", headers=bearer(agent_token), json={"hostname": "edge-1"}
    )
    assert back.status_code == 200


def test_delete_with_revoke_key_kills_the_live_jwt_too(tmp_path, monkeypatch):
    """Revoking the key stops the JWT already minted from it, not just the next one.

    The token is valid for two hours and its signature still verifies; what
    refuses it is the database check in ``require_agent``.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    operator = login(client, "operator")
    minted = _mint_key(client, admin)
    agent_token = _agent_jwt(client, minted["key"], agent_id="agent_one")["access_token"]
    _register(client, agent_token)

    deleted = client.delete("/api/agents/agent_one?revoke_key=true", headers=bearer(operator))
    assert deleted.status_code == 200
    assert deleted.json()["key_revoked"] is True
    assert deleted.json()["provisioning_key_id"] == minted["key_id"]

    back = client.post(
        "/api/agent/register", headers=bearer(agent_token), json={"hostname": "edge-1"}
    )
    assert back.status_code == 401
    assert "revoked" in back.json()["detail"]

    # And the key cannot be exchanged for a fresh token either.
    again = client.post("/api/auth/agent/token", json={"provisioning_key": minted["key"]})
    assert again.status_code == 401


def test_revoking_a_key_disarms_every_agent_that_registered_with_it(tmp_path, monkeypatch):
    """Revocation reaches the fleet at once, without waiting out the JWT TTL."""
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    minted = _mint_key(client, admin)
    agent_token = _agent_jwt(client, minted["key"], agent_id="agent_one")["access_token"]
    _register(client, agent_token)

    revoked = client.post(
        f"/api/tenants/default/provisioning-keys/{minted['key_id']}/revoke",
        headers=bearer(admin),
    )
    assert revoked.status_code == 200

    beat = client.post(
        "/api/agent/heartbeat",
        headers=bearer(agent_token),
        json={"agent_id": "agent_one", "status": "idle"},
    )
    assert beat.status_code == 401


def test_delete_reports_that_there_was_no_key_to_revoke(tmp_path, monkeypatch):
    """A legacy shared-token agent has no per-agent credential to revoke.

    Answering ``key_revoked: true`` would tell an operator a live door is shut.
    """
    client = configured_client(
        tmp_path, monkeypatch, job_execution_mode="agent", agent_token="legacy-shared"
    )
    operator = login(client, "operator")
    agent_id = client.post(
        "/api/agent/register", headers=bearer("legacy-shared"), json={"hostname": "lab"}
    ).json()["agent_id"]

    deleted = client.delete(f"/api/agents/{agent_id}?revoke_key=true", headers=bearer(operator))
    assert deleted.status_code == 200
    assert deleted.json() == {
        "status": "deleted",
        "agent_id": agent_id,
        "provisioning_key_id": None,
        "key_revoked": False,
        "other_agents_on_key": 0,
    }


# --------------------------------------------------------------------------
# 4. Provisioning key expiry.
# --------------------------------------------------------------------------


def test_new_keys_carry_an_expiry_from_the_configured_ttl(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, provisioning_key_ttl_days=30)
    admin = login(client, "admin")
    minted = _mint_key(client, admin, label="edge-lab")

    assert minted["expires_at"] is not None
    expires_at = datetime.fromisoformat(minted["expires_at"].replace("Z", "+00:00"))
    delta = expires_at - datetime.now(UTC)
    assert timedelta(days=29) < delta <= timedelta(days=30)
    # 30 days out is not "soon" — the warning window is two weeks.
    assert minted["expires_soon"] is False

    listed = client.get("/api/tenants/default/provisioning-keys", headers=bearer(admin)).json()
    assert listed[0]["expires_at"] == minted["expires_at"]


def test_a_ttl_of_zero_mints_perpetual_keys(tmp_path, monkeypatch):
    """0 is the documented escape hatch, and it is what pre-#308 keys already are."""
    client = _client(tmp_path, monkeypatch, provisioning_key_ttl_days=0)
    admin = login(client, "admin")
    minted = _mint_key(client, admin)
    assert minted["expires_at"] is None
    assert minted["expires_soon"] is False


def test_a_key_expiring_within_the_warning_window_is_flagged(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch, provisioning_key_ttl_days=3)
    admin = login(client, "admin")
    assert _mint_key(client, admin)["expires_soon"] is True


def test_an_expired_key_cannot_be_exchanged_and_stops_its_agents(tmp_path, monkeypatch):
    from api.db import models
    from api.db.engine import get_session

    settings = _settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    admin = login(client, "admin")
    minted = _mint_key(client, admin)
    agent_token = _agent_jwt(client, minted["key"], agent_id="agent_one")["access_token"]
    _register(client, agent_token)

    # Reaching into the row rather than waiting 90 days, and reaching in the
    # way the API writes it: naive UTC, like every other timestamp here.
    with get_session(settings.postgres_url) as session:
        row = session.get(models.ProvisioningKey, minted["key_id"])
        row.expires_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1)

    exchanged = client.post("/api/auth/agent/token", json={"provisioning_key": minted["key"]})
    assert exchanged.status_code == 401

    # The JWT minted while the key was live stops working too, which is the
    # point: an expiry an existing token outlives is a rotation reminder, not
    # an expiry.
    beat = client.post(
        "/api/agent/heartbeat",
        headers=bearer(agent_token),
        json={"agent_id": "agent_one", "status": "idle"},
    )
    assert beat.status_code == 401
    assert "expired" in beat.json()["detail"]

    listed = client.get("/api/tenants/default/provisioning-keys", headers=bearer(admin)).json()
    # Already expired is not "expiring soon" — it is done.
    assert listed[0]["expires_soon"] is False


# --------------------------------------------------------------------------
# 5. The exchange itself, and the sequence a real worker performs.
# --------------------------------------------------------------------------


def test_the_worker_sequence_exchange_register_refresh_heartbeat(tmp_path, monkeypatch):
    """The four calls agent/worker.py makes, in the order it makes them.

    This is the sequence that shipped broken: the worker exchanged its key
    *without* an agent_id, so the server minted a random one into the token,
    and the very next call — a register carrying OCTO_AGENT_ID — was refused
    as impersonation. Every host with a provisioning key would have restarted
    every five seconds. Asserted end to end rather than per-route, because
    each route on its own was fine.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin)["key"]

    # 1. Exchange, carrying the id the installer wrote into OCTO_AGENT_ID.
    exchanged = _agent_jwt(client, key, agent_id="edge-01")
    assert exchanged["agent_id"] == "edge-01"

    # 2. Register as that id.
    registered = client.post(
        "/api/agent/register",
        headers=bearer(exchanged["access_token"]),
        json={"agent_id": "edge-01", "hostname": "edge-01.lab"},
    )
    assert registered.status_code == 200, registered.text
    assert registered.json()["agent_id"] == "edge-01"

    # 3. The refresh on the JWT timer — same id, and a token minted for it.
    # (Not asserted to differ from the first: minted in the same second, from
    # the same claims, it legitimately is the same string.)
    refreshed = _agent_jwt(client, key, agent_id="edge-01")
    assert refreshed["agent_id"] == "edge-01"

    # 4. Heartbeat on the refreshed token, still as itself.
    beat = client.post(
        "/api/agent/heartbeat",
        headers=bearer(refreshed["access_token"]),
        json={"agent_id": "edge-01", "status": "idle"},
    )
    assert beat.status_code == 200, beat.text
    assert beat.json()["agent_id"] == "edge-01"

    operator = login(client, "operator")
    # One agent, not one per exchange.
    assert client.get("/api/agents", headers=bearer(operator)).json()["total"] == 1


def test_an_exchange_without_an_agent_id_cannot_register_as_a_named_one(tmp_path, monkeypatch):
    """The failure mode above, pinned so it cannot come back.

    A token minted for a server-chosen id may register — as *that* id. What it
    may not do is carry OCTO_AGENT_ID in the body and become the host's own
    agent, and the 403 is what the fix in agent/worker.py exists to avoid.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin)["key"]

    anonymous = _agent_jwt(client, key)
    assert anonymous["agent_id"].startswith("agent_")

    refused = client.post(
        "/api/agent/register",
        headers=bearer(anonymous["access_token"]),
        json={"agent_id": "edge-01", "hostname": "edge-01.lab"},
    )
    assert refused.status_code == 403
    assert "bound to a different agent_id" in refused.json()["detail"]

    # Without the body id it registers as the id the token names.
    accepted = _register(client, anonymous["access_token"])
    assert accepted["agent_id"] == anonymous["agent_id"]


def test_a_second_key_cannot_exchange_for_a_live_agents_identity(tmp_path, monkeypatch):
    """403 at the exchange, before a token for that id exists at all.

    Binding the id only at register time left the door open one step earlier:
    any holder of any valid key in the tenant could ask for a live agent's id,
    get a token that then passes every downstream check, and rewrite that
    agent's hostname and labels.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    fleet_key = _mint_key(client, admin, label="fleet")["key"]
    other_key = _mint_key(client, admin, label="other")["key"]
    _register(client, _agent_jwt(client, fleet_key, agent_id="edge-01")["access_token"], "edge-01")

    stolen = client.post(
        "/api/auth/agent/token",
        json={"provisioning_key": other_key, "agent_id": "edge-01"},
    )
    assert stolen.status_code == 403
    assert "different provisioning key" in stolen.json()["detail"]
    # 401 is reserved for a key that is not exchangeable; this key is fine.
    assert client.post(
        "/api/auth/agent/token", json={"provisioning_key": other_key}
    ).status_code == 200


def test_rotating_the_key_releases_the_agent_id_once_the_old_key_is_revoked(
    tmp_path, monkeypatch
):
    """The documented rotation order, asserted so the binding is not a trap.

    Revoke first, then re-provision: the revocation already stops the old
    key's live JWTs, so nothing is impersonated by letting the new key adopt
    the id.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    old = _mint_key(client, admin, label="old")
    new_key = _mint_key(client, admin, label="new")["key"]
    _register(client, _agent_jwt(client, old["key"], agent_id="edge-01")["access_token"], "edge-01")

    # Before the revocation, the new key is refused the id.
    assert client.post(
        "/api/auth/agent/token", json={"provisioning_key": new_key, "agent_id": "edge-01"}
    ).status_code == 403

    revoked = client.post(
        f"/api/tenants/default/provisioning-keys/{old['key_id']}/revoke", headers=bearer(admin)
    )
    assert revoked.status_code == 200

    rotated = client.post(
        "/api/auth/agent/token", json={"provisioning_key": new_key, "agent_id": "edge-01"}
    )
    assert rotated.status_code == 200, rotated.text
    reregistered = client.post(
        "/api/agent/register",
        headers=bearer(rotated.json()["access_token"]),
        json={"agent_id": "edge-01", "hostname": "edge-01.lab"},
    )
    assert reregistered.status_code == 200


def test_a_quarantined_agent_cannot_exchange_its_key_for_a_fresh_token(tmp_path, monkeypatch):
    """Restarting the host is not a way out of quarantine.

    The register refusal alone was not enough: the exchange came first and
    happily minted a token, so the state only bit one call later — and the
    agent's own run loop needs the refusal to carry the lifecycle wording, or
    it retries at the poll interval instead of backing off.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin)["key"]
    _register(client, _agent_jwt(client, key, agent_id="edge-01")["access_token"], "edge-01")

    client.patch(
        "/api/agents/edge-01",
        headers=bearer(admin),
        json={"status": "quarantined", "reason": "credential leak"},
    )
    refused = client.post(
        "/api/auth/agent/token", json={"provisioning_key": key, "agent_id": "edge-01"}
    )
    assert refused.status_code == 403
    assert "quarantined by an operator" in refused.json()["detail"]
    assert "credential leak" in refused.json()["detail"]


def test_result_upload_refuses_a_form_agent_id_that_is_not_the_tokens(tmp_path, monkeypatch):
    """The fourth route, and the only one that takes its agent_id from a form.

    Multipart is why it was missed: the id arrives as a form field rather than
    JSON or a query parameter, so a check written against either of those
    would not have covered it.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    operator = login(client, "operator")
    key = _mint_key(client, admin)["key"]
    victim = _agent_jwt(client, key, agent_id="edge-01")
    thief = _agent_jwt(client, key, agent_id="edge-02")
    _register(client, victim["access_token"], "edge-01")
    _register(client, thief["access_token"], "edge-02")

    job_id = _queue_job(client, operator)
    claimed = client.post(
        "/api/agent/jobs/claim?agent_id=edge-01", headers=bearer(victim["access_token"])
    )
    assert claimed.status_code == 200, claimed.text

    stolen = client.post(
        f"/api/agent/jobs/{job_id}/results",
        headers=bearer(thief["access_token"]),
        data={"agent_id": "edge-01", "exit_code": "0"},
    )
    assert stolen.status_code == 403
    assert "bound to a different agent_id" in stolen.json()["detail"]


def test_a_quarantined_agent_stops_feeding_the_endpoint_inventory(tmp_path, monkeypatch):
    """Quarantine means stop writing, not stop writing half of it (#308).

    ``POST /api/endpoint/inventory`` checked that the token matched the
    agent_id but never that the agent was allowed to be talking at all, so a
    quarantined host kept adding devices and software to the tenant's
    inventory.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    key = _mint_key(client, admin)["key"]
    agent_token = _agent_jwt(client, key, agent_id="edge-01")["access_token"]
    _register(client, agent_token, "edge-01")

    # The same golden schema-v1 body the inventory suite posts, re-stamped for
    # this agent; only the lifecycle state differs between the two calls.
    snapshot = _inventory_snapshot("edge-01")
    accepted = client.post("/api/endpoint/inventory", headers=bearer(agent_token), json=snapshot)
    assert accepted.status_code in (200, 201), accepted.text

    client.patch(
        "/api/agents/edge-01",
        headers=bearer(admin),
        json={"status": "quarantined", "reason": "credential leak"},
    )
    snapshot = _inventory_snapshot("edge-01", snapshot_id="snap_edge01_second")
    refused = client.post("/api/endpoint/inventory", headers=bearer(agent_token), json=snapshot)
    assert refused.status_code == 403
    assert "quarantined by an operator" in refused.json()["detail"]


def test_delete_reports_how_many_agents_share_the_key(tmp_path, monkeypatch):
    """The blast radius of ``revoke_key``, counted before the click (#308).

    One key commonly provisions a whole fleet, and revoking it deregisters
    nothing but stops every one of them — the console needs the number to say
    so in the confirmation.
    """
    client = _client(tmp_path, monkeypatch)
    admin = login(client, "admin")
    operator = login(client, "operator")
    key = _mint_key(client, admin)["key"]
    for agent_id in ("edge-01", "edge-02", "edge-03"):
        _register(client, _agent_jwt(client, key, agent_id=agent_id)["access_token"], agent_id)

    # Before the click: the drawer reads the agent, and the warning above the
    # "revoke the key" checkbox is built from this number.
    detail = client.get("/api/agents/edge-01", headers=bearer(operator))
    assert detail.status_code == 200
    assert detail.json()["other_agents_on_key"] == 2

    deleted = client.delete("/api/agents/edge-01", headers=bearer(operator))
    assert deleted.status_code == 200
    assert deleted.json()["other_agents_on_key"] == 2

    # And after it, with one fewer agent left on the key.
    remaining = client.get("/api/agents/edge-02", headers=bearer(operator))
    assert remaining.json()["other_agents_on_key"] == 1
