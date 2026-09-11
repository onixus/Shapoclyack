"""Tenant scan policy: how hard the platform may scan, decided centrally (#362).

Before this the API told an agent ``--mode`` and nothing else, and every rate
the packets ran at came from the ``scanner/config/default.yaml`` on the agent's
own host — 2000 packets per second for ``safe`` discovery, whatever the local
admin had edited it to, and no way for the platform operator to say otherwise.
Nothing in the code knew that modbus, DNP3 or BACnet exist.

Each test below pins one half of the control that replaces it: the ceiling that
cannot be raised from a request, the OT profile whose floor cannot be raised
from the stored row, the document that travels to the executor and only to the
executor, and the agent that is refused work it could not pace. Every one of
them fails on the pre-#362 code.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.services import scan_policy
from api.settings import Settings
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

# Agent execution, with the legacy shared token still configured: what the
# claim hands the worker is half of what is under test here, and minting a
# provisioning key per agent would only add noise to it.
SETTINGS = {"job_execution_mode": "agent"}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **{**SETTINGS, **overrides})


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def _agent_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-agent-token"}


def _register(client: TestClient, hostname: str, *, capabilities: list[str] | None = None) -> str:
    body: dict[str, object] = {"hostname": hostname, "version": "0.3.2.1", "labels": {}}
    if capabilities is not None:
        body["capabilities"] = capabilities
    response = client.post("/api/agent/register", headers=_agent_headers(), json=body)
    assert response.status_code == 200, response.text
    return response.json()["agent_id"]


def _set_policy(client: TestClient, **fields: object):
    return client.put(
        "/api/tenants/default/scan-policy",
        headers=auth_headers(client, "admin"),
        json=fields,
    )


def _start_scan(client: TestClient, **body: object):
    return client.post(
        "/api/jobs",
        headers=auth_headers(client, "operator"),
        json={"mode": "safe", "domains": "example.com", **body},
    )


def _claim(client: TestClient, agent_id: str):
    return client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())


# ---------------------------------------------------------------------------
# A tenant with no policy is scanned exactly as it was before
# ---------------------------------------------------------------------------


def test_a_tenant_without_a_policy_is_unchanged(tmp_path, monkeypatch):
    """The upgrade must not need an administrator: no policy means no ceiling
    pushed, no document on the job, and an agent that knows nothing about
    policies still takes the work."""
    client = _client(tmp_path, monkeypatch)
    assert (
        client.get("/api/tenants/default/scan-policy", headers=auth_headers(client, "admin")).json()
        is None
    )

    started = _start_scan(client, mode="fast")
    assert started.status_code == 202, started.text
    assert "scan_policy" not in (started.json()["scan_options"] or {})

    agent_id = _register(client, "old-agent")  # no capabilities reported
    claimed = _claim(client, agent_id)
    assert claimed.status_code == 200, claimed.text
    assert "scan_policy.json" not in claimed.json()["inputs"]


# ---------------------------------------------------------------------------
# Safe-only is a refusal, not a hidden button
# ---------------------------------------------------------------------------


def test_safe_only_refuses_an_aggressive_mode(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, safe_only=True).status_code == 200

    refused = _start_scan(client, mode="fast")
    assert refused.status_code == 403, refused.text
    assert "safe" in refused.json()["detail"]
    # ``test`` is not a way around it: it is the smoke profile, and its
    # discovery rate is 4000 pps.
    assert _start_scan(client, mode="test").status_code == 403
    assert _start_scan(client, mode="safe").status_code == 202


def test_the_fragile_profile_forces_safe_only_and_its_own_floor(tmp_path, monkeypatch):
    """``fragile`` is the OT/ICS profile and it is a floor, not a default: a row
    that names it carries the fieldbus avoid-list and the minimum pace even
    though the operator stored neither."""
    client = _client(tmp_path, monkeypatch)
    written = _set_policy(client, profile="fragile")
    assert written.status_code == 200, written.text
    effective = written.json()["effective"]

    assert effective["safe_only"] is True
    assert effective["max_discover_rate"] == 100
    assert effective["max_host_concurrency"] == 1
    assert effective["skip_service_probe"] is True
    # Modbus, DNP3 and BACnet, which nothing in this repository knew about
    # before #362.
    assert {502, 20000, 47808} <= set(effective["avoid_ports"])

    assert _start_scan(client, mode="balanced").status_code == 403


def test_a_stored_value_cannot_raise_the_profile_floor(tmp_path, monkeypatch):
    """The interesting direction. An operator who sets ``fragile`` and then
    types 10000 pps gets 100 — otherwise the profile would be advice."""
    client = _client(tmp_path, monkeypatch)
    written = _set_policy(
        client,
        profile="fragile",
        max_discover_rate=10_000,
        max_host_concurrency=32,
        safe_only=False,
        avoid_ports=[9100],
    )
    assert written.status_code == 200, written.text
    body = written.json()

    # Stored as typed — the operator's input is not rewritten behind their back…
    assert body["max_discover_rate"] == 10_000
    # …and enforced as the floor says.
    assert body["effective"]["max_discover_rate"] == 100
    assert body["effective"]["max_host_concurrency"] == 1
    assert body["effective"]["safe_only"] is True
    # The tenant's own avoided port is added to the profile's list, not
    # substituted for it.
    assert {502, 9100} <= set(body["effective"]["avoid_ports"])


def test_a_scan_may_not_name_an_avoided_port(tmp_path, monkeypatch):
    """Refused rather than silently filtered: an operator who asked to scan 502
    should hear no, not receive results that omit it without saying so."""
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, avoid_ports=[502]).status_code == 200

    refused = _start_scan(client, ranges="10.0.0.1", ports="80,502")
    assert refused.status_code == 403, refused.text
    assert "502" in refused.json()["detail"]
    # The UDP list is held to the same list — BACnet is 47808/udp, and a check
    # on one of the two protocols would guard the wrong half of an OT estate.
    assert _set_policy(client, avoid_ports=[47808]).status_code == 200
    assert _start_scan(client, ranges="10.0.0.1", ports_udp="47808").status_code == 403
    assert _start_scan(client, ranges="10.0.0.1", ports="80,443").status_code == 202


def test_a_port_range_covering_an_avoided_port_is_refused_too(tmp_path, monkeypatch):
    """A sweep is the easy way around a list of single ports, and ``1-65535``
    is a legitimate thing to ask for — so the check reads ranges rather than
    matching literals."""
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, avoid_ports=[502]).status_code == 200

    refused = _start_scan(client, ranges="10.0.0.1", ports="1-65535")
    assert refused.status_code == 403, refused.text
    assert "502" in refused.json()["detail"]
    assert _start_scan(client, ranges="10.0.0.1", ports="1-400").status_code == 202


# ---------------------------------------------------------------------------
# The policy reaches the executor, and only the executor
# ---------------------------------------------------------------------------


def test_the_policy_travels_with_the_job_to_the_agent_that_claimed_it(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, profile="fragile").status_code == 200

    started = _start_scan(client)
    assert started.status_code == 202, started.text
    options = started.json()["scan_options"]
    # On the job, so the run is answerable afterwards for the ceiling it ran
    # under rather than for whatever the table says today.
    assert options["scan_policy"]["profile"] == "fragile"
    assert options["scan_policy"]["digest"]
    # A fragile scan runs without the service-probe stage, and the job says so.
    assert options["skip_nse"] is True
    assert "--skip-nse" in started.json()["command"]

    agent_id = _register(client, "ot-agent", capabilities=["scan_policy"])
    claimed = _claim(client, agent_id)
    assert claimed.status_code == 200, claimed.text
    document = json.loads(claimed.json()["inputs"]["scan_policy.json"])
    assert document["max_discover_rate"] == 100
    assert 502 in document["avoid_ports"]


def test_the_policy_is_not_broadcast_in_the_job_offer(tmp_path, monkeypatch):
    """The offer reaches every agent of the group, including the ones that will
    not get this job (#361). A tenant's scanning constraints are not something
    to hand those workers."""
    from api.services import nats_bus

    published: list[dict] = []

    class _Bus:
        def publish_job_offer(self, payload: dict) -> bool:
            published.append(payload)
            return True

    monkeypatch.setattr(nats_bus, "get_bus", lambda url: _Bus())
    client = _client(tmp_path, monkeypatch, nats_url="nats://unused:4222")
    assert _set_policy(client, profile="fragile").status_code == 200

    started = _start_scan(client)
    assert started.status_code == 202, started.text
    assert len(published) == 1
    assert "scan_policy" not in published[0]
    assert "502" not in json.dumps(published[0])


def test_the_policy_snapshot_is_frozen_at_admission(tmp_path, monkeypatch):
    """A policy edited while the job sits in the queue must not change what was
    admitted — the operator answered for the scan that was accepted."""
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, max_discover_rate=500).status_code == 200
    started = _start_scan(client)
    assert started.status_code == 202, started.text

    assert _set_policy(client, max_discover_rate=50_000).status_code == 200

    agent_id = _register(client, "agent-1", capabilities=["scan_policy"])
    claimed = _claim(client, agent_id)
    assert claimed.status_code == 200, claimed.text
    document = json.loads(claimed.json()["inputs"]["scan_policy.json"])
    assert document["max_discover_rate"] == 500


# ---------------------------------------------------------------------------
# An agent that cannot pace itself is not handed a network that needs pacing
# ---------------------------------------------------------------------------


def test_an_agent_that_cannot_apply_a_policy_is_refused_the_job(tmp_path, monkeypatch):
    """Refused visibly — 426, in that agent's own journal — rather than handed
    a job it would run at 2000 pps, and rather than silently skipped over,
    which would leave an operator with a queue that does not move and an agent
    that reports itself healthy."""
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, profile="fragile").status_code == 200
    started = _start_scan(client)
    assert started.status_code == 202, started.text
    job_id = started.json()["job_id"]

    old_agent = _register(client, "old-agent")
    refused = _claim(client, old_agent)
    assert refused.status_code == 426, refused.text
    assert "scan_policy" in refused.json()["detail"]

    # The job is untouched and waiting for a worker that can hold to it.
    operator = auth_headers(client, "operator")
    assert client.get(f"/api/jobs/{job_id}", headers=operator).json()["status"] == "queued"

    new_agent = _register(client, "new-agent", capabilities=["scan_policy"])
    claimed = _claim(client, new_agent)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == job_id


def test_an_agent_without_the_capability_still_takes_unpoliced_jobs(tmp_path, monkeypatch):
    """The refusal is about the job it would get, not about the agent as such:
    a tenant with no policy is served by every agent it always was."""
    client = _client(tmp_path, monkeypatch)
    started = _start_scan(client)
    assert started.status_code == 202, started.text

    old_agent = _register(client, "old-agent")
    assert _claim(client, old_agent).status_code == 200


# ---------------------------------------------------------------------------
# Who may write it, and where it is recorded
# ---------------------------------------------------------------------------


def test_writing_a_policy_needs_the_named_permission(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")

    refused = client.put(
        "/api/tenants/default/scan-policy", headers=operator, json={"profile": "fragile"}
    )
    assert refused.status_code == 403, refused.text
    # Reading is the scope reader's right, and an operator is not one either.
    assert client.get("/api/tenants/default/scan-policy", headers=operator).status_code == 403
    assert _set_policy(client, profile="fragile").status_code == 200


def test_the_policy_change_and_the_refusal_are_in_the_audit_trail(tmp_path, monkeypatch):
    from api.services import audit as audit_service

    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, profile="fragile", note="plant network").status_code == 200
    assert _start_scan(client, mode="fast").status_code == 403

    written, total = audit_service.list_events(action=audit_service.ACTION_SCAN_POLICY_UPDATE)
    assert total == 1
    # The whole document, before and after: "who took the plant network's rate
    # limit off, and what had it been" is what this trail is asked later.
    assert written[0]["actor"] == "admin"
    assert written[0]["before"] is None
    assert written[0]["after"]["profile"] == "fragile"

    refusals, refused_total = audit_service.list_events(
        action=audit_service.ACTION_SCAN_POLICY_BLOCK
    )
    assert refused_total == 1
    assert refusals[0]["actor"] == "operator"
    assert refusals[0]["after"]["reason"] == "safe_only"


def test_removing_the_policy_puts_the_tenant_back_to_no_ceilings(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, profile="fragile").status_code == 200
    assert _start_scan(client, mode="fast").status_code == 403

    admin = auth_headers(client, "admin")
    removed = client.delete("/api/tenants/default/scan-policy", headers=admin)
    assert removed.status_code == 204, removed.text
    assert client.get("/api/tenants/default/scan-policy", headers=admin).json() is None
    assert _start_scan(client, mode="fast").status_code == 202


def test_a_policy_the_scanner_would_refuse_is_refused_at_write_time(tmp_path, monkeypatch):
    """A ceiling discovered at the first scan rather than here is a ceiling
    discovered by the customer."""
    client = _client(tmp_path, monkeypatch)
    assert _set_policy(client, max_discover_rate=0).status_code == 422
    assert _set_policy(client, avoid_ports=[70000]).status_code == 422
    assert _set_policy(client, profile="gentle").status_code == 422


def test_the_resolved_policy_is_pure_and_never_loosens(tmp_path, monkeypatch):
    """The service-level statement the two routes above rest on, asserted
    without a request in the way: ``resolve`` folds the floor in and takes the
    stricter of the two, in both directions."""
    _client(tmp_path, monkeypatch)
    stricter = scan_policy.resolve(
        {"profile": "fragile", "safe_only": False, "max_port_rate": 10, "avoid_ports": []}
    )
    assert stricter is not None
    assert stricter["max_port_rate"] == 10  # the tenant's own is the tighter one
    assert stricter["safe_only"] is True
    assert scan_policy.resolve(None) is None
