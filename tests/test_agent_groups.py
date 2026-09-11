"""Agent groups: which of a tenant's agents may execute which of its jobs (#361).

Before this, ``claim_job`` filtered by tenant and by "queued" and nothing else,
so every agent of a tenant could take every job of that tenant. Each test below
pins one half of the control that replaces it — the claim filter, the selector
the server refuses to take on trust, and the scope entry that decides which
group a set of targets may be reached from. The first three fail on the
pre-#361 code, which is what makes them worth having.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from api.settings import Settings
from tests.conftest import (
    approve_scan_scope,
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

# Agent execution, with the legacy shared token still configured: the claim
# path is the thing under test, and minting a provisioning key per agent would
# only add noise to it (agent identity itself is tests/test_agent_identity.py).
SETTINGS = {"job_execution_mode": "agent"}


def _settings(tmp_path: Path, **overrides: object) -> Settings:
    return make_settings(tmp_path, **{**SETTINGS, **overrides})


def _client(tmp_path: Path, monkeypatch, **overrides: object) -> TestClient:
    return configured_client(tmp_path, monkeypatch, **{**SETTINGS, **overrides})


def _agent_headers() -> dict[str, str]:
    return {"Authorization": "Bearer test-agent-token"}


def _register(client: TestClient, hostname: str, labels: dict[str, str] | None = None) -> str:
    response = client.post(
        "/api/agent/register",
        headers=_agent_headers(),
        json={"hostname": hostname, "version": "0.3.2.1", "labels": labels or {}},
    )
    assert response.status_code == 200, response.text
    return response.json()["agent_id"]


def _create_group(client: TestClient, name: str) -> dict:
    response = client.post(
        "/api/agent-groups",
        headers=auth_headers(client, "admin"),
        json={"name": name, "description": f"{name} segment"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _assign(client: TestClient, agent_id: str, group: str | None) -> dict:
    response = client.put(
        f"/api/agents/{agent_id}/group",
        headers=auth_headers(client, "admin"),
        json={"group": group},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _start_scan(client: TestClient, **body: object):
    return client.post(
        "/api/jobs",
        headers=auth_headers(client, "operator"),
        json={"mode": "test", "domains": "example.com", **body},
    )


def _claim(client: TestClient, agent_id: str):
    return client.post(f"/api/agent/jobs/claim?agent_id={agent_id}", headers=_agent_headers())


# ---------------------------------------------------------------------------
# The claim filter
# ---------------------------------------------------------------------------


def test_a_job_addressed_to_a_group_is_not_claimable_from_outside_it(tmp_path, monkeypatch):
    """The defect itself: one tenant, two agents, and a job that belongs to one
    of them. Before #361 whichever agent polled first got it."""
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    _create_group(client, "office")
    inside = _register(client, "pci-1")
    outside = _register(client, "office-1")
    _assign(client, inside, "pci")
    _assign(client, outside, "office")

    started = _start_scan(client, agent_group="pci")
    assert started.status_code == 202, started.text
    job_id = started.json()["job_id"]
    assert started.json()["agent_group"] == "pci"

    # The wrong segment's agent is told there is nothing for it — 204, not a
    # 403: it has no business learning that another group has work queued.
    assert _claim(client, outside).status_code == 204
    # Naming the job explicitly (the NATS pull path) does not get around it.
    assert (
        client.post(
            f"/api/agent/jobs/claim?agent_id={outside}&job_id={job_id}",
            headers=_agent_headers(),
        ).status_code
        == 204
    )

    claimed = _claim(client, inside)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == job_id


def test_an_agent_in_no_group_keeps_taking_the_jobs_addressed_to_none(tmp_path, monkeypatch):
    """Backwards compatibility, and the reason no operator action is needed on
    upgrade: an ungrouped agent and an ungrouped job behave exactly as before,
    and a grouped agent still serves the ungrouped queue it already served."""
    client = _client(tmp_path, monkeypatch)
    legacy = _register(client, "legacy-1")

    started = _start_scan(client)
    assert started.status_code == 202, started.text
    assert started.json()["agent_group"] is None
    assert started.json()["agent_group_unavailable"] is False

    claimed = _claim(client, legacy)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == started.json()["job_id"]

    # And a grouped agent is not fenced off from the ungrouped queue.
    _create_group(client, "pci")
    grouped = _register(client, "pci-1")
    _assign(client, grouped, "pci")
    second = _start_scan(client)
    assert second.status_code == 202, second.text
    assert _claim(client, grouped).json()["job_id"] == second.json()["job_id"]


def test_an_agent_cannot_put_itself_into_a_group_by_reporting_a_label(tmp_path, monkeypatch):
    """Membership decides what a worker may claim, so it is a grant rather than
    something the worker declares about itself."""
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    agent_id = _register(client, "liar-1", labels={"agent_group": "pci", "group": "pci"})

    detail = client.get(
        f"/api/agents/{agent_id}", headers=auth_headers(client, "operator")
    ).json()
    assert detail["labels"] == {"agent_group": "pci", "group": "pci"}
    assert detail["agent_group"] is None

    started = _start_scan(client, agent_group="pci")
    assert started.status_code == 202, started.text
    assert _claim(client, agent_id).status_code == 204


def test_moving_an_agent_out_of_a_group_takes_effect_on_the_next_claim(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    agent_id = _register(client, "pci-1")
    _assign(client, agent_id, "pci")

    first = _start_scan(client, agent_group="pci")
    assert _claim(client, agent_id).status_code == 200

    assert _assign(client, agent_id, None)["agent_group"] is None
    second = _start_scan(client, agent_group="pci", domains="other.example.com")
    assert second.status_code == 202, second.text
    assert _claim(client, agent_id).status_code == 204
    # The job it already holds is untouched — a running scan is not recalled.
    held = client.get(
        f"/api/jobs/{first.json()['job_id']}", headers=auth_headers(client, "operator")
    ).json()
    assert held["assigned_agent_id"] == agent_id


# ---------------------------------------------------------------------------
# The selector is not taken on trust
# ---------------------------------------------------------------------------


def test_a_scan_naming_a_group_the_tenant_does_not_have_is_refused(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    refused = _start_scan(client, agent_group="does-not-exist")
    assert refused.status_code == 422
    assert "does-not-exist" in refused.json()["detail"]


def test_the_scope_entry_decides_which_group_may_reach_its_range(tmp_path, monkeypatch):
    """The rule the issue asks for: an allow entry can name the agent groups
    entitled to scan what it approves, and the scan is addressed to one of them
    whether or not the operator thought to say so."""
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    _create_group(client, "office")
    approve_scan_scope(
        settings,
        entries=[
            {
                "effect": "allow",
                "kind": "cidr",
                "value": "10.1.0.0/16",
                "agent_groups": ["pci"],
            },
            {"effect": "allow", "kind": "cidr", "value": "192.168.0.0/16"},
        ],
    )

    # Nobody named a group, and the scope leaves exactly one candidate.
    restricted = _start_scan(client, domains=None, ranges="10.1.2.0/24")
    assert restricted.status_code == 202, restricted.text
    assert restricted.json()["agent_group"] == "pci"

    # An unrestricted entry covers this one, so the scan is addressed to
    # nobody in particular — the pre-#361 behaviour.
    unrestricted = _start_scan(client, domains=None, ranges="192.168.5.0/24")
    assert unrestricted.status_code == 202, unrestricted.text
    assert unrestricted.json()["agent_group"] is None

    # And the selector is checked against the scope, not merely against the
    # tenant's list of groups.
    denied = _start_scan(client, domains=None, ranges="10.1.2.0/24", agent_group="office")
    assert denied.status_code == 403, denied.text
    assert "office" in denied.json()["detail"]


def test_the_restriction_follows_the_target_not_the_field_it_arrived_in(
    tmp_path, monkeypatch
):
    """Defence in depth, asserted on the resolver itself.

    ``parse_target_payload`` refuses an address in the domains field today, so
    a scan cannot reach the resolver that way — but a wildcard domain entry
    *does* cover ``10.1.2.3``, and had the requirement been derived from which
    box a value was typed into, that one line would have escaped the group
    restriction on the ``10.1.0.0/16`` entry it sits inside. The classification
    is by what the value is, and this is what keeps it that way.
    """
    from api.services import scan_scopes

    # The client is built for its side effect: it configures the services and
    # seeds the default tenant that the scope below is written for.
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    approve_scan_scope(
        settings,
        entries=[
            {"effect": "allow", "kind": "cidr", "value": "10.1.0.0/16", "agent_groups": ["pci"]},
            {"effect": "allow", "kind": "domain", "value": "*"},
        ],
    )

    required = scan_scopes.required_agent_groups(
        settings, tenant_id="default", ranges_text=None, domains_text="10.1.2.3"
    )
    assert required == frozenset({"pci"})


def test_targets_restricted_to_different_groups_cannot_be_scanned_together(
    tmp_path, monkeypatch
):
    """One job runs on one agent, so two ranges with no group in common have no
    agent that may do both. Refused rather than silently run from one of them."""
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    _create_group(client, "office")
    approve_scan_scope(
        settings,
        entries=[
            {"effect": "allow", "kind": "cidr", "value": "10.1.0.0/16", "agent_groups": ["pci"]},
            {
                "effect": "allow",
                "kind": "cidr",
                "value": "10.2.0.0/16",
                "agent_groups": ["office"],
            },
        ],
    )

    refused = _start_scan(client, domains=None, ranges="10.1.2.0/24\n10.2.3.0/24")
    assert refused.status_code == 403, refused.text
    assert "nothing in common" in refused.json()["detail"]


def test_an_ambiguous_restriction_asks_the_operator_to_choose(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci-a")
    _create_group(client, "pci-b")
    approve_scan_scope(
        settings,
        entries=[
            {
                "effect": "allow",
                "kind": "cidr",
                "value": "10.1.0.0/16",
                "agent_groups": ["pci-a", "pci-b"],
            }
        ],
    )

    refused = _start_scan(client, domains=None, ranges="10.1.2.0/24")
    assert refused.status_code == 422, refused.text
    assert "pci-a, pci-b" in refused.json()["detail"]

    chosen = _start_scan(client, domains=None, ranges="10.1.2.0/24", agent_group="pci-b")
    assert chosen.status_code == 202, chosen.text
    assert chosen.json()["agent_group"] == "pci-b"


def test_a_scope_entry_cannot_name_a_group_that_does_not_exist(tmp_path, monkeypatch):
    """Caught where the approver can still fix it, rather than at 02:00 by a
    scan nobody can claim."""
    client = _client(tmp_path, monkeypatch)
    refused = client.put(
        "/api/tenants/default/scan-scope",
        headers=auth_headers(client, "admin"),
        json={
            "entries": [
                {
                    "effect": "allow",
                    "kind": "cidr",
                    "value": "10.0.0.0/8",
                    "agent_groups": ["ghost"],
                }
            ]
        },
    )
    assert refused.status_code == 422, refused.text
    assert "ghost" in refused.json()["detail"]


def test_a_deny_entry_may_not_carry_agent_groups(tmp_path, monkeypatch):
    """"Denied, except for these agents" is not something this scope expresses,
    so it is refused rather than silently read as something else."""
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    refused = client.put(
        "/api/tenants/default/scan-scope",
        headers=auth_headers(client, "admin"),
        json={
            "entries": [
                {"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"},
                {
                    "effect": "deny",
                    "kind": "cidr",
                    "value": "10.1.2.3/32",
                    "agent_groups": ["pci"],
                },
            ]
        },
    )
    assert refused.status_code == 422, refused.text


# ---------------------------------------------------------------------------
# A job nobody can claim must not look like an ordinary queued one
# ---------------------------------------------------------------------------


def test_a_job_addressed_to_an_empty_group_is_queued_but_flagged(tmp_path, monkeypatch):
    """Accepted — an agent that is restarting comes back in seconds — but the
    job says so, instead of sitting in ``queued`` with nothing to explain it."""
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")

    started = _start_scan(client, agent_group="pci")
    assert started.status_code == 202, started.text
    assert started.json()["agent_group"] == "pci"
    assert started.json()["agent_group_unavailable"] is True

    # And it stays on the job as read back, not only on the response.
    job = client.get(
        f"/api/jobs/{started.json()['job_id']}", headers=auth_headers(client, "operator")
    ).json()
    assert job["agent_group_unavailable"] is True

    agent_id = _register(client, "pci-1")
    _assign(client, agent_id, "pci")
    later = _start_scan(client, agent_group="pci", domains="other.example.com")
    assert later.json()["agent_group_unavailable"] is False


# ---------------------------------------------------------------------------
# Managing the groups
# ---------------------------------------------------------------------------


def test_group_management_needs_the_named_permission(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    refused = client.post(
        "/api/agent-groups",
        headers=auth_headers(client, "operator"),
        json={"name": "pci"},
    )
    assert refused.status_code == 403

    # Reading them is the scan form's vocabulary, so a viewer may.
    _create_group(client, "pci")
    listed = client.get("/api/agent-groups", headers=auth_headers(client, "viewer"))
    assert listed.status_code == 200
    assert [item["name"] for item in listed.json()] == ["pci"]
    assert listed.json()[0]["agent_count"] == 0


def test_a_group_name_is_normalised_and_unique(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    duplicate = client.post(
        "/api/agent-groups", headers=auth_headers(client, "admin"), json={"name": "PCI"}
    )
    assert duplicate.status_code == 422, duplicate.text
    invalid = client.post(
        "/api/agent-groups", headers=auth_headers(client, "admin"), json={"name": "pci segment"}
    )
    assert invalid.status_code == 422


def test_deleting_a_group_anything_still_names_is_refused(tmp_path, monkeypatch):
    """A cascade here would turn a deletion into a silent widening: a scope
    entry restricted to a group that no longer exists permits any agent."""
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    admin = auth_headers(client, "admin")

    agent_id = _register(client, "pci-1")
    _assign(client, agent_id, "pci")
    held = client.delete("/api/agent-groups/pci", headers=admin)
    assert held.status_code == 409
    assert "agent" in held.json()["detail"]

    _assign(client, agent_id, None)
    approve_scan_scope(
        settings,
        entries=[
            {"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8", "agent_groups": ["pci"]},
            {"effect": "allow", "kind": "domain", "value": "*"},
        ],
    )
    required = client.delete("/api/agent-groups/pci", headers=admin)
    assert required.status_code == 409
    assert "scan-scope" in required.json()["detail"]

    approve_scan_scope(settings)
    assert client.delete("/api/agent-groups/pci", headers=admin).status_code == 200
    assert client.delete("/api/agent-groups/pci", headers=admin).status_code == 404


def test_the_group_changes_are_in_the_audit_trail(tmp_path, monkeypatch):
    """Membership decides which worker may execute which customer's scan, so
    moving an agent between groups is an access-control change (#327)."""
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    agent_id = _register(client, "pci-1")
    _assign(client, agent_id, "pci")

    events = client.get(
        "/api/audit?limit=100", headers=auth_headers(client, "admin")
    ).json()
    actions = {item["action"] for item in events["items"]}
    assert {"agent_group.create", "agent_group.assign"} <= actions


# ---------------------------------------------------------------------------
# Schedules
# ---------------------------------------------------------------------------


def test_a_schedule_carries_its_agent_group_and_refuses_an_unknown_one(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    headers = auth_headers(client, "operator")

    created = client.post(
        "/api/schedules",
        headers=headers,
        json={
            "name": "nightly",
            "interval_seconds": 3600,
            "domains": "example.com",
            "agent_group": "pci",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["scan_options"]["agent_group"] == "pci"

    refused = client.post(
        "/api/schedules",
        headers=headers,
        json={"name": "bad", "interval_seconds": 3600, "agent_group": "ghost"},
    )
    assert refused.status_code == 422, refused.text
    assert "ghost" in refused.json()["detail"]


def test_an_existing_schedule_without_a_group_keeps_dispatching(tmp_path, monkeypatch):
    """The upgrade path: a schedule written before #361 has no ``agent_group``
    in its options and dispatches a job any agent of the tenant may claim."""
    from api.schemas import StartScanRequest
    from api.services import jobs as jobs_service
    from api.services import scan_schedules

    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    agent_id = _register(client, "legacy-1")

    created = client.post(
        "/api/schedules",
        headers=auth_headers(client, "operator"),
        json={"name": "nightly", "interval_seconds": 3600, "domains": "example.com"},
    )
    assert created.status_code == 201, created.text
    stored = scan_schedules.get_schedule(created.json()["schedule_id"])
    # A schedule written before #361 simply has no entry for the key; drop it
    # to make this one of those rather than one carrying an explicit null.
    options = {k: v for k, v in stored["scan_options"].items() if k != "agent_group"}

    # The dispatcher's own replay, without waiting for its poll loop: what is
    # under test is that stored options still build a startable request.
    request = StartScanRequest(tenant_id=stored["tenant_id"], **options, **stored["targets"])
    job = jobs_service.start_scan(settings, request, username="scheduler")
    assert job.agent_group is None

    claimed = _claim(client, agent_id)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == job.job_id
