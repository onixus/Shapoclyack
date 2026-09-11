"""Agent groups: which of a tenant's agents may execute which of its jobs (#361).

Before this, ``claim_job`` filtered by tenant and by "queued" and nothing else,
so every agent of a tenant could take every job of that tenant. Each test below
pins one half of the control that replaces it — the claim filter, the selector
the server refuses to take on trust, and the scope entry that decides which
group a set of targets may be reached from. The first three fail on the
pre-#361 code, which is what makes them worth having.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.db import models
from api.db.engine import get_session
from api.services import agent_groups, scan_schedules, scan_scopes
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


# ---------------------------------------------------------------------------
# The configuration every upgraded installation actually has
# ---------------------------------------------------------------------------

#: What migration 0025 writes onto every tenant that predates the scope table
#: (``_GRANDFATHER_ENTRIES``). Reproduced literally, because the defect this
#: pins was invisible to every test that approved a scope by hand: a scan of a
#: restricted range found the restricted entry *and* ``0.0.0.0/0``, and the
#: rule "the widest covering entry wins" then handed the job to any agent. The
#: control was dead on arrival on every upgraded installation, with a 200 and
#: an audit line saying it had been applied.
_GRANDFATHERED = [
    {
        "effect": "allow",
        "kind": "cidr",
        "value": "0.0.0.0/0",
        "note": "grandfathered on upgrade to 0025 (#226) — narrow this",
    },
    {
        "effect": "allow",
        "kind": "cidr",
        "value": "::/0",
        "note": "grandfathered on upgrade to 0025 (#226) — narrow this",
    },
    {
        "effect": "allow",
        "kind": "domain",
        "value": "*",
        "note": "grandfathered on upgrade to 0025 (#226) — narrow this",
    },
]


def test_a_restriction_is_not_cancelled_by_the_grandfathered_allow_all(tmp_path, monkeypatch):
    """The narrowest covering entry decides, so the first restriction an
    operator writes on an upgraded installation actually restricts."""
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    _create_group(client, "office")
    approve_scan_scope(
        settings,
        entries=[
            *_GRANDFATHERED,
            {"effect": "allow", "kind": "cidr", "value": "10.1.0.0/16", "agent_groups": ["pci"]},
            {
                "effect": "allow",
                "kind": "domain",
                "value": "pci.example.com",
                "agent_groups": ["pci"],
            },
        ],
    )

    restricted = _start_scan(client, domains=None, ranges="10.1.2.0/24")
    assert restricted.status_code == 202, restricted.text
    assert restricted.json()["agent_group"] == "pci"

    # A suffix match under a restricted domain entry, against ``domain *``.
    by_domain = _start_scan(client, domains="api.pci.example.com")
    assert by_domain.status_code == 202, by_domain.text
    assert by_domain.json()["agent_group"] == "pci"

    # And it is not a restriction on everything: a target the operator never
    # narrowed is still claimable by any agent, which is the upgrade promise.
    untouched = _start_scan(client, domains=None, ranges="192.168.5.0/24")
    assert untouched.status_code == 202, untouched.text
    assert untouched.json()["agent_group"] is None

    # The claim filter then holds for real, which is the point of the whole
    # thing: the office agent gets the unrestricted job and, once that is gone,
    # is told there is nothing for it — never one of the two pci jobs.
    office = _register(client, "office-1")
    _assign(client, office, "office")
    first = _claim(client, office)
    assert first.status_code == 200, first.text
    assert first.json()["job_id"] == untouched.json()["job_id"]
    assert _claim(client, office).status_code == 204


def test_a_promoted_domain_does_not_decide_which_group_must_run_the_scan(
    tmp_path, monkeypatch
):
    """A promoted related domain rides along with every scan the tenant starts,
    so letting it contribute to the requirement sent an ordinary external scan
    out from the card-data segment — the reverse of the control — and two
    promoted domains restricted to different groups intersected to nothing and
    refused every scan the tenant had, with advice the operator could not
    follow: the form has no way to leave a promoted domain out.
    """
    from api.services import promoted_domains

    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    _create_group(client, "ops-eu")
    approve_scan_scope(settings, entries=_GRANDFATHERED)
    for domain in ("pci.example.com", "ops.example.com"):
        promoted_domains.promote(
            settings,
            tenant_id="default",
            domain=domain,
            source_run_id="run_1",
            promoted_by="operator",
        )
    approve_scan_scope(
        settings,
        entries=[
            *_GRANDFATHERED,
            {
                "effect": "allow",
                "kind": "domain",
                "value": "pci.example.com",
                "agent_groups": ["pci"],
            },
            {
                "effect": "allow",
                "kind": "domain",
                "value": "ops.example.com",
                "agent_groups": ["ops-eu"],
            },
        ],
    )

    started = _start_scan(client, domains="www.example.com")
    assert started.status_code == 202, started.text
    # Both promoted domains are in the scan…
    assert set(started.json()["scan_options"]["promoted_domains"]) == {
        "ops.example.com",
        "pci.example.com",
    }
    # …and neither decides who executes it.
    assert started.json()["agent_group"] is None

    # A target the operator *did* type still carries its own restriction.
    typed = _start_scan(client, domains="api.pci.example.com")
    assert typed.status_code == 202, typed.text
    assert typed.json()["agent_group"] == "pci"


# ---------------------------------------------------------------------------
# Deleting a group, and what still names it
# ---------------------------------------------------------------------------


def test_deleting_a_group_an_unfinished_job_is_addressed_to_is_refused(tmp_path, monkeypatch):
    """The job would become unclaimable or, worse, claimable by anybody."""
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    admin = auth_headers(client, "admin")

    started = _start_scan(client, agent_group="pci")
    assert started.status_code == 202, started.text

    held = client.delete("/api/agent-groups/pci", headers=admin)
    assert held.status_code == 409, held.text
    assert "unfinished job" in held.json()["detail"]

    cancelled = client.post(
        f"/api/jobs/{started.json()['job_id']}/cancel", headers=auth_headers(client, "operator")
    )
    assert cancelled.status_code == 200, cancelled.text
    assert client.delete("/api/agent-groups/pci", headers=admin).status_code == 200


def test_deleting_a_group_a_schedule_dispatches_to_is_refused(tmp_path, monkeypatch):
    """Nothing else catches it. The dispatcher builds its request from options
    stored days ago, ``start_scan`` refuses the unknown group, ``_tick``
    swallows it into ``errors`` and leaves ``next_run_at`` alone — so the
    schedule fails on every poll forever and the only symptom is that the
    nightly scans stopped appearing."""
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")
    admin = auth_headers(client, "admin")

    created = client.post(
        "/api/schedules",
        headers=auth_headers(client, "operator"),
        json={
            "name": "nightly",
            "interval_seconds": 3600,
            "domains": "example.com",
            "agent_group": "pci",
        },
    )
    assert created.status_code == 201, created.text

    held = client.delete("/api/agent-groups/pci", headers=admin)
    assert held.status_code == 409, held.text
    assert "schedule" in held.json()["detail"]

    removed = client.delete(f"/api/schedules/{created.json()['schedule_id']}", headers=admin)
    assert removed.status_code in (200, 204), removed.text
    assert client.delete("/api/agent-groups/pci", headers=admin).status_code == 200


# ---------------------------------------------------------------------------
# The dispatcher, called rather than imitated
# ---------------------------------------------------------------------------


def test_the_dispatcher_carries_the_schedules_group_onto_the_job(tmp_path, monkeypatch):
    """Through ``ScheduleDispatcher._tick`` itself, not through a hand-rolled
    replay of it: the three lists of option keys this has to pass
    (``routes/schedules``, ``scan_schedules``, and what ``StartScanRequest``
    accepts) can drift apart, and a test that rebuilds the request itself would
    agree with every one of those drifts."""
    from api.services import schedule_dispatcher

    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    agent_id = _register(client, "pci-1")
    _assign(client, agent_id, "pci")

    created = client.post(
        "/api/schedules",
        headers=auth_headers(client, "operator"),
        json={
            "name": "nightly",
            "interval_seconds": 60,
            "domains": "example.com",
            "agent_group": "pci",
        },
    )
    assert created.status_code == 201, created.text
    schedule_id = created.json()["schedule_id"]
    # Due now: record a dispatch an hour ago, so the next run is in the past.
    scan_schedules.record_dispatch(
        schedule_id, job_id=None, ran_at=datetime.now(UTC) - timedelta(hours=1)
    )

    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert dispatcher.stats["errors"] == 0
    dispatched = scan_schedules.get_schedule(schedule_id)["last_job_id"]
    assert dispatched, "the schedule dispatched nothing"
    job = client.get(f"/api/jobs/{dispatched}", headers=auth_headers(client, "operator")).json()
    assert job["agent_group"] == "pci"

    # And the group's agent is the one that can take it.
    claimed = _claim(client, agent_id)
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job_id"] == dispatched


# ---------------------------------------------------------------------------
# The NATS offer
# ---------------------------------------------------------------------------


def test_the_offer_names_the_job_and_not_its_targets(tmp_path, monkeypatch):
    """The offer used to carry ``inputs`` — the whole target list — into the
    tenant's shared subject, where any agent read it before being refused the
    claim. It now names the group instead, which decides the subject, and the
    targets travel only in the claim response."""
    from api.services import jobs as jobs_service
    from api.services import nats_bus

    published: list[dict] = []

    class _Bus:
        def publish_job_offer(self, payload: dict) -> bool:
            published.append(payload)
            return True

    monkeypatch.setattr(nats_bus, "get_bus", lambda url: _Bus())
    client = _client(tmp_path, monkeypatch, nats_url="nats://unused:4222")
    _create_group(client, "pci")

    started = _start_scan(client, agent_group="pci", domains="example.com")
    assert started.status_code == 202, started.text

    assert len(published) == 1
    offer = published[0]
    assert offer["job_id"] == started.json()["job_id"]
    assert offer["agent_group"] == "pci"
    assert "inputs" not in offer
    assert "example.com" not in json.dumps(offer)
    # The subject the bus will use is the group's own, so no other agent of the
    # tenant is even woken by it.
    assert (
        nats_bus.jobs_scan_subject(offer["tenant_id"], offer["agent_group"])
        == "jobs.scan.default.pci"
    )
    # And the claim response is where the targets are, for the one agent the
    # API bound the job to.
    agent_id = _register(client, "pci-1")
    _assign(client, agent_id, "pci")
    claimed = jobs_service.claim_job(_settings(tmp_path), agent_id, job_id=offer["job_id"])
    assert claimed is not None and claimed.inputs


# ---------------------------------------------------------------------------
# "Nothing is listening" is a fact about now
# ---------------------------------------------------------------------------


def test_the_unavailable_flag_clears_when_an_agent_joins_the_group(tmp_path, monkeypatch):
    """It was computed once, at queue time, and stored in ``scan_options``: a
    job queued while the group's only agent was restarting went on reporting
    "nothing can execute this" for the rest of its life, including after it had
    been claimed and run."""
    client = _client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")
    _create_group(client, "pci")

    started = _start_scan(client, agent_group="pci")
    assert started.status_code == 202, started.text
    job_id = started.json()["job_id"]
    assert started.json()["agent_group_unavailable"] is True

    agent_id = _register(client, "pci-1")
    _assign(client, agent_id, "pci")

    job = client.get(f"/api/jobs/{job_id}", headers=operator).json()
    assert job["agent_group_unavailable"] is False
    listed = client.get("/api/jobs?limit=50", headers=operator).json()["items"]
    assert [item["agent_group_unavailable"] for item in listed if item["job_id"] == job_id] == [
        False
    ]
    # Nothing stale was written onto the job either.
    assert "agent_group_unavailable" not in (job["scan_options"] or {})


# ---------------------------------------------------------------------------
# One name, one spelling, and no way to write a reference to a group that is
# being deleted underneath it
# ---------------------------------------------------------------------------


def test_a_group_is_deleted_by_the_name_it_was_created_with(tmp_path, monkeypatch):
    """Creating normalised the name and reading it did not, so an operator who
    re-sent the exact string they had just posted was told there was no such
    group."""
    client = _client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    created = client.post(
        "/api/agent-groups", headers=admin, json={"name": "  PCI  "}
    )
    assert created.status_code == 201, created.text
    assert created.json()["name"] == "pci"

    deleted = client.delete("/api/agent-groups/PCI", headers=admin)
    assert deleted.status_code == 200, deleted.text
    assert client.get("/api/agent-groups", headers=admin).json() == []

    # A name no group could have is a malformed request, not a busy group —
    # the delete route answers 409 for "still in use" and must not reuse it
    # here.
    malformed = client.delete("/api/agent-groups/pci%20segment", headers=admin)
    assert malformed.status_code == 422, malformed.text


def test_the_loser_of_a_simultaneous_create_is_told_the_name_is_taken(
    tmp_path, monkeypatch
):
    """``create_group`` checks and then inserts. Two requests for one name both
    pass the check — each reads a snapshot taken before the other's insert —
    and the loser met ``uq_agent_groups_tenant_name`` as an unhandled
    IntegrityError, i.e. a 500 for a request whose only fault is being second.
    """
    client = _client(tmp_path, monkeypatch)
    _create_group(client, "pci")

    # The loser's view of the table, reproduced: the existence check finds
    # nothing and the unique index is what decides.
    monkeypatch.setattr(agent_groups, "_row_by_name", lambda *a, **kw: None)
    duplicate = client.post(
        "/api/agent-groups", headers=auth_headers(client, "admin"), json={"name": "pci"}
    )
    assert duplicate.status_code == 422, duplicate.text
    assert "already exists" in duplicate.json()["detail"]


def test_a_scope_cannot_be_approved_against_a_group_deleted_while_it_validated(
    tmp_path, monkeypatch
):
    """The TOCTOU between the two writers.

    ``replace_scope`` used to check its group names on a connection of its own
    and then open a second one to write. A ``DELETE /api/agent-groups/pci``
    landing in that window finds no scope entry among its blockers — the entry
    is not inserted yet — and removes the row; the entry is then committed
    against a group that no longer exists. Nothing reports it, and every scan
    of those targets is queued to a group no agent can be put into.

    The window is the gap between validation and the writing session, so the
    deletion is fired from inside it.
    """
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")

    real_now = scan_scopes._now

    def _delete_the_group_mid_flight():
        # Called once, after the entries are validated and before the session
        # that writes them is opened.
        monkeypatch.setattr(scan_scopes, "_now", real_now)
        with get_session(settings.postgres_url) as session:
            session.query(models.AgentGroup).filter(
                models.AgentGroup.name == "pci"
            ).delete()
        return real_now()

    monkeypatch.setattr(scan_scopes, "_now", _delete_the_group_mid_flight)

    with pytest.raises(ValueError, match="unknown agent group"):
        approve_scan_scope(
            settings,
            entries=[
                {
                    "effect": "allow",
                    "kind": "cidr",
                    "value": "10.1.0.0/16",
                    "agent_groups": ["pci"],
                },
            ],
        )
    # Refused wholesale: the scope the tenant already had is untouched, and no
    # entry anywhere in it names the group that went.
    assert not [
        entry
        for entry in scan_scopes.list_entries(settings, "default")
        if entry["agent_groups"]
    ]


def test_a_scan_restricted_to_a_group_that_is_gone_is_refused_not_queued(
    tmp_path, monkeypatch
):
    """The residual case, however the scope came to name a missing group.

    With one candidate the resolver used to take the scope's word for it
    without checking the group still exists, so the job was queued to a name
    nothing can join — ``set_agent_group`` refuses an unknown group — and it
    was never claimed by anybody, with nothing in the job to say why.
    """
    client = _client(tmp_path, monkeypatch)
    settings = _settings(tmp_path)
    _create_group(client, "pci")
    approve_scan_scope(
        settings,
        entries=[
            {
                "effect": "allow",
                "kind": "cidr",
                "value": "10.1.0.0/16",
                "agent_groups": ["pci"],
            },
        ],
    )
    # Around the service, which would refuse the deletion: this is the state,
    # not the path that reaches it.
    with get_session(settings.postgres_url) as session:
        session.query(models.AgentGroup).filter(
            models.AgentGroup.name == "pci"
        ).delete()

    refused = _start_scan(client, domains=None, ranges="10.1.2.0/24")
    assert refused.status_code == 403, refused.text
    assert "pci" in refused.json()["detail"]
