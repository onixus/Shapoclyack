"""Remediation campaigns (#579, stage 2).

What these tests are for, in the order the issue's acceptance list states it:
the composition is frozen and previewed exactly; a retried create does not
duplicate; membership changes are explicit, attributed and survive a restart;
a campaign's date and edits never touch a finding's SLA/owner/exception;
progress categories are separate and a ticket or a finished campaign never
makes anything machine-verified; a recurrence returns the campaign to work;
another tenant's data does not leak through ids, counts or filters.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from api.db import models
from api.db.engine import get_engine, get_session
from api.services import remediation_campaigns as campaigns
from api.services import tenants as tenants_service
from api.services import vulnerabilities as vulns
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)
from tests.test_problems import add_finding, seed_fleet

pytestmark = requires_postgres

URL = "/api/remediation-campaigns"


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


@pytest.fixture
def env(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    settings = make_settings(tmp_path)
    tenant_id = tenants_service.DEFAULT_TENANT_ID
    ids = seed_fleet(settings, tenant_id)
    operator = auth_headers(client, "operator")
    return client, settings, tenant_id, ids, operator


def _create(client, headers, selection, *, name="Upgrade openssl", key=None, **extra):
    request_headers = dict(headers)
    if key:
        request_headers["Idempotency-Key"] = key
    return client.post(
        URL, json={"name": name, "selection": selection, **extra}, headers=request_headers
    )


def _campaign(client, headers, campaign_id) -> dict:
    response = client.get(f"{URL}/{campaign_id}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _members(client, headers, campaign_id, **params) -> dict:
    response = client.get(
        f"{URL}/{campaign_id}/members", params={"limit": 200, **params}, headers=headers
    )
    assert response.status_code == 200, response.text
    return response.json()


def _events(client, headers, campaign_id) -> list[dict]:
    response = client.get(f"{URL}/{campaign_id}/events", params={"limit": 200}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["items"]


def _set(settings, vuln_id, **fields):
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        for name, value in fields.items():
            setattr(row, name, value)
        row.updated_at = _now()


C1 = {"problem_keys": ["cve:CVE-2024-1111"]}


# --------------------------------------------------------------------------
# Preview and snapshot
# --------------------------------------------------------------------------


def test_preview_is_the_exact_composition_and_foreign_ids_look_like_missing_ones(env):
    client, settings, tenant_id, ids, operator = env
    other = tenants_service.create_tenant(tenant_id="ten_b", name="B")["tenant_id"]
    with get_session(settings.postgres_url) as session:
        foreign = add_finding(session, other, "b1", cve="CVE-2024-1111")
    _set(settings, ids["c2"][1], state="CLOSED", closed_at=_now())

    preview = client.post(
        f"{URL}/preview",
        json={**C1, "vuln_ids": [foreign, "vln_missing", ids["c2"][1], ids["c2"][0]]},
        headers=operator,
    ).json()

    assert preview["total"] == 5  # 4 by problem + 1 explicit open finding
    assert preview["assets"] == 3
    assert {i["vuln_id"] for i in preview["items"]} == set(ids["c1"]) | {ids["c2"][0]}
    skipped = {s["id"]: s["reason"] for s in preview["skipped"]}
    # Another tenant's finding is answered exactly like one that never existed.
    assert skipped[foreign] == skipped["vln_missing"] == "not_found"
    assert skipped[ids["c2"][1]] == "closed"
    import hashlib

    assert preview["composition_hash"] == hashlib.sha256(
        "\n".join(sorted({*ids["c1"], ids["c2"][0]})).encode()
    ).hexdigest()
    assert [p["problem_key"] for p in preview["problems"]][0] == "cve:CVE-2024-1111"


def test_snapshot_is_frozen_new_matching_findings_are_not_added(env):
    client, settings, tenant_id, ids, operator = env
    preview = client.post(f"{URL}/preview", json=C1, headers=operator).json()
    created = _create(client, operator, C1, composition_hash=preview["composition_hash"])
    assert created.status_code == 201, created.text
    campaign = created.json()
    assert campaign["snapshot_size"] == 4 and campaign["progress"]["total"] == 4

    with get_session(settings.postgres_url) as session:
        late = add_finding(session, tenant_id, "a8", cve="CVE-2024-1111")

    after = _campaign(client, operator, campaign["campaign_id"])
    assert after["progress"]["total"] == 4
    assert late not in {m["vuln_id"] for m in _members(client, operator, campaign["campaign_id"])["items"]}
    # The same selection now resolves to five; the reviewed preview is stale.
    stale = _create(client, operator, C1, composition_hash=preview["composition_hash"])
    assert stale.status_code == 409
    assert "preview again" in stale.json()["detail"]
    fresh = client.post(f"{URL}/preview", json=C1, headers=operator).json()
    assert fresh["total"] == 5 and fresh["composition_hash"] != preview["composition_hash"]


def test_an_empty_or_unknown_selection_is_refused(env):
    client, _, _, _, operator = env
    assert _create(client, operator, {}).status_code == 422
    assert _create(client, operator, {"problem_keys": ["cve:CVE-2099-9999"]}).status_code == 422
    assert _create(client, operator, {"problem_keys": ["bogus"]}).status_code == 422
    assert _create(client, operator, {"vuln_ids": ["vln_nope"]}).status_code == 422
    bad_filter = _create(client, operator, {**C1, "filters": {"nonsense": 1}})
    assert bad_filter.status_code == 422
    assert client.get(URL, headers=operator).json()["total"] == 0


def test_filters_restrict_the_problem_expansion_and_closed_findings_are_never_eligible(env):
    client, settings, _, ids, operator = env
    _set(settings, ids["c1"][3], state="CLOSED", closed_at=_now())
    default = client.post(f"{URL}/preview", json=C1, headers=operator).json()
    assert default["total"] == 3  # the closed instance is not eligible
    narrowed = client.post(
        f"{URL}/preview", json={**C1, "filters": {"severity": "high"}}, headers=operator
    ).json()
    assert narrowed["total"] == 2


# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------


def test_a_retried_create_replays_instead_of_duplicating(env):
    client, _, _, _, operator = env
    first = _create(client, operator, C1, key="retry-me")
    again = _create(client, operator, C1, key="retry-me")

    assert first.status_code == 201 and again.status_code == 200
    assert again.json()["campaign_id"] == first.json()["campaign_id"]
    assert again.json()["replayed"] is True
    assert client.get(URL, headers=operator).json()["total"] == 1

    # The same key for a different body is refused, not silently replayed.
    different = _create(client, operator, C1, key="retry-me", name="Something else")
    assert different.status_code == 409
    assert client.get(URL, headers=operator).json()["total"] == 1


def test_the_same_key_in_two_tenants_makes_two_campaigns_without_leaking_either(env):
    client, settings, tenant_id, ids, operator = env
    other = tenants_service.create_tenant(tenant_id="ten_b", name="B")["tenant_id"]
    with get_session(settings.postgres_url) as session:
        theirs = add_finding(session, other, "b1", cve="CVE-2024-1111")
    admin = auth_headers(client, "admin")
    for tenant in ("ten_b", tenant_id):
        granted = client.put(f"/api/tenants/{tenant}/members/operator", headers=admin, json={"role": "operator"})
        assert granted.status_code == 200, granted.text
    headers = {**operator, "Idempotency-Key": "shared-key"}
    mine = client.post(URL, params={"tenant_id": tenant_id}, headers=headers,
                       json={"name": "same", "selection": {"vuln_ids": ids["c1"]}})
    foreign = client.post(URL, params={"tenant_id": "ten_b"}, headers=headers,
                          json={"name": "same", "selection": {"vuln_ids": [theirs]}})
    assert mine.status_code == 201 and foreign.status_code == 201, foreign.text
    assert mine.json()["campaign_id"] != foreign.json()["campaign_id"]
    assert foreign.json()["snapshot_size"] == 1 and "replayed" not in foreign.json()
    # Each tenant's retry replays its own answer, never the other's.
    again = client.post(URL, params={"tenant_id": "ten_b"}, headers=headers,
                        json={"name": "same", "selection": {"vuln_ids": [theirs]}})
    assert again.status_code == 200 and again.json()["campaign_id"] == foreign.json()["campaign_id"]
    assert client.get(URL, params={"tenant_id": "ten_b"}, headers=operator).json()["total"] == 1
    assert client.get(URL, params={"tenant_id": tenant_id}, headers=operator).json()["total"] == 1


def test_a_failed_create_gives_its_key_back(env):
    client, _, _, _, operator = env
    refused = _create(client, operator, {"problem_keys": ["cve:CVE-2099-9999"]}, key="k1")
    assert refused.status_code == 422
    ok = _create(client, operator, C1, key="k1")
    assert ok.status_code == 201


def test_without_a_key_two_creates_are_two_campaigns(env):
    client, _, _, _, operator = env
    assert _create(client, operator, C1).status_code == 201
    assert _create(client, operator, C1).status_code == 201
    assert client.get(URL, headers=operator).json()["total"] == 2


# --------------------------------------------------------------------------
# Membership: explicit, attributed, durable
# --------------------------------------------------------------------------


def test_adding_and_excluding_is_explicit_attributed_audited_and_never_double_counts(env):
    client, settings, tenant_id, ids, operator = env
    campaign = _create(client, operator, {"vuln_ids": ids["c1"][:2]}).json()
    cid = campaign["campaign_id"]
    assert campaign["progress"]["total"] == 2

    # A reason is mandatory for every membership change.
    assert client.post(
        f"{URL}/{cid}/members", json={"selection": {"vuln_ids": [ids["c1"][2]]}, "reason": ""},
        headers=operator,
    ).status_code == 422

    added = client.post(
        f"{URL}/{cid}/members",
        json={"selection": {"vuln_ids": [ids["c1"][2], ids["c1"][0], "vln_missing"]},
              "reason": "same host class"},
        headers=operator,
    ).json()
    outcomes = {r["id"]: r["outcome"] for r in added["results"]}
    assert outcomes[ids["c1"][2]] == "added"
    assert outcomes[ids["c1"][0]] == "already_member"  # no double count
    assert outcomes["vln_missing"] == "not_found"
    assert added["campaign"]["progress"]["total"] == 3

    gone = client.post(
        f"{URL}/{cid}/members/exclude",
        json={"vuln_ids": [ids["c1"][1], ids["c1"][3]], "reason": "decommissioned host"},
        headers=operator,
    ).json()
    assert {r["id"]: r["outcome"] for r in gone["results"]} == {
        ids["c1"][1]: "excluded", ids["c1"][3]: "not_member"
    }
    assert gone["campaign"]["progress"]["total"] == 2
    assert gone["campaign"]["progress"]["excluded"] == 1

    # Re-including the excluded finding restores it once.
    back = client.post(
        f"{URL}/{cid}/members",
        json={"selection": {"vuln_ids": [ids["c1"][1]]}, "reason": "host is back"},
        headers=operator,
    ).json()
    assert {r["id"]: r["outcome"] for r in back["results"]} == {ids["c1"][1]: "readded"}
    assert back["campaign"]["progress"]["total"] == 3
    assert back["campaign"]["progress"]["excluded"] == 0
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(func.count()).select_from(models.RemediationCampaignMember)
            .where(models.RemediationCampaignMember.campaign_id == cid)
        ).scalar_one()
    assert rows == 3  # one row per (campaign, finding), whatever the history

    events = _events(client, operator, cid)
    kinds = [e["kind"] for e in events]
    assert kinds == ["members_added", "members_excluded", "members_added", "created"]
    exclusion = next(e for e in events if e["kind"] == "members_excluded")
    assert exclusion["actor"] == "operator" and exclusion["reason"] == "decommissioned host"
    assert ids["c1"][1] in exclusion["detail"]["excluded"]["ids"]
    assert exclusion["occurred_at"].endswith("Z")

    with get_session(settings.postgres_url) as session:
        actions = session.execute(
            select(models.AuditEvent.action, models.AuditEvent.actor)
            .where(models.AuditEvent.resource_id == cid)
        ).all()
    assert sorted(a for a, _ in actions) == [
        "campaign.create", "campaign.members", "campaign.members", "campaign.members"
    ]
    assert {actor for _, actor in actions} == {"operator"}


def test_the_history_survives_a_restart(env):
    client, settings, tenant_id, ids, operator = env
    cid = _create(client, operator, {"vuln_ids": ids["c1"][:2]}).json()["campaign_id"]
    client.post(f"{URL}/{cid}/members/exclude",
                json={"vuln_ids": [ids["c1"][0]], "reason": "not ours"}, headers=operator)
    before = _events(client, operator, cid)
    # A restart drops every pooled connection and in-process cache; what is
    # left is what the database holds.
    get_engine(settings.postgres_url).dispose()
    assert _events(client, operator, cid) == before
    assert _campaign(client, operator, cid)["progress"]["total"] == 1
    members = _members(client, operator, cid, status="excluded")["items"]
    assert [m["vuln_id"] for m in members] == [ids["c1"][0]]
    assert members[0]["excluded_by"] == "operator" and members[0]["exclude_reason"] == "not ours"


# --------------------------------------------------------------------------
# A campaign never rewrites a finding
# --------------------------------------------------------------------------


def test_campaign_dates_and_edits_leave_finding_sla_owner_and_exception_alone(env):
    client, settings, tenant_id, ids, operator = env
    target = ids["c1"][0]
    until = _now() + timedelta(days=20)
    _set(settings, target, assignee="ada", owner_team="platform", exception_until=until,
         exception_state="exception_approved", exception_reason="vendor patch", exception_by="boss")
    before = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=target)

    cid = _create(
        client, operator, {"vuln_ids": [target]},
        due_at=(datetime.now(UTC) - timedelta(days=5)).isoformat(),  # already past
        owner="grace", description="upgrade to 3.0.14",
    ).json()["campaign_id"]
    patched = client.patch(
        f"{URL}/{cid}", json={"owner": "linus", "due_at": None, "description": "and restart"},
        headers=operator,
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["owner"] == "linus" and patched.json()["due_at"] is None
    assert client.patch(f"{URL}/{cid}", json={"bogus": 1}, headers=operator).status_code == 422

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=target)
    for field in ("due_at", "sla_days", "sla_source", "sla_state", "assignee", "owner_team",
                  "exception_until", "exception_state", "exception_reason", "exception_by", "state"):
        assert after[field] == before[field], field
    created = _campaign(client, operator, cid)
    assert created["description"] == "and restart"
    kinds = [e["kind"] for e in _events(client, operator, cid)]
    # The only member is an accepted risk, which counts as resolved.
    assert kinds == ["updated", "completed", "created"]


def test_a_past_due_campaign_is_flagged_but_not_a_finding_breach(env):
    client, settings, tenant_id, ids, operator = env
    created = _create(client, operator, {"vuln_ids": [ids["c1"][0]]},
                      due_at=(datetime.now(UTC) - timedelta(days=1)).isoformat()).json()
    assert created["past_due"] is True
    finding = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=ids["c1"][0])
    assert finding["sla_state"] == "on_track"


# --------------------------------------------------------------------------
# Progress categories
# --------------------------------------------------------------------------


def _shape_every_category(settings, ids):
    now = _now()
    c1, c2, tpl, unk = ids["c1"], ids["c2"], ids["tpl"], ids["unknown"]
    _set(settings, c1[1], state="FIXING")
    _set(settings, c1[2], state="VERIFYING", verification_job_id="job-1")
    _set(settings, c1[3], state="CLOSED", closed_at=now, machine_verified=True,
         closure_reason="verified_remediated", last_verified_at=now)
    _set(settings, c2[0], exception_until=now + timedelta(days=10), exception_state="exception_approved")
    _set(settings, c2[1], state="CLOSED", closed_at=now, closure_reason="false_positive",
         fp_suppress_until=now + timedelta(days=30))
    _set(settings, tpl[0], state="CLOSED", closed_at=now, closure_reason="manual")
    _set(settings, tpl[1], state="CLOSED", closed_at=now, closure_reason="ticket_resolved",
         ticket_system="jira", ticket_key="SEC-1", ticket_url="https://jira.example.com/browse/SEC-1")
    _set(settings, unk[0], state="CLOSED", closed_at=now, closure_reason="endpoint_unreachable")
    _set(settings, unk[1], state="FIXING", state_changed_at=now)
    with get_session(settings.postgres_url) as session:
        session.add(models.VulnerabilityEvent(
            vuln_id=unk[1], tenant_id="default", occurred_at=now, kind="verification_inconclusive",
            from_state="VERIFYING", to_state="FIXING", actor="system:verification",
            note="coverage incomplete", detail={"gaps": ["nuclei template not run"]},
        ))


def test_progress_categories_are_separate_and_never_summed_into_fixed(env):
    client, settings, tenant_id, ids, operator = env
    every = [i for group in ids.values() for i in group]
    cid = _create(client, operator, {"vuln_ids": every}).json()["campaign_id"]
    assert _campaign(client, operator, cid)["progress"]["categories"]["open"] == 10
    _shape_every_category(settings, ids)

    progress = _campaign(client, operator, cid)["progress"]
    assert progress["categories"] == {
        "open": 1,            # c1[0] untouched
        "fixing": 1,          # c1[1]
        "awaiting_verification": 1,  # c1[2]
        "verified": 1,        # c1[3]: closed AND machine verified
        "accepted_risk": 1,   # c2[0]
        "false_positive": 1,  # c2[1]
        "closed_unverified": 2,  # manual close and ticket resolution
        "unavailable": 2,     # unreachable closure and inconclusive verification
    }
    assert progress["total"] == 10 == sum(progress["categories"].values())
    # Nothing summed into a "fixed" figure.
    assert not {"fixed", "done", "resolved", "percent_complete"} & set(progress)
    assert progress["unresolved"] == 7
    assert progress["tickets"] == {"linked_findings": 1, "distinct_tickets": 1}

    by_cat = {c: _members(client, operator, cid, category=c)["items"] for c in campaigns.CATEGORIES}
    assert {len(v) for v in by_cat.values()} == {1, 2}
    ticket_member = by_cat["closed_unverified"][0] if by_cat["closed_unverified"][0]["ticket_key"] else by_cat["closed_unverified"][1]
    assert ticket_member["ticket_key"] == "SEC-1" and ticket_member["machine_verified"] is False
    gap_member = by_cat["unavailable"][0] if by_cat["unavailable"][0]["verification"] else by_cat["unavailable"][1]
    assert gap_member["verification"]["kind"] == "verification_inconclusive"
    assert gap_member["verification"]["gaps"] == ["nuclei template not run"]
    assert client.get(f"{URL}/{cid}/members", params={"category": "fixed"}, headers=operator).status_code == 422


def test_a_ticket_resolution_and_a_manual_close_never_make_a_member_verified(env):
    client, settings, tenant_id, ids, operator = env
    cid = _create(client, operator, {"vuln_ids": ids["c2"]}).json()["campaign_id"]
    first, second = ids["c2"]
    for vuln_id in (first, second):
        for state in ("ACKNOWLEDGED", "PLANNED", "FIXING"):
            vulns.transition(settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=state, actor="a")
    vulns.transition(settings, tenant_id=tenant_id, vuln_id=first, to_state="CLOSED", actor="a")
    _set(settings, second, ticket_system="jira", ticket_key="SEC-9")
    vulns.apply_ticket_status(
        settings, tenant_id=tenant_id, vuln_id=second, suggested_state="CLOSED", raw_status="Done"
    )
    progress = _campaign(client, operator, cid)["progress"]
    assert progress["categories"]["verified"] == 0
    assert progress["categories"]["closed_unverified"] == 2
    row = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=second)
    assert row["closure_reason"] == "ticket_resolved" and row["machine_verified"] is False
    # And so the campaign is not complete, however finished the tickets look.
    assert _campaign(client, operator, cid)["status"] == "active"


# --------------------------------------------------------------------------
# Completion and recurrence policy
# --------------------------------------------------------------------------


def _verify_closed(settings, vuln_id):
    _set(settings, vuln_id, state="CLOSED", closed_at=_now(), machine_verified=True,
         closure_reason="verified_remediated", last_verified_at=_now())


def test_completion_needs_every_member_resolved_and_a_recurrence_reopens_the_campaign(env):
    client, settings, tenant_id, ids, operator = env
    a, b = ids["c2"]
    cid = _create(client, operator, {"vuln_ids": [a, b]}).json()["campaign_id"]

    _verify_closed(settings, a)
    assert _campaign(client, operator, cid)["status"] == "active"  # one member still open
    _verify_closed(settings, b)

    done = _campaign(client, operator, cid)
    assert done["status"] == "completed" and done["completed_at"]
    # Reading again, any number of times, records the completion once.
    _campaign(client, operator, cid)
    client.get(URL, headers=operator)
    assert [e["kind"] for e in _events(client, operator, cid)].count("completed") == 1

    # The scanner sees one of them again: the standard reopen path.
    vulns.transition(settings, tenant_id=tenant_id, vuln_id=a, to_state="OPEN", actor="system")
    back = _campaign(client, operator, cid)
    assert back["status"] == "active" and back["completed_at"] is None
    assert back["reopen_count"] == 1
    assert back["progress"]["recurred"] == 1
    assert back["progress"]["categories"]["open"] == 1 and back["progress"]["categories"]["verified"] == 1
    reopened = next(e for e in _events(client, operator, cid) if e["kind"] == "reopened")
    assert reopened["detail"]["recurred"] == 1
    assert [e["kind"] for e in _events(client, operator, cid)].count("reopened") == 1
    member = next(m for m in _members(client, operator, cid)["items"] if m["vuln_id"] == a)
    assert member["recurred"] is True and member["state"] == "OPEN"

    # Fixed again: completed again, and the history shows both rounds.
    _verify_closed(settings, a)
    assert _campaign(client, operator, cid)["status"] == "completed"
    assert [e["kind"] for e in _events(client, operator, cid)].count("completed") == 2


def test_a_derived_transition_made_by_a_read_is_audited_as_the_system(env):
    client, settings, tenant_id, ids, operator = env
    a = ids["c2"][0]
    cid = _create(client, operator, {"vuln_ids": [a]}).json()["campaign_id"]
    _verify_closed(settings, a)
    # A viewer's GET is what notices the completion.
    assert _campaign(client, auth_headers(client, "viewer"), cid)["status"] == "completed"
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.AuditEvent.actor, models.AuditEvent.actor_type, models.AuditEvent.after)
            .where(models.AuditEvent.resource_id == cid, models.AuditEvent.action == "campaign.status")
        ).all()
    assert len(rows) == 1
    actor, actor_type, after = rows[0]
    assert actor != "viewer" and actor_type == "system"
    assert after["derived"] is True and after["status"] == "completed"
    event = next(e for e in _events(client, operator, cid) if e["kind"] == "completed")
    assert event["actor"] is None


def test_adding_unresolved_work_to_a_completed_campaign_reopens_it(env):
    client, settings, tenant_id, ids, operator = env
    a, b = ids["c2"]
    cid = _create(client, operator, {"vuln_ids": [a]}).json()["campaign_id"]
    _verify_closed(settings, a)
    assert _campaign(client, operator, cid)["status"] == "completed"
    added = client.post(f"{URL}/{cid}/members", json={"selection": {"vuln_ids": [b]}, "reason": "missed one"},
                        headers=operator).json()
    assert added["campaign"]["status"] == "active" and added["campaign"]["reopen_count"] == 1
    reopened = next(e for e in _events(client, operator, cid) if e["kind"] == "reopened")
    assert reopened["detail"]["cause"] == "members_added"


def test_excluding_every_unresolved_member_completes_and_an_empty_campaign_does_not(env):
    client, settings, tenant_id, ids, operator = env
    a, b = ids["c2"]
    cid = _create(client, operator, {"vuln_ids": [a, b]}).json()["campaign_id"]
    _verify_closed(settings, a)
    out = client.post(f"{URL}/{cid}/members/exclude", json={"vuln_ids": [b], "reason": "out of scope"},
                      headers=operator).json()
    assert out["campaign"]["status"] == "completed"
    # Excluding the last verified one leaves nothing: an empty campaign is not "done".
    reopened = client.post(f"{URL}/{cid}/members/exclude", json={"vuln_ids": [a], "reason": "mistake"},
                           headers=operator).json()
    assert reopened["campaign"]["progress"]["total"] == 0
    assert reopened["campaign"]["status"] == "completed"  # never silently flips on emptiness


def test_cancel_and_resume_are_explicit_and_data_never_changes_a_cancelled_campaign(env):
    client, settings, tenant_id, ids, operator = env
    a, _ = ids["c2"]
    cid = _create(client, operator, {"vuln_ids": [a]}).json()["campaign_id"]
    assert client.post(f"{URL}/{cid}/cancel", json={"reason": "x"}, headers=operator).status_code == 422
    cancelled = client.post(f"{URL}/{cid}/cancel", json={"reason": "superseded"}, headers=operator)
    assert cancelled.json()["status"] == "cancelled"
    _verify_closed(settings, a)
    assert _campaign(client, operator, cid)["status"] == "cancelled"  # data does not resurrect it
    for call in (
        client.patch(f"{URL}/{cid}", json={"name": "z"}, headers=operator),
        client.post(f"{URL}/{cid}/members", json={"selection": {"vuln_ids": [a]}, "reason": "again"}, headers=operator),
        client.post(f"{URL}/{cid}/verify", json={}, headers=operator),
        client.post(f"{URL}/{cid}/cancel", json={"reason": "twice"}, headers=operator),
    ):
        assert call.status_code == 409, call.text
    resumed = client.post(f"{URL}/{cid}/resume", json={"reason": "needed after all"}, headers=operator)
    assert resumed.status_code == 200
    # Resuming re-derives: the only member is verified, so it completes.
    assert resumed.json()["status"] == "completed"
    assert client.post(f"{URL}/{cid}/resume", json={"reason": "nope!"}, headers=operator).status_code == 409


# --------------------------------------------------------------------------
# Tenants and roles
# --------------------------------------------------------------------------


def test_another_tenant_cannot_read_change_or_probe_a_campaign(env):
    client, settings, tenant_id, ids, operator = env
    tenants_service.create_tenant(tenant_id="ten_b", name="B")
    admin = auth_headers(client, "admin")
    for tenant in ("ten_b", tenant_id):
        granted = client.put(
            f"/api/tenants/{tenant}/members/operator", headers=admin, json={"role": "operator"}
        )
        assert granted.status_code == 200, granted.text
    # The operator now belongs to two tenants, so each call names its tenant.
    mine_scope = {"tenant_id": tenant_id}
    foreign = {"tenant_id": "ten_b"}
    own = client.post(
        URL, params=mine_scope, headers=operator,
        json={"name": "Upgrade openssl", "selection": {"vuln_ids": ids["c1"]}},
    )
    assert own.status_code == 201, own.text
    cid = own.json()["campaign_id"]

    # Direct id: 404 for every verb, never 403 (existence is not confirmed).
    for response in (
        client.get(f"{URL}/{cid}", params=foreign, headers=operator),
        client.get(f"{URL}/{cid}/members", params=foreign, headers=operator),
        client.get(f"{URL}/{cid}/events", params=foreign, headers=operator),
        client.patch(f"{URL}/{cid}", params=foreign, json={"name": "mine"}, headers=operator),
        client.post(f"{URL}/{cid}/verify", params=foreign, json={}, headers=operator),
        client.post(f"{URL}/{cid}/cancel", params=foreign, json={"reason": "take over"}, headers=operator),
        client.post(f"{URL}/{cid}/members", params=foreign,
                    json={"selection": {"vuln_ids": ids["c2"]}, "reason": "sabotage"}, headers=operator),
        client.post(f"{URL}/{cid}/members/exclude", params=foreign,
                    json={"vuln_ids": ids["c1"], "reason": "sabotage"}, headers=operator),
    ):
        assert response.status_code == 404, response.text
    # Counts and filters.
    listing = client.get(URL, params=foreign, headers=operator).json()
    assert listing["total"] == 0 and listing["items"] == []
    assert client.get(URL, params={**foreign, "q": "openssl"}, headers=operator).json()["total"] == 0
    # Findings of tenant A cannot be pulled into a campaign of tenant B.
    probe = client.post(
        f"{URL}/preview", params=foreign, json={"vuln_ids": ids["c1"]}, headers=operator
    ).json()
    assert probe["total"] == 0 and {s["reason"] for s in probe["skipped"]} == {"not_found"}
    stolen = client.post(
        URL, params=foreign, headers=operator,
        json={"name": "steal", "selection": {"vuln_ids": ids["c1"]}},
    )
    assert stolen.status_code == 422
    # Untouched.
    mine = client.get(f"{URL}/{cid}", params=mine_scope, headers=operator).json()
    assert mine["name"] == "Upgrade openssl" and mine["status"] == "active"
    assert mine["progress"]["total"] == 4
    events = client.get(f"{URL}/{cid}/events", params=mine_scope, headers=operator).json()
    assert [e["kind"] for e in events["items"]] == ["created"]
    # A tenant the caller is not a member of is refused outright.
    outsider = client.get(URL, params={"tenant_id": "ten_zzz"}, headers=operator)
    assert outsider.status_code in (403, 404)


def test_the_service_checks_the_tenant_itself_not_only_through_row_security(env):
    """No request context: Postgres row-level security has no tenant to apply,
    so every one of these is the service's own predicate at work."""
    client, settings, tenant_id, ids, operator = env
    other = tenants_service.create_tenant(tenant_id="ten_b", name="B")["tenant_id"]
    with get_session(settings.postgres_url) as session:
        theirs = add_finding(session, other, "b1", cve="CVE-2024-1111")
    cid = _create(client, operator, {"vuln_ids": ids["c1"]}).json()["campaign_id"]
    common = {"tenant_id": other, "campaign_id": cid}

    for call in (
        lambda: campaigns.get_campaign(settings, **common),
        lambda: campaigns.list_members(settings, **common),
        lambda: campaigns.list_events(settings, **common),
        lambda: campaigns.update_campaign(settings, **common, actor="x", audit=None, changes={"name": "n"}),
        lambda: campaigns.set_status(settings, **common, actor="x", audit=None, action="cancel", reason="because"),
        lambda: campaigns.exclude_members(settings, **common, actor="x", audit=None, vuln_ids=ids["c1"], reason="because"),
        lambda: campaigns.add_members(settings, **common, actor="x", audit=None,
                                      selection={"vuln_ids": [theirs]}, reason="because"),
        lambda: campaigns.verify_members(settings, **common, actor="x", audit=None),
    ):
        with pytest.raises(LookupError):
            call()
    assert campaigns.list_campaigns(settings, tenant_id=other)[1] == 0
    foreign = campaigns.preview(settings, tenant_id=other, selection={"vuln_ids": ids["c1"]})
    assert foreign["total"] == 0
    # A problem key shared by both tenants expands to each tenant's own findings only.
    own_view = campaigns.preview(settings, tenant_id=other, selection={"problem_keys": ["cve:CVE-2024-1111"]})
    assert [i["vuln_id"] for i in own_view["items"]] == [theirs]
    created = campaigns.create_campaign(
        settings, tenant_id=other, actor="x", audit=None, name="theirs",
        selection={"problem_keys": ["cve:CVE-2024-1111"]},
    )
    assert created["snapshot_size"] == 1
    mine = _campaign(client, operator, cid)
    assert mine["status"] == "active" and mine["progress"]["total"] == 4 and mine["name"] == "Upgrade openssl"


def test_reads_cost_a_fixed_number_of_statements_whatever_the_campaign_size(env):
    from sqlalchemy import event

    client, settings, tenant_id, ids, operator = env
    small_id = _create(client, operator, {"vuln_ids": ids["c2"]}).json()["campaign_id"]
    with get_session(settings.postgres_url) as session:
        many = [
            add_finding(session, tenant_id, f"m{index % 11}", cve=f"CVE-2032-{index:04d}",
                        ticket_system="jira", ticket_key=f"SEC-{index % 7}")
            for index in range(150)
        ]
    big_id = _create(client, operator, {"vuln_ids": many}).json()["campaign_id"]
    engine = get_engine(settings.postgres_url)

    def statements(call) -> int:
        seen: list[str] = []

        def before(conn, cursor, statement, parameters, context, executemany):
            seen.append(statement)

        event.listen(engine, "before_cursor_execute", before)
        try:
            call()
        finally:
            event.remove(engine, "before_cursor_execute", before)
        return len(seen)

    for label, path, params in (
        ("detail", "{id}", {}),
        ("members", "{id}/members", {"limit": 200}),
        ("events", "{id}/events", {"limit": 200}),
    ):
        def read(cid, path=path, params=params):
            response = client.get(f"{URL}/{path.format(id=cid)}", params=params, headers=operator)
            assert response.status_code == 200

        read(small_id)  # warm-up
        assert statements(lambda: read(small_id)) == statements(lambda: read(big_id)), label

    def listing():
        assert client.get(URL, headers=operator).status_code == 200

    listing()
    two = statements(listing)
    for index in range(4):
        _create(client, operator, {"vuln_ids": many[index * 10:(index + 1) * 10]}, name=f"c{index}")
    assert statements(listing) == two  # six campaigns cost what two did


def test_viewers_read_but_cannot_write(env):
    client, settings, tenant_id, ids, operator = env
    viewer = auth_headers(client, "viewer")
    cid = _create(client, operator, {"vuln_ids": ids["c1"]}).json()["campaign_id"]
    assert client.get(f"{URL}/{cid}", headers=viewer).status_code == 200
    assert client.get(URL, headers=viewer).status_code == 200
    assert client.get(f"{URL}/{cid}/members", headers=viewer).status_code == 200
    assert client.get(f"{URL}/{cid}/events", headers=viewer).status_code == 200
    writes = (
        client.post(f"{URL}/preview", json={"vuln_ids": ids["c1"]}, headers=viewer),
        _create(client, viewer, {"vuln_ids": ids["c1"]}),
        client.patch(f"{URL}/{cid}", json={"name": "x"}, headers=viewer),
        client.post(f"{URL}/{cid}/members", json={"selection": {"vuln_ids": ids["c2"]}, "reason": "abc"}, headers=viewer),
        client.post(f"{URL}/{cid}/members/exclude", json={"vuln_ids": ids["c1"], "reason": "abc"}, headers=viewer),
        client.post(f"{URL}/{cid}/verify", json={}, headers=viewer),
        client.post(f"{URL}/{cid}/cancel", json={"reason": "abc"}, headers=viewer),
    )
    assert [r.status_code for r in writes] == [403] * len(writes)
    assert client.get(URL).status_code == 401
