"""Bulk operator verbs and the ``Idempotency-Key`` behind them (#346).

Two properties are what this endpoint is for, and they pull against each other:

* **a batch is a partial success.** One id that closed since the operator
  loaded the page, or one id from a tenant they cannot write in, must not
  refuse the other hundred and ninety-nine — otherwise the bulk bar is
  unusable exactly when the selection is large, which is the case it exists
  for.
* **doing a hundred of a thing is not cheaper than doing one.** The role,
  the tenant scope and the state machine apply per id, unchanged. A bulk
  endpoint that took the weakest of its members' guarantees would be a way
  round the ``admin`` gate on risk acceptance and suppression.

The idempotency tests pin the third: a retry after a timeout replays the first
answer instead of applying the batch twice, and a *failed* request gives its
key back rather than burning it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from api.db import models
from api.db.engine import get_session
from api.services import bulk_actions
from api.services import idempotency as idempotency_service
from api.services import vuln_states
from api.services import vulnerabilities as vulns
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)
from tests.test_api_vulnerabilities import _seed

pytestmark = requires_postgres

_VULN_URL = "/api/vulnerabilities/bulk"
_ASSET_URL = "/api/assets/bulk"


def _client(tmp_path, monkeypatch):
    """A client over a database holding the two seeded findings and one asset."""
    client = configured_client(tmp_path, monkeypatch)
    settings, tenant_id = _seed(tmp_path)
    return client, settings, tenant_id


def _vuln_ids(settings, tenant_id: str) -> list[str]:
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id)
    return [item["vuln_id"] for item in items]


def _outcomes(report: dict) -> dict[str, str]:
    return {item["id"]: item["outcome"] for item in report["results"]}


def _event_kinds(settings, tenant_id: str, vuln_id: str) -> list[str]:
    items, _ = vulns.list_events(settings, tenant_id=tenant_id, vuln_id=vuln_id)
    return [item["kind"] for item in items]


def _audit_rows(settings, action: str) -> list[models.AuditEvent]:
    with get_session(settings.postgres_url) as session:
        rows = session.execute(
            select(models.AuditEvent).where(models.AuditEvent.action == action)
        ).scalars().all()
        # Detached copies of the two fields the assertions read: the session
        # closes with the ``with`` block.
        return [
            {
                "tenant_id": row.tenant_id,
                "resource_id": row.resource_id,
                "after": dict(row.after or {}),
            }
            for row in rows
        ]


# --------------------------------------------------------------------------
# The batch applies, and it applies the same verb the single route does
# --------------------------------------------------------------------------


def test_one_request_assigns_every_selected_finding(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)

    response = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada", "owner_team": "platform"}},
        headers=auth_headers(client, "operator"),
    )

    assert response.status_code == 200, response.text
    report = response.json()
    assert (report["requested"], report["succeeded"], report["failed"]) == (2, 2, 0)
    assert set(_outcomes(report).values()) == {"ok"}
    assert report["replayed"] is False
    # The same write the single route makes, including its event row — a bulk
    # assign that skipped ``vulnerability_events`` would be invisible in the
    # remediation trail the console's timeline reads.
    for vuln_id in ids:
        detail = client.get(
            f"/api/vulnerabilities/{vuln_id}", headers=auth_headers(client, "viewer")
        ).json()
        assert (detail["assignee"], detail["owner_team"]) == ("ada", "platform")
        assert "assigned" in _event_kinds(settings, tenant_id, vuln_id)


def test_an_explicit_null_unassigns_the_whole_selection(tmp_path, monkeypatch):
    """``exclude_unset`` carries the single route's contract into the batch."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    operator = auth_headers(client, "operator")
    client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada", "owner_team": "platform"}},
        headers=operator,
    )

    cleared = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": None}},
        headers=operator,
    )

    assert cleared.status_code == 200, cleared.text
    detail = client.get(
        f"/api/vulnerabilities/{ids[0]}", headers=auth_headers(client, "viewer")
    ).json()
    assert detail["assignee"] is None
    # Untouched: the key was not in the payload at all.
    assert detail["owner_team"] == "platform"


def test_a_duplicate_id_is_applied_once(tmp_path, monkeypatch):
    """A selection naming one id twice must not write two lifecycle events."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    vuln_id = _vuln_ids(settings, tenant_id)[0]

    report = client.post(
        _VULN_URL,
        json={
            "action": "transition",
            "vuln_ids": [vuln_id, vuln_id, f" {vuln_id} "],
            "payload": {"state": "ACKNOWLEDGED"},
        },
        headers=auth_headers(client, "operator"),
    ).json()

    assert report["requested"] == 1
    assert _event_kinds(settings, tenant_id, vuln_id).count("state_change") == 1


# --------------------------------------------------------------------------
# Partial success: one bad id does not fail the batch
# --------------------------------------------------------------------------


def test_a_foreign_id_is_not_found_and_the_rest_still_apply(tmp_path, monkeypatch):
    """404-shaped, not 403-shaped: a write scope must not confirm existence."""
    from api.services import tenants as tenants_service

    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    other = tenants_service.create_tenant(tenant_id="ten_other", name="Other")
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, ids[1])
        row.tenant_id = other["tenant_id"]
    foreign_id = ids[1]

    response = client.post(
        _VULN_URL,
        json={
            "action": "assign",
            "vuln_ids": [ids[0], foreign_id, "vln_never_existed"],
            "payload": {"assignee": "ada"},
        },
        headers=auth_headers(client, "operator"),
    )

    assert response.status_code == 200, response.text
    report = response.json()
    assert (report["succeeded"], report["failed"]) == (1, 2)
    outcomes = _outcomes(report)
    assert outcomes[ids[0]] == "ok"
    # The other tenant's finding and an id that never existed are the same
    # answer, on purpose.
    assert outcomes[foreign_id] == "not_found"
    assert outcomes["vln_never_existed"] == "not_found"


def test_an_illegal_transition_is_a_conflict_for_that_id_only(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    first, second = _vuln_ids(settings, tenant_id)
    operator = auth_headers(client, "operator")
    # One of the two is already ACKNOWLEDGED, so the batch's move is a
    # same-state transition for it and legal for the other.
    assert (
        client.post(
            f"/api/vulnerabilities/{first}/transition",
            json={"state": "ACKNOWLEDGED"},
            headers=operator,
        ).status_code
        == 200
    )

    report = client.post(
        _VULN_URL,
        json={
            "action": "transition",
            "vuln_ids": [first, second],
            "payload": {"state": "ACKNOWLEDGED"},
        },
        headers=operator,
    ).json()

    assert (report["succeeded"], report["failed"]) == (1, 1)
    outcomes = _outcomes(report)
    assert outcomes[first] == "conflict"
    assert outcomes[second] == "ok"
    # The refusal carries the state machine's own message, so the console can
    # say *why* rather than "1 failed".
    failed = next(item for item in report["results"] if not item["ok"])
    assert "ACKNOWLEDGED" in (failed["error"] or "")


def test_an_acceptance_on_a_closed_finding_is_invalid_for_that_id(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    first, second = _vuln_ids(settings, tenant_id)
    admin = auth_headers(client, "admin")
    client.post(
        f"/api/vulnerabilities/{first}/transition",
        json={"state": "CLOSED"},
        headers=auth_headers(client, "operator"),
    )
    until = (datetime.now(UTC) + timedelta(days=30)).isoformat()

    report = client.post(
        _VULN_URL,
        json={
            "action": "exception",
            "vuln_ids": [first, second],
            "payload": {"until": until, "reason": "compensating control in place"},
        },
        headers=admin,
    ).json()

    outcomes = _outcomes(report)
    assert outcomes[first] == "invalid"
    assert outcomes[second] == "ok"


# --------------------------------------------------------------------------
# Role and scope, per verb
# --------------------------------------------------------------------------


def test_the_bulk_verb_needs_the_role_its_single_route_needs(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    operator = auth_headers(client, "operator")
    until = (datetime.now(UTC) + timedelta(days=30)).isoformat()

    # ``admin`` verbs, refused for an operator exactly as one at a time.
    accepted = client.post(
        _VULN_URL,
        json={
            "action": "exception",
            "vuln_ids": ids,
            "payload": {"until": until, "reason": "accepted"},
        },
        headers=operator,
    )
    assert accepted.status_code == 403, accepted.text
    suppressed = client.post(
        _VULN_URL,
        json={"action": "false_positive", "vuln_ids": ids, "payload": {"reason": "noise"}},
        headers=operator,
    )
    assert suppressed.status_code == 403
    # ...and nothing was applied by the refusal.
    assert client.get(
        f"/api/vulnerabilities/{ids[0]}", headers=auth_headers(client, "viewer")
    ).json()["exception_until"] is None

    # ``operator`` verbs stay open to an operator.
    assert (
        client.post(
            _VULN_URL,
            json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}},
            headers=operator,
        ).status_code
        == 200
    )
    # A viewer reaches none of it: the route's floor is ``operator``.
    assert (
        client.post(
            _VULN_URL,
            json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}},
            headers=auth_headers(client, "viewer"),
        ).status_code
        == 403
    )


def test_an_admin_may_suppress_the_whole_selection(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)

    report = client.post(
        _VULN_URL,
        json={
            "action": "false_positive",
            "vuln_ids": ids,
            "payload": {"reason": "load balancer health probe", "suppress_days": 30},
        },
        headers=auth_headers(client, "admin"),
    ).json()

    assert report["succeeded"] == 2
    for vuln_id in ids:
        detail = client.get(
            f"/api/vulnerabilities/{vuln_id}", headers=auth_headers(client, "viewer")
        ).json()
        assert detail["state"] == vuln_states.CLOSED
        assert detail["fp_suppress_until"] is not None


# --------------------------------------------------------------------------
# The batch has a ceiling
# --------------------------------------------------------------------------


def test_the_batch_size_is_capped_by_the_schema_and_by_the_service(tmp_path, monkeypatch):
    """Both layers, because both have callers: the schema is the HTTP contract
    and the service is the invariant. The cap is not cosmetic — the single audit
    row #346 asks for lists every id, and a document over 16 KiB is stored as a
    marker that says a change happened but not what it was."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    too_many = [f"vln_{index:05d}" for index in range(bulk_actions.MAX_BULK_IDS + 1)]

    response = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": too_many, "payload": {"assignee": "ada"}},
        headers=auth_headers(client, "operator"),
    )
    assert response.status_code == 422, response.text

    # An empty selection is refused too, rather than answering "0 of 0 applied".
    assert (
        client.post(
            _VULN_URL,
            json={"action": "assign", "vuln_ids": [], "payload": {"assignee": "ada"}},
            headers=auth_headers(client, "operator"),
        ).status_code
        == 422
    )

    # The service refuses the same thing, so the ceiling is not route-only.
    try:
        bulk_actions.validate_ids(too_many)
    except ValueError as exc:
        assert str(bulk_actions.MAX_BULK_IDS) in str(exc)
    else:  # pragma: no cover - the assertion above is the test
        raise AssertionError("an oversized batch was accepted by the service")

    # Exactly at the ceiling is allowed: the bound is inclusive, and an
    # off-by-one here is a console page size nobody can submit.
    assert (
        len(bulk_actions.validate_ids(too_many[: bulk_actions.MAX_BULK_IDS]))
        == bulk_actions.MAX_BULK_IDS
    )


def test_an_over_long_id_is_refused_by_the_schema_and_by_the_service(tmp_path, monkeypatch):
    """The count is not the only bound the audit row needs.

    ``MAX_BULK_IDS`` caps how *many* ids a batch names; nothing capped how long
    one was, and two hundred 120-character ids were a 27 KiB document — stored
    as the marker that says a change happened but not what it was, with not one
    id left in it.
    """
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    long_id = "vln_" + "a" * bulk_actions.MAX_BULK_ID_LENGTH

    response = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": [long_id], "payload": {"assignee": "ada"}},
        headers=auth_headers(client, "operator"),
    )
    assert response.status_code == 422, response.text

    try:
        bulk_actions.validate_ids([long_id])
    except ValueError as exc:
        assert str(bulk_actions.MAX_BULK_ID_LENGTH) in str(exc)
    else:  # pragma: no cover - the assertion above is the test
        raise AssertionError("an over-long id was accepted by the service")

    # An id at the ceiling is still accepted — it simply does not exist, which
    # is the ordinary ``not_found`` and not a refusal of the batch.
    at_ceiling = "v" * bulk_actions.MAX_BULK_ID_LENGTH
    ok = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": [at_ceiling], "payload": {"assignee": "ada"}},
        headers=auth_headers(client, "operator"),
    )
    assert ok.status_code == 200, ok.text
    assert _outcomes(ok.json()) == {at_ceiling: "not_found"}


# --------------------------------------------------------------------------
# The audit trail: one row, listing the ids
# --------------------------------------------------------------------------


def test_a_batch_is_one_audit_row_listing_the_ids(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)

    client.post(
        _VULN_URL,
        json={
            "action": "assign",
            "vuln_ids": [*ids, "vln_never_existed"],
            "payload": {"assignee": "ada"},
        },
        headers=auth_headers(client, "operator"),
    )

    rows = _audit_rows(settings, "vulnerability.bulk")
    # One row for the request, not one per id: the point is that this was a
    # single decision.
    assert len(rows) == 1
    assert rows[0]["resource_id"] == "bulk:assign"
    after = rows[0]["after"]
    assert sorted(after["applied"]) == sorted(ids)
    assert after["rejected"] == {"vln_never_existed": "not_found"}
    assert (after["requested"], after["succeeded"], after["failed"]) == (3, 2, 1)
    assert after["payload"] == {"assignee": "ada"}


def _crash_on_second_assign(monkeypatch):
    """``vulns.assign`` applied for real once, then a failure nothing classifies.

    Stands in for what actually kills a batch part-way: a deadlock, a pool that
    went away, a tracker call that timed out. The point is that the id before it
    is *committed* — one transaction per id is the design — so the batch cannot
    be treated as though it had not happened.
    """
    real = vulns.assign
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("the tracker call hung and the pool gave up")
        return real(*args, **kwargs)

    monkeypatch.setattr(vulns, "assign", flaky)


def test_a_batch_that_dies_part_way_records_what_it_applied(tmp_path, monkeypatch):
    """The audit row is written *before* the 500 leaves.

    A batch that assigned ninety-nine findings and recorded nothing is exactly
    the silent change ``docs/api-and-rbac.md`` says is impossible for anything
    that is a database write. A partial report is still a report.
    """
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)

    with monkeypatch.context() as patched:
        _crash_on_second_assign(patched)
        try:
            client.post(
                _VULN_URL,
                json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}},
                headers=auth_headers(client, "operator"),
            )
        except bulk_actions.BulkActionAborted:
            pass  # TestClient re-raises the handler's exception; that is the 500.
        else:  # pragma: no cover - the batch is rigged to abort
            raise AssertionError("the rigged batch did not abort")

    # The first id really was applied, so the trail has to say so.
    applied_id = ids[0]
    detail = client.get(
        f"/api/vulnerabilities/{applied_id}", headers=auth_headers(client, "viewer")
    ).json()
    assert detail["assignee"] == "ada"

    rows = _audit_rows(settings, "vulnerability.bulk")
    assert len(rows) == 1, "a batch that changed a finding and recorded nothing"
    after = rows[0]["after"]
    assert after["applied"] == [applied_id]
    # ``requested`` stays the id count, so how far the batch got is readable:
    # two asked for, one reached.
    assert (after["requested"], after["succeeded"]) == (2, 1)
    assert after["aborted"] is True


def test_a_partly_applied_batch_keeps_its_key_and_replays_its_partial_report(
    tmp_path, monkeypatch
):
    """A failed request gives its key back — unless it did half the work.

    Releasing here would let the retry apply the ids that landed a second time:
    for ``transition`` a hundred conflicts, for ``false_positive`` a second
    suppression window. So the retry is answered with what happened instead,
    which is also how it learns which ids are still to send.
    """
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    headers = {**auth_headers(client, "operator"), "Idempotency-Key": "half-done"}
    body = {"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}}

    with monkeypatch.context() as patched:
        _crash_on_second_assign(patched)
        try:
            client.post(_VULN_URL, json=body, headers=headers)
        except bulk_actions.BulkActionAborted:
            pass

    retried = client.post(_VULN_URL, json=body, headers=headers)

    assert retried.status_code == 200, retried.text
    report = retried.json()
    assert report["replayed"] is True
    assert report["aborted"] is True
    # One id, not two: the replay is the partial report, and the second finding
    # was never touched — by this request or the one it retries.
    assert (report["requested"], report["succeeded"]) == (2, 1)
    assert _outcomes(report) == {ids[0]: "ok"}
    # And the retry applied nothing, so the trail still has exactly one row.
    assert len(_audit_rows(settings, "vulnerability.bulk")) == 1


def test_a_platform_admins_batch_is_audited_in_the_tenant_it_changed(tmp_path, monkeypatch):
    """The row belongs to the customer whose finding moved, not to the admin.

    ``_write_scope`` is ``None`` for a platform admin however they arrived, so
    ``?tenant_id=default`` reads to a human like a boundary and is not one. One
    row filed under the caller's tenant left the affected tenant's audit read —
    and the SIEM forward, which filters by tenant — with no record of the edit.
    """
    from api.services import tenants as tenants_service

    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    victim = tenants_service.create_tenant(tenant_id="ten_victim", name="Victim")[
        "tenant_id"
    ]
    with get_session(settings.postgres_url) as session:
        session.get(models.Vulnerability, ids[1]).tenant_id = victim
    victim_id = ids[1]

    response = client.post(
        _VULN_URL,
        params={"tenant_id": tenant_id},
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}},
        headers=auth_headers(client, "admin"),
    )

    assert response.status_code == 200, response.text
    assert response.json()["succeeded"] == 2
    rows = {row["tenant_id"]: row["after"] for row in _audit_rows(settings, "vulnerability.bulk")}
    # One row per tenant touched, each naming only that tenant's ids.
    assert rows[victim]["applied"] == [victim_id]
    assert rows[tenant_id]["applied"] == [ids[0]]
    # And the row says the caller was not confined to one tenant, so a reader
    # does not take it for an ordinary in-tenant edit.
    assert rows[victim]["write_scope"] == "*"
    # The HTTP report does not carry the tenant of somebody else's finding.
    assert all("tenant_id" not in item for item in response.json()["results"])


def test_a_bulky_payload_never_costs_the_audit_row_its_ids(tmp_path, monkeypatch):
    """``false_positive``'s ``evidence`` is a free dict with no size bound.

    Twenty kilobytes of it on a batch of *two* findings was enough to push the
    document past the 16 KiB cap, and the row then said only that something had
    happened. The ids are what the row owes, so the body is what gives way.
    """
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)

    response = client.post(
        _VULN_URL,
        json={
            "action": "false_positive",
            "vuln_ids": ids,
            "payload": {
                "reason": "the scanner matched a backported package version",
                "evidence": {"log": "y" * 20_000},
            },
        },
        headers=auth_headers(client, "admin"),
    )

    assert response.status_code == 200, response.text
    after = _audit_rows(settings, "vulnerability.bulk")[0]["after"]
    assert "truncated" not in after
    assert sorted(after["applied"]) == sorted(ids)
    # The reason survives, because the reason is small; the 20 KiB dict is
    # recorded as its size, which is what a reader of the row can act on.
    assert after["payload"]["reason"].startswith("the scanner matched")
    assert "bytes omitted" in after["payload"]["evidence"]


def test_two_hundred_ids_at_full_length_still_fit_the_audit_document():
    """The bound the ceilings exist for, checked on the document itself.

    Two hundred ids of ``MAX_BULK_ID_LENGTH``, every one of them rejected —
    the worst case, since a rejected id costs its outcome too — plus a payload.
    It has to come out under the budget *with the ids still in it*.
    """
    ids = [f"vln_{index:0{bulk_actions.MAX_BULK_ID_LENGTH - 4}d}" for index in range(200)]
    report = {
        "action": "transition",
        "requested": len(ids),
        "succeeded": 0,
        "failed": len(ids),
        "results": [
            {"id": vuln_id, "ok": False, "outcome": "conflict", "error": "already CLOSED"}
            for vuln_id in ids
        ],
    }

    document = bulk_actions.audit_document(report, {"state": "CLOSED"}, write_scope="acme")

    assert bulk_actions._document_bytes(document) <= bulk_actions.AUDIT_DOCUMENT_BUDGET_BYTES
    assert sorted(document["rejected"]) == sorted(ids)
    assert "rejected_collapsed" not in document


# --------------------------------------------------------------------------
# Idempotency-Key
# --------------------------------------------------------------------------


def test_a_retry_with_the_same_key_replays_instead_of_reapplying(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    vuln_id = _vuln_ids(settings, tenant_id)[0]
    body = {
        "action": "transition",
        "vuln_ids": [vuln_id],
        "payload": {"state": "ACKNOWLEDGED"},
    }
    headers = {**auth_headers(client, "operator"), "Idempotency-Key": "triage-batch-1"}

    first = client.post(_VULN_URL, json=body, headers=headers)
    second = client.post(_VULN_URL, json=body, headers=headers)

    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["replayed"] is False
    assert second.json()["replayed"] is True
    # Same report, and — the point — the transition happened once. Without the
    # key the second call would be a same-state 409 for this id; with it, the
    # caller gets the answer it missed.
    assert _outcomes(second.json()) == _outcomes(first.json()) == {vuln_id: "ok"}
    assert _event_kinds(settings, tenant_id, vuln_id).count("state_change") == 1
    assert len(_audit_rows(settings, "vulnerability.bulk")) == 1


def test_a_reshuffled_selection_is_the_same_batch(tmp_path, monkeypatch):
    """The digest sorts the ids: a retry that reorders its selection is a retry,
    and 409-ing it would punish an honest client."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    headers = {**auth_headers(client, "operator"), "Idempotency-Key": "triage-batch-2"}
    payload = {"assignee": "ada"}

    client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": payload},
        headers=headers,
    )
    replay = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": list(reversed(ids)), "payload": payload},
        headers=headers,
    )

    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True


def test_the_same_key_for_a_different_batch_is_a_conflict(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    headers = {**auth_headers(client, "operator"), "Idempotency-Key": "triage-batch-3"}

    client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}},
        headers=headers,
    )
    # Different payload under the same key: replaying the first answer would
    # report an assignment to somebody this caller never named.
    other_payload = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "grace"}},
        headers=headers,
    )
    # ...and so would a different selection.
    other_ids = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids[:1], "payload": {"assignee": "ada"}},
        headers=headers,
    )

    assert other_payload.status_code == 409, other_payload.text
    assert other_ids.status_code == 409
    assert (
        client.get(
            f"/api/vulnerabilities/{ids[0]}", headers=auth_headers(client, "viewer")
        ).json()["assignee"]
        == "ada"
    )


def test_a_key_still_in_flight_is_a_conflict(tmp_path, monkeypatch):
    """Two concurrent sends of one key: the loser is told to wait, not served a
    half-built answer and not allowed to apply the batch a second time."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    body = {"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}}
    # Stand in for the request that got there first and has not finished: a
    # reservation with no answer stored against it.
    assert (
        idempotency_service.reserve(
            settings,
            tenant_id=tenant_id,
            endpoint="vulnerabilities.bulk",
            key="racing",
            request_digest=idempotency_service.digest(
                {"action": "assign", "ids": sorted(ids), "payload": {"assignee": "ada"}}
            ),
        )
        is None
    )

    response = client.post(
        _VULN_URL,
        json=body,
        headers={**auth_headers(client, "operator"), "Idempotency-Key": "racing"},
    )

    assert response.status_code == 409, response.text
    assert "still being processed" in response.json()["detail"]


def test_a_reservation_whose_process_died_is_retryable_once_its_lease_expires(
    tmp_path, monkeypatch
):
    """"Still being processed" has to stop being true at some point.

    ``release()`` runs in the handler, so a replica the OOM killer took — or a
    pod that was evicted — leaves ``response`` NULL for good. Before the lease,
    the retry was answered 409 an hour later and six hours later, until the
    24-hour purge; the batch was never applied and never reported.
    """
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    body = {"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}}
    assert (
        idempotency_service.reserve(
            settings,
            tenant_id=tenant_id,
            endpoint="vulnerabilities.bulk",
            key="abandoned",
            request_digest=idempotency_service.digest(
                {"action": "assign", "ids": sorted(ids), "payload": {"assignee": "ada"}}
            ),
        )
        is None
    )
    # The process that made the reservation is gone. Age the row rather than
    # sleeping out the lease.
    with get_session(settings.postgres_url) as session:
        row = session.execute(select(models.IdempotencyRecord)).scalars().one()
        row.created_at = datetime.now(UTC).replace(tzinfo=None) - timedelta(
            seconds=idempotency_service.RESERVATION_LEASE_SECONDS + 60
        )

    response = client.post(
        _VULN_URL,
        json=body,
        headers={**auth_headers(client, "operator"), "Idempotency-Key": "abandoned"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["succeeded"] == 2
    assert response.json()["replayed"] is False
    # And the key is now answered: the retry that took it over owns it.
    replay = client.post(
        _VULN_URL,
        json=body,
        headers={**auth_headers(client, "operator"), "Idempotency-Key": "abandoned"},
    )
    assert replay.json()["replayed"] is True


def test_a_failed_request_gives_its_key_back(tmp_path, monkeypatch):
    """A batch that died must be retryable with the same key. A reservation that
    never got an answer is not an answer."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    headers = {**auth_headers(client, "operator"), "Idempotency-Key": "retry-me"}
    body = {"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}}

    def boom(*_args, **_kwargs):
        raise RuntimeError("database went away mid-batch")

    # A nested context, not ``monkeypatch.undo()``: undo would also unwind the
    # settings patches ``configured_client`` installed, and the retry below
    # would authenticate against a different config than the app runs on.
    with monkeypatch.context() as patched:
        patched.setattr(bulk_actions, "apply_vulnerability_action", boom)
        try:
            client.post(_VULN_URL, json=body, headers=headers)
        except RuntimeError:
            pass  # TestClient re-raises the handler's exception; that is it.

    retried = client.post(_VULN_URL, json=body, headers=headers)

    assert retried.status_code == 200, retried.text
    assert retried.json()["succeeded"] == 2
    assert retried.json()["replayed"] is False


def test_the_key_is_namespaced_by_endpoint(tmp_path, monkeypatch):
    """One key on two endpoints is two promises, not a collision."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    headers = {**auth_headers(client, "operator"), "Idempotency-Key": "nightly"}
    asset_id = client.get("/api/assets", headers=auth_headers(client, "viewer")).json()["items"][0][
        "asset_id"
    ]

    vulns_response = client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}},
        headers=headers,
    )
    assets_response = client.post(
        _ASSET_URL,
        json={"action": "context", "asset_ids": [asset_id], "payload": {"owner_email": "ada@example.com"}},
        headers=headers,
    )

    assert vulns_response.status_code == 200, vulns_response.text
    assert assets_response.status_code == 200, assets_response.text
    assert assets_response.json()["replayed"] is False


def test_records_are_purged_once_past_their_ttl(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)
    client.post(
        _VULN_URL,
        json={"action": "assign", "vuln_ids": ids, "payload": {"assignee": "ada"}},
        headers={**auth_headers(client, "operator"), "Idempotency-Key": "old-key"},
    )

    # Nothing to purge yet: the record is minutes old and is what makes the
    # retry window work.
    assert idempotency_service.purge_expired(settings) == 0

    later = datetime.now(UTC).replace(tzinfo=None) + timedelta(
        seconds=idempotency_service.RETENTION_SECONDS + 60
    )
    assert idempotency_service.purge_expired(settings, now=later) == 1
    with get_session(settings.postgres_url) as session:
        assert session.execute(select(models.IdempotencyRecord)).scalars().all() == []


# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------


def test_one_request_sets_context_on_every_selected_asset(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    viewer = auth_headers(client, "viewer")
    asset_id = client.get("/api/assets", headers=viewer).json()["items"][0]["asset_id"]

    response = client.post(
        _ASSET_URL,
        json={
            "action": "context",
            "asset_ids": [asset_id, "ast_never_existed"],
            "payload": {
                "owner_email": "ada@example.com",
                "asset_criticality": 3,
                "exposure_level": "internet",
            },
        },
        headers=auth_headers(client, "operator"),
    )

    assert response.status_code == 200, response.text
    report = response.json()
    assert (report["succeeded"], report["failed"]) == (1, 1)
    assert _outcomes(report)["ast_never_existed"] == "not_found"
    detail = client.get(f"/api/assets/{asset_id}", headers=viewer).json()
    assert detail["owner_email"] == "ada@example.com"
    assert detail["asset_criticality"] == 3
    assert detail["exposure_level"] == "internet"
    # The per-asset context events are still written: the batch audit row is in
    # addition to them, not instead of them.
    events = client.get(f"/api/assets/{asset_id}/events", headers=viewer).json()
    assert {item["field"] for item in events["items"]} >= {"owner_email", "asset_criticality"}
    assert len(_audit_rows(settings, "asset.bulk")) == 1


def test_an_empty_asset_payload_is_refused(tmp_path, monkeypatch):
    """"Apply nothing to forty assets" is a mistake, not a no-op worth auditing."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    asset_id = client.get("/api/assets", headers=auth_headers(client, "viewer")).json()["items"][0][
        "asset_id"
    ]

    response = client.post(
        _ASSET_URL,
        json={"action": "context", "asset_ids": [asset_id], "payload": {}},
        headers=auth_headers(client, "operator"),
    )

    assert response.status_code == 422, response.text
    assert _audit_rows(settings, "asset.bulk") == []


def test_asset_bulk_needs_operator(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    asset_id = client.get("/api/assets", headers=auth_headers(client, "viewer")).json()["items"][0][
        "asset_id"
    ]

    response = client.post(
        _ASSET_URL,
        json={"action": "context", "asset_ids": [asset_id], "payload": {"business_unit": "ops"}},
        headers=auth_headers(client, "viewer"),
    )

    assert response.status_code == 403, response.text


def test_an_unknown_action_is_refused_by_the_schema(tmp_path, monkeypatch):
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)

    response = client.post(
        _VULN_URL,
        json={"action": "delete_everything", "vuln_ids": ids, "payload": {}},
        headers=auth_headers(client, "operator"),
    )

    assert response.status_code == 422, response.text
    # And the service, for a caller that skipped the schema.
    try:
        bulk_actions.apply_vulnerability_action(
            make_settings(tmp_path),
            tenant_id=tenant_id,
            vuln_ids=ids,
            action="delete_everything",
            payload={},
        )
    except ValueError as exc:
        assert "unknown bulk action" in str(exc)
    else:  # pragma: no cover - the assertion above is the test
        raise AssertionError("the service accepted an unknown action")


def test_a_transition_batch_without_its_state_is_a_schema_error(tmp_path, monkeypatch):
    """The discriminated union is what makes this a 422 rather than a KeyError."""
    client, settings, tenant_id = _client(tmp_path, monkeypatch)
    ids = _vuln_ids(settings, tenant_id)

    response = client.post(
        _VULN_URL,
        json={"action": "transition", "vuln_ids": ids, "payload": {}},
        headers=auth_headers(client, "operator"),
    )

    assert response.status_code == 422, response.text
