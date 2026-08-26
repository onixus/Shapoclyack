"""Approved per-tenant scanning scope (#226): matching, both barriers, the API.

The failure this covers is not a crash: before it, a well-formed target was an
authorized target, so a tenant operator could scan a link-local address, the
provider's cluster range, or a third party, and nothing recorded whether they
had been allowed to.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from api.schemas import StartScanRequest
from api.services import auth_audit
from api.services import jobs as jobs_service
from api.services import scan_schedules
from api.services import schedule_dispatcher
from api.services import scan_scopes
from api.services import tenants as tenants_service
from api.services.targets import parse_target_payload
from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

ALLOW_TEN_NET = {"effect": "allow", "kind": "cidr", "value": "10.0.0.0/8"}
DENY_METADATA = {"effect": "deny", "kind": "cidr", "value": "169.254.0.0/16"}
ALLOW_EXAMPLE = {"effect": "allow", "kind": "domain", "value": "example.com"}
DENY_INTERNAL_EXAMPLE = {"effect": "deny", "kind": "domain", "value": "internal.example.com"}


@pytest.fixture()
def settings(tmp_path: Path):
    """A clean control plane whose default tenant has *no* approved scope yet."""
    base = make_settings(tmp_path, state_dir=tmp_path / "state", output_dir=tmp_path / "output")
    base.state_dir.mkdir(parents=True, exist_ok=True)
    base.output_dir.mkdir(parents=True, exist_ok=True)
    tenants_service.configure(base)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(base)
    auth_audit.configure(base)
    auth_audit.reset_for_tests()
    scan_schedules.configure(base)
    scan_schedules.reset_for_tests()
    return base


def _scope(settings, *entries: dict) -> scan_scopes.ScanScope:
    scan_scopes.replace_scope(
        settings, tenant_id="default", entries=list(entries), approved_by="admin"
    )
    return scan_scopes.load_scope(settings, "default")


# --- matching ---------------------------------------------------------------


def test_a_range_inside_an_allowed_range_is_in_scope(settings):
    scope = _scope(settings, ALLOW_TEN_NET)
    assert scope.rejects_network("10.1.2.0/24") is None


def test_a_range_outside_every_allowed_range_is_refused(settings):
    scope = _scope(settings, ALLOW_TEN_NET)
    assert scope.rejects_network("192.168.1.0/24") == "not inside any allowed range"


def test_a_range_only_partly_allowed_is_not_half_approved(settings):
    """Containment, not intersection: 10.0.0.0/7 reaches outside the approval."""
    scope = _scope(settings, ALLOW_TEN_NET)
    assert scope.rejects_network("10.0.0.0/7") == "not inside any allowed range"


def test_deny_beats_allow(settings):
    """The property the whole table hangs on, in its plainest form."""
    scope = _scope(
        settings,
        {"effect": "allow", "kind": "cidr", "value": "0.0.0.0/0"},
        DENY_METADATA,
    )
    assert scope.rejects_network("169.254.169.254/32") == "denied by 169.254.0.0/16"


def test_deny_cannot_be_stepped_over_by_widening_the_target(settings):
    """A denied address inside a wider allowed range denies the wider range too.

    Overlap, not containment: were deny checked the way allow is, asking for
    ``10.0.0.0/8`` would be a way to reach the ``10.1.2.0/24`` that was denied.
    """
    scope = _scope(
        settings,
        ALLOW_TEN_NET,
        {"effect": "deny", "kind": "cidr", "value": "10.1.2.0/24"},
    )
    assert scope.rejects_network("10.1.2.7/32") == "denied by 10.1.2.0/24"
    assert scope.rejects_network("10.0.0.0/8") == "denied by 10.1.2.0/24"


def test_a_domain_allow_covers_its_subdomains_and_nothing_else(settings):
    scope = _scope(settings, ALLOW_EXAMPLE)
    assert scope.rejects_domain("example.com") is None
    assert scope.rejects_domain("www.example.com") is None
    assert scope.rejects_domain("notexample.com") == "not under any allowed domain"


def test_a_denied_subdomain_beats_the_allowed_parent(settings):
    scope = _scope(settings, ALLOW_EXAMPLE, DENY_INTERNAL_EXAMPLE)
    assert scope.rejects_domain("db.internal.example.com") == "denied by internal.example.com"
    assert scope.rejects_domain("www.example.com") is None


def test_a_tenant_with_no_entries_has_no_scope_at_all(settings):
    scope = scan_scopes.load_scope(settings, "default")
    assert scope.approved is False
    with pytest.raises(scan_scopes.ScanScopeDenied, match="no approved scan scope"):
        scope.require_approved()


# --- the two barriers -------------------------------------------------------


def test_a_tenant_without_an_approved_scope_starts_no_scan(settings):
    """Fail-closed: not even a run on the installation's default target files."""
    with pytest.raises(scan_scopes.ScanScopeDenied, match="no approved scan scope"):
        jobs_service.start_scan(settings, StartScanRequest(mode="balanced"), username="operator")


def test_parsing_refuses_a_target_the_scope_does_not_cover(settings):
    """The first barrier on its own: no job, no database, just the input."""
    scope = _scope(settings, ALLOW_TEN_NET)
    with pytest.raises(scan_scopes.ScanScopeDenied, match="outside the approved scan scope"):
        parse_target_payload(
            scope=scope,
            ranges_text="192.168.0.0/24",
            domains_text=None,
            ports_text=None,
        )


def test_parsing_refuses_a_tenant_with_no_approved_scope(settings):
    """Even a payload that would have meant "use the server defaults"."""
    scope = scan_scopes.load_scope(settings, "default")
    with pytest.raises(scan_scopes.ScanScopeDenied, match="no approved scan scope"):
        parse_target_payload(
            scope=scope, ranges_text=None, domains_text=None, ports_text=None
        )


def test_an_out_of_scope_target_does_not_start_a_scan(settings):
    _scope(settings, ALLOW_TEN_NET)
    with pytest.raises(scan_scopes.ScanScopeDenied, match="outside the approved scan scope"):
        jobs_service.start_scan(
            settings,
            StartScanRequest(mode="balanced", ranges="192.168.0.0/24"),
            username="operator",
        )


def test_start_scan_refuses_out_of_scope_targets_even_with_the_first_barrier_gone(
    settings, monkeypatch
):
    """The second barrier has to stand on its own.

    ``start_scan`` is also reached from paths that never ran the input check —
    the schedule dispatcher replays targets stored days earlier — so this
    removes the first barrier (parsing with an allow-everything scope) and
    asserts the scan is still refused.
    """
    _scope(settings, ALLOW_TEN_NET)
    real_parse = jobs_service.parse_target_payload
    permissive = scan_scopes.ScanScope(
        tenant_id="default",
        allow_networks=(scan_scopes._network("0.0.0.0/0"),),  # noqa: SLF001
        allow_domains=("*",),
        approved=True,
    )
    monkeypatch.setattr(
        jobs_service,
        "parse_target_payload",
        lambda *, scope, **kwargs: real_parse(scope=permissive, **kwargs),
    )

    with pytest.raises(scan_scopes.ScanScopeDenied, match="outside the approved scan scope"):
        jobs_service.start_scan(
            settings,
            StartScanRequest(mode="balanced", ranges="192.168.0.0/24"),
            username="operator",
        )


def test_the_schedule_dispatcher_cannot_start_a_scan_the_scope_no_longer_allows(settings):
    """Targets approved when the schedule was written, refused when it fires."""
    _scope(settings, {"effect": "allow", "kind": "cidr", "value": "0.0.0.0/0"})
    sched = scan_schedules.create_schedule(
        tenant_id="default",
        name="nightly",
        cron=None,
        interval_seconds=60,
        scan_options={"mode": "fast"},
        targets={"ranges": "192.168.0.0/24"},
        created_by="operator",
    )
    scan_schedules.record_dispatch(
        sched["schedule_id"], job_id="prior", ran_at=datetime.now(UTC) - timedelta(hours=1)
    )
    # The scope is narrowed after the schedule was stored.
    _scope(settings, ALLOW_TEN_NET)

    dispatcher = schedule_dispatcher.ScheduleDispatcher(settings=settings)
    dispatcher._tick()  # noqa: SLF001

    assert dispatcher.stats["dispatched"] == 0
    _, total = jobs_service.list_jobs(settings)
    assert total == 0


def test_a_refusal_lands_in_the_access_decision_journal(settings):
    _scope(settings, ALLOW_TEN_NET)
    with pytest.raises(scan_scopes.ScanScopeDenied):
        jobs_service.start_scan(
            settings,
            StartScanRequest(mode="balanced", ranges="192.168.0.0/24"),
            username="operator",
        )

    events, total = auth_audit.list_events(outcome=auth_audit.OUTCOME_DENIED)
    assert total == 1
    assert events[0]["username"] == "operator"
    assert events[0]["reason"] == auth_audit.REASON_SCAN_SCOPE
    assert "192.168.0.0/24" in events[0]["detail"]


# --- resolution -------------------------------------------------------------


def test_a_name_resolving_into_a_denied_range_is_refused(settings, monkeypatch):
    """A domain inside the scope by suffix cannot be a way into a denied range."""
    _scope(settings, ALLOW_EXAMPLE, DENY_METADATA)
    monkeypatch.setattr(scan_scopes, "_resolve", lambda host: ["169.254.169.254"])

    with pytest.raises(scan_scopes.ScanScopeDenied, match="resolve into a denied range"):
        jobs_service.start_scan(
            settings,
            StartScanRequest(mode="balanced", domains="metadata.example.com"),
            username="operator",
        )


def test_names_are_not_resolved_when_the_scope_denies_no_ranges(settings, monkeypatch):
    """No deny entry, no lookup: nothing a resolved address could be refused by."""
    _scope(settings, ALLOW_EXAMPLE)
    calls: list[str] = []
    monkeypatch.setattr(scan_scopes, "_resolve", lambda host: calls.append(host) or [])

    scan_scopes.assert_scan_allowed(
        settings, tenant_id="default", ranges_text=None, domains_text="www.example.com"
    )
    assert calls == []


def test_the_resolution_check_can_be_turned_off(settings, monkeypatch):
    _scope(settings, ALLOW_EXAMPLE, DENY_METADATA)
    monkeypatch.setattr(scan_scopes, "_resolve", lambda host: ["169.254.169.254"])
    settings.scan_scope_resolve_check = False

    scan_scopes.assert_scan_allowed(
        settings, tenant_id="default", ranges_text=None, domains_text="metadata.example.com"
    )


# --- the admin API ----------------------------------------------------------


def test_scope_round_trips_through_the_admin_api(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    stored = client.put(
        "/api/tenants/default/scan-scope",
        headers=admin,
        json={"entries": [ALLOW_TEN_NET, DENY_METADATA]},
    )
    assert stored.status_code == 200
    values = {(e["effect"], e["value"]) for e in stored.json()}
    assert values == {("allow", "10.0.0.0/8"), ("deny", "169.254.0.0/16")}
    assert all(e["approved_by"] == "admin" and e["approved_at"] for e in stored.json())

    listed = client.get("/api/tenants/default/scan-scope", headers=admin)
    assert listed.status_code == 200
    assert {(e["effect"], e["value"]) for e in listed.json()} == values


def test_replacing_a_scope_drops_what_it_no_longer_lists(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    client.put(
        "/api/tenants/default/scan-scope", headers=admin, json={"entries": [ALLOW_TEN_NET]}
    )
    replaced = client.put(
        "/api/tenants/default/scan-scope", headers=admin, json={"entries": [ALLOW_EXAMPLE]}
    )
    assert [e["value"] for e in replaced.json()] == ["example.com"]


def test_an_operator_cannot_approve_their_own_scope(tmp_path, monkeypatch):
    """Approval is administrative, like minting a provisioning key (#231)."""
    client = configured_client(tmp_path, monkeypatch)
    operator = auth_headers(client, "operator")

    assert (
        client.put(
            "/api/tenants/default/scan-scope",
            headers=operator,
            json={"entries": [{"effect": "allow", "kind": "cidr", "value": "0.0.0.0/0"}]},
        ).status_code
        == 403
    )
    assert client.get("/api/tenants/default/scan-scope", headers=operator).status_code == 403


def test_a_malformed_entry_is_refused_with_422(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    assert (
        client.put(
            "/api/tenants/default/scan-scope",
            headers=admin,
            json={"entries": [{"effect": "allow", "kind": "cidr", "value": "not-a-cidr"}]},
        ).status_code
        == 422
    )


def test_the_scope_of_an_unknown_tenant_is_404(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    assert client.get("/api/tenants/nope/scan-scope", headers=admin).status_code == 404
    assert (
        client.put(
            "/api/tenants/nope/scan-scope", headers=admin, json={"entries": []}
        ).status_code
        == 404
    )


def test_starting_an_out_of_scope_scan_over_the_api_is_403(tmp_path, monkeypatch):
    """403, not 422: the target is well-formed, the tenant is not entitled."""
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    # configured_client() approves an allow-all scope; narrow it first.
    client.put(
        "/api/tenants/default/scan-scope", headers=admin, json={"entries": [ALLOW_TEN_NET]}
    )

    refused = client.post(
        "/api/jobs",
        headers=auth_headers(client, "operator"),
        json={"mode": "safe", "ranges": "192.168.0.0/24"},
    )
    assert refused.status_code == 403
    assert "outside the approved scan scope" in refused.json()["detail"]
