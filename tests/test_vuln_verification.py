"""Closed-loop remediation: machine verification and ticket sync (#183).

The property under test is narrow and it is the whole point of the feature: a
finding is only closed as ``machine_verified`` when the scan that was
*dispatched to look for it* failed to find it. Every other way a scan can touch
the asset must leave the finding where it is.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from api.services import vuln_states
from api.services import vulnerabilities as vulns
from api.services.integrations import ticket_sync
from api.services.integrations.delivery import DeliveryResult
from tests.conftest import approve_scan_scope, requires_postgres

from tests.test_vuln_lifecycle import _seed, _write_run


# --------------------------------------------------------------------------
# Ticket mapping and URL construction (no database)
# --------------------------------------------------------------------------


def test_jira_status_maps_to_lifecycle_state():
    payload = {"fields": {"status": {"name": "Done"}}}
    assert ticket_sync.map_remote_status_to_vuln_state("jira", payload) == ("CLOSED", "Done")
    payload = {"fields": {"status": {"name": "In Progress"}}}
    assert ticket_sync.map_remote_status_to_vuln_state("jira", payload) == ("FIXING", "In Progress")


def test_unknown_jira_status_suggests_nothing():
    """An unmapped workflow step must not be read as progress in either direction."""
    payload = {"fields": {"status": {"name": "Waiting for Vendor"}}}
    suggested, raw = ticket_sync.map_remote_status_to_vuln_state("jira", payload)
    assert suggested is None
    assert raw == "Waiting for Vendor"


def test_no_tracker_ever_suggests_verifying():
    """Only a scan can say a finding is being verified."""
    for mapping in (ticket_sync.JIRA_STATUS_MAP, ticket_sync.SNOW_STATE_MAP):
        assert vuln_states.VERIFYING not in mapping.values()


def test_servicenow_result_list_is_unwrapped():
    payload = {"result": [{"incident_state": "6", "state": "6"}]}
    assert ticket_sync.map_remote_status_to_vuln_state("servicenow", payload)[0] == "CLOSED"


def test_defectdojo_mitigated_is_closed_and_active_is_not():
    assert ticket_sync.map_remote_status_to_vuln_state(
        "defectdojo", {"active": False, "is_mitigated": True}
    ) == ("CLOSED", "Mitigated")
    assert ticket_sync.map_remote_status_to_vuln_state(
        "defectdojo", {"active": True, "is_mitigated": False}
    ) == ("FIXING", "Active")


def test_ticket_key_cannot_walk_the_request_off_its_path():
    """A key is a key. It does not get to choose the host or climb the path."""
    calls: list[str] = []

    def fake_request(method, url, body, headers, **kwargs):
        calls.append(url)
        return DeliveryResult(ok=True, status_code=200, error=None, retryable=False, body="{}")

    ticket_sync.fetch_ticket_status(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="../../admin",
        request_fn=fake_request,
    )
    assert calls == ["https://jira.example.com/rest/api/2/issue/..%2F..%2Fadmin"]


def test_base_url_must_be_absolute():
    with pytest.raises(Exception):
        ticket_sync._url("jira.example.com/x", "rest/api/2/issue/A-1")


def test_unreachable_tracker_suggests_nothing():
    """A tracker we cannot read is never read as 'the work is done'."""

    def fake_request(method, url, body, headers, **kwargs):
        return DeliveryResult(
            ok=False, status_code=503, error="HTTP 503", retryable=True, body=None
        )

    suggested, raw, payload = ticket_sync.fetch_ticket_status(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="SEC-1",
        request_fn=fake_request,
    )
    assert suggested is None
    assert raw is None
    assert payload["status_code"] == 503


def test_servicenow_update_goes_to_sys_id_not_the_collection():
    """A PATCH against the query URL updates nothing; the Table API needs sys_id."""
    seen: list[tuple[str, str]] = []

    def fake_request(method, url, body, headers, **kwargs):
        seen.append((method, url))
        if method == "GET":
            return DeliveryResult(
                ok=True,
                status_code=200,
                error=None,
                retryable=False,
                body=json.dumps({"result": [{"sys_id": "abc123"}]}),
            )
        return DeliveryResult(ok=True, status_code=200, error=None, retryable=False)

    assert ticket_sync.push_status_update(
        transport="servicenow",
        base_url="https://snow.example.com",
        ticket_key="INC001",
        to_state="CLOSED",
        request_fn=fake_request,
    )
    method, url = seen[-1]
    assert method == "PATCH"
    assert url == "https://snow.example.com/api/now/table/incident/abc123"


def test_servicenow_update_gives_up_when_sys_id_is_unknown():
    def fake_request(method, url, body, headers, **kwargs):
        return DeliveryResult(
            ok=True, status_code=200, error=None, retryable=False, body=json.dumps({"result": []})
        )

    assert not ticket_sync.push_status_update(
        transport="servicenow",
        base_url="https://snow.example.com",
        ticket_key="INC404",
        to_state="CLOSED",
        request_fn=fake_request,
    )


def test_jira_push_uses_an_available_transition():
    seen: list[tuple[str, str, bytes]] = []

    def fake_request(method, url, body, headers, **kwargs):
        seen.append((method, url, body))
        if method == "GET":
            return DeliveryResult(
                ok=True,
                status_code=200,
                error=None,
                retryable=False,
                body=json.dumps({"transitions": [{"id": "31", "name": "Done"}]}),
            )
        return DeliveryResult(ok=True, status_code=200, error=None, retryable=False)

    assert ticket_sync.push_status_update(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="SEC-1",
        to_state="CLOSED",
        request_fn=fake_request,
    )
    assert json.loads(seen[-1][2]) == {"transition": {"id": "31"}}


def test_jira_push_reports_failure_when_the_workflow_has_no_such_step():
    def fake_request(method, url, body, headers, **kwargs):
        return DeliveryResult(
            ok=True,
            status_code=200,
            error=None,
            retryable=False,
            body=json.dumps({"transitions": [{"id": "11", "name": "Start Progress"}]}),
        )

    assert not ticket_sync.push_status_update(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="SEC-1",
        to_state="CLOSED",
        request_fn=fake_request,
    )


def test_credentials_reach_the_tracker():
    """The whole sync is useless if the request goes out unauthenticated."""
    captured: dict[str, str] = {}

    def fake_request(method, url, body, headers, **kwargs):
        captured.update(headers)
        return DeliveryResult(ok=True, status_code=200, error=None, retryable=False, body="{}")

    ticket_sync.fetch_ticket_status(
        transport="jira",
        base_url="https://jira.example.com",
        ticket_key="SEC-1",
        secret="s3cr3t",
        request_fn=fake_request,
    )
    assert captured["Authorization"] == "Bearer s3cr3t"


# --------------------------------------------------------------------------
# The closure gate (Postgres)
# --------------------------------------------------------------------------


def _vuln_ids(settings, tenant_id):
    items, _ = vulns.list_vulnerabilities(settings, tenant_id=tenant_id, limit=50)
    return {v["cve"]: v for v in items}


def _park_in_verifying(settings, tenant_id, vuln_id, job_id):
    """Put a finding in VERIFYING behind ``job_id`` without dispatching a scan."""
    from api.db import models
    from api.db.engine import get_session

    with get_session(settings.postgres_url) as session:
        row = session.get(models.Vulnerability, vuln_id)
        row.state = vuln_states.VERIFYING
        row.verification_job_id = job_id
        row.state_changed_at = datetime.now(UTC).replace(tzinfo=None)
        session.commit()


def _job_for_run(settings, tenant_id, job_id, run_id):
    from api.db import models
    from api.db.engine import get_session

    now = datetime.now(UTC).replace(tzinfo=None)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id=job_id,
                tenant_id=tenant_id,
                status="succeeded",
                run_id=run_id,
                queued_at=now,
                finished_at=now,
            )
        )
        session.commit()


@requires_postgres
def test_unrelated_run_does_not_close_a_verifying_finding(tmp_path):
    """The regression this feature is one bad query away from.

    A routine scan that happens to touch the same asset is not a verification.
    """
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    tracked = _vuln_ids(settings, tenant_id)
    target = tracked["CVE-2024-0001"]["vuln_id"]
    _park_in_verifying(settings, tenant_id, target, "job-verify")

    # A later, unrelated run of the same asset that no longer reports the CVE.
    _write_run(
        settings.output_dir,
        "run-2",
        [{"host": "10.0.0.5", "hostname": "app.example.com"}],
        [{"host": "10.0.0.5", "port": "80", "cve": "CVE-2024-0002", "severity": "medium"}],
    )
    _job_for_run(settings, tenant_id, "job-routine", "run-2")
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-2")

    assert stats.verification_passed == 0
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=target)
    assert after["state"] == vuln_states.VERIFYING
    assert after["machine_verified"] is False


@requires_postgres
def test_verification_run_that_finds_nothing_closes_the_finding(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    tracked = _vuln_ids(settings, tenant_id)
    target = tracked["CVE-2024-0001"]["vuln_id"]
    _park_in_verifying(settings, tenant_id, target, "job-verify")

    _write_run(
        settings.output_dir,
        "run-verify",
        [{"host": "10.0.0.5", "hostname": "app.example.com"}],
        [{"host": "10.0.0.5", "port": "80", "cve": "CVE-2024-0002", "severity": "medium"}],
    )
    _job_for_run(settings, tenant_id, "job-verify", "run-verify")
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-verify")

    assert stats.verification_passed == 1
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=target)
    assert after["state"] == vuln_states.CLOSED
    assert after["machine_verified"] is True
    assert after["closure_reason"] == "verified_remediated"


@requires_postgres
def test_an_empty_verification_run_still_closes_the_loop(tmp_path):
    """A scan that finds nothing at all *is* the success case, not a no-op."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    tracked = _vuln_ids(settings, tenant_id)
    target = tracked["CVE-2024-0001"]["vuln_id"]
    _park_in_verifying(settings, tenant_id, target, "job-verify")

    _write_run(settings.output_dir, "run-clean", [{"host": "10.0.0.5"}], [])
    _job_for_run(settings, tenant_id, "job-verify", "run-clean")
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-clean")

    assert stats.verification_passed == 1
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=target)
    assert after["state"] == vuln_states.CLOSED
    assert after["machine_verified"] is True


@requires_postgres
def test_verification_that_still_sees_the_finding_bounces_it_back(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    tracked = _vuln_ids(settings, tenant_id)
    target = tracked["CVE-2024-0001"]["vuln_id"]
    _park_in_verifying(settings, tenant_id, target, "job-verify")

    _write_run(
        settings.output_dir,
        "run-verify",
        [{"host": "10.0.0.5", "hostname": "app.example.com"}],
        [{"host": "10.0.0.5", "port": "443", "cve": "CVE-2024-0001", "severity": "critical"}],
    )
    _job_for_run(settings, tenant_id, "job-verify", "run-verify")
    stats = vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-verify")

    assert stats.verification_failed == 1
    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=target)
    assert after["state"] == vuln_states.FIXING
    assert after["machine_verified"] is False


@requires_postgres
def test_manual_closure_is_never_machine_verified(tmp_path):
    """The metric is worthless if an operator can assert it about their own work."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    tracked = _vuln_ids(settings, tenant_id)
    target = tracked["CVE-2024-0001"]["vuln_id"]

    closed = vulns.transition(
        settings,
        tenant_id=tenant_id,
        vuln_id=target,
        to_state=vuln_states.CLOSED,
        actor="alice",
        note="patched",
    )
    assert closed["machine_verified"] is False
    assert closed["closure_reason"] == "manual"


@requires_postgres
def test_reopening_clears_the_verification_verdict(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    target = _vuln_ids(settings, tenant_id)["CVE-2024-0001"]["vuln_id"]
    _park_in_verifying(settings, tenant_id, target, "job-verify")
    _write_run(settings.output_dir, "run-clean", [{"host": "10.0.0.5"}], [])
    _job_for_run(settings, tenant_id, "job-verify", "run-clean")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-clean")

    reopened = vulns.transition(
        settings, tenant_id=tenant_id, vuln_id=target, to_state=vuln_states.OPEN, actor="bob"
    )
    assert reopened["machine_verified"] is False
    assert reopened["closure_reason"] is None


def _advance_to_fixing(settings, tenant_id, vuln_id):
    for state in (vuln_states.ACKNOWLEDGED, vuln_states.PLANNED, vuln_states.FIXING):
        vulns.transition(
            settings, tenant_id=tenant_id, vuln_id=vuln_id, to_state=state, actor="alice"
        )


@requires_postgres
def test_verification_is_refused_when_scanning_is_disabled(tmp_path):
    """No scan means no VERIFYING: a parked finding would later close falsely."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    target = _vuln_ids(settings, tenant_id)["CVE-2024-0001"]["vuln_id"]
    _advance_to_fixing(settings, tenant_id, target)
    settings.allow_scan_start = False

    with pytest.raises(vulns.VerificationDispatchError):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=target, actor="alice")

    after = vulns.get_vulnerability(settings, tenant_id=tenant_id, vuln_id=target)
    assert after["state"] == vuln_states.FIXING
    assert after["verification_job_id"] is None


@requires_postgres
def test_verification_is_dispatched_even_with_the_scan_quota_spent(tmp_path):
    """A spent monthly quota must not strand a finding in FIXING.

    The verification re-scan is the platform closing its own loop, so it is
    exempt — and the exemption has to survive the fact that this path carries
    the *analyst's* username into ``start_scan``, which is what made an earlier
    username-keyed exemption never fire.
    """
    from api.db import models
    from api.db.engine import get_session
    from api.services import quotas

    settings, tenant_id = _seed(tmp_path)
    approve_scan_scope(settings)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    target = _vuln_ids(settings, tenant_id)["CVE-2024-0001"]["vuln_id"]
    _advance_to_fixing(settings, tenant_id, target)

    quotas.set_quota(settings, tenant_id, max_assets=None, max_scans_per_month=1)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Job(
                job_id="quota-filler",
                tenant_id=tenant_id,
                status="succeeded",
                queued_at=datetime.now(UTC).replace(tzinfo=None),
            )
        )
    with pytest.raises(quotas.QuotaExceeded):
        quotas.assert_scan_quota(settings, tenant_id=tenant_id)

    result = vulns.trigger_verification(
        settings, tenant_id=tenant_id, vuln_id=target, actor="alice"
    )

    assert result is not None
    assert result["state"] == vuln_states.VERIFYING
    assert result["verification_job_id"]
    # And it did not spend the customer's entitlement on the way through.
    assert quotas.scans_used(settings, tenant_id) == 1


@requires_postgres
def test_verification_respects_the_state_machine(tmp_path):
    """An untriaged finding is not re-verified; nobody has claimed to fix it."""
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    target = _vuln_ids(settings, tenant_id)["CVE-2024-0001"]["vuln_id"]

    with pytest.raises(vuln_states.InvalidVulnTransition):
        vulns.trigger_verification(settings, tenant_id=tenant_id, vuln_id=target, actor="alice")


@requires_postgres
def test_summary_reports_the_verification_rate(tmp_path):
    settings, tenant_id = _seed(tmp_path)
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-1")
    tracked = _vuln_ids(settings, tenant_id)
    verified = tracked["CVE-2024-0001"]["vuln_id"]
    manual = tracked["CVE-2024-0002"]["vuln_id"]

    _park_in_verifying(settings, tenant_id, verified, "job-verify")
    _write_run(settings.output_dir, "run-clean", [{"host": "10.0.0.5"}], [])
    _job_for_run(settings, tenant_id, "job-verify", "run-clean")
    vulns.register_findings_from_run(settings, tenant_id=tenant_id, run_id="run-clean")
    vulns.transition(
        settings, tenant_id=tenant_id, vuln_id=manual, to_state=vuln_states.CLOSED, actor="alice"
    )

    summary = vulns.summary(settings, tenant_id=tenant_id)
    assert summary["closed_total"] == 2
    assert summary["machine_verified_closed"] == 1
    assert summary["manual_closed"] == 1
    assert summary["machine_verification_rate"] == 50.0
