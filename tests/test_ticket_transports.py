"""ROADMAP P2: Jira/ServiceNow/DefectDojo as transports on the webhook queue."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from api.db import models
from api.db.engine import get_session
from api.services import tenants as tenants_service
from api.services import vulnerabilities as vulns_service
from api.services.integrations import delivery as delivery_transport
from api.services.integrations import tickets
from api.services.integrations import webhooks
from tests.conftest import make_settings, requires_postgres


def test_jira_body_and_parse():
    payload = {
        "event": {
            "kind": "new_cve",
            "host": "10.0.0.1",
            "port": 443,
            "run_id": "run-1",
            "data": {"cve": "CVE-2026-1", "severity": "critical"},
        }
    }
    cfg = tickets.validate_transport_config("jira", {"project_key": "SEC"})
    body = json.loads(tickets.build_body("jira", payload, cfg))
    assert body["fields"]["project"]["key"] == "SEC"
    assert body["fields"]["issuetype"]["name"] == "Bug"
    assert "CVE-2026-1" in body["fields"]["summary"]
    assert "not confirmation" in body["fields"]["description"]
    key, url = tickets.parse_created(
        "jira", "https://jira.example", '{"id":"1","key":"SEC-9"}'
    )
    assert key == "SEC-9"
    assert url == "https://jira.example/browse/SEC-9"


def test_servicenow_and_defectdojo_parse():
    key, url = tickets.parse_created(
        "servicenow",
        "https://ex.service-now.com",
        '{"result":{"number":"INC001","sys_id":"abc"}}',
    )
    assert key == "INC001"
    assert "sys_id=abc" in (url or "")
    key, url = tickets.parse_created("defectdojo", "https://dd.example", '{"id": 42}')
    assert key == "42"
    assert url == "https://dd.example/finding/42"


def test_jira_requires_project_key():
    with pytest.raises(tickets.TicketSpecError, match="project_key"):
        tickets.validate_transport_config("jira", {})


def test_hmac_is_not_applied_to_ticket_headers():
    headers = tickets.request_headers("jira", secret="tok", extra_headers={"X-Foo": "1"})
    assert headers["Authorization"] == "Bearer tok"
    assert "X-Shapoclyack-Signature" not in headers
    dd = tickets.request_headers("defectdojo", secret="ddtok", extra_headers=None)
    assert dd["Authorization"] == "Token ddtok"


def test_ticket_endpoint_stays_on_subscription_host():
    url = tickets.endpoint_url("jira", "https://jira.example/jira", {"project_key": "SEC"})
    assert url == "https://jira.example/jira/rest/api/2/issue"
    origin = tickets.endpoint_url("jira", "https://jira.example", {"project_key": "SEC"})
    assert origin == "https://jira.example/rest/api/2/issue"


pytestmark_pg = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
    s = make_settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    webhooks.configure(s)
    webhooks.reset_for_tests()
    return s


def _event(**overrides):
    body = {
        "kind": "new_cve",
        "tenant_id": "default",
        "event_id": "ev-ticket-1",
        "run_id": "run-1",
        "host": "10.0.0.1",
        "port": 443,
        "occurred_at": "2026-08-20T10:00:00+00:00",
        "source": "run_diff",
        "data": {"severity": "critical", "cve": "CVE-2026-1"},
    }
    body.update(overrides)
    return body


@requires_postgres
def test_jira_subscription_creates_ticket_and_links_finding(settings):
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Asset(
                asset_id="asset-1",
                tenant_id="default",
                status="active",
                first_seen=now,
                last_seen=now,
            )
        )
        session.add(
            models.AssetIdentifier(
                asset_id="asset-1",
                tenant_id="default",
                identifier_type="ip",
                identifier_value="10.0.0.1",
            )
        )
        session.add(
            models.Vulnerability(
                vuln_id="vln_1",
                tenant_id="default",
                asset_id="asset-1",
                finding_key=vulns_service.finding_key(
                    asset_id="asset-1", cve="CVE-2026-1", script_id=None, port="443"
                ),
                cve="CVE-2026-1",
                port="443",
                title="CVE-2026-1",
                severity="critical",
                state="OPEN",
                state_changed_at=now,
                first_seen_at=now,
                last_seen_at=now,
                sla_started_at=now,
                created_at=now,
                updated_at=now,
            )
        )

    sub = webhooks.create_subscription(
        tenant_id="default",
        name="jira-soc",
        url="https://jira.example",
        transport="jira",
        transport_config={"project_key": "SEC"},
        secret="jira-token",
        created_by="admin",
    )
    assert sub["transport"] == "jira"
    assert sub["secret"] == "jira-token"

    captured: list[tuple[str, bytes]] = []

    def fake_post(url, body, headers, **kwargs):
        captured.append((url, body))
        assert "X-Shapoclyack-Signature" not in headers
        assert headers.get("Authorization") == "Bearer jira-token"
        return delivery_transport.DeliveryResult(
            ok=True,
            status_code=201,
            error=None,
            retryable=False,
            body='{"id":"10001","key":"SEC-7"}',
        )

    created = webhooks.enqueue_event(_event())
    assert created
    outcome = webhooks.dispatch_once(post=fake_post)
    assert outcome["delivered"] == 1
    assert captured[0][0] == "https://jira.example/rest/api/2/issue"
    fields = json.loads(captured[0][1])["fields"]
    assert fields["project"]["key"] == "SEC"

    finding = vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_1")
    assert finding is not None
    assert finding["ticket_system"] == "jira"
    assert finding["ticket_key"] == "SEC-7"
    assert finding["ticket_url"] == "https://jira.example/browse/SEC-7"


@requires_postgres
def test_existing_ticket_is_not_overwritten(settings):
    now = datetime.now(UTC)
    with get_session(settings.postgres_url) as session:
        session.add(
            models.Asset(
                asset_id="asset-2",
                tenant_id="default",
                status="active",
                first_seen=now,
                last_seen=now,
            )
        )
        session.add(
            models.AssetIdentifier(
                asset_id="asset-2",
                tenant_id="default",
                identifier_type="ip",
                identifier_value="10.0.0.2",
            )
        )
        session.add(
            models.Vulnerability(
                vuln_id="vln_2",
                tenant_id="default",
                asset_id="asset-2",
                finding_key=vulns_service.finding_key(
                    asset_id="asset-2", cve="CVE-2026-2", script_id=None, port="80"
                ),
                cve="CVE-2026-2",
                port="80",
                title="CVE-2026-2",
                severity="high",
                state="OPEN",
                state_changed_at=now,
                first_seen_at=now,
                last_seen_at=now,
                sla_started_at=now,
                ticket_system="jira",
                ticket_key="SEC-KEEP",
                ticket_url="https://jira.example/browse/SEC-KEEP",
                created_at=now,
                updated_at=now,
            )
        )

    webhooks.create_subscription(
        tenant_id="default",
        name="jira-soc",
        url="https://jira.example",
        transport="jira",
        transport_config={"project_key": "SEC"},
        secret="tok",
        created_by="admin",
    )

    def fake_post(url, body, headers, **kwargs):
        return delivery_transport.DeliveryResult(
            ok=True,
            status_code=201,
            error=None,
            retryable=False,
            body='{"key":"SEC-NEW"}',
        )

    webhooks.enqueue_event(
        _event(event_id="ev-keep", host="10.0.0.2", port=80, data={"cve": "CVE-2026-2", "severity": "high"})
    )
    webhooks.dispatch_once(post=fake_post)
    finding = vulns_service.get_vulnerability(settings, tenant_id="default", vuln_id="vln_2")
    assert finding["ticket_key"] == "SEC-KEEP"


@requires_postgres
def test_webhook_transport_still_hmac_posts(settings):
    sub = webhooks.create_subscription(
        tenant_id="default",
        name="hook",
        url="https://receiver.example/hook",
        created_by="admin",
    )
    assert sub["transport"] == "webhook"
    seen = []

    def fake_post(url, body, headers, **kwargs):
        seen.append(headers)
        return delivery_transport.DeliveryResult(
            ok=True, status_code=200, error=None, retryable=False
        )

    webhooks.enqueue_event(_event(event_id="ev-hmac"))
    webhooks.dispatch_once(post=fake_post)
    assert any(h.get("X-Shapoclyack-Signature", "").startswith("sha256=") for h in seen)
