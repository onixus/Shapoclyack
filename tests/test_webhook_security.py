"""P0 regression coverage for webhook hardening (#151)."""

from __future__ import annotations

from pathlib import Path

import pytest

from api.services import tenants as tenants_service
from api.services.integrations import delivery as delivery_transport
from api.services.integrations import webhooks
from api.settings import Settings
from tests.conftest import make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    value = make_settings(tmp_path)
    tenants_service.configure(value)
    tenants_service.load_tenants(value)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(value)
    webhooks.configure(value)
    webhooks.reset_for_tests()
    return value


def _subscribe(settings: Settings, **overrides) -> dict:
    payload = {
        "tenant_id": "default",
        "name": "soc",
        "url": "https://receiver.example/hook",
        "created_by": "admin",
    }
    payload.update(overrides)
    return webhooks.create_subscription(**payload)


def _event(event_id: str = "ev-security") -> dict:
    return {
        "kind": "new_cve",
        "tenant_id": "default",
        "event_id": event_id,
        "run_id": "run-1",
        "host": "10.0.0.1",
        "port": 443,
        "occurred_at": "2026-08-14T09:00:00+00:00",
        "source": "run_diff",
        "data": {"severity": "critical", "cve": "CVE-2026-1"},
    }


def _ok(*args, **kwargs) -> delivery_transport.DeliveryResult:
    return delivery_transport.DeliveryResult(
        ok=True,
        status_code=204,
        error=None,
        retryable=False,
    )


def test_custom_header_values_are_write_only(settings):
    created = _subscribe(
        settings,
        headers={
            "Authorization": "Bearer super-secret-token",
            "X-Api-Key": "api-key-value",
        },
    )

    assert created["secret"]
    assert created["headers"] == {
        "Authorization": "***",
        "X-Api-Key": "***",
    }

    fetched = webhooks.get_subscription(created["subscription_id"])
    assert fetched is not None
    assert fetched["headers"] == {
        "Authorization": "***",
        "X-Api-Key": "***",
    }
    assert "super-secret-token" not in repr(fetched)
    assert "api-key-value" not in repr(fetched)

    listed, total = webhooks.list_subscriptions(tenant_id="default")
    assert total == 1
    assert listed[0]["headers"] == {
        "Authorization": "***",
        "X-Api-Key": "***",
    }


def test_disabled_subscription_freezes_queued_delivery_and_reenable_resumes(settings):
    subscription = _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]
    assert webhooks.update_subscription(subscription["subscription_id"], enabled=False)["enabled"] is False

    sent: list[str] = []

    def _capture(url, body, headers, **kwargs):
        sent.append(url)
        return _ok()

    outcome = webhooks.dispatch_once(post=_capture)
    assert outcome == {"attempted": 0, "delivered": 0, "retrying": 0, "dead": 0}
    assert sent == []

    frozen = webhooks.get_delivery(delivery_id)
    assert frozen is not None
    assert frozen["status"] == "pending"
    assert frozen["attempts"] == 0

    assert webhooks.update_subscription(subscription["subscription_id"], enabled=True)["enabled"] is True
    resumed = webhooks.dispatch_once(post=_capture)
    assert resumed["attempted"] == 1
    assert resumed["delivered"] == 1
    assert sent == ["https://receiver.example/hook"]

    delivered = webhooks.get_delivery(delivery_id)
    assert delivered is not None
    assert delivered["status"] == "delivered"
    assert delivered["attempts"] == 1


def test_disable_winning_after_claim_releases_attempt_without_sending(settings, monkeypatch):
    _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event("ev-race"))[0]

    sent = False

    def _capture(*args, **kwargs):
        nonlocal sent
        sent = True
        return _ok()

    # Simulate an administrator disabling the subscription after the row was
    # claimed and snapshotted but before the wire call.
    monkeypatch.setattr(webhooks, "_subscription_is_enabled", lambda subscription_id: False)

    outcome = webhooks.dispatch_once(post=_capture)
    assert outcome["attempted"] == 0
    assert sent is False

    row = webhooks.get_delivery(delivery_id)
    assert row is not None
    assert row["status"] == "pending"
    assert row["attempts"] == 0
