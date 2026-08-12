"""Phase 10.3: the routing policy and the retry ladder.

The pure half of api/services/integrations/webhooks.py — deciding *whether* an
event goes to a subscription and *when* the next attempt is due needs neither a
database nor a socket. The queue itself is covered in tests/test_webhooks.py.
"""

from __future__ import annotations

import pytest

from api.services.integrations import webhooks
from api.settings import Settings


def _subscription(**overrides):
    base = {
        "subscription_id": "wh_1",
        "tenant_id": "acme",
        "enabled": True,
        "event_kinds": [],
        "min_severity": None,
    }
    base.update(overrides)
    return base


def _event(kind="new_cve", severity=None):
    envelope = {"kind": kind, "tenant_id": "acme", "event_id": "ev1", "data": {}}
    if severity:
        envelope["data"]["severity"] = severity
    return envelope


def test_empty_kind_list_means_every_kind():
    subscription = _subscription()
    for kind in webhooks.asset_events.EVENT_KINDS:
        assert webhooks.matches(subscription, _event(kind=kind)) is True


def test_kind_filter_excludes_other_kinds():
    subscription = _subscription(event_kinds=["new_cve", "cert_expiring"])
    assert webhooks.matches(subscription, _event(kind="new_cve")) is True
    assert webhooks.matches(subscription, _event(kind="cert_expiring")) is True
    assert webhooks.matches(subscription, _event(kind="new_asset")) is False


def test_disabled_subscription_matches_nothing():
    assert webhooks.matches(_subscription(enabled=False), _event()) is False


@pytest.mark.parametrize(
    ("minimum", "severity", "expected"),
    [
        ("high", "critical", True),
        ("high", "high", True),
        ("high", "medium", False),
        ("high", None, False),  # unknown severity is below every threshold
        ("low", "unknown", False),
        (None, "low", True),
    ],
)
def test_min_severity_applies_to_new_cve(minimum, severity, expected):
    subscription = _subscription(min_severity=minimum)
    assert webhooks.matches(subscription, _event(severity=severity)) is expected


def test_min_severity_does_not_swallow_severityless_kinds():
    """"critical only" is a statement about CVEs, not about port changes."""
    subscription = _subscription(min_severity="critical")
    assert webhooks.matches(subscription, _event(kind="new_open_port")) is True
    assert webhooks.matches(subscription, _event(kind="decommissioned_host")) is True
    assert webhooks.matches(subscription, _event(kind="new_cve", severity="low")) is False


def test_event_severity_reads_the_nested_payload():
    assert webhooks.event_severity(_event(severity="High")) == "high"
    assert webhooks.event_severity({"kind": "new_cve"}) is None
    assert webhooks.event_severity({"kind": "new_cve", "data": "not-a-dict"}) is None


def test_validate_event_kinds_rejects_unknown_and_dedupes():
    assert webhooks._validate_event_kinds(["new_cve", "new_cve"]) == ["new_cve"]
    assert webhooks._validate_event_kinds(None) == []
    with pytest.raises(ValueError, match="unknown event kind"):
        webhooks._validate_event_kinds(["events.asset.>"])


def test_validate_min_severity_normalises_and_rejects():
    assert webhooks._validate_min_severity(" High ") == "high"
    assert webhooks._validate_min_severity("") is None
    with pytest.raises(ValueError, match="unknown severity"):
        webhooks._validate_min_severity("catastrophic")


def test_backoff_doubles_then_caps():
    settings = Settings(webhook_retry_base_seconds=30, webhook_retry_max_seconds=600)
    assert [webhooks.backoff_seconds(n, settings) for n in range(1, 8)] == [
        30,
        60,
        120,
        240,
        480,
        600,
        600,
    ]


def test_backoff_never_overflows_on_a_large_attempt_count():
    settings = Settings(webhook_retry_base_seconds=30, webhook_retry_max_seconds=3600)
    assert webhooks.backoff_seconds(10_000, settings) == 3600
