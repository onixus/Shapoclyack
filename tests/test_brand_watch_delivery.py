"""Brand-watch diffs ride the existing webhook queue. Kind ``brand_watch.diff``.

Opt-in: a subscription that does not list the kind gets nothing, including one
whose ``event_kinds`` is empty (that still means every asset event). A raise
from the queue is logged and does not fail the applied result. The kind is
not an asset event.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from api.db import models
from api.services import asset_events, brand_watch
from api.services.integrations import webhooks


def test_kind_is_accepted_and_is_not_an_asset_event():
    assert brand_watch.DIFF_KIND == "brand_watch.diff"
    assert webhooks.BRAND_WATCH_DIFF_KIND == "brand_watch.diff"
    assert "brand_watch.diff" not in asset_events.EVENT_KINDS
    assert webhooks._validate_event_kinds(["brand_watch.diff", "brand_watch.diff"]) == [
        "brand_watch.diff"
    ]
    with pytest.raises(ValueError, match="unknown event kind"):
        webhooks._validate_event_kinds(["brand_watch"])


def test_empty_and_other_kinds_do_not_match():
    envelope = {"kind": "brand_watch.diff", "tenant_id": "acme", "event_id": "ev1", "data": {}}
    empty = {"enabled": True, "event_kinds": [], "min_severity": "critical"}
    other = {"enabled": True, "event_kinds": ["new_cve"], "min_severity": None}
    named = {"enabled": True, "event_kinds": ["brand_watch.diff"], "min_severity": "critical"}
    disabled = {"enabled": False, "event_kinds": ["brand_watch.diff"], "min_severity": None}
    assert webhooks.matches(empty, envelope) is False
    assert webhooks.matches(other, envelope) is False
    assert webhooks.matches(named, envelope) is True
    assert webhooks.matches(disabled, envelope) is False
    # Naming the kind must not start delivering asset events to that subscription.
    assert webhooks.matches(named, {"kind": "new_cve", "data": {"severity": "critical"}}) is False


def test_enqueue_failure_is_logged_and_swallowed(caplog):
    event = brand_watch.diff_event(
        name="acme-login.example",
        from_state="unregistered",
        to_state="registered",
        severity="informational",
        reasons=["state"],
        candidate_id="bwc_1",
        last_changed="2026-11-12T00:00:00",
    )

    def _boom(_envelope):
        raise RuntimeError("queue down")

    caplog.set_level("WARNING")
    brand_watch._enqueue_diffs("acme", "bwj_1", [event])  # unconfigured: logged, not raised
    webhooks.enqueue_event = _boom
    try:
        brand_watch._enqueue_diffs("acme", "bwj_1", [event])
    finally:
        del webhooks.enqueue_event
    assert "queue down" in caplog.text


def test_envelope_is_the_diff_not_the_page(monkeypatch):
    seen: list[dict] = []
    monkeypatch.setattr(webhooks, "enqueue_event", seen.append)
    event = brand_watch.diff_event(
        name="acme-login.example",
        from_state="registered",
        to_state="resolving",
        severity="low",
        reasons=["state"],
        candidate_id="bwc_1",
        profile_id="bwp_1",
        punycode="acme-login.example",
        last_changed="2026-11-12T00:00:00",
    )
    brand_watch._enqueue_diffs("acme", "bwj_1", [event])
    assert len(seen) == 1
    envelope = seen[0]
    assert envelope["kind"] == "brand_watch.diff"
    assert envelope["tenant_id"] == "acme"
    assert envelope["event_id"]
    assert "html" not in envelope["data"]
    assert envelope["data"]["from_state"] == "registered"
    assert envelope["data"]["to_state"] == "resolving"
    assert envelope["data"]["name"] == "acme-login.example"
    assert "page" not in envelope["data"]
    brand_watch._enqueue_diffs("acme", "bwj_1", [])
    assert len(seen) == 1


def test_enqueue_event_delivers_only_to_the_named_kind(monkeypatch):
    """A real fan-out: empty and CVE subscriptions get no delivery row."""
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    models.Base.metadata.create_all(engine)

    @contextmanager
    def get_session(_url):
        with Session(engine) as session:
            yield session
            session.commit()

    import api.services.integrations.webhooks as webhook_impl

    # enqueue_event closes over a globals dict that is not the module dict, so
    # patching the attribute would leave the function on the unconfigured path.
    monkeypatch.setitem(webhook_impl.enqueue_event.__globals__, "get_session", get_session)
    monkeypatch.setitem(
        webhook_impl.enqueue_event.__globals__,
        "_settings",
        type("S", (), {"postgres_url": "sqlite://"})(),
    )
    now = datetime.now(UTC)
    with get_session("") as session:
        session.add(models.Tenant(tenant_id="acme", name="acme", created_at=now))
        for subscription_id, kinds in (
            ("wh_all", []),
            ("wh_cve", ["new_cve"]),
            ("wh_bw", ["brand_watch.diff"]),
        ):
            session.add(models.WebhookSubscription(
                subscription_id=subscription_id,
                tenant_id="acme",
                name=subscription_id,
                url=f"https://receiver.example/{subscription_id}",
                enabled=True,
                event_kinds=kinds,
                headers={},
                transport="webhook",
                transport_config={},
                created_at=now,
            ))
    envelope = brand_watch._webhook_envelope(
        "acme",
        "bwj_1",
        brand_watch.diff_event(
            name="acme-login.example",
            from_state="unregistered",
            to_state="registered",
            severity="informational",
            reasons=["state"],
            candidate_id="bwc_1",
            last_changed="2026-11-12T00:00:00",
        ),
    )
    created = webhooks.enqueue_event(envelope)
    assert len(created) == 1
    with get_session("") as session:
        rows = [
            (row.subscription_id, row.event_kind, row.payload)
            for row in session.query(models.WebhookDelivery).all()
        ]
    assert [row[0] for row in rows] == ["wh_bw"]
    assert rows[0][1] == "brand_watch.diff"
    assert rows[0][2]["event"]["data"]["to_state"] == "registered"
    assert "html" not in rows[0][2]["event"]["data"]
    assert webhooks.enqueue_event(envelope) == []
