"""Phase 10.3: webhook subscriptions, the delivery queue, the DLQ and the API.

The dispatch loop is driven synchronously here with an injected transport
(``dispatch_once(post=...)``) rather than by the background thread, so the
retry ladder and the dead-letter transition are asserted deterministically and
without a listening socket.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import update

from api.db import models
from api.db.engine import get_session
from api.services import tenants as tenants_service
from api.services.integrations import delivery as delivery_transport
from api.services.integrations import webhooks
from api.settings import Settings
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path) -> Settings:
    s = make_settings(tmp_path)
    tenants_service.configure(s)
    tenants_service.load_tenants(s)
    tenants_service.reset_for_tests()
    tenants_service.load_tenants(s)
    webhooks.configure(s)
    webhooks.reset_for_tests()
    return s


def _subscribe(settings: Settings, **overrides) -> dict:
    payload = {
        "tenant_id": "default",
        "name": "soc",
        "url": "https://receiver.example/hook",
        "created_by": "admin",
    }
    payload.update(overrides)
    return webhooks.create_subscription(**payload)


def _event(kind: str = "new_cve", *, event_id: str = "ev-1", severity: str = "critical") -> dict:
    return {
        "kind": kind,
        "tenant_id": "default",
        "event_id": event_id,
        "run_id": "run-1",
        "host": "10.0.0.1",
        "port": 443,
        "occurred_at": "2026-08-12T10:00:00+00:00",
        "source": "run_diff",
        "data": {"severity": severity, "cve": "CVE-2026-1"},
    }


def _force_due(settings: Settings) -> None:
    """Pull every pending delivery's next attempt into the past.

    The dispatcher schedules retries minutes ahead; a test that wants the next
    rung of the ladder should not sleep for them.
    """
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.WebhookDelivery)
            .where(models.WebhookDelivery.status == "pending")
            .values(next_attempt_at=datetime.now(UTC) - timedelta(seconds=1))
        )


def _ok(*args, **kwargs) -> delivery_transport.DeliveryResult:
    return delivery_transport.DeliveryResult(ok=True, status_code=200, error=None, retryable=False)


def _server_error(*args, **kwargs) -> delivery_transport.DeliveryResult:
    return delivery_transport.DeliveryResult(
        ok=False, status_code=503, error="HTTP 503", retryable=True
    )


def _client_error(*args, **kwargs) -> delivery_transport.DeliveryResult:
    return delivery_transport.DeliveryResult(
        ok=False, status_code=400, error="HTTP 400: bad payload", retryable=False
    )


# --------------------------------------------------------------------------
# Subscriptions
# --------------------------------------------------------------------------


def test_create_generates_a_secret_and_returns_it_once(settings):
    created = _subscribe(settings)
    assert created["subscription_id"].startswith("wh_")
    assert created["secret"]
    assert created["has_secret"] is True

    fetched = webhooks.get_subscription(created["subscription_id"])
    assert "secret" not in fetched
    assert fetched["has_secret"] is True

    listed, total = webhooks.list_subscriptions(tenant_id="default")
    assert total == 1
    assert "secret" not in listed[0]


def test_create_rejects_unknown_tenant_kind_and_severity(settings):
    with pytest.raises(ValueError, match="Unknown tenant_id"):
        _subscribe(settings, tenant_id="nope")
    with pytest.raises(ValueError, match="unknown event kind"):
        _subscribe(settings, event_kinds=["not_a_kind"])
    with pytest.raises(ValueError, match="unknown severity"):
        _subscribe(settings, min_severity="apocalyptic")


def test_create_rejects_internal_url_unless_opted_in(settings):
    with pytest.raises(delivery_transport.WebhookTargetError, match="non-public"):
        _subscribe(settings, url="http://127.0.0.1:9000/hook")

    settings.webhook_allow_private_targets = True
    assert _subscribe(settings, url="http://127.0.0.1:9000/hook")["url"].endswith("/hook")


def test_subscription_count_is_capped_per_tenant(settings):
    settings.webhook_max_subscriptions_per_tenant = 2
    _subscribe(settings, name="one")
    _subscribe(settings, name="two")
    with pytest.raises(ValueError, match="limit 2"):
        _subscribe(settings, name="three")


def test_rotate_secret_changes_it_and_reveals_it_once(settings):
    created = _subscribe(settings)
    rotated = webhooks.rotate_secret(created["subscription_id"])
    assert rotated["secret"] and rotated["secret"] != created["secret"]
    assert "secret" not in webhooks.get_subscription(created["subscription_id"])


def test_delete_takes_the_deliveries_with_it(settings):
    created = _subscribe(settings)
    webhooks.enqueue_event(_event())
    assert webhooks.list_deliveries(subscription_id=created["subscription_id"])[1] == 1

    assert webhooks.delete_subscription(created["subscription_id"]) is True
    assert webhooks.list_deliveries(subscription_id=created["subscription_id"])[1] == 0
    assert webhooks.delete_subscription(created["subscription_id"]) is False


# --------------------------------------------------------------------------
# Fan-out
# --------------------------------------------------------------------------


def test_enqueue_fans_out_only_to_matching_subscriptions(settings):
    everything = _subscribe(settings, name="all")
    criticals = _subscribe(settings, name="crit", min_severity="critical")
    ports_only = _subscribe(settings, name="ports", event_kinds=["new_open_port"])
    disabled = _subscribe(settings, name="off", enabled=False)

    created = webhooks.enqueue_event(_event(severity="medium"))

    targets = {
        webhooks.get_delivery(delivery_id)["subscription_id"] for delivery_id in created
    }
    assert targets == {everything["subscription_id"]}
    for other in (criticals, ports_only, disabled):
        assert webhooks.list_deliveries(subscription_id=other["subscription_id"])[1] == 0


def test_enqueue_is_idempotent_for_a_redelivered_event(settings):
    _subscribe(settings)
    first = webhooks.enqueue_event(_event())
    second = webhooks.enqueue_event(_event())
    assert len(first) == 1
    assert second == []
    assert webhooks.list_deliveries(tenant_id="default")[1] == 1


def test_enqueue_ignores_events_from_other_tenants(settings):
    _subscribe(settings)
    envelope = _event()
    envelope["tenant_id"] = "other"
    assert webhooks.enqueue_event(envelope) == []


def test_enqueue_ignores_malformed_envelopes(settings):
    _subscribe(settings)
    assert webhooks.enqueue_event({"kind": "new_cve"}) == []
    assert webhooks.enqueue_event({"tenant_id": "default", "event_id": "x"}) == []


def test_queued_payload_is_the_body_that_gets_sent(settings):
    subscription = _subscribe(settings)
    sent: dict = {}

    def _capture(url, body, headers, **kwargs):
        sent["url"] = url
        sent["body"] = body
        sent["headers"] = headers
        return _ok()

    delivery_id = webhooks.enqueue_event(_event())[0]
    webhooks.dispatch_once(post=_capture)

    assert sent["url"] == "https://receiver.example/hook"
    assert sent["headers"][delivery_transport.EVENT_HEADER] == "new_cve"
    assert sent["headers"][delivery_transport.DELIVERY_HEADER] == delivery_id
    signature = delivery_transport.sign(
        subscription["secret"], sent["headers"][delivery_transport.TIMESTAMP_HEADER], sent["body"]
    )
    assert sent["headers"][delivery_transport.SIGNATURE_HEADER] == signature


# --------------------------------------------------------------------------
# Dispatch, retries, DLQ
# --------------------------------------------------------------------------


def test_successful_delivery_is_recorded_and_not_re_sent(settings):
    subscription = _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]

    assert webhooks.dispatch_once(post=_ok)["delivered"] == 1
    row = webhooks.get_delivery(delivery_id)
    assert row["status"] == "delivered"
    assert row["attempts"] == 1
    assert row["delivered_at"] is not None
    assert row["next_attempt_at"] is None
    assert webhooks.get_subscription(subscription["subscription_id"])["last_status"] == "delivered"

    assert webhooks.dispatch_once(post=_ok)["attempted"] == 0


def test_retryable_failure_backs_off_then_dead_letters(settings):
    settings.webhook_max_attempts = 3
    delivery_id = None
    _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]

    outcome = webhooks.dispatch_once(post=_server_error)
    assert outcome["retrying"] == 1
    row = webhooks.get_delivery(delivery_id)
    assert row["status"] == "pending"
    assert row["attempts"] == 1
    assert row["last_status_code"] == 503
    # Scheduled into the future — a second tick right now must not re-send it.
    assert webhooks.dispatch_once(post=_server_error)["attempted"] == 0

    _force_due(settings)
    assert webhooks.dispatch_once(post=_server_error)["retrying"] == 1
    _force_due(settings)
    assert webhooks.dispatch_once(post=_server_error)["dead"] == 1

    row = webhooks.get_delivery(delivery_id)
    assert row["status"] == "dead"
    assert row["attempts"] == 3
    assert row["next_attempt_at"] is None


def test_non_retryable_failure_dead_letters_on_the_first_attempt(settings):
    settings.webhook_max_attempts = 6
    _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]

    assert webhooks.dispatch_once(post=_client_error)["dead"] == 1
    row = webhooks.get_delivery(delivery_id)
    assert row["status"] == "dead"
    assert row["attempts"] == 1
    assert row["last_status_code"] == 400


def test_dispatch_survives_a_transport_that_raises(settings):
    _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]

    def _explode(*args, **kwargs):
        raise RuntimeError("boom")

    outcome = webhooks.dispatch_once(post=_explode)
    assert outcome["dead"] == 1
    assert "RuntimeError" in webhooks.get_delivery(delivery_id)["last_error"]


def test_requeue_refuses_a_delivered_row(settings):
    """#152: replay is a DLQ operation, not a second notification."""
    _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]
    webhooks.dispatch_once(post=_ok)
    with pytest.raises(ValueError, match="delivered"):
        webhooks.requeue_delivery(delivery_id)
    assert webhooks.get_delivery(delivery_id)["status"] == "delivered"


def test_late_duplicate_result_does_not_un_deliver(settings):
    _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]
    webhooks.dispatch_once(post=_ok)
    status = webhooks._record_result(  # noqa: SLF001
        delivery_id=delivery_id,
        result=_server_error(),
        now=datetime.now(UTC),
    )
    assert status == "delivered"
    assert webhooks.get_delivery(delivery_id)["status"] == "delivered"


def test_claim_visibility_covers_the_serial_batch(settings):
    settings.webhook_timeout_seconds = 10
    assert webhooks.claim_visibility_seconds(timeout_seconds=10, batch_len=50) == 520
    assert webhooks.claim_visibility_seconds(timeout_seconds=1, batch_len=0) == 30

    _subscribe(settings)
    ids = [webhooks.enqueue_event(_event(event_id=f"ev-{i}"))[0] for i in range(4)]
    claimed = threading.Event()
    released = threading.Event()

    def _slow(*args, **kwargs):
        claimed.set()
        released.wait(timeout=5)
        return _ok()

    holder = threading.Thread(target=lambda: webhooks.dispatch_once(post=_slow, limit=4))
    holder.start()
    assert claimed.wait(timeout=5), "first dispatcher never claimed"
    try:
        assert webhooks.dispatch_once(post=_ok, limit=4)["attempted"] == 0
    finally:
        released.set()
        holder.join()
    assert all(webhooks.get_delivery(did)["status"] == "delivered" for did in ids)


def test_a_long_batch_is_not_reclaimed_while_it_is_still_being_sent(settings, monkeypatch):
    """The claim window covers the whole batch, not three timeouts (#255).

    The live claim is ``secure_webhooks._claim_due``, and it carried its own
    ``max(30, timeout * 3)`` while the batch-aware formula sat on a copy of the
    dispatch loop nothing called. Charging every POST a full
    ``webhook_timeout_seconds`` of *queue* time makes the consequence
    deterministic: five deliveries cost 100 seconds of it, the old lease
    expired after 60, and a peer replica legally re-sent a row this dispatcher
    had not reached yet — the duplicate POST #152 forbids, with no race at all.
    """
    settings.webhook_timeout_seconds = 20
    _subscribe(settings)
    ids = [webhooks.enqueue_event(_event(event_id=f"ev-{i}"))[0] for i in range(5)]

    fake_now = datetime.now(UTC)
    monkeypatch.setattr(webhooks._base, "_now", lambda: fake_now)  # noqa: SLF001
    stolen: list[str] = []

    def _peer(url, body, headers, **kwargs):
        stolen.append(headers[delivery_transport.DELIVERY_HEADER])
        return _ok()

    def _slow(*args, **kwargs):
        nonlocal fake_now
        fake_now += timedelta(seconds=settings.webhook_timeout_seconds)
        # A second replica ticking while this batch is still mid-flight.
        webhooks.dispatch_once(post=_peer, limit=10)
        return _ok()

    webhooks.dispatch_once(post=_slow, limit=5)

    assert not stolen, f"claimed by a peer while still being sent: {stolen}"
    assert all(webhooks.get_delivery(delivery_id)["status"] == "delivered" for delivery_id in ids)


def test_a_failure_mid_batch_releases_the_rest_of_the_claim(settings, monkeypatch):
    """A raise after the POST must not strand the rows behind it (#256).

    The batch is claimed in one transaction — ``attempts`` incremented,
    ``next_attempt_at`` pushed out by the visibility window — so an exception
    from the bookkeeping left the tail claimed, unsent and invisible until that
    window expired. Only the row whose outcome was lost keeps its claim: its
    POST may well have arrived.
    """
    _subscribe(settings)
    ids = [webhooks.enqueue_event(_event(event_id=f"ev-{i}"))[0] for i in range(4)]
    sent: list[str] = []
    record_result = webhooks._base._record_result  # noqa: SLF001

    def _post(url, body, headers, **kwargs):
        sent.append(headers[delivery_transport.DELIVERY_HEADER])
        return _ok()

    def _flaky_record(*, delivery_id, result, now):
        if len(sent) == 2:  # the second delivery's outcome, two rows still unsent
            raise RuntimeError("bookkeeping is down")
        return record_result(delivery_id=delivery_id, result=result, now=now)

    monkeypatch.setattr(webhooks._base, "_record_result", _flaky_record)  # noqa: SLF001
    with pytest.raises(RuntimeError, match="bookkeeping"):
        webhooks.dispatch_once(post=_post, limit=4)

    rows = {delivery_id: webhooks.get_delivery(delivery_id) for delivery_id in ids}
    assert rows[sent[0]]["status"] == "delivered"
    assert rows[sent[1]]["status"] == "pending"
    assert rows[sent[1]]["attempts"] == 1

    tail = [delivery_id for delivery_id in ids if delivery_id not in sent]
    assert len(tail) == 2
    for delivery_id in tail:
        assert rows[delivery_id]["status"] == "pending"
        # No attempt was made, so the claim must not have cost retry budget.
        assert rows[delivery_id]["attempts"] == 0

    monkeypatch.setattr(webhooks._base, "_record_result", record_result)  # noqa: SLF001
    sent.clear()
    # Due again on the very next tick, and only the tail: the row that raised
    # keeps its window so its receiver is not POSTed twice.
    assert webhooks.dispatch_once(post=_post, limit=4)["delivered"] == 2
    assert sorted(sent) == sorted(tail)


def test_concurrent_dispatchers_do_not_double_post(settings):
    """Two replicas divide the queue; a delivery is POSTed once (#152)."""
    _subscribe(settings)
    ids = [webhooks.enqueue_event(_event(event_id=f"ev-{i}"))[0] for i in range(10)]
    seen: list[str] = []
    lock = threading.Lock()

    def _post(url, body, headers, **kwargs):
        with lock:
            seen.append(headers[delivery_transport.DELIVERY_HEADER])
        time.sleep(0.02)
        return _ok()

    # Исключение внутри потока join() не поднимает, поэтому упавший диспетчер
    # раньше выглядел как «доставил меньше», и падение сообщало лишь дифф
    # идентификаторов. Собираем ошибки явно: недоставка и крах — разные
    # диагнозы, и второй означает, что заявленные #152 гарантии не держатся.
    errors: list[BaseException] = []

    def _dispatch() -> None:
        try:
            webhooks.dispatch_once(post=_post, limit=10)
        except BaseException as exc:  # noqa: BLE001 - переносим в основной поток
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=_dispatch) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors, f"диспетчер упал: {errors!r}"
    missing = sorted(set(ids) - set(seen))
    assert not missing, (
        f"claimed, но не отправлено: {missing} "
        f"(отправлено {len(seen)} из {len(ids)})"
    )
    assert sorted(seen) == sorted(ids)
    assert len(seen) == len(set(seen))


def test_an_open_claim_does_not_hide_the_rest_of_the_queue(settings):
    """A peer's in-flight claim must cost the others one row, not the queue (#238).

    The kill-switch claim joins ``webhook_subscriptions``, and every delivery of
    one subscription joins the same row. Locked ``FOR UPDATE``, that row made
    the whole backlog invisible to the other replicas — the non-deterministic
    half of ``test_concurrent_dispatchers_do_not_double_post``, where a tick
    POSTed four of ten and the rest went nowhere without anything raising.
    Holding one claim open here is that race made deterministic.
    """
    _subscribe(settings)
    ids = [webhooks.enqueue_event(_event(event_id=f"ev-{i}"))[0] for i in range(5)]
    seen: list[str] = []

    def _post(url, body, headers, **kwargs):
        seen.append(headers[delivery_transport.DELIVERY_HEADER])
        return _ok()

    with get_session(settings.postgres_url) as peer:
        held = webhooks._claim_due(peer, now=datetime.now(UTC), limit=1)
        assert len(held) == 1
        held_id = held[0].delivery_id
        webhooks.dispatch_once(post=_post, limit=10)

    assert sorted(seen) == sorted(set(ids) - {held_id})


def test_disabling_a_subscription_holds_its_queued_backlog(settings):
    """The #151 kill switch covers what is already queued, not just new events.

    Pinned here because #238 narrows the claim's lock to ``webhook_deliveries``:
    the enabled-at-claim-time filter is the half of that query that must not
    move, and nothing else asserted it.
    """
    subscription = _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]
    webhooks.update_subscription(subscription["subscription_id"], enabled=False)

    assert webhooks.dispatch_once(post=_ok)["attempted"] == 0
    held = webhooks.get_delivery(delivery_id)
    assert held["status"] == "pending"
    # Switched off is not a delivery attempt: the retry budget is untouched.
    assert held["attempts"] == 0

    webhooks.update_subscription(subscription["subscription_id"], enabled=True)
    assert webhooks.dispatch_once(post=_ok)["delivered"] == 1


def test_requeue_puts_a_dead_delivery_back_in_the_queue(settings):
    settings.webhook_max_attempts = 1
    _subscribe(settings)
    delivery_id = webhooks.enqueue_event(_event())[0]
    webhooks.dispatch_once(post=_server_error)
    assert webhooks.get_delivery(delivery_id)["status"] == "dead"

    requeued = webhooks.requeue_delivery(delivery_id)
    assert requeued["status"] == "pending"
    assert requeued["attempts"] == 0
    assert webhooks.dispatch_once(post=_ok)["delivered"] == 1


def test_dispatch_batch_is_bounded(settings):
    _subscribe(settings)
    for index in range(5):
        webhooks.enqueue_event(_event(event_id=f"ev-{index}"))
    assert webhooks.dispatch_once(post=_ok, limit=2)["delivered"] == 2
    assert webhooks.queue_depth()["pending"] == 3


def test_test_delivery_goes_through_the_normal_path(settings):
    subscription = _subscribe(settings)
    delivery_id = webhooks.enqueue_test_delivery(
        subscription["subscription_id"], requested_by="admin"
    )
    row = webhooks.get_delivery(delivery_id)
    assert row["event_kind"] == webhooks.TEST_EVENT_KIND
    assert row["status"] == "pending"
    assert webhooks.dispatch_once(post=_ok)["delivered"] == 1


def test_prune_removes_only_old_terminal_deliveries(settings):
    settings.webhook_delivery_retention_days = 7
    _subscribe(settings)
    delivered = webhooks.enqueue_event(_event(event_id="ev-old"))[0]
    webhooks.dispatch_once(post=_ok)
    pending = webhooks.enqueue_event(_event(event_id="ev-new"))[0]

    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.WebhookDelivery).values(
                updated_at=datetime.now(UTC) - timedelta(days=30)
            )
        )

    assert webhooks.prune_deliveries() == 1
    assert webhooks.get_delivery(delivered) is None
    assert webhooks.get_delivery(pending) is not None

    settings.webhook_delivery_retention_days = 0
    assert webhooks.prune_deliveries() == 0


# --------------------------------------------------------------------------
# HTTP surface
# --------------------------------------------------------------------------


def test_api_crud_and_rbac(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    body = {"name": "soc", "url": "https://receiver.example/hook"}

    # operator may read but not create: a webhook sends this tenant's exposure
    # data somewhere of the creator's choosing.
    assert client.post("/api/webhooks", json=body, headers=auth_headers(client, "operator")).status_code == 403
    assert client.get("/api/webhooks", headers=auth_headers(client, "viewer")).status_code == 403
    assert client.get("/api/webhooks", headers=auth_headers(client, "operator")).status_code == 200

    admin = auth_headers(client, "admin")
    created = client.post("/api/webhooks", json=body, headers=admin)
    assert created.status_code == 201, created.text
    subscription_id = created.json()["subscription_id"]
    assert created.json()["secret"]

    fetched = client.get(f"/api/webhooks/{subscription_id}", headers=admin)
    assert fetched.status_code == 200
    assert fetched.json()["secret"] is None
    assert fetched.json()["has_secret"] is True

    patched = client.patch(
        f"/api/webhooks/{subscription_id}",
        json={"enabled": False, "event_kinds": ["new_cve"], "min_severity": "high"},
        headers=admin,
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False
    assert patched.json()["event_kinds"] == ["new_cve"]

    assert client.delete(f"/api/webhooks/{subscription_id}", headers=admin).status_code == 204
    assert client.get(f"/api/webhooks/{subscription_id}", headers=admin).status_code == 404


def test_api_rejects_bad_url_and_unknown_kind(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")

    blocked = client.post(
        "/api/webhooks", json={"name": "x", "url": "http://169.254.169.254/"}, headers=admin
    )
    assert blocked.status_code == 422
    assert "non-public" in blocked.json()["detail"]

    bad_kind = client.post(
        "/api/webhooks",
        json={"name": "x", "url": "https://receiver.example/hook", "event_kinds": ["nope"]},
        headers=admin,
    )
    assert bad_kind.status_code == 422


def test_api_test_endpoint_queues_a_delivery(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    subscription_id = client.post(
        "/api/webhooks",
        json={"name": "soc", "url": "https://receiver.example/hook"},
        headers=admin,
    ).json()["subscription_id"]

    response = client.post(f"/api/webhooks/{subscription_id}/test", headers=admin)
    assert response.status_code == 202
    assert response.json()["status"] == "pending"
    assert response.json()["event_kind"] == webhooks.TEST_EVENT_KIND

    listed = client.get(f"/api/webhooks/{subscription_id}/deliveries", headers=admin)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1


def test_api_dlq_view_and_retry(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    settings_for_service = webhooks._require_settings()
    settings_for_service.webhook_max_attempts = 1

    subscription_id = client.post(
        "/api/webhooks",
        json={"name": "soc", "url": "https://receiver.example/hook"},
        headers=admin,
    ).json()["subscription_id"]
    webhooks.enqueue_event(_event())
    webhooks.dispatch_once(post=_server_error)

    dead = client.get("/api/webhooks/deliveries", params={"status": "dead"}, headers=admin)
    assert dead.status_code == 200
    assert dead.json()["total"] == 1
    delivery_id = dead.json()["items"][0]["delivery_id"]
    assert dead.json()["items"][0]["subscription_id"] == subscription_id

    bad_filter = client.get(
        "/api/webhooks/deliveries", params={"status": "exploded"}, headers=admin
    )
    assert bad_filter.status_code == 422

    retried = client.post(f"/api/webhooks/deliveries/{delivery_id}/retry", headers=admin)
    assert retried.status_code == 200
    assert retried.json()["status"] == "pending"
    assert retried.json()["attempts"] == 0

    assert (
        client.post("/api/webhooks/deliveries/whd_missing/retry", headers=admin).status_code == 404
    )

    webhooks.dispatch_once(post=_ok)
    delivered_id = client.get(
        "/api/webhooks/deliveries", params={"status": "delivered"}, headers=admin
    ).json()["items"][0]["delivery_id"]
    refused = client.post(f"/api/webhooks/deliveries/{delivered_id}/retry", headers=admin)
    assert refused.status_code == 409


def test_api_rotate_secret(tmp_path, monkeypatch):
    client = configured_client(tmp_path, monkeypatch)
    admin = auth_headers(client, "admin")
    created = client.post(
        "/api/webhooks",
        json={"name": "soc", "url": "https://receiver.example/hook"},
        headers=admin,
    ).json()

    rotated = client.post(
        f"/api/webhooks/{created['subscription_id']}/rotate-secret", headers=admin
    )
    assert rotated.status_code == 200
    assert rotated.json()["secret"] not in (None, created["secret"])


def test_the_subscription_cap_holds_under_concurrent_creates(settings: Settings, monkeypatch):
    """#153: count-then-insert let two requests both pass at N-1. With the
    tenant row locked for the transaction, exactly ``limit`` rows exist
    afterwards no matter how many creates raced for the last slot.

    The window between the count and the insert is microseconds, which is why
    the race was never seen in a test; ``flush`` is slowed so every thread has
    counted before any has inserted. With the lock, the slow flush happens
    inside the critical section and the others wait at the ``SELECT … FOR
    UPDATE`` instead — that is the whole difference under test.
    """
    from sqlalchemy.orm import Session

    limit = 5
    settings.webhook_max_subscriptions_per_tenant = limit
    for i in range(limit - 1):
        _subscribe(settings, name=f"seed-{i}", url=f"https://receiver.example/{i}")

    real_flush = Session.flush

    def slow_flush(self, *args, **kwargs):
        time.sleep(0.2)
        return real_flush(self, *args, **kwargs)

    monkeypatch.setattr(Session, "flush", slow_flush)

    gate = threading.Barrier(8)
    outcomes: list[str] = []
    lock = threading.Lock()

    def race(i: int) -> None:
        gate.wait()
        try:
            _subscribe(settings, name=f"race-{i}", url=f"https://receiver.example/race/{i}")
            result = "created"
        except ValueError as exc:
            result = "refused" if "limit" in str(exc) else f"error: {exc}"
        with lock:
            outcomes.append(result)

    threads = [threading.Thread(target=race, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert outcomes.count("created") == 1, outcomes
    assert outcomes.count("refused") == 7, outcomes
    with get_session(settings.postgres_url) as session:
        total = session.query(models.WebhookSubscription).filter_by(tenant_id="default").count()
    assert total == limit
