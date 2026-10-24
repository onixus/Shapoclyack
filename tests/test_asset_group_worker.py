from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from api.services import asset_group_worker as worker


@pytest.fixture(autouse=True)
def reset_stop():
    worker._stop.clear()
    yield
    worker._stop.clear()


def test_tick_pages_tenants_and_isolates_failures(monkeypatch):
    session = MagicMock()
    session.execute.return_value.scalars.return_value.all.side_effect = [
        [f"tenant-{i:03}" for i in range(100)], ["tenant-100"], [],
    ]
    context = MagicMock()
    context.__enter__.return_value = session
    monkeypatch.setattr(worker, "get_session", lambda _: context)
    calls = []

    def reconcile(settings, tenant, *, limit):
        calls.append((tenant, limit))
        if tenant == "tenant-005":
            raise RuntimeError("simulated one-tenant failure")

    monkeypatch.setattr("api.services.asset_groups.reconcile_batch", reconcile)
    worker.tick(SimpleNamespace(postgres_url="test", asset_groups_batch_size=25))
    assert calls == [(f"tenant-{i:03}", 25) for i in range(101)]
    assert session.execute.call_count == 3


def test_stop_prevents_starting_another_tenant_batch(monkeypatch):
    context = MagicMock()
    context.__enter__.return_value.execute.return_value.scalars.return_value.all.return_value = ["a", "b"]
    monkeypatch.setattr(worker, "get_session", lambda _: context)
    calls = []

    def reconcile(settings, tenant, **kwargs):
        calls.append(tenant)
        worker._stop.set()

    monkeypatch.setattr("api.services.asset_groups.reconcile_batch", reconcile)
    worker.tick(SimpleNamespace(postgres_url="test", asset_groups_batch_size=25))
    assert calls == ["a"]


def test_disabled_worker_does_not_spawn(monkeypatch):
    thread = MagicMock()
    monkeypatch.setattr(worker.threading, "Thread", thread)
    worker.start_worker(SimpleNamespace(asset_groups_enabled=False))
    thread.assert_not_called()
