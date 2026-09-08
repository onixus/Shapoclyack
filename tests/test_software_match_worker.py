"""The queue that keeps software findings from going stale (Track E, M3).

The worker's own loop and leader lock are the same shape as the schedule
dispatcher's and are covered there; what is specific here is *which* devices a
sweep considers due, because that is what makes the queue survive a restart
without a column of its own.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.services import software_match_worker
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_software_findings import (
    ADVISORIES,
    refresh,
    snapshot_body,
    software_findings_of,
    submit,
)

pytestmark = requires_postgres


@pytest.fixture()
def settings(tmp_path: Path):
    return make_settings(tmp_path)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch, settings) -> TestClient:
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(ADVISORIES / "ubuntu-lifecycle.json"))
    monkeypatch.setenv("OCTO_CVSS4_DATABASE", str(tmp_path / "no-cvss4.json"))
    from api.services import advisories, software_findings

    advisories.reload_providers()
    software_findings.reset_cvss4_cache_for_tests()
    built = configured_client(tmp_path, monkeypatch, settings=settings)
    yield built
    advisories.reload_providers()
    software_findings.reset_cvss4_cache_for_tests()


def test_a_never_matched_device_is_due_and_a_matched_one_is_not(
    client: TestClient, settings
) -> None:
    device_id = submit(client, snapshot_body(snapshot_id="snap_worker_0001"))
    assert software_match_worker.pending_device_ids(
        settings, tenant_id="default", limit=10
    ) == [device_id]

    refresh(client, device_id)
    assert (
        software_match_worker.pending_device_ids(settings, tenant_id="default", limit=10) == []
    )


def test_a_new_snapshot_puts_the_device_back_on_the_queue(client: TestClient, settings) -> None:
    """The durable queue is the snapshot comparison, not a list in memory.

    ``ingest_snapshot`` only nudges the worker; what actually makes a device
    due is that its ``latest_snapshot_id`` no longer matches the one its
    ``software_cve_matches`` rows were written from — which is still true after
    a restart, and true in every replica.
    """
    device_id = submit(client, snapshot_body(snapshot_id="snap_worker_0002"))
    refresh(client, device_id)

    submit(client, snapshot_body(snapshot_id="snap_worker_0003"))
    assert software_match_worker.pending_device_ids(
        settings, tenant_id="default", limit=10
    ) == [device_id]


def test_a_sweep_creates_the_findings_the_snapshot_earned(
    client: TestClient, settings
) -> None:
    submit(client, snapshot_body(snapshot_id="snap_worker_0004"))
    assert software_findings_of(client) == []

    stats = software_match_worker.sweep_tenant(settings, "default")
    assert stats["created"] == 2
    assert {item["cve"] for item in software_findings_of(client)} == {
        "CVE-2023-38545",
        "CVE-2026-22222",
    }
    # And the device is no longer due, so the next tick is a no-op rather than
    # a re-match of everything the estate has.
    assert software_match_worker.sweep_tenant(settings, "default") == {"devices": 0}


def test_the_sweep_is_confined_to_one_tenant(client: TestClient, settings) -> None:
    submit(client, snapshot_body(snapshot_id="snap_worker_0005"))
    admin = auth_headers(client, "admin")
    assert (
        client.post(
            "/api/tenants", headers=admin, json={"name": "Other", "tenant_id": "ten_other"}
        ).status_code
        == 201
    )
    assert software_match_worker.pending_device_ids(
        settings, tenant_id="ten_other", limit=10
    ) == []
    assert software_match_worker.sweep_tenant(settings, "ten_other") == {"devices": 0}
