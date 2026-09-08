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


# --------------------------------------------------------------------------
# The queue has to drain
# --------------------------------------------------------------------------

#: An Ubuntu host with nothing the advisory dataset has anything to say about
#: and nothing unassessable: every package is matchable, so the matcher writes
#: **zero** rows — not even an ``unknown`` placeholder.
CLEAN_SOFTWARE = [
    {
        "name": "bash",
        "version": "5.0-6ubuntu1.2",
        "publisher": "Canonical",
        "architecture": "amd64",
        "source": "dpkg",
        "install_location": None,
    }
]


def test_a_clean_host_leaves_the_queue(client: TestClient, settings) -> None:
    """"Matched, found nothing" and "never matched" have to be different rows.

    The queue compared ``endpoint_devices.latest_snapshot_id`` against the
    ``snapshot_id`` on the device's match rows — and a host with nothing to
    report has no match rows, so it was due forever. At ``batch_size`` devices
    a tick and no ``ORDER BY``, a few hundred of those permanently crowd out
    the devices that actually changed.
    """
    device_id = submit(
        client, snapshot_body(snapshot_id="snap_worker_0006", software=CLEAN_SOFTWARE)
    )
    stats = software_match_worker.sweep_tenant(settings, "default")
    assert stats["devices"] == 1
    assert stats["created"] == 0

    assert (
        software_match_worker.pending_device_ids(settings, tenant_id="default", limit=10) == []
    ), "a host with no matches is due forever"
    assert software_match_worker.sweep_tenant(settings, "default") == {"devices": 0}
    assert device_id


def test_one_poisonous_device_does_not_stop_the_tenant(
    client: TestClient, settings, monkeypatch
) -> None:
    """A device that raises used to take its whole batch with it — and the
    tenant sweep caught at tenant level, so the next tick re-read the same
    batch and failed at the same device, forever."""
    from api.services import software_findings

    first = submit(client, snapshot_body(snapshot_id="snap_worker_0007"))
    second = submit(
        client,
        snapshot_body(
            snapshot_id="snap_worker_0008",
            agent_id="lariska-agent-0002",
            hostname="workstation-02.example.internal",
        ),
    )
    real_fold = software_findings._fold_device  # noqa: SLF001

    def exploding_fold(session, *, tenant_id, context, min_severity, now):
        if context.device.device_id == first:
            raise RuntimeError("advisory row this device trips over")
        return real_fold(
            session, tenant_id=tenant_id, context=context, min_severity=min_severity, now=now
        )

    monkeypatch.setattr(software_findings, "_fold_device", exploding_fold)
    stats = software_match_worker.sweep_tenant(settings, "default")

    assert stats["errors"] == 1
    assert stats["created"] == 2, "the healthy device in the same batch was folded"
    assert {item["device_id"] for item in software_findings_of(client)} == {second}

    # And it is not retried on the very next tick: it carries a backoff.
    assert first not in software_match_worker.pending_device_ids(
        settings, tenant_id="default", limit=10
    )


def test_a_sweep_drains_the_queue_rather_than_one_batch_per_tick(
    client: TestClient, settings
) -> None:
    """``OCTO_SOFTWARE_MATCH_INTERVAL_SECONDS`` is documented as a ceiling on
    how stale a tracked software finding can be. With one batch per tick the
    real ceiling was ``devices / batch_size × interval`` — for 50k due devices
    at the defaults, most of a working week."""
    import dataclasses

    for index in range(3):
        submit(
            client,
            snapshot_body(
                snapshot_id=f"snap_worker_001{index}",
                agent_id=f"lariska-agent-001{index}",
                hostname=f"workstation-1{index}.example.internal",
            ),
        )

    stats = software_match_worker.sweep_tenant(
        dataclasses.replace(settings, software_match_batch_size=1), "default"
    )
    assert stats["devices"] == 3
    assert (
        software_match_worker.pending_device_ids(settings, tenant_id="default", limit=10) == []
    )
