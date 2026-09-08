"""When a software finding may be closed — and the two cases where it may not.

The scan path closes a finding only when a scan *it dispatched* went and
looked. The inventory cannot be aimed, so the observation that closes a
software finding is the device's next accepted snapshot. Three conditions gate
it, and two of them exist because the same "no match" is produced by a device
that was patched and by a device that stopped telling us anything.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_software_findings import (
    ADVISORIES,
    SOFTWARE,
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


def _open_curl_finding(client: TestClient) -> dict:
    return next(item for item in software_findings_of(client) if item["cve"] == "CVE-2023-38545")


def _seed_vulnerable(client: TestClient) -> tuple[str, dict]:
    device_id = submit(client, snapshot_body(snapshot_id="snap_close_0001"))
    refresh(client, device_id)
    finding = _open_curl_finding(client)
    assert finding["state"] == "OPEN"
    return device_id, finding


def _patched_software() -> list[dict]:
    software = [dict(item) for item in SOFTWARE]
    for item in software:
        if item["name"] == "curl":
            item["version"] = "7.68.0-1ubuntu2.22"
    return software


# --------------------------------------------------------------------------


def test_an_upgrade_plus_a_fresh_snapshot_closes_the_finding_as_patched(
    client: TestClient,
) -> None:
    device_id, finding = _seed_vulnerable(client)

    submit(
        client,
        snapshot_body(snapshot_id="snap_close_0002", software=_patched_software()),
    )
    refresh(client, device_id)

    closed = client.get(
        f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
    ).json()
    assert closed["state"] == "CLOSED"
    assert closed["closure_reason"] == "patched"
    # Machine-verified, and legitimately so: a newer accepted snapshot from the
    # device itself said the package moved. That is an observation, not an
    # assertion by whoever pressed the button.
    assert closed["machine_verified"] is True
    assert closed["closed_at"]

    events = client.get(
        f"/api/vulnerabilities/{finding['vuln_id']}/events", headers=auth_headers(client)
    ).json()["items"]
    passed = next(event for event in events if event["kind"] == "verification_passed")
    assert passed["actor"] == "system:inventory"
    assert passed["detail"]["closure_reason"] == "patched"
    assert passed["detail"]["snapshot_id"] == "snap_close_0002"


def test_a_match_that_vanished_without_a_new_snapshot_is_not_closed(
    client: TestClient, settings
) -> None:
    """Absence of observation is not observation.

    A device that went quiet produces exactly the same "no match" as a device
    that was patched. Closing on it would mean the platform forgives findings
    whenever the agent stops reporting — the failure mode
    ``docs/vulnerability-lifecycle.md`` refuses for the scan path.
    """
    from sqlalchemy import delete

    from api.db import models
    from api.db.engine import get_session
    from api.services import software_findings

    device_id, finding = _seed_vulnerable(client)

    # The matches are gone, but the device has submitted nothing since.
    with get_session(settings.postgres_url) as session:
        session.execute(
            delete(models.SoftwareCveMatch).where(
                models.SoftwareCveMatch.device_id == device_id
            )
        )

    stats = software_findings.ingest_device(
        settings, tenant_id="default", device_id=device_id, run_matcher=False
    )
    assert stats.closed == 0
    assert stats.held_open_stale_snapshot >= 1

    after = client.get(
        f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
    ).json()
    assert after["state"] == "OPEN"
    # And ``last_seen_at`` did not move either, so ``?stale_days=`` still
    # surfaces this finding as one nobody has re-observed.
    assert after["last_seen_at"] == finding["last_seen_at"]


def test_a_distribution_that_stopped_resolving_does_not_close_anything(
    client: TestClient,
) -> None:
    """``packages_assessed == 0`` is the third gate.

    A snapshot whose OS the matcher can no longer resolve produces nothing but
    ``unknown`` rows — the same empty result as a patched host. Treating it as
    remediation would close a host's whole backlog because someone changed an
    ``os_name`` string.
    """
    device_id, finding = _seed_vulnerable(client)

    submit(
        client,
        snapshot_body(
            snapshot_id="snap_close_0003",
            os_name="Some Appliance OS",
            os_version="1.0",
        ),
    )
    result = refresh(client, device_id)
    assert result["packages_assessed"] == 0
    assert result["by_status"]["vulnerable"] == 0
    assert result["lifecycle"]["closed"] == 0
    assert result["lifecycle"]["held_open_stale_snapshot"] >= 1

    after = client.get(
        f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
    ).json()
    assert after["state"] == "OPEN"


def test_a_closed_finding_reopens_when_the_package_comes_back(client: TestClient) -> None:
    """A regression is the most important thing this model can report."""
    device_id, finding = _seed_vulnerable(client)
    submit(client, snapshot_body(snapshot_id="snap_close_0004", software=_patched_software()))
    refresh(client, device_id)
    assert (
        client.get(
            f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
        ).json()["state"]
        == "CLOSED"
    )

    # Someone rolled the package back.
    submit(client, snapshot_body(snapshot_id="snap_close_0005"))
    refresh(client, device_id)

    reopened = client.get(
        f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
    ).json()
    assert reopened["state"] == "OPEN"
    assert reopened["reopen_count"] == 1
    assert reopened["closure_reason"] is None
    assert reopened["machine_verified"] is False
    kinds = [
        event["kind"]
        for event in client.get(
            f"/api/vulnerabilities/{finding['vuln_id']}/events", headers=auth_headers(client)
        ).json()["items"]
    ]
    assert "reopened" in kinds
