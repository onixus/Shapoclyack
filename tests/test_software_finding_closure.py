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


# --------------------------------------------------------------------------
# The three ways a closure was false
# --------------------------------------------------------------------------


def test_a_feed_that_went_missing_does_not_close_the_estate(
    client: TestClient, settings, monkeypatch, tmp_path: Path
) -> None:
    """The gate has to be "we could ask", not "we had something to ask about".

    ``packages_assessed`` is counted before the provider is consulted, so a
    volume that stopped mounting, a ``fetch`` that wrote an empty file or a
    release dropped from the export all produce ``assessed > 0, matches == 0``
    — indistinguishable, to the old gate, from an estate that was patched
    overnight. One quiet device then closed the tenant's whole software
    backlog as ``patched``, machine-verified, by ``system:inventory``.
    """
    from api.services import advisories, software_findings

    device_id, finding = _seed_vulnerable(client)
    submit(client, snapshot_body(snapshot_id="snap_close_0006"))

    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(tmp_path / "feed-volume-gone.json"))
    advisories.reload_providers()

    stats = software_findings.ingest_device(
        settings, tenant_id="default", device_id=device_id, run_matcher=True
    )
    assert stats.closed == 0
    assert stats.held_open_stale_snapshot >= 1

    after = client.get(
        f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
    ).json()
    assert after["state"] == "OPEN"


def test_both_fold_paths_answer_the_gate_the_same_way(
    client: TestClient, settings, monkeypatch, tmp_path: Path
) -> None:
    """``run_matcher=True`` and ``run_matcher=False`` are one rule, not two.

    The refresh path recovered the gate from the match rows and the worker path
    from the run summary, and with no feed loaded those two answered opposite
    ways for the same device and the same snapshot.
    """
    from api.services import advisories, software_findings

    device_id, finding = _seed_vulnerable(client)
    submit(client, snapshot_body(snapshot_id="snap_close_0007"))
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(tmp_path / "feed-volume-gone.json"))
    advisories.reload_providers()

    from_worker = software_findings.ingest_device(
        settings, tenant_id="default", device_id=device_id, run_matcher=True
    )
    from_refresh = software_findings.ingest_device(
        settings, tenant_id="default", device_id=device_id, run_matcher=False
    )
    assert from_worker.closed == from_refresh.closed == 0
    assert (
        client.get(
            f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
        ).json()["state"]
        == "OPEN"
    )


def test_a_withdrawn_fix_is_not_a_patched_host(
    client: TestClient, settings, monkeypatch, tmp_path: Path
) -> None:
    """A USN reissued as "affected, no fix yet" leaves the match ``vulnerable``
    and empties ``fixed_version``, which drops it below ``is_trackable``. The
    host did not move; the vendor did. Closing it as ``patched`` reports a
    remediation nobody performed."""
    import json as _json

    from api.services import advisories, software_findings

    device_id, finding = _seed_vulnerable(client)

    payload = _json.loads((ADVISORIES / "ubuntu-lifecycle.json").read_text(encoding="utf-8"))
    for entry in payload["entries"]:
        if entry["advisory_id"] == "USN-6408-1":
            entry["state"] = "open"
            entry["fixed_version"] = None
    withdrawn = tmp_path / "ubuntu-fix-withdrawn.json"
    withdrawn.write_text(_json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(withdrawn))
    advisories.reload_providers()

    submit(client, snapshot_body(snapshot_id="snap_close_0008"))
    stats = software_findings.ingest_device(
        settings, tenant_id="default", device_id=device_id, run_matcher=True
    )
    assert stats.closed == 0

    after = client.get(
        f"/api/vulnerabilities/{finding['vuln_id']}", headers=auth_headers(client)
    ).json()
    assert after["state"] == "OPEN"
    assert after["closure_reason"] is None


def test_raising_the_severity_floor_does_not_patch_anything(
    client: TestClient, settings, monkeypatch
) -> None:
    """``OCTO_SOFTWARE_FINDING_MIN_SEVERITY`` is a floor on *creation*, which is
    what ``docs/configuration.md`` says it is. Raising it used to close every
    software finding below the new floor as ``patched`` and machine-verified —
    a config change reported as estate-wide remediation."""
    import dataclasses

    from api.services import software_findings

    device_id, _ = _seed_vulnerable(client)
    low = next(
        item for item in software_findings_of(client) if item["cve"] == "CVE-2026-22222"
    )
    assert low["severity"] == "low"

    submit(client, snapshot_body(snapshot_id="snap_close_0009"))
    stats = software_findings.ingest_device(
        dataclasses.replace(settings, software_finding_min_severity="high"),
        tenant_id="default",
        device_id=device_id,
        run_matcher=True,
    )
    assert stats.closed == 0
    assert stats.held_open_untracked_match >= 1

    after = client.get(
        f"/api/vulnerabilities/{low['vuln_id']}", headers=auth_headers(client)
    ).json()
    assert after["state"] == "OPEN"
    assert after["closure_reason"] is None
