"""A false-positive verdict has to hold against *every* observer, not one.

The verdict is a statement about a finding, not about the path that found it,
and the endpoint-software fold is the second path that re-observes findings on
a timer. It had its own copy of the re-open rule and knew nothing about
verdicts, so a finding marked as noise came back ``OPEN`` on the next inventory
snapshot with ``reopen_count`` incremented and the SLA clock restarted, while
the console still rendered the suppression on it — the exact defect the verdict
was built to remove, surviving on half the estate and needing no human to
trigger it.

Closure has ``tests/test_software_finding_closure.py``; this file is only about
what a verdict does to the fold.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from api.db import models
from api.db.engine import get_session
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_software_findings import (
    ADVISORIES,
    refresh,
    snapshot_body,
    software_findings_of,
    submit,
)

pytestmark = requires_postgres

CURL_CVE = "CVE-2023-38545"


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


def _marked(client: TestClient, *, suppress_days: int = 365) -> tuple[str, str]:
    """Seed a software finding and close it as a false positive. Returns ids."""
    device_id = submit(client, snapshot_body(snapshot_id="snap_fp_0001"))
    refresh(client, device_id)
    vuln_id = next(item for item in software_findings_of(client) if item["cve"] == CURL_CVE)[
        "vuln_id"
    ]
    response = client.post(
        f"/api/vulnerabilities/{vuln_id}/false-positive",
        json={"reason": "The agent reports the vendor-backported build", "suppress_days": suppress_days},
        headers=auth_headers(client, "admin"),
    )
    assert response.status_code == 200, response.text
    return device_id, vuln_id


def _finding(client: TestClient, vuln_id: str) -> dict:
    response = client.get(f"/api/vulnerabilities/{vuln_id}", headers=auth_headers(client))
    assert response.status_code == 200, response.text
    return response.json()


def _events(client: TestClient, vuln_id: str) -> list[dict]:
    return client.get(
        f"/api/vulnerabilities/{vuln_id}/events", headers=auth_headers(client)
    ).json()["items"]


def _next_snapshot(client: TestClient, device_id: str, snapshot_id: str) -> dict:
    submit(client, snapshot_body(snapshot_id=snapshot_id))
    return refresh(client, device_id)


# --------------------------------------------------------------------------


def test_the_next_inventory_snapshot_does_not_reopen_a_suppressed_finding(
    client: TestClient,
) -> None:
    """The matcher runs on a timer, so this defect needed nobody at all."""
    device_id, vuln_id = _marked(client)

    result = _next_snapshot(client, device_id, "snap_fp_0002")

    after = _finding(client, vuln_id)
    assert after["state"] == "CLOSED"
    assert after["closure_reason"] == "false_positive"
    assert after["reopen_count"] == 0
    assert after["fp_suppressed"] is True
    assert after["fp_suppress_until"]
    assert after["fp_observations"] == 1
    assert result["lifecycle"]["fp_suppressed"] == 1
    assert result["lifecycle"]["reopened"] == 0
    # One event per verdict rather than one per fold: the matcher is re-run on
    # a timer and ``vulnerability_events`` has no retention sweep behind it.
    _next_snapshot(client, device_id, "snap_fp_0003")
    assert [event["kind"] for event in _events(client, vuln_id)].count("fp_reobserved") == 1
    assert _finding(client, vuln_id)["fp_observations"] == 2


def test_a_worse_assessment_breaks_the_verdict_on_the_software_path_too(
    client: TestClient, settings
) -> None:
    """New intelligence is new evidence, on whichever path it arrives."""
    device_id, vuln_id = _marked(client)
    # The verdict was made when the finding read `medium`; the advisory feed
    # now scores the same match `critical`.
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Vulnerability)
            .where(models.Vulnerability.vuln_id == vuln_id)
            .values(severity="medium")
        )

    result = _next_snapshot(client, device_id, "snap_fp_0002")

    after = _finding(client, vuln_id)
    assert result["lifecycle"]["fp_overridden"] == 1
    assert result["lifecycle"]["reopened"] == 1
    assert after["state"] == "OPEN"
    assert after["closure_reason"] is None
    # The verdict is dropped rather than left on an open row, where the console
    # reads it as a current judgement and offers to withdraw it.
    assert after["fp_reason"] is None and after["fp_suppress_until"] is None
    assert after["fp_suppressed"] is False
    kinds = [event["kind"] for event in _events(client, vuln_id)]
    assert "fp_overridden" in kinds
    override = next(event for event in _events(client, vuln_id) if event["kind"] == "fp_overridden")
    assert override["detail"]["changed"] == ["severity"]
    assert override["detail"]["source"] == "endpoint_software"
    reopened = next(event for event in _events(client, vuln_id) if event["kind"] == "reopened")
    assert reopened["detail"]["after_fp_suppression"] is True


def test_a_lapsed_verdict_falls_back_to_the_ordinary_reopen(
    client: TestClient, settings
) -> None:
    """The mandatory expiry has to mean the same thing on both paths."""
    from datetime import UTC, datetime, timedelta

    device_id, vuln_id = _marked(client, suppress_days=1)
    with get_session(settings.postgres_url) as session:
        session.execute(
            update(models.Vulnerability)
            .where(models.Vulnerability.vuln_id == vuln_id)
            .values(fp_suppress_until=datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=1))
        )

    result = _next_snapshot(client, device_id, "snap_fp_0002")

    after = _finding(client, vuln_id)
    assert result["lifecycle"]["reopened"] == 1
    assert result["lifecycle"]["fp_suppressed"] == 0
    assert after["state"] == "OPEN"
    assert after["reopen_count"] == 1
    assert after["fp_reason"] is None
    reopened = next(event for event in _events(client, vuln_id) if event["kind"] == "reopened")
    assert reopened["detail"]["after_fp_suppression"] is True


def test_refolding_the_same_snapshot_is_not_another_sighting(client: TestClient) -> None:
    """``fp_observations`` counts observations, not passes of the matcher."""
    device_id, vuln_id = _marked(client)
    _next_snapshot(client, device_id, "snap_fp_0002")

    refresh(client, device_id)
    refresh(client, device_id)

    assert _finding(client, vuln_id)["fp_observations"] == 1
