"""Software→CVE matches folded into the vulnerability lifecycle (Track E, M3).

Closure has its own file (``tests/test_software_finding_closure.py``) because
it is the part with the safety property; this one is about what becomes a
tracked finding at all, and what deliberately does not.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import (
    auth_headers,
    configured_client,
    make_settings,
    requires_postgres,
)

pytestmark = requires_postgres

FIXTURES = Path(__file__).parent / "fixtures"
ADVISORIES = FIXTURES / "advisories"
AGENT_HEADERS = {"Authorization": "Bearer test-agent-token"}

#: One backported package (``fixed``), one behind a published fix
#: (``vulnerable``, critical), one affected with no fix yet (``vulnerable``,
#: nothing to run), one low-severity fix, and one package no distribution
#: package manager owns (``unknown``).
SOFTWARE = [
    {
        "name": "openssl",
        "version": "1.1.1f-1ubuntu2.16",
        "publisher": "Canonical",
        "architecture": "amd64",
        "source": "dpkg",
        "install_location": None,
    },
    {
        "name": "curl",
        "version": "7.68.0-1ubuntu2.1",
        "publisher": "Canonical",
        "architecture": "amd64",
        "source": "dpkg",
        "install_location": None,
    },
    {
        "name": "nginx",
        "version": "1.18.0-0ubuntu1",
        "publisher": "Canonical",
        "architecture": "amd64",
        "source": "dpkg",
        "install_location": None,
    },
    {
        "name": "zlib1g",
        "version": "1:1.2.11.dfsg-2ubuntu1",
        "publisher": "Canonical",
        "architecture": "amd64",
        "source": "dpkg",
        "install_location": None,
    },
    {
        "name": "Some Vendor Agent",
        "version": "3.2.1",
        "publisher": "Vendor",
        "architecture": "amd64",
        "source": "other",
        "install_location": None,
    },
]


def snapshot_body(
    *,
    snapshot_id: str,
    agent_id: str = "lariska-agent-0001",
    hostname: str = "workstation-01.example.internal",
    os_name: str | None = "Ubuntu",
    os_version: str | None = "20.04",
    software: list[dict] | None = None,
) -> dict:
    body = json.loads((FIXTURES / "endpoint_inventory_v1_valid.json").read_text(encoding="utf-8"))
    body["collected_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    body["snapshot_id"] = snapshot_id
    body["agent_id"] = agent_id
    body["hostname"] = hostname
    body["os_name"] = os_name
    body["os_version"] = os_version
    body["identifiers"] = []
    body["software"] = [dict(item) for item in (software if software is not None else SOFTWARE)]
    return body


@pytest.fixture()
def settings(tmp_path: Path):
    return make_settings(tmp_path)


@pytest.fixture()
def client(tmp_path: Path, monkeypatch, settings) -> TestClient:
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(ADVISORIES / "ubuntu-lifecycle.json"))
    monkeypatch.setenv("OCTO_DEBIAN_ADVISORY_DATABASE", str(ADVISORIES / "debian-test.json"))
    # No CVSS4 overlay: a software finding has to score from the vendor
    # severity alone, which is the normal case for an offline install.
    monkeypatch.setenv("OCTO_CVSS4_DATABASE", str(tmp_path / "no-cvss4.json"))
    from api.services import advisories, software_findings

    advisories.reload_providers()
    software_findings.reset_cvss4_cache_for_tests()
    built = configured_client(tmp_path, monkeypatch, settings=settings)
    yield built
    advisories.reload_providers()
    software_findings.reset_cvss4_cache_for_tests()


def submit(client: TestClient, body: dict) -> str:
    response = client.post("/api/endpoint/inventory", headers=AGENT_HEADERS, json=body)
    assert response.status_code == 201, response.text
    return response.json()["device_id"]


def refresh(client: TestClient, device_id: str) -> dict:
    response = client.post(
        f"/api/endpoint/devices/{device_id}/cve-matches/refresh",
        headers=auth_headers(client, "operator"),
    )
    assert response.status_code == 200, response.text
    return response.json()


def seed(client: TestClient, **kwargs) -> str:
    device_id = submit(client, snapshot_body(snapshot_id="snap_life_0001", **kwargs))
    refresh(client, device_id)
    return device_id


def software_findings_of(client: TestClient) -> list[dict]:
    response = client.get(
        "/api/vulnerabilities?source=endpoint_software&limit=100",
        headers=auth_headers(client),
    )
    assert response.status_code == 200, response.text
    return response.json()["items"]


# --------------------------------------------------------------------------
# What becomes a finding
# --------------------------------------------------------------------------


def test_a_vulnerable_match_with_a_published_fix_becomes_a_tracked_finding(
    client: TestClient,
) -> None:
    device_id = seed(client)
    items = software_findings_of(client)

    # Both packages that are behind a published fix, and nothing else.
    assert {item["cve"] for item in items} == {"CVE-2023-38545", "CVE-2026-22222"}
    finding = next(item for item in items if item["cve"] == "CVE-2023-38545")
    assert finding["source"] == "endpoint_software"
    assert finding["device_id"] == device_id
    assert finding["state"] == "OPEN"
    # A software finding is about an installed package, not about a listener.
    assert finding["port"] is None
    assert finding["script_id"] is None
    assert finding["severity"] == "critical"
    # It got the whole lifecycle, not just a row: a deadline, an SLA reading
    # and the asset's owner as the default remediation owner.
    assert finding["due_at"]
    assert finding["sla_days"] == 15
    assert finding["sla_state"] in {"on_track", "due_soon"}
    assert "curl" in finding["title"] and "7.68.0-1ubuntu2.20" in finding["title"]


def test_the_finding_carries_an_audit_trail_from_its_first_observation(
    client: TestClient,
) -> None:
    seed(client)
    vuln_id = next(
        item for item in software_findings_of(client) if item["cve"] == "CVE-2023-38545"
    )["vuln_id"]
    events = client.get(
        f"/api/vulnerabilities/{vuln_id}/events", headers=auth_headers(client)
    ).json()["items"]
    assert [event["kind"] for event in events] == ["observed"]
    detail = events[0]["detail"]
    assert detail["source"] == "endpoint_software"
    assert detail["first_seen"] is True
    assert detail["advisory_id"] == "USN-6408-1"
    assert detail["fixed_version"] == "7.68.0-1ubuntu2.20"


def test_fixed_and_unknown_matches_never_become_findings(client: TestClient) -> None:
    """The evidence that the matcher looked is not a piece of work.

    A backport reading as ``fixed`` and an unassessable package reading as
    ``unknown`` are both correct answers. Giving either an SLA deadline would
    put the breach report behind a statement nobody made.
    """
    device_id = seed(client)
    matches = client.get(
        f"/api/endpoint/devices/{device_id}/cve-matches", headers=auth_headers(client)
    ).json()
    statuses = {row["cve_id"]: row["status"] for row in matches}
    assert statuses["CVE-2021-3711"] == "fixed"
    assert statuses[""] == "unknown"

    tracked = {item["cve"] for item in software_findings_of(client)}
    assert "CVE-2021-3711" not in tracked
    assert None not in tracked and "" not in tracked


def test_a_vulnerable_match_with_no_published_fix_is_not_tracked(client: TestClient) -> None:
    """"Affected, no fix yet" is real risk with nothing to run.

    It is also the bulk of a full feed across an estate, and every one of those
    rows would arrive with a deadline nobody can meet. It stays a match, and
    ``patch_gap`` reports it as ``unfixed_findings``.
    """
    device_id = seed(client)
    matches = {
        row["cve_id"]: row
        for row in client.get(
            f"/api/endpoint/devices/{device_id}/cve-matches", headers=auth_headers(client)
        ).json()
    }
    assert matches["CVE-2026-11111"]["status"] == "vulnerable"
    assert matches["CVE-2026-11111"]["fixed_version"] is None

    assert "CVE-2026-11111" not in {item["cve"] for item in software_findings_of(client)}


def test_a_severity_floor_keeps_low_findings_out_of_the_sla_report(
    tmp_path: Path, monkeypatch
) -> None:
    """The tenant-tunable half of the volume rule.

    ``zlib1g`` is behind a published low-severity fix, so it is trackable by
    default and must disappear once a floor of ``high`` is set.
    """
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(ADVISORIES / "ubuntu-lifecycle.json"))
    monkeypatch.setenv("OCTO_CVSS4_DATABASE", str(tmp_path / "no-cvss4.json"))
    from api.services import advisories, software_findings

    advisories.reload_providers()
    software_findings.reset_cvss4_cache_for_tests()
    settings = make_settings(tmp_path, software_finding_min_severity="high")
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    try:
        seed(client)
        assert {item["cve"] for item in software_findings_of(client)} == {"CVE-2023-38545"}
    finally:
        advisories.reload_providers()
        software_findings.reset_cvss4_cache_for_tests()


def test_without_a_floor_a_low_severity_fix_is_tracked(client: TestClient) -> None:
    """The counterpart of the test above: the floor is what removes it, not the
    absence of a code path."""
    seed(client)
    assert "CVE-2026-22222" in {item["cve"] for item in software_findings_of(client)}


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------


def test_refolding_the_same_snapshot_creates_no_second_finding(client: TestClient) -> None:
    device_id = seed(client)
    before = software_findings_of(client)
    vuln_id = before[0]["vuln_id"]
    assert len(before) == 2

    refresh(client, device_id)
    refresh(client, device_id)

    after = software_findings_of(client)
    assert [item["vuln_id"] for item in after] == [item["vuln_id"] for item in before]
    # And the audit trail stays one event: re-running the matcher over a
    # snapshot that has not moved is not a new observation of anything.
    events = client.get(
        f"/api/vulnerabilities/{vuln_id}/events", headers=auth_headers(client)
    ).json()
    assert events["total"] == 1
    assert all(item["observation_count"] == 1 for item in after)


def test_the_scan_finding_key_is_not_reused(client: TestClient) -> None:
    """The software key must not collide with the scan key for the same CVE.

    Widening ``vulnerabilities.finding_key`` to tell the two apart would have
    renamed every finding that already exists and reopened the whole backlog,
    so the software path has its own namespaced hash instead.
    """
    from api.services import software_findings, vulnerabilities

    scan_key = vulnerabilities.finding_key(
        asset_id="ast_1", cve="CVE-2023-38545", script_id=None, port=None
    )
    software_key = software_findings.software_finding_key(
        asset_id="ast_1", device_id="dev_1", cve="CVE-2023-38545"
    )
    assert scan_key != software_key
    # And two endpoints on one asset are two pieces of work, not one.
    assert software_key != software_findings.software_finding_key(
        asset_id="ast_1", device_id="dev_2", cve="CVE-2023-38545"
    )


def test_two_endpoints_on_the_same_advisory_are_two_findings(client: TestClient) -> None:
    submit(client, snapshot_body(snapshot_id="snap_life_a"))
    submit(
        client,
        snapshot_body(
            snapshot_id="snap_life_b",
            agent_id="lariska-agent-0002",
            hostname="workstation-02.example.internal",
        ),
    )
    response = client.post(
        "/api/endpoint/cve-matches/refresh", headers=auth_headers(client, "operator")
    )
    assert response.status_code == 200, response.text
    assert response.json()["lifecycle"]["created"] == 4

    curl_findings = [
        item for item in software_findings_of(client) if item["cve"] == "CVE-2023-38545"
    ]
    assert len({item["device_id"] for item in curl_findings}) == 2


# --------------------------------------------------------------------------
# Scoring and skipping
# --------------------------------------------------------------------------


def test_a_finding_is_scored_without_a_cvss_vector(client: TestClient) -> None:
    """No CVSS4 overlay is configured here, which is the offline default.

    The finding must still carry a NIST risk level and a contextual score —
    from the vendor severity — and must report its network exposure as
    ``unknown`` rather than inventing one: the inventory knows what is
    installed, not what is reachable.
    """
    seed(client)
    finding = next(
        item for item in software_findings_of(client) if item["cve"] == "CVE-2023-38545"
    )
    assert finding["risk_level"]
    assert finding["contextual_score"] is not None
    assert finding["network_exposure"] == "unknown"
    assert finding["cvss"] is None
    assert finding["cwe"] == []


def test_an_unlinked_device_is_skipped_rather_than_tracked_against_nothing(
    client: TestClient, settings
) -> None:
    """A device the asset quota refused to link has ``asset_id IS NULL``.

    The scan path skips a finding whose host never became an asset for the same
    reason: a finding against nothing addressable is not a record of anything.
    """
    from api.db import models
    from api.db.engine import get_session
    from api.services import software_findings

    device_id = submit(client, snapshot_body(snapshot_id="snap_life_unlinked"))
    with get_session(settings.postgres_url) as session:
        device = session.get(models.EndpointDevice, device_id)
        device.asset_id = None
        device.reconciliation_status = "unlinked"

    stats = software_findings.ingest_device(
        settings, tenant_id="default", device_id=device_id
    )
    assert stats.skipped_unlinked == 1
    assert stats.created == 0
    assert software_findings_of(client) == []
