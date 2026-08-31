"""``/api/endpoint/cve-matches`` — RBAC, tenant isolation, filters, refresh."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.conftest import auth_headers, configured_client, requires_postgres

pytestmark = requires_postgres

FIXTURES = Path(__file__).parent / "fixtures"
ADVISORIES = FIXTURES / "advisories"
AGENT_HEADERS = {"Authorization": "Bearer test-agent-token"}


def _snapshot(
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
    body["software"] = software if software is not None else [
        # Backported: fixed by USN-5051-2 at 1.1.1f-1ubuntu2.8.
        {
            "name": "openssl",
            "version": "1.1.1f-1ubuntu2.16",
            "publisher": "Canonical",
            "architecture": "amd64",
            "source": "dpkg",
            "install_location": None,
        },
        # Below the fixed version: genuinely vulnerable.
        {
            "name": "curl",
            "version": "7.68.0-1ubuntu2.1",
            "publisher": "Canonical",
            "architecture": "amd64",
            "source": "dpkg",
            "install_location": None,
        },
        # Not a distribution package at all: unassessable, and it must say so.
        {
            "name": "Some Vendor Agent",
            "version": "3.2.1",
            "publisher": "Vendor",
            "architecture": "amd64",
            "source": "other",
            "install_location": None,
        },
    ]
    return body


@pytest.fixture()
def client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(ADVISORIES / "ubuntu-test.json"))
    monkeypatch.setenv("OCTO_DEBIAN_ADVISORY_DATABASE", str(ADVISORIES / "debian-test.json"))
    from api.services import advisories

    advisories.reload_providers()
    built = configured_client(tmp_path, monkeypatch)
    yield built
    advisories.reload_providers()


def _submit(client: TestClient, body: dict) -> str:
    response = client.post("/api/endpoint/inventory", headers=AGENT_HEADERS, json=body)
    assert response.status_code == 201, response.text
    return response.json()["device_id"]


def _seed(client: TestClient, **kwargs) -> str:
    """One ingested snapshot plus one matcher run; returns the device id."""
    device_id = _submit(client, _snapshot(snapshot_id="snap_cve_0001", **kwargs))
    operator = auth_headers(client, "operator")
    response = client.post(
        f"/api/endpoint/devices/{device_id}/cve-matches/refresh", headers=operator
    )
    assert response.status_code == 200, response.text
    return device_id


# --------------------------------------------------------------------------
# Running the matcher
# --------------------------------------------------------------------------


def test_refresh_reports_what_it_did(client: TestClient) -> None:
    device_id = _submit(client, _snapshot(snapshot_id="snap_cve_0001"))
    response = client.post(
        f"/api/endpoint/devices/{device_id}/cve-matches/refresh",
        headers=auth_headers(client, "operator"),
    )
    assert response.status_code == 200
    summary = response.json()
    assert summary["device_id"] == device_id
    assert (summary["distro"], summary["distro_release"]) == ("ubuntu", "focal")
    assert summary["packages_total"] == 3
    assert summary["packages_assessed"] == 2
    assert summary["packages_unassessed"] == 1
    assert summary["by_status"]["vulnerable"] == 1
    assert summary["by_status"]["fixed"] == 2
    assert summary["by_status"]["unknown"] == 1


def test_matches_carry_installed_and_fixed_versions(client: TestClient) -> None:
    device_id = _seed(client)
    rows = client.get(
        f"/api/endpoint/devices/{device_id}/cve-matches", headers=auth_headers(client)
    ).json()
    by_cve = {row["cve_id"]: row for row in rows}

    vulnerable = by_cve["CVE-2023-38545"]
    assert vulnerable["status"] == "vulnerable"
    assert vulnerable["installed_version"] == "7.68.0-1ubuntu2.1"
    assert vulnerable["fixed_version"] == "7.68.0-1ubuntu2.20"
    assert vulnerable["advisory_id"] == "USN-6408-1"
    assert vulnerable["advisory_url"].startswith("https://ubuntu.com/security/notices/")
    assert vulnerable["provider"] == "ubuntu-usn"
    assert vulnerable["feed_date"] == "2026-08-01"
    assert vulnerable["purl"].startswith("pkg:deb/ubuntu/curl@")
    assert vulnerable["cpe23"].startswith("cpe:2.3:a:ubuntu:curl:")

    # The backport, which is the case that must not read as vulnerable.
    assert by_cve["CVE-2021-3711"]["status"] == "fixed"

    unassessable = by_cve[""]
    assert unassessable["status"] == "unknown"
    assert unassessable["unknown_reason"] == "non_distro_source"
    assert unassessable["evidence"]["package_count"] == 1


def test_worst_status_sorts_first(client: TestClient) -> None:
    device_id = _seed(client)
    rows = client.get(
        f"/api/endpoint/devices/{device_id}/cve-matches", headers=auth_headers(client)
    ).json()
    assert rows[0]["status"] == "vulnerable"


def test_rerunning_replaces_rather_than_accumulates(client: TestClient) -> None:
    device_id = _seed(client)
    operator = auth_headers(client, "operator")
    before = client.get(
        f"/api/endpoint/devices/{device_id}/cve-matches", headers=operator
    ).json()
    client.post(f"/api/endpoint/devices/{device_id}/cve-matches/refresh", headers=operator)
    after = client.get(
        f"/api/endpoint/devices/{device_id}/cve-matches", headers=operator
    ).json()
    assert len(after) == len(before)


def test_a_patched_endpoint_loses_its_vulnerable_row(client: TestClient) -> None:
    """A match is a statement about the current snapshot: once the host
    upgrades, the old ``vulnerable`` must disappear rather than linger."""
    device_id = _seed(client)
    operator = auth_headers(client, "operator")
    patched = _snapshot(snapshot_id="snap_cve_0002")
    patched["software"][1]["version"] = "7.68.0-1ubuntu2.22"
    assert client.post("/api/endpoint/inventory", headers=AGENT_HEADERS, json=patched).status_code == 201
    client.post(f"/api/endpoint/devices/{device_id}/cve-matches/refresh", headers=operator)
    rows = client.get(
        f"/api/endpoint/devices/{device_id}/cve-matches?match_status=vulnerable",
        headers=operator,
    ).json()
    assert rows == []


def test_unknown_os_matches_nothing_and_says_so(client: TestClient) -> None:
    device_id = _submit(
        client, _snapshot(snapshot_id="snap_cve_0003", os_name="Some Appliance OS", os_version="1.0")
    )
    response = client.post(
        f"/api/endpoint/devices/{device_id}/cve-matches/refresh",
        headers=auth_headers(client, "operator"),
    )
    summary = response.json()
    assert summary["distro"] is None
    # Two unknown rows, one per reason: the two dpkg packages could not be
    # assessed because the release is unresolved, the vendor agent because it
    # does not come from a distribution package manager at all.
    assert summary["by_status"] == {
        "vulnerable": 0,
        "fixed": 0,
        "not_applicable": 0,
        "unknown": 2,
    }
    rows = client.get(
        f"/api/endpoint/devices/{device_id}/cve-matches", headers=auth_headers(client)
    ).json()
    assert {row["unknown_reason"] for row in rows} == {"unknown_distro", "non_distro_source"}
    assert all(row["cve_id"] == "" for row in rows)


# --------------------------------------------------------------------------
# Filters
# --------------------------------------------------------------------------


def test_tenant_list_filters(client: TestClient) -> None:
    _seed(client)
    viewer = auth_headers(client)

    all_rows = client.get("/api/endpoint/cve-matches", headers=viewer).json()
    assert len(all_rows) == 4
    assert all(row["hostname"] == "workstation-01.example.internal" for row in all_rows)

    vulnerable = client.get(
        "/api/endpoint/cve-matches?match_status=vulnerable", headers=viewer
    ).json()
    assert [row["cve_id"] for row in vulnerable] == ["CVE-2023-38545"]

    critical = client.get("/api/endpoint/cve-matches?severity=critical", headers=viewer).json()
    assert [row["cve_id"] for row in critical] == ["CVE-2023-38545"]

    by_cve = client.get(
        "/api/endpoint/cve-matches?cve=cve-2021-3711", headers=viewer
    ).json()
    assert [row["status"] for row in by_cve] == ["fixed"]

    assert client.get("/api/endpoint/cve-matches?limit=1", headers=viewer).json().__len__() == 1


def test_unknown_status_value_is_rejected(client: TestClient) -> None:
    assert (
        client.get(
            "/api/endpoint/cve-matches?match_status=maybe", headers=auth_headers(client)
        ).status_code
        == 422
    )


def test_summary_reports_tallies_and_provider_provenance(client: TestClient) -> None:
    _seed(client)
    summary = client.get("/api/endpoint/cve-matches/summary", headers=auth_headers(client)).json()
    assert summary["total"] == 4
    assert summary["by_status"]["vulnerable"] == 1
    assert summary["by_status"]["fixed"] == 2
    assert summary["vulnerable_by_severity"]["critical"] == 1
    assert summary["last_matched_at"]
    providers = {entry["distro"]: entry for entry in summary["providers"]}
    assert providers["ubuntu"]["source"] == "ubuntu-usn-fixture"
    assert providers["ubuntu"]["updated"] == "2026-08-01"
    assert providers["ubuntu"]["entries"] > 0
    assert "focal" in providers["ubuntu"]["releases"]


# --------------------------------------------------------------------------
# RBAC and tenant isolation
# --------------------------------------------------------------------------


def test_reads_require_authentication(client: TestClient) -> None:
    for path in (
        "/api/endpoint/cve-matches",
        "/api/endpoint/cve-matches/summary",
        "/api/endpoint/devices/dev_x/cve-matches",
    ):
        assert client.get(path).status_code == 401, path


def test_a_viewer_cannot_run_the_matcher(client: TestClient) -> None:
    device_id = _submit(client, _snapshot(snapshot_id="snap_cve_0004"))
    viewer = auth_headers(client)
    assert client.post("/api/endpoint/cve-matches/refresh", headers=viewer).status_code == 403
    assert (
        client.post(
            f"/api/endpoint/devices/{device_id}/cve-matches/refresh", headers=viewer
        ).status_code
        == 403
    )
    # …but reading is a viewer's right.
    assert client.get("/api/endpoint/cve-matches", headers=viewer).status_code == 200


def test_an_unknown_device_is_a_404_not_an_empty_list(client: TestClient) -> None:
    viewer = auth_headers(client)
    assert client.get("/api/endpoint/devices/dev_nope/cve-matches", headers=viewer).status_code == 404
    assert (
        client.post(
            "/api/endpoint/devices/dev_nope/cve-matches/refresh",
            headers=auth_headers(client, "operator"),
        ).status_code
        == 404
    )


def test_matches_are_confined_to_their_tenant(client: TestClient) -> None:
    device_id = _seed(client)
    admin = auth_headers(client, "admin")
    assert (
        client.post(
            "/api/tenants", headers=admin, json={"name": "Other", "tenant_id": "ten_other"}
        ).status_code
        == 201
    )

    # The other tenant sees none of it, and cannot reach the device by id.
    assert client.get("/api/endpoint/cve-matches?tenant_id=ten_other", headers=admin).json() == []
    assert (
        client.get(
            f"/api/endpoint/devices/{device_id}/cve-matches?tenant_id=ten_other", headers=admin
        ).status_code
        == 404
    )
    assert (
        client.post(
            f"/api/endpoint/devices/{device_id}/cve-matches/refresh?tenant_id=ten_other",
            headers=admin,
        ).status_code
        == 404
    )
    # A tenant-wide run in the other tenant touches nothing here.
    other_run = client.post(
        "/api/endpoint/cve-matches/refresh?tenant_id=ten_other", headers=admin
    ).json()
    assert other_run == {
        "tenant_id": "ten_other",
        "devices": 0,
        "matches": 0,
        "by_status": {"vulnerable": 0, "fixed": 0, "not_applicable": 0, "unknown": 0},
        "results": [],
    }
    assert len(client.get("/api/endpoint/cve-matches", headers=admin).json()) == 4


def test_tenant_wide_refresh_covers_every_device(client: TestClient) -> None:
    _submit(client, _snapshot(snapshot_id="snap_cve_0005"))
    _submit(
        client,
        _snapshot(
            snapshot_id="snap_cve_0006",
            agent_id="lariska-agent-0002",
            hostname="workstation-02.example.internal",
        ),
    )
    run = client.post(
        "/api/endpoint/cve-matches/refresh", headers=auth_headers(client, "operator")
    ).json()
    assert run["devices"] == 2
    assert run["by_status"]["vulnerable"] == 2
    assert len(run["results"]) == 2
