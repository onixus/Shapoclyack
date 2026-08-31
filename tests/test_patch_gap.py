"""Patch-gap analysis over the software→CVE matcher (Track E M2).

Two things here are easy to get wrong and are what these tests are for: a
vulnerable package with no published fix must never appear as work an operator
can do, and the target version for a package must be the *highest* fix among
its CVEs, so that one upgrade closes all of them.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from api.services import patch_gap
from api.services import version_compare
from tests.conftest import auth_headers, configured_client, requires_postgres

FIXTURES = Path(__file__).parent / "fixtures"
ADVISORIES = FIXTURES / "advisories"
AGENT_HEADERS = {"Authorization": "Bearer test-agent-token"}


# --------------------------------------------------------------------------
# Grouping and ordering (no database)
# --------------------------------------------------------------------------


def _row(**kwargs):
    base = {
        "cve_id": "CVE-2024-0001",
        "severity": "medium",
        "installed_package": "curl",
        "source_package": "curl",
        "installed_version": "7.68.0-1ubuntu2.1",
        "fixed_version": "7.68.0-1ubuntu2.7",
        "purl": "pkg:deb/ubuntu/curl@7.68.0-1ubuntu2.1",
        "distro": "ubuntu",
        "distro_release": "focal",
    }
    return SimpleNamespace(**{**base, **kwargs})


def test_one_package_with_several_cves_is_one_upgrade():
    gaps, unfixed = patch_gap._build_gaps(
        [
            _row(cve_id="CVE-2024-0001", fixed_version="7.68.0-1ubuntu2.7"),
            _row(cve_id="CVE-2024-0002", fixed_version="7.68.0-1ubuntu2.10"),
            _row(cve_id="CVE-2024-0003", fixed_version="7.68.0-1ubuntu2.4"),
        ]
    )
    assert unfixed == 0
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["cve_count"] == 3
    # The newest fix, by dpkg ordering — 2.10 is above 2.7, not below it.
    assert gap["target_version"] == "7.68.0-1ubuntu2.10"


def test_target_version_uses_distro_ordering_not_string_ordering():
    """A plain string comparison puts 2.10 below 2.7 and understates the fix."""
    assert version_compare.compare(
        "7.68.0-1ubuntu2.10", "7.68.0-1ubuntu2.7", flavor=version_compare.DEB
    ) > 0
    gaps, _ = patch_gap._build_gaps(
        [
            _row(cve_id="CVE-1", fixed_version="7.68.0-1ubuntu2.7"),
            _row(cve_id="CVE-2", fixed_version="7.68.0-1ubuntu2.10"),
        ]
    )
    assert gaps[0]["target_version"] == "7.68.0-1ubuntu2.10"


def test_vulnerable_without_a_published_fix_is_not_a_patch_gap():
    """No fix means no command. Listing it would be advice that cannot work."""
    gaps, unfixed = patch_gap._build_gaps(
        [
            _row(cve_id="CVE-2024-9999", fixed_version=None),
            _row(cve_id="CVE-2024-9998", fixed_version=""),
        ]
    )
    assert gaps == []
    assert unfixed == 2


def test_unfixed_is_counted_alongside_a_real_gap_not_folded_into_it():
    gaps, unfixed = patch_gap._build_gaps(
        [
            _row(cve_id="CVE-1", fixed_version="7.68.0-1ubuntu2.7"),
            _row(cve_id="CVE-2", fixed_version=None),
        ]
    )
    assert unfixed == 1
    assert gaps[0]["cve_count"] == 1
    assert gaps[0]["cve_ids"] == ["CVE-1"]


def test_unorderable_fixes_yield_no_command_rather_than_a_guess():
    """A target that may not close every listed CVE is worse than no target."""
    gaps, _ = patch_gap._build_gaps(
        [
            _row(cve_id="CVE-1", fixed_version="1.0", purl=None),
            _row(cve_id="CVE-2", fixed_version="2.0", purl=None),
        ]
    )
    assert gaps[0]["target_version"] is None
    assert gaps[0]["upgrade_command"] is None


def test_worst_severity_wins_within_a_package():
    gaps, _ = patch_gap._build_gaps(
        [
            _row(cve_id="CVE-1", severity="low"),
            _row(cve_id="CVE-2", severity="critical"),
            _row(cve_id="CVE-3", severity="medium"),
        ]
    )
    assert gaps[0]["worst_severity"] == "critical"
    assert gaps[0]["by_severity"] == {"critical": 1, "medium": 1, "low": 1}


def test_gaps_are_ordered_worst_first():
    gaps, _ = patch_gap._build_gaps(
        [
            _row(installed_package="zlib", severity="low", cve_id="CVE-1"),
            _row(installed_package="openssl", severity="critical", cve_id="CVE-2"),
            _row(installed_package="curl", severity="medium", cve_id="CVE-3"),
        ]
    )
    assert [gap["installed_package"] for gap in gaps] == ["openssl", "curl", "zlib"]


# --------------------------------------------------------------------------
# The command
# --------------------------------------------------------------------------


def test_deb_command_upgrades_only_the_named_packages():
    command = patch_gap.upgrade_command(version_compare.DEB, ["curl", "openssl"])
    assert command == (
        "sudo apt-get update && sudo apt-get install --only-upgrade curl openssl"
    )


def test_rpm_command_uses_dnf():
    assert patch_gap.upgrade_command(version_compare.RPM, ["curl"]) == "sudo dnf upgrade curl"


def test_no_command_for_an_unknown_package_manager():
    assert patch_gap.upgrade_command(None, ["curl"]) is None
    assert patch_gap.upgrade_command("brew", ["curl"]) is None


def test_no_command_without_packages():
    assert patch_gap.upgrade_command(version_compare.DEB, []) is None


def test_package_names_are_shell_quoted():
    """Inventory comes from a remote host and the command is pasted into a
    root shell, so a package name is data, never syntax."""
    command = patch_gap.upgrade_command(version_compare.DEB, ["curl; rm -rf /"])
    assert "; rm -rf /" not in command.replace("'curl; rm -rf /'", "")
    assert "'curl; rm -rf /'" in command


def test_flavor_comes_from_the_purl_type():
    assert patch_gap._flavor_for("pkg:deb/ubuntu/curl@7.68.0") == version_compare.DEB
    assert patch_gap._flavor_for("pkg:rpm/fedora/curl@7.68.0") == version_compare.RPM
    assert patch_gap._flavor_for("pkg:npm/left-pad@1.0.0") is None
    assert patch_gap._flavor_for(None) is None


# --------------------------------------------------------------------------
# End to end over the API
# --------------------------------------------------------------------------

def _snapshot(*, snapshot_id: str, software: list[dict] | None = None) -> dict:
    body = json.loads((FIXTURES / "endpoint_inventory_v1_valid.json").read_text(encoding="utf-8"))
    body["collected_at"] = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    body["snapshot_id"] = snapshot_id
    body["agent_id"] = "lariska-agent-0001"
    body["hostname"] = "workstation-01.example.internal"
    body["os_name"] = "Ubuntu"
    body["os_version"] = "20.04"
    body["identifiers"] = []
    body["software"] = software if software is not None else [
        # Already carries the backport: fixed, so not a gap.
        {
            "name": "openssl",
            "version": "1.1.1f-1ubuntu2.16",
            "publisher": "Canonical",
            "architecture": "amd64",
            "source": "dpkg",
            "install_location": None,
        },
        # Below the fixed version: a real gap.
        {
            "name": "curl",
            "version": "7.68.0-1ubuntu2.1",
            "publisher": "Canonical",
            "architecture": "amd64",
            "source": "dpkg",
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


def _seed(client: TestClient) -> str:
    response = client.post(
        "/api/endpoint/inventory", headers=AGENT_HEADERS, json=_snapshot(snapshot_id="snap_pg_0001")
    )
    assert response.status_code == 201, response.text
    device_id = response.json()["device_id"]
    refresh = client.post(
        f"/api/endpoint/devices/{device_id}/cve-matches/refresh",
        headers=auth_headers(client, "operator"),
    )
    assert refresh.status_code == 200, refresh.text
    return device_id


@requires_postgres
def test_device_patch_gap_names_the_upgrade(client: TestClient) -> None:
    device_id = _seed(client)
    response = client.get(
        f"/api/endpoint/devices/{device_id}/patch-gap", headers=auth_headers(client, "viewer")
    )
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["device_id"] == device_id
    packages = {gap["installed_package"] for gap in body["gaps"]}
    # The backported package is fixed and must not be work.
    assert "openssl" not in packages
    assert "curl" in packages
    curl = next(gap for gap in body["gaps"] if gap["installed_package"] == "curl")
    assert curl["upgrade_command"].startswith("sudo apt-get update && sudo apt-get install")
    assert "curl" in curl["upgrade_command"]
    assert curl["cve_count"] >= 1


@requires_postgres
def test_a_clean_device_is_empty_not_a_404(client: TestClient) -> None:
    """"Nothing outstanding" and "no such device" are different answers."""
    response = client.post(
        "/api/endpoint/inventory",
        headers=AGENT_HEADERS,
        json=_snapshot(
            snapshot_id="snap_pg_clean",
            software=[
                {
                    "name": "openssl",
                    "version": "1.1.1f-1ubuntu2.16",
                    "publisher": "Canonical",
                    "architecture": "amd64",
                    "source": "dpkg",
                    "install_location": None,
                }
            ],
        ),
    )
    device_id = response.json()["device_id"]
    client.post(
        f"/api/endpoint/devices/{device_id}/cve-matches/refresh",
        headers=auth_headers(client, "operator"),
    )
    gap = client.get(
        f"/api/endpoint/devices/{device_id}/patch-gap", headers=auth_headers(client, "viewer")
    )
    assert gap.status_code == 200
    assert gap.json()["gaps"] == []
    assert gap.json()["packages_to_upgrade"] == 0


@requires_postgres
def test_unknown_device_is_404(client: TestClient) -> None:
    response = client.get(
        "/api/endpoint/devices/dev_nope/patch-gap", headers=auth_headers(client, "viewer")
    )
    assert response.status_code == 404


@requires_postgres
def test_tenant_patch_gap_totals_cover_the_estate(client: TestClient) -> None:
    _seed(client)
    response = client.get("/api/endpoint/patch-gaps", headers=auth_headers(client, "viewer"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["devices_with_gaps"] >= 1
    assert body["packages_to_upgrade"] >= 1
    assert body["cves_closed_by_upgrade"] >= 1
    assert body["devices"][0]["hostname"] == "workstation-01.example.internal"


@requires_postgres
def test_patch_gap_needs_authentication(client: TestClient) -> None:
    assert client.get("/api/endpoint/patch-gaps").status_code == 401
    assert client.get("/api/endpoint/devices/dev_x/patch-gap").status_code == 401


@requires_postgres
def test_totals_survive_a_truncated_device_list(client: TestClient) -> None:
    """A capped list must never make the estate look smaller than it is."""
    _seed(client)
    response = client.get(
        "/api/endpoint/patch-gaps?limit=1", headers=auth_headers(client, "viewer")
    )
    body = response.json()
    assert len(body["devices"]) <= 1
    assert body["packages_to_upgrade"] >= len(body["devices"])
