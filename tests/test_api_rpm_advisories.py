"""Real PostgreSQL/API RPM provider and finding lifecycle integration (#358)."""
from __future__ import annotations

import pytest

from api.services import advisories, software_findings
from tests.conftest import auth_headers, configured_client, make_settings, requires_postgres
from tests.test_rpm_advisories import DEVICES, PROVIDERS, imported, installed
from tests.test_software_findings import refresh, snapshot_body, software_findings_of, submit

pytestmark = requires_postgres


@pytest.mark.parametrize("vendor,name,below,fixed", [
    ("rhel", "curl", "7.76.1-23.el9_2.7", "7.76.1-23.el9_2.8"),
    ("suse", "ucode-intel", "20240910-143.0", "20240910-143.1"),
    ("alas", "libExample", "1.0-1.amzn2023.0.1", "1:1.0-5.amzn2023.0.1"),
])
def test_inventory_match_persist_fold_and_upgrade(tmp_path, monkeypatch, vendor, name, below, fixed):
    provider = imported(tmp_path, vendor)
    monkeypatch.setenv(PROVIDERS[vendor].env_var, str(provider.path()))
    monkeypatch.setenv("OCTO_CVSS4_DATABASE", str(tmp_path / "absent.json"))
    advisories.reload_providers()
    software_findings.reset_cvss4_cache_for_tests()
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    try:
        body = snapshot_body(snapshot_id="rpm-snapshot-0001", software=[installed(name, below)], **DEVICES[vendor])
        device_id = submit(client, body)
        summary = refresh(client, device_id)
        assert summary["packages_assessed"] == 1
        records = software_findings_of(client)
        assert records and all(r["state"] == "OPEN" for r in records)
        keys = {r["vuln_id"] for r in records}
        matches = client.get(f"/api/endpoint/devices/{device_id}/cve-matches", headers=auth_headers(client)).json()
        assert all(r["evidence"]["source_sha256"] and r["provider"] == provider.name for r in matches)
        assert all(r["installed_package"] == name for r in matches)
        gap_response = client.get(f"/api/endpoint/devices/{device_id}/patch-gap", headers=auth_headers(client))
        assert gap_response.status_code == 200, gap_response.text
        gap_body = gap_response.json()
        command = ("sudo zypper refresh && sudo zypper update " if vendor == "suse" else "sudo dnf upgrade ") + name
        assert gap_body["combined_upgrade_command"] == command
        assert all(gap["upgrade_command"] == command and gap["target_version"] == fixed for gap in gap_body["gaps"])
        # A caller from a different tenant cannot retrieve these match rows.
        assert client.get(f"/api/endpoint/devices/{device_id}/cve-matches?tenant_id=other",
                          headers=auth_headers(client)).status_code in (403, 404)
        submit(client, snapshot_body(snapshot_id="rpm-snapshot-0002", software=[installed(name, fixed)], **DEVICES[vendor]))
        refresh(client, device_id)
        for key in keys:
            row = client.get(f"/api/vulnerabilities/{key}", headers=auth_headers(client)).json()
            assert row["state"] == "CLOSED" and row["closure_reason"] == "patched"
            assert row["machine_verified"] is True
        refresh(client, device_id)
        assert {r["vuln_id"] for r in software_findings_of(client)} == keys
    finally:
        client.close()
        advisories.reload_providers()
        software_findings.reset_cvss4_cache_for_tests()


def test_feed_recovery_does_not_close_recorded_unknown(tmp_path, monkeypatch):
    provider = imported(tmp_path)
    content = provider.path().read_bytes()
    monkeypatch.setenv(PROVIDERS["alas"].env_var, str(provider.path()))
    advisories.reload_providers()
    settings = make_settings(tmp_path)
    client = configured_client(tmp_path, monkeypatch, settings=settings)
    try:
        software = [installed("libExample", "1.0-1.amzn2023")]
        device_id = submit(client, snapshot_body(snapshot_id="rpm-unknown-0001", software=software, **DEVICES["alas"]))
        refresh(client, device_id)
        row, = software_findings_of(client)
        submit(client, snapshot_body(snapshot_id="rpm-unknown-0002", software=software, **DEVICES["alas"]))
        provider.path().unlink()
        from api.services import software_cve_match
        software_cve_match.run_for_device(settings, tenant_id="default", device_id=device_id)
        provider.path().write_bytes(content)
        stats = software_findings.ingest_device(settings, tenant_id="default", device_id=device_id, run_matcher=False)
        assert stats.closed == 0 and stats.errors == 0
        current = client.get(f"/api/vulnerabilities/{row['vuln_id']}", headers=auth_headers(client)).json()
        assert current["state"] == "OPEN" and not current["machine_verified"]
    finally:
        client.close()
        advisories.reload_providers()
