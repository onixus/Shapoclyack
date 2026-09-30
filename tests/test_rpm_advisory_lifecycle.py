"""RPM partial feeds cannot prove remediation by absence."""
from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from api.services import software_findings as findings, vuln_states


def fold(monkeypatch, matches, *, os_name="Amazon Linux", os_version="2023"):
    before = datetime(2026, 9, 1)
    key = findings.software_finding_key(asset_id="asset", device_id="device", cve="CVE-2026-10001")
    row = SimpleNamespace(
        vuln_id="v1", finding_key=key, state=vuln_states.OPEN, last_seen_at=before,
        machine_verified=False, due_at=before + timedelta(days=30), assignee="owner",
        exception_until=before + timedelta(days=90), exception_by="owner", exception_reason="accepted",
    )
    original = vars(row).copy()
    events = []
    monkeypatch.setattr(findings.vulns_service, "_record_event", lambda *a, **kw: events.append(kw))
    session = SimpleNamespace(scalars=lambda _: SimpleNamespace(all=lambda: [row]))
    context = findings._DeviceContext(
        device=SimpleNamespace(device_id="device", latest_snapshot_id="snap-2", hostname="host",
                               os_family="linux", os_name=os_name, os_version=os_version),
        asset=SimpleNamespace(asset_id="asset"), observed_at=before + timedelta(days=1),
        assessment_possible=True, matches=matches,
    )
    stats = findings._fold_device(session, tenant_id="tenant", context=context, min_severity="", now=before + timedelta(days=2))
    return stats, row, original, events


def fixed(**overrides):
    return SimpleNamespace(**(dict(status="fixed", cve_id="CVE-2026-10001", snapshot_id="snap-2",
                                  evidence={"assessment_scope": "installed_binary_rpm"}) | overrides))


@pytest.mark.parametrize("rows", [
    [], [fixed(snapshot_id="snap-1")], [fixed(evidence={})],
    [SimpleNamespace(status="unknown", cve_id="", unknown_reason="rpm_package_not_covered")],
    [fixed(), SimpleNamespace(status="unknown", cve_id="", unknown_reason="rpm_module_context_required")],
    [fixed(), SimpleNamespace(status="unknown", cve_id="", unknown_reason="unparsable_version")],
])
def test_no_positive_complete_current_rpm_assessment_means_no_closure(monkeypatch, rows):
    stats, row, original, events = fold(monkeypatch, rows)
    assert stats.closed == 0 and stats.held_open_stale_snapshot == 1
    assert vars(row) == original
    assert events == []


@pytest.mark.parametrize("os_name,os_version", [
    ("Amazon Linux", "2023"), ("Red Hat Enterprise Linux", "9.2"), ("SLES", "12.5"),
])
def test_a_confirmed_rpm_upgrade_closes_once(monkeypatch, os_name, os_version):
    stats, row, _, events = fold(monkeypatch, [fixed()], os_name=os_name, os_version=os_version)
    assert stats.closed == 1 and row.state == vuln_states.CLOSED and row.machine_verified
    assert events[0]["detail"]["snapshot_id"] == "snap-2"


def test_non_distribution_inventory_does_not_block_an_assessed_rpm(monkeypatch):
    rows = [fixed(), SimpleNamespace(status="unknown", cve_id="", unknown_reason="non_distro_source")]
    assert fold(monkeypatch, rows)[0].closed == 1
