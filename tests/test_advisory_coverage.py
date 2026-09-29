"""Missing advisory data is unassessed inventory, never a clean assessment (#358)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.services import software_cve_match as matcher
from api.services.advisories.base import AdvisoryProvider, JsonAdvisoryProvider
from api.services.advisories.coverage import coverage_reason, snapshot_provider

DEVICE = {
    "device_id": "coverage-device",
    "latest_snapshot_id": "coverage-snapshot",
    "os_family": "linux",
    "os_name": "Ubuntu",
    "os_version": "20.04",
}
FIXED = "1.1.1f-1ubuntu2.8"


class FixtureProvider(JsonAdvisoryProvider):
    name = "coverage-fixture"
    distro = "ubuntu"


def package(name="openssl", version="1.1.1f-1ubuntu2.16", source="dpkg"):
    return dict(name=name, version=version, source=source, architecture="amd64")


def entry(name="openssl", cve="CVE-2026-10001", release="focal", **changes):
    return dict(
        advisory_id="FIXTURE-1",
        cve_ids=[cve],
        release=release,
        source_package=name,
        fixed_version=FIXED,
        state="resolved",
        severity="high",
    ) | changes


def write_feed(path, entries=None, updated="2026-09-01"):
    path.write_text(
        json.dumps({
            "source": "synthetic-coverage-fixture",
            "updated": updated,
            "entries": [entry()] if entries is None else entries,
        }),
        encoding="utf-8",
    )


def run(provider, software=None, device=None):
    return matcher.match_software(
        device=DEVICE if device is None else device,
        software=[package()] if software is None else software,
        provider_for=lambda _: provider,
    )


def assert_unassessed(result, reason, count=1):
    assert result.packages_total == count
    assert result.packages_assessed == 0
    assert result.packages_unassessed == count
    assert result.counts() == dict(vulnerable=0, fixed=0, not_applicable=0, unknown=1)
    row, = result.candidates
    assert row.cve_id == ""
    assert row.status == "unknown"
    assert row.unknown_reason == reason
    assert row.fixed_version is None
    assert row.evidence["reason"] == reason
    assert row.evidence["package_count"] == count
    return row


@pytest.mark.parametrize("document", [
    None,
    b"{not-json",
    b"[]",
    b"{}",
    b'{"entries": []}',
    b'{"entries": {"not": "a list"}}',
    b'{"entries": [null, {}, "bad"]}',
    b'\xff\xfe',
    b"[" * 2000 + b"]" * 2000,
])
def test_missing_empty_or_invalid_feed_is_not_assessed(tmp_path, document):
    path = tmp_path / "advisories.json"
    if document is not None:
        path.write_bytes(document)
    row = assert_unassessed(run(FixtureProvider(path)), "no_advisory_data")
    assert row.provider == "coverage-fixture"
    assert str(tmp_path) not in repr(row.evidence)


def test_unreadable_feed_is_not_assessed(tmp_path, monkeypatch):
    path = tmp_path / "denied.json"
    write_feed(path)
    original = Path.read_text

    def denied(self, *args, **kwargs):
        if self == path:
            raise PermissionError("fixture read refused")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    assert_unassessed(run(FixtureProvider(path)), "no_advisory_data")


def test_no_registered_provider_is_not_assessed():
    row = assert_unassessed(run(None), "no_advisory_data")
    assert row.provider == ""
    assert row.feed_date is None


def test_a_loaded_feed_without_the_devices_release_is_unknown(tmp_path):
    path = tmp_path / "jammy-only.json"
    write_feed(path, [entry(release="jammy")])
    row = assert_unassessed(run(FixtureProvider(path)), "advisory_release_not_covered")
    assert row.distro == "ubuntu"
    assert row.distro_release == "focal"
    assert row.feed_date == "2026-09-01"


def test_no_entry_for_a_package_is_not_the_same_as_no_release(tmp_path):
    path = tmp_path / "focal.json"
    write_feed(path)
    result = run(FixtureProvider(path), [package(name="unlisted-package")])
    assert result.candidates == []
    assert result.packages_total == result.packages_assessed == 1
    assert result.packages_unassessed == 0


@pytest.mark.parametrize(("installed", "expected"), [
    ("1.1.1f-1ubuntu2.4", "vulnerable"),
    (FIXED, "fixed"),
    ("1.1.1f-1ubuntu2.16", "fixed"),
    ("1:1.1.1f-1ubuntu2.1", "fixed"),
])
def test_existing_backport_and_epoch_decisions_are_preserved(tmp_path, installed, expected):
    path = tmp_path / "feed.json"
    write_feed(path)
    result = run(FixtureProvider(path), [package(version=installed)])
    row, = result.candidates
    assert row.status == expected
    assert row.fixed_version == FIXED
    assert row.feed_date == "2026-09-01"
    assert row.provider == "coverage-fixture"
    assert row.unknown_reason is None
    assert result.packages_assessed == 1
    assert result.packages_unassessed == 0


@pytest.mark.parametrize(("state", "expected"), [
    ("open", "vulnerable"), ("not_affected", "not_applicable"),
])
def test_existing_vendor_states_are_preserved(tmp_path, state, expected):
    path = tmp_path / "feed.json"
    write_feed(path, [entry(state=state, fixed_version=None)])
    row, = run(FixtureProvider(path)).candidates
    assert row.status == expected
    assert row.fixed_version is None


def test_identity_errors_take_precedence_over_a_missing_feed(tmp_path):
    result = run(FixtureProvider(tmp_path / "missing.json"), [
        package(name="no-version", version=None),
        package(name="bad-version", version="1:"),
        package(name="python-library", source="pip"),
        package(),
    ])
    reasons = {row.unknown_reason: row for row in result.candidates}
    assert set(reasons) == {
        "no_version", "unparsable_version", "non_distro_source", "no_advisory_data",
    }
    assert all(row.evidence["package_count"] == 1 for row in reasons.values())
    assert result.packages_total == result.packages_unassessed == 4
    assert result.packages_assessed == 0


@pytest.mark.parametrize(("os_name", "os_version", "reason"), [
    ("Red Hat Enterprise Linux", "9", "unsupported_distro"),
    ("Rocky Linux", "9", "unsupported_distro"),
    ("AlmaLinux", "9", "unsupported_distro"),
    ("SUSE Linux Enterprise Server", "15", "unsupported_distro"),
    ("Amazon Linux", "2023", "unsupported_distro"),
    ("Unknown appliance", "1", "unknown_distro"),
    ("Ubuntu", "unrecognised", "unknown_release"),
])
def test_no_new_distribution_support_is_implied(os_name, os_version, reason):
    result = run(None, [package(source="rpm")], DEVICE | {
        "os_name": os_name, "os_version": os_version,
    })
    assert_unassessed(result, reason)


def test_missing_feed_rows_are_bounded_and_have_stable_identity():
    software = [package(name=f"pkg-{n:04}") for n in range(1000)]
    row = assert_unassessed(run(None, software), "no_advisory_data", count=1000)
    assert row.evidence["packages"] == [f"pkg-{n:04}" for n in range(25)]
    assert row.evidence["truncated"] is True
    again = run(None, list(reversed(software))).candidates[0]
    assert again.match_key == row.match_key
    assert again.evidence == row.evidence


def test_empty_inventory_does_not_invent_an_unassessed_package():
    result = run(None, [])
    assert result.candidates == []
    assert result.packages_total == result.packages_assessed == result.packages_unassessed == 0


def test_feed_recovery_replaces_unknown_on_the_next_pass(tmp_path):
    path = tmp_path / "feed.json"
    provider = FixtureProvider(path)
    assert_unassessed(run(provider), "no_advisory_data")
    write_feed(path)
    provider.reload()
    result = run(provider)
    assert result.packages_assessed == 1
    assert result.packages_unassessed == 0
    assert [c.status for c in result.candidates] == ["fixed"]


def test_reloading_a_feed_cannot_change_half_a_device_pass(tmp_path, monkeypatch):
    path = tmp_path / "feed.json"
    write_feed(path, [entry(), entry(name="curl", cve="CVE-2026-10002")])
    provider = FixtureProvider(path)
    original = matcher.evaluate_package
    seen = []

    def evaluate_then_remove(identity, selected):
        seen.append(identity.name)
        result = original(identity, selected)
        if len(seen) == 1:
            path.unlink()
            provider.reload()
        return result

    monkeypatch.setattr(matcher, "evaluate_package", evaluate_then_remove)
    software = [package(), package(name="curl")]
    result = run(provider, software)
    assert seen == ["openssl", "curl"]
    assert {c.cve_id for c in result.candidates} == {"CVE-2026-10001", "CVE-2026-10002"}
    assert {c.status for c in result.candidates} == {"fixed"}
    assert {c.feed_date for c in result.candidates} == {"2026-09-01"}
    assert result.packages_assessed == 2
    assert_unassessed(run(provider, software), "no_advisory_data", count=2)


def test_json_provider_is_statted_once_not_per_package(tmp_path, monkeypatch):
    path = tmp_path / "feed.json"
    write_feed(path)
    provider = FixtureProvider(path)
    original = provider._stat_key
    calls = []

    def stat_once(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(provider, "_stat_key", stat_once)
    result = run(provider, [package(name=f"package-{n}") for n in range(2000)])
    assert result.packages_assessed == 2000
    assert calls == [path]


def test_snapshot_keeps_the_protocol_and_reuses_the_index(tmp_path):
    path = tmp_path / "feed.json"
    write_feed(path)
    provider = FixtureProvider(path)
    view = snapshot_provider(provider)
    assert isinstance(view, AdvisoryProvider)
    assert view.data is provider.dataset()
    assert view.entry_count() == 1
    assert view.source_label() == "synthetic-coverage-fixture"
    assert view.advisories_for(release=" FOCAL ", source_package=" OpenSSL ")
    assert coverage_reason(view, release="focal") is None
    provider.reload()
    path.unlink()
    assert view.available()
    assert coverage_reason(snapshot_provider(provider), release="focal") == "no_advisory_data"


def test_programming_errors_are_not_swallowed(tmp_path, monkeypatch):
    def broken():
        raise RuntimeError("implementation defect")

    provider = FixtureProvider(tmp_path / "feed.json")
    monkeypatch.setattr(provider, "dataset", broken)
    with pytest.raises(RuntimeError, match="implementation defect"):
        run(provider)


def test_unknown_provenance_survives_the_existing_storage_and_read_contract(tmp_path):
    path = tmp_path / "feed.json"
    write_feed(path, [entry(release="jammy")])
    result = run(FixtureProvider(path))
    stamp = datetime(2026, 9, 29, tzinfo=UTC)
    payload, = matcher._match_payloads(
        tenant_id="tenant-a", device_id=DEVICE["device_id"], result=result, matched_at=stamp,
    )
    assert payload["tenant_id"] == "tenant-a"
    assert payload["device_id"] == DEVICE["device_id"]
    assert payload["snapshot_id"] == DEVICE["latest_snapshot_id"]
    row = matcher._row_to_dict(SimpleNamespace(**payload))
    assert row["status"] == "unknown"
    assert row["unknown_reason"] == "advisory_release_not_covered"
    assert row["provider"] == "coverage-fixture"
    assert row["feed_date"] == "2026-09-01"
    assert row["evidence"]["package_count"] == 1
    assert row["cve_id"] == ""
    assert row["vuln_id"] is None


def test_windows_dispatch_does_not_consult_the_linux_provider(monkeypatch):
    expected = object()
    monkeypatch.setattr(matcher, "_match_windows", lambda **kwargs: expected)

    def forbidden(_):
        raise AssertionError("Windows must not consult a Linux provider")

    assert matcher.match_software(
        device=DEVICE | {"os_family": " Windows "}, software=[package(source="winreg")],
        provider_for=forbidden,
    ) is expected
