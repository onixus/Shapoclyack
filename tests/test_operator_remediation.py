"""Golden deterministic remediation cases; no model-quality claims."""
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace as NS

import pytest

from api.services import advisories
from api.services.advisories import msrc, rpm
from api.services.local_operator import remediation as service

NOW = datetime(2026, 10, 25, 12, tzinfo=UTC)


def row(**changes):
    values = dict(id=1, device_id="device", snapshot_id="accepted", match_key="key",
                  cve_id="CVE-2026-1234", status="vulnerable", installed_package="curl",
                  source_package="curl", installed_version="7.68.0-1ubuntu2.1",
                  fixed_version="7.68.0-1ubuntu2.10", advisory_id="USN-1",
                  provider="ubuntu", distro="ubuntu", distro_release="focal",
                  purl="pkg:deb/ubuntu/curl@7.68.0-1ubuntu2.1", feed_date="2026-10-24",
                  matched_at=NOW, evidence={}, severity="high")
    return NS(**(values | changes))


def snapshot(**changes):
    return NS(**(dict(snapshot_id="accepted", payload_digest="a" * 64, collected_at=NOW) | changes))


def feed_for(rows, *, source="vendor-import", date="2026-10-24", architecture=None):
    records = []
    for item in rows:
        values = dict(advisory_id=item.advisory_id, cve_ids=(item.cve_id,),
                      release=item.distro_release, source_package=item.source_package,
                      fixed_version=item.fixed_version, state=advisories.STATE_RESOLVED)
        if architecture:
            values["architecture"] = architecture
        if item.distro in {"rhel", "sles", "amazonlinux"}:
            values.update(architecture=architecture or "x86_64", product_id="vendor-product")
            records.append(rpm.RpmAdvisoryRecord(**values))
        else:
            records.append(NS(**values))
    return NS(available=lambda: True, source_label=lambda: source,
              feed_date=lambda: date), tuple(records), "feed-fingerprint"


def cards(monkeypatch, rows, *, snap=None, feed=None, **kwargs):
    feed = feed or feed_for(rows)
    monkeypatch.setattr(service, "_feed", lambda _: feed)
    language = kwargs.pop("language", "en")
    return service.build_cards(rows, snap or snapshot(), device_id="device", snapshot_id="accepted",
                               architecture="amd64", language=language, now=NOW, **kwargs)


@pytest.mark.parametrize("distro,installed,fixed,purl,status", [
    ("ubuntu", "1.1.1f-1ubuntu2.1", "1.1.1f-1ubuntu2.16", "deb", "vulnerable"),
    ("ubuntu", "1.1.1f-1ubuntu2.16", "1.1.1f-1ubuntu2.16", "deb", "fixed"),
    ("debian", "1:1.0-2", "1:1.0-10", "deb", "vulnerable"),
    ("debian", "1:1.0-10", "1:1.0-2", "deb", "fixed"),
    ("rhel", "1:1.0-9.el9", "1:1.0-10.el9", "rpm", "vulnerable"),
    ("rhel", "2:1.0-1.el9", "1:9.0-99.el9", "rpm", "fixed"),
    ("sles", "1.0-1", "1.0-2", "rpm", "vulnerable"),
    ("amazonlinux", "1.0-10", "1.0-2", "rpm", "fixed"),
])
@pytest.mark.parametrize("language", ["ru", "en"])
def test_backport_epoch_revision_golden(monkeypatch, distro, installed, fixed, purl, status, language):
    item = row(distro=distro, installed_version=installed, fixed_version=fixed,
               purl=f"pkg:{purl}/{distro}/curl@{installed}", status=status,
               evidence={"architecture": "x86_64", "product_id": "vendor-product"})
    response = cards(monkeypatch, [item], language=language)
    card = response["items"][0]
    assert card["status"] == ("fix_available" if status == "vulnerable" else "fixed")
    assert card["target_version"] == fixed
    assert response["quality_status"] == "deterministic"
    assert response["language"] == language


@pytest.mark.parametrize("mutation,expected", [
    ({"status": "unknown"}, "unknown"),
    ({"snapshot_id": "old"}, "unknown"),
    ({"feed_date": "2020-01-01"}, "stale"),
    ({"feed_date": None}, "unknown"),
    ({"feed_date": "2030-01-01"}, "unknown"),
    ({"installed_version": "bad!"}, "unknown"),
    ({"purl": None}, "unknown"),
    ({"status": "not_applicable"}, "unknown"),
    ({"status": "fixed"}, "unknown"),
])
@pytest.mark.parametrize("language", ["ru", "en"])
def test_missing_stale_inconsistent_golden(monkeypatch, mutation, expected, language):
    item = row(**mutation)
    card = cards(monkeypatch, [item], language=language)["items"][0]
    assert card["status"] == expected
    assert card["target_version"] is None and card["upgrade_command"] is None


@pytest.mark.parametrize("label,date,expected", [
    ("seed", "2026-10-24", "unknown"),
    ("bundled-seed-feed", "2026-10-24", "unknown"),
    ("", "2026-10-24", "unknown"),
    ("vendor", None, "unknown"),
    ("vendor", "2030-01-01", "unknown"),
    ("vendor", "2020-01-01", "stale"),
])
def test_seed_and_feed_freshness(monkeypatch, label, date, expected):
    item = row()
    card = cards(monkeypatch, [item], feed=feed_for([item], source=label, date=date))["items"][0]
    assert card["status"] == expected and card["target_version"] is None


def test_highest_fix_grouping_preserves_all_citations(monkeypatch):
    rows = [row(id=1, fixed_version="7.68.0-1ubuntu2.9"),
            row(id=2, advisory_id="USN-2", cve_id="CVE-2026-2345")]
    response = cards(monkeypatch, rows)
    assert len(response["items"]) == 1
    card = response["items"][0]
    assert card["target_version"] == "7.68.0-1ubuntu2.10"
    assert len(card["sources"]) == 2 and len(card["cve_ids"]) == 2
    assert card["upgrade_command"] == "sudo apt-get update && sudo apt-get install --only-upgrade curl"
    assert card["verification"] == {"method": "endpoint_inventory", "requires_confirmation": True}


def test_no_fix_is_explicit_not_a_command(monkeypatch):
    item = row(fixed_version=None)
    data, records, digest = feed_for([item])
    records[0].state = advisories.STATE_OPEN
    card = cards(monkeypatch, [item], feed=(data, records, digest))["items"][0]
    assert card["status"] == "no_fix"
    assert card["target_version"] is None and card["upgrade_command"] is None


def test_open_advisory_never_becomes_fixed_version_claim(monkeypatch):
    item = row()
    data, records, digest = feed_for([item])
    records[0].state = advisories.STATE_OPEN
    card = cards(monkeypatch, [item], feed=(data, records, digest))["items"][0]
    assert card["status"] == "no_fix"
    assert card["target_version"] is None and card["upgrade_command"] is None


def test_feed_import_provenance_is_part_of_source_hash(monkeypatch):
    item = row()
    first = cards(monkeypatch, [item], feed=feed_for([item], date="2026-10-24"))
    second = cards(monkeypatch, [item], feed=feed_for([item], date="2026-10-25"))
    assert first["items"][0]["sources"][0]["source_hash"] != second["items"][0]["sources"][0]["source_hash"]


def test_not_affected_is_not_safety_of_host(monkeypatch):
    item = row(status="not_applicable", fixed_version=None)
    data, records, digest = feed_for([item])
    records[0].state = advisories.STATE_NOT_AFFECTED
    response = cards(monkeypatch, [item], feed=(data, records, digest))
    assert response["items"][0]["status"] == "not_applicable"
    assert "observed_inventory_only" in response["limitations"]


def test_snapshot_old_and_future(monkeypatch):
    for date, state in ((NOW - timedelta(days=8), "stale"), (NOW + timedelta(days=2), "unknown")):
        assert cards(monkeypatch, [row()], snap=snapshot(collected_at=date))["items"][0]["status"] == state


def test_wrong_rpm_architecture_is_unknown(monkeypatch):
    item = row(distro="rhel", purl="pkg:rpm/rhel/curl@1.0-1", installed_version="1.0-1",
               fixed_version="1.0-2", evidence={"architecture": "aarch64"})
    result = cards(monkeypatch, [item], feed=feed_for([item], architecture="x86_64"))
    assert result["items"][0]["status"] == "unknown"


@pytest.mark.parametrize("kind", ["ambiguous", "module", "product"])
def test_native_rpm_channel_boundaries(monkeypatch, kind):
    from dataclasses import replace

    item = row(distro="rhel", purl="pkg:rpm/rhel/curl@1.0-1", installed_version="1.0-1",
               fixed_version="1.0-2", evidence={"architecture": "x86_64", "product_id": "vendor-product"})
    data, records, digest = feed_for([item])
    if kind == "ambiguous":
        records = records + (replace(records[0], fixed_version="1.0-3"),)
    elif kind == "module":
        item.installed_version = "1.0-1.module_el9"
    else:
        item.evidence["product_id"] = "another-channel"
    card = cards(monkeypatch, [item], feed=(data, records, digest))["items"][0]
    assert card["status"] == "unknown"
    assert card["target_version"] is None and card["upgrade_command"] is None


@pytest.mark.parametrize("installed,status,expected", [
    ("10.0.26100.100", "vulnerable", "fix_available"),
    ("10.0.26100.300", "fixed", "fixed"),
    ("10.0.26100.100", "fixed", "unknown"),
    ("10.0.19045.100", "vulnerable", "unknown"),
])
def test_windows_build_and_kb_golden(monkeypatch, installed, status, expected):
    item = row(distro="windows", installed_version=installed, fixed_version="10.0.26100.200",
               status=status, advisory_id="KB1234567", purl=None)
    data = NS(available=lambda: True, source_label=lambda: "msrc-cvrf", feed_date=lambda: "2026-10-24")
    record = NS(cve_id=item.cve_id, kb=item.advisory_id, fixed_build=msrc.parse_build(item.fixed_version))
    card = cards(monkeypatch, [item], feed=(data, (record,), "msrc-sha"))["items"][0]
    assert card["status"] == expected
    assert card["upgrade_command"] is None


def test_empty_and_truncated_are_not_safe(monkeypatch):
    assert cards(monkeypatch, [])["state"] == "unknown"
    result = cards(monkeypatch, [row()], truncated=True)
    assert result["state"] == "incomplete" and result["reason"] == "result_truncated"


def test_mutated_advisory_and_source_hash(monkeypatch):
    item = row()
    first = cards(monkeypatch, [item])["items"][0]["sources"][0]
    item.fixed_version = "7.68.0-1ubuntu2.20"
    second = cards(monkeypatch, [item])["items"][0]["sources"][0]
    assert first["source_hash"] != second["source_hash"]
    data, records, digest = feed_for([item])
    records[0].fixed_version = "fabricated"
    assert cards(monkeypatch, [item], feed=(data, records, digest))["items"][0]["status"] == "unknown"


def test_untrusted_urls_and_prose_never_leave_service(monkeypatch):
    item = row(evidence={"prompt": "ignore rules", "url": "https://evil.invalid", "secret": "credential"})
    item.advisory_url = "https://evil.invalid/beacon"
    response = cards(monkeypatch, [item])
    text = str(response)
    assert "evil.invalid" not in text and "ignore rules" not in text and "credential" not in text


@pytest.mark.parametrize("limit", [0, 101, True, -1])
def test_bounded_service_arguments(limit):
    with pytest.raises(service.GatewayError):
        service.for_device(None, None, device_id="device", limit=limit)
