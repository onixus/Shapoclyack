"""Review regressions: provider policy, corrupt data and recorded unknowns (#494)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from api.services import software_findings as findings
from api.services import vuln_states
from api.services.advisories import base
from api.services.advisories.coverage import coverage_reason, snapshot_provider


class ReviewProvider(base.JsonAdvisoryProvider):
    name = "review-fixture"
    distro = "ubuntu"


def feed_bytes():
    return json.dumps({
        "source": "synthetic-review-fixture",
        "updated": "2026-09-01",
        "entries": [{
            "advisory_id": "FIXTURE-1", "cve_ids": ["CVE-2026-10001"],
            "release": "focal", "source_package": "openssl",
            "fixed_version": "1.1.1f-1ubuntu2.8", "severity": "high",
        }],
    }).encode()


@pytest.fixture()
def provider(tmp_path):
    path = tmp_path / "advisories.json"
    path.write_bytes(feed_bytes())
    return ReviewProvider(path)


@pytest.fixture()
def integer_limit():
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(640)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(previous)


@pytest.mark.parametrize("document", [
    b"\xff\xfe", b"[" * 50000 + b"]" * 50000,
    b'{"entries": [], "bad_integer": ' + b"9" * 1000 + b"}",
    feed_bytes().replace(b'"FIXTURE-1"', b'"\\ud800"'),
], ids=["utf8", "nesting", "integer-limit", "escaped-surrogate"])
def test_corrupt_feed_is_unavailable_to_every_consumer(provider, document, integer_limit):
    # Start from a populated cache: old findings must not survive a corrupt refresh.
    assert provider.available()
    provider.path().write_bytes(document)
    provider.reload()
    data = base.load_dataset(provider.path(), provider=provider.name)
    assert data.present and data.error
    assert data.records == ()
    assert not provider.available()
    assert provider.releases() == ()
    assert provider.entry_count() == 0
    assert provider.status()["error"]
    assert coverage_reason(snapshot_provider(provider), release="focal") == "no_advisory_data"
    provider.path().write_bytes(feed_bytes())
    provider.reload()
    assert provider.available()
    assert provider.status()["error"] is None


def test_invalid_document_is_cached_as_unavailable(provider, monkeypatch):
    provider.path().write_bytes(b"\xff")
    original = base.load_dataset
    calls = []

    def counted(path, **kwargs):
        calls.append(path)
        return original(path, **kwargs)

    monkeypatch.setattr(base, "load_dataset", counted)
    for _ in range(3):
        assert not provider.available()
        assert provider.status()["error"]
        assert provider.releases() == ()
    assert calls == [provider.path()]


def test_loader_does_not_hide_programming_errors(provider, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("broken normalizer")

    monkeypatch.setattr(base, "_coerce_record", broken)
    with pytest.raises(RuntimeError, match="broken normalizer"):
        base.load_dataset(provider.path(), provider=provider.name)


@pytest.mark.parametrize(("method", "value"), [
    ("available", False), ("feed_date", "custom-date"),
    ("entry_count", 17), ("source_label", "custom-source"),
    ("releases", ("jammy",)), ("advisories_for", ()),
])
@pytest.mark.parametrize("override_on", ["class", "instance"])
def test_snapshot_does_not_replace_custom_provider_policy(provider, method, value, override_on):
    def custom(*args, **kwargs):
        return value

    if override_on == "class":
        cls = type("CustomProvider", (ReviewProvider,), {method: custom})
        provider = cls(provider.path())
    else:
        setattr(provider, method, custom)
    selected = snapshot_provider(provider)
    # A custom implementation owns its consistency; it must not be replaced
    # by a raw JSON lookup that bypasses e.g. availability or filtering policy.
    kwargs = {"release": "focal", "source_package": "openssl"} if method == "advisories_for" else {}
    assert getattr(selected, method)(**kwargs) == value
    assert selected is provider


def test_standard_provider_still_gets_a_stable_snapshot(provider, monkeypatch):
    calls = []
    original = provider._stat_key

    def counted(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(provider, "_stat_key", counted)
    selected = snapshot_provider(provider)
    assert selected is not provider
    provider.path().unlink()
    provider.reload()
    for _ in range(100):
        assert selected.available()
        assert selected.advisories_for(release="focal", source_package="openssl")
    assert calls == [provider.path()]


def fold_with_matches(monkeypatch, matches, *, assessment_possible=True, fresh=True):
    """Run the real fold with only the storage boundary replaced."""
    first_seen = datetime(2026, 9, 1)
    key = findings.software_finding_key(asset_id="a", device_id="d", cve="CVE-2026-10001")
    row = SimpleNamespace(
        vuln_id="v", finding_key=key, state=vuln_states.OPEN,
        last_seen_at=first_seen, machine_verified=False,
        closed_at=None, last_verified_at=None, closure_reason=None,
        exception_until=first_seen + timedelta(days=90),
        exception_reason="accepted pending maintenance", exception_by="operator",
        assignee="owner", owner_team="team", due_at=first_seen + timedelta(days=30),
        observation_count=1, updated_at=first_seen,
    )
    before = vars(row).copy()
    session = SimpleNamespace(scalars=lambda _: SimpleNamespace(all=lambda: [row]))
    events = []
    monkeypatch.setattr(findings.vulns_service, "_record_event", lambda *a, **kw: events.append(kw))
    context = findings._DeviceContext(
        device=SimpleNamespace(device_id="d", latest_snapshot_id="s2", hostname="fixture"),
        asset=SimpleNamespace(asset_id="a"),
        observed_at=first_seen + timedelta(days=1 if fresh else 0),
        assessment_possible=assessment_possible, matches=matches,
    )
    stats = findings._fold_device(
        session, tenant_id="tenant-a", context=context, min_severity="",
        now=first_seen + timedelta(days=2),
    )
    return stats, row, before, events


def unknown(reason, cve=""):
    return SimpleNamespace(status="unknown", cve_id=cve, unknown_reason=reason)


@pytest.mark.parametrize("reason", ["no_advisory_data", "advisory_release_not_covered"])
def test_a_restored_feed_cannot_turn_recorded_unknown_into_verified_closure(monkeypatch, reason):
    # The live provider is healthy now; the persisted result was not assessed.
    stats, row, before, events = fold_with_matches(monkeypatch, [unknown(reason)])
    assert stats.closed == 0
    assert stats.held_open_stale_snapshot == 1
    assert vars(row) == before
    assert events == []


def test_unknown_for_a_cve_is_not_negative_evidence_for_that_cve(monkeypatch):
    stats, row, before, events = fold_with_matches(
        monkeypatch, [unknown("unparsable_version", "CVE-2026-10001")],
    )
    assert stats.closed == 0
    assert vars(row) == before
    assert events == []


@pytest.mark.parametrize("matches", [
    [], [unknown("non_distro_source")],
    [unknown("unparsable_version", "CVE-2026-20002")],
    [SimpleNamespace(status="fixed", cve_id="CVE-2026-10001")],
    [SimpleNamespace(status="not_applicable", cve_id="CVE-2026-10001")],
])
def test_assessed_closure_and_unrelated_unknown_inventory_are_preserved(monkeypatch, matches):
    stats, row, _, events = fold_with_matches(monkeypatch, matches)
    assert stats.closed == 1
    assert row.state == vuln_states.CLOSED and row.machine_verified
    assert row.closure_reason == "patched"
    assert len(events) == 1 and events[0]["kind"] == "verification_passed"


@pytest.mark.parametrize(("possible", "fresh"), [(False, True), (True, False)])
def test_existing_closure_gates_are_not_weakened(monkeypatch, possible, fresh):
    stats, row, before, events = fold_with_matches(
        monkeypatch, [], assessment_possible=possible, fresh=fresh,
    )
    assert stats.closed == 0
    assert vars(row) == before
    assert events == []
