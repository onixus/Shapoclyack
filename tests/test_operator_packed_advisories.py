"""Merged packed-provider integration; no database, embedding or model calls."""
import json

import pytest

from api.services.advisories import base, fetch
from api.services.advisories.ubuntu import UbuntuAdvisoryProvider
from api.services.local_operator import remediation, semantic
from tests.test_operator_remediation import NOW, row, snapshot


def write_feed(path, *, fixed="7.68.0-1ubuntu2.10", source="ubuntu-usn", updated="2026-10-24"):
    path.write_text(json.dumps({"source": source, "updated": updated, "entries": [
        {"advisory_id": "USN-1", "cve_ids": ["CVE-2026-1234"], "release": "focal",
         "source_package": "curl", "fixed_version": fixed, "state": "resolved"},
        {"advisory_id": "USN-UNRELATED", "cve_ids": ["CVE-2026-9999"], "release": "jammy",
         "source_package": "unrelated-package", "fixed_version": "1.0-2", "state": "resolved"},
    ]}))


def response(provider, monkeypatch):
    monkeypatch.setattr(remediation.advisories, "get_provider", lambda _: provider)
    return remediation.build_cards([row(provider=provider.name)], snapshot(), device_id="device",
        snapshot_id="accepted", architecture="amd64", language="en", now=NOW)


def corpus(provider, monkeypatch):
    def current(*_, **__):
        return response(provider, monkeypatch)
    monkeypatch.setattr(remediation, "for_device", current)
    return semantic.device_corpus(None, None, "device")


def test_remediation_and_semantic_decode_only_the_requested_packed_bucket(tmp_path, monkeypatch):
    path = tmp_path / "vendor.json"
    write_feed(path)
    provider = UbuntuAdvisoryProvider(path)
    data = provider.dataset()
    assert len(data.records) == 2 and not isinstance(data.records, tuple)
    monkeypatch.setattr(type(data.records), "__iter__", lambda _: pytest.fail("Decoded the entire packed feed"))
    monkeypatch.setattr(fetch, "refresh", lambda *a, **kw: pytest.fail("Offline operator read invoked feed fetch"))
    decoded = []
    decode = base._PackedStore._decode
    def one_bucket(store, key):
        decoded.append(key)
        return decode(store, key)
    monkeypatch.setattr(base._PackedStore, "_decode", one_bucket)
    card = response(provider, monkeypatch)["items"][0]
    assert card["status"] == "fix_available" and card["target_version"] == "7.68.0-1ubuntu2.10"
    assert card["upgrade_command"] == "sudo apt-get update && sudo apt-get install --only-upgrade curl"
    current = corpus(provider, monkeypatch)
    assert current["state"] == "partial"
    assert {item["source_kind"] for item in current["items"]} == {"inventory", "advisory"}
    assert decoded == [("focal", "curl")]  # second read uses the bounded bucket cache
    assert "unrelated-package" not in str(current)


def test_packed_and_reference_records_produce_identical_bound_cards(tmp_path, monkeypatch):
    path = tmp_path / "vendor.json"
    write_feed(path)
    provider = UbuntuAdvisoryProvider(path)
    packed = provider.dataset()
    actual = response(provider, monkeypatch)
    records = tuple(base._coerce_record(raw, provider=provider.name, feed_date=packed.updated)
                    for raw in json.loads(path.read_text())["entries"])
    provider._dataset = base.AdvisoryDataset(source=packed.source, updated=packed.updated, records=records,
        index={(record.release, record.source_package): (record,) for record in records},
        present=True, releases=packed.releases, digest=packed.digest)
    assert response(provider, monkeypatch) == actual


def test_changed_packed_advisory_invalidates_semantic_corpus_and_old_fix(tmp_path, monkeypatch):
    path = tmp_path / "vendor.json"
    write_feed(path)
    provider = UbuntuAdvisoryProvider(path)
    before = corpus(provider, monkeypatch)
    write_feed(path, fixed="7.68.0-1ubuntu2.20")
    provider.reload()  # same explicit invalidation used after a feed import
    after = corpus(provider, monkeypatch)
    assert after["source_snapshot"] != before["source_snapshot"]
    assert after["corpus_hash"] != before["corpus_hash"]
    assert after["state"] == "unknown" and after["items"] == []
    card = response(provider, monkeypatch)["items"][0]
    assert card["status"] == "unknown" and card["target_version"] is None and card["upgrade_command"] is None


@pytest.mark.parametrize("mutation,expected", [
    ({"source": "bundled-seed"}, "unknown"),
    ({"updated": "2020-01-01"}, "stale"),
    ({"updated": None}, "unknown"),
])
def test_packed_seed_stale_unknown_feeds_do_not_gain_semantic_fix_claims(tmp_path, monkeypatch, mutation, expected):
    path = tmp_path / "vendor.json"
    write_feed(path, **mutation)
    provider = UbuntuAdvisoryProvider(path)
    card = response(provider, monkeypatch)["items"][0]
    assert card["status"] == expected and card["target_version"] is None
    current = corpus(provider, monkeypatch)
    assert current["state"] == expected and current["items"] == []


def test_invalid_streamed_document_is_unavailable_for_operator_consumers(tmp_path, monkeypatch):
    path = tmp_path / "vendor.json"
    path.write_bytes(b'{"source":"ubuntu-usn","entries":[')
    provider = UbuntuAdvisoryProvider(path)
    assert provider.dataset().error and not provider.available()
    card = response(provider, monkeypatch)["items"][0]
    assert card["status"] == "unknown" and "no_advisory_data" in card["limitations"]
    assert corpus(provider, monkeypatch)["items"] == []


def test_packed_provider_override_filter_is_not_bypassed_by_snapshot(tmp_path, monkeypatch):
    class FilteredProvider(UbuntuAdvisoryProvider):
        def advisories_for(self, **_):
            return ()
    path = tmp_path / "vendor.json"
    write_feed(path)
    provider = FilteredProvider(path)
    assert provider.available() and len(provider.dataset().records) == 2
    card = response(provider, monkeypatch)["items"][0]
    assert card["status"] == "unknown" and card["target_version"] is None
    assert corpus(provider, monkeypatch)["items"] == []
