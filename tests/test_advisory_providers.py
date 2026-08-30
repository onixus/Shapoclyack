"""Vendor-advisory providers: dataset loading, normalization, opt-in fetching."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from api.services import advisories
from api.services.advisories import base, debian, fetch, ubuntu

FIXTURES = Path(__file__).parent / "fixtures" / "advisories"
SEEDS = Path("scanner/data/advisories")


def _ubuntu() -> ubuntu.UbuntuAdvisoryProvider:
    return ubuntu.UbuntuAdvisoryProvider(FIXTURES / "ubuntu-test.json")


def _debian() -> debian.DebianAdvisoryProvider:
    return debian.DebianAdvisoryProvider(FIXTURES / "debian-test.json")


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------


def test_ubuntu_provider_loads_the_fixture() -> None:
    provider = _ubuntu()
    assert provider.available() is True
    assert provider.distro == "ubuntu"
    assert provider.feed_date() == "2026-08-01"
    assert provider.source_label() == "ubuntu-usn-fixture"
    assert set(provider.releases()) == {"focal", "jammy"}


def test_debian_provider_loads_the_fixture() -> None:
    provider = _debian()
    assert provider.available() is True
    assert provider.distro == "debian"
    assert provider.feed_date() == "2026-08-02"
    assert provider.releases() == ("bullseye",)


def test_lookup_is_scoped_to_a_release() -> None:
    provider = _ubuntu()
    focal = provider.advisories_for(release="focal", source_package="openssl")
    jammy = provider.advisories_for(release="jammy", source_package="openssl")
    assert [r.fixed_version for r in focal] == ["1.1.1f-1ubuntu2.8"]
    assert [r.fixed_version for r in jammy] == ["3.0.2-0ubuntu1.1"]
    # A release the dataset has nothing for answers nothing, not the wrong thing.
    assert provider.advisories_for(release="noble", source_package="openssl") == ()


def test_lookup_normalises_case_and_whitespace() -> None:
    provider = _ubuntu()
    assert provider.advisories_for(release=" FOCAL ", source_package=" OpenSSL ")


def test_unusable_entries_are_dropped_not_fatal() -> None:
    """A single malformed record in a third-party feed must not take the whole
    dataset — and therefore every match on the installation — offline."""
    provider = _ubuntu()
    packages = {record.source_package for record in provider.dataset().records}
    assert "dropped-because-no-cve" not in packages
    assert "dropped-because-no-release" not in packages
    assert "openssl" in packages


def test_resolved_without_a_fixed_version_is_read_as_open() -> None:
    """"Fixed, but we will not say in what" cannot be compared against an
    installed version, so the honest reading is that the release is open."""
    record = _debian().advisories_for(release="bullseye", source_package="coerced-to-open")[0]
    assert record.state == base.STATE_OPEN
    assert record.fixed_version is None


def test_not_affected_carries_no_fixed_version() -> None:
    record = _debian().advisories_for(release="bullseye", source_package="curl")[0]
    assert record.state == base.STATE_NOT_AFFECTED
    assert record.fixed_version is None


def test_missing_dataset_is_unavailable_rather_than_empty(tmp_path: Path) -> None:
    """The distinction matters: "no data loaded" must not be reported to the
    matcher as "the vendor knows of no advisories", which reads as clean."""
    provider = ubuntu.UbuntuAdvisoryProvider(tmp_path / "absent.json")
    assert provider.available() is False
    assert provider.entry_count() == 0
    assert provider.status()["error"] == "missing"


def test_malformed_dataset_degrades_softly(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    provider = ubuntu.UbuntuAdvisoryProvider(path)
    assert provider.available() is False
    assert "invalid JSON" in (provider.status()["error"] or "")


def test_dataset_reloads_when_the_file_changes(tmp_path: Path) -> None:
    path = tmp_path / "ds.json"
    payload = {
        "version": 1,
        "source": "t",
        "updated": "2026-01-01",
        "entries": [
            {
                "advisory_id": "USN-1",
                "cve_ids": ["CVE-2020-1111"],
                "release": "focal",
                "source_package": "curl",
                "fixed_version": "1.0",
                "state": "resolved",
            }
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    provider = ubuntu.UbuntuAdvisoryProvider(path)
    assert provider.entry_count() == 1
    payload["entries"].append(dict(payload["entries"][0], advisory_id="USN-2"))
    payload["entries"][1]["cve_ids"] = ["CVE-2020-2222"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    provider.reload()
    assert provider.entry_count() == 2


def test_env_override_selects_the_dataset(monkeypatch) -> None:
    monkeypatch.setenv("OCTO_UBUNTU_ADVISORY_DATABASE", str(FIXTURES / "ubuntu-test.json"))
    provider = ubuntu.UbuntuAdvisoryProvider()
    assert provider.path() == FIXTURES / "ubuntu-test.json"
    assert provider.available() is True


def test_providers_satisfy_the_protocol() -> None:
    for provider in (_ubuntu(), _debian()):
        assert isinstance(provider, base.AdvisoryProvider)


# --------------------------------------------------------------------------
# The committed seeds
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "provider_cls", "distro"),
    [
        (SEEDS / "ubuntu-advisories.json", ubuntu.UbuntuAdvisoryProvider, "ubuntu"),
        (SEEDS / "debian-advisories.json", debian.DebianAdvisoryProvider, "debian"),
    ],
)
def test_committed_seed_datasets_are_loadable(path, provider_cls, distro) -> None:
    """The image ships a seed so an offline installation matches *something*
    and GET /api/system reports a dataset rather than a hole."""
    provider = provider_cls(path)
    assert provider.available() is True
    assert provider.entry_count() > 0
    assert provider.distro == distro
    # Small on purpose: this is a seed, not a feed dump (see the roadmap note
    # about not committing a large dump).
    assert provider.entry_count() < 500


def test_registry_covers_debian_and_ubuntu() -> None:
    assert set(advisories.providers()) == {"debian", "ubuntu"}
    assert advisories.get_provider("Ubuntu") is advisories.get_provider("ubuntu")
    assert advisories.get_provider("rocky") is None
    assert advisories.get_provider(None) is None


def test_registry_status_is_reportable() -> None:
    entries = advisories.status()
    assert {entry["distro"] for entry in entries} == {"debian", "ubuntu"}
    for entry in entries:
        assert set(entry) >= {"name", "path", "present", "entries", "releases"}


# --------------------------------------------------------------------------
# Normalization of the vendors' own shapes
# --------------------------------------------------------------------------


def test_normalize_debian_tracker_json() -> None:
    payload = {
        "openssl": {
            "CVE-2023-0286": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "fixed_version": "1.1.1n-0+deb11u4",
                        "urgency": "high",
                    },
                    "buster": {"status": "open", "urgency": "not yet assigned"},
                    # The tracker's sentinel for "this release was never
                    # affected" — not a version anything can be compared against.
                    "bookworm": {"status": "resolved", "fixed_version": "0"},
                    "stretch": {"status": "not-affected", "urgency": "unimportant"},
                    "sid": {"status": "undetermined"},
                }
            }
        }
    }
    entries = {(e["release"], e["state"]): e for e in debian.normalize_tracker_json(payload)}
    assert entries[("bullseye", "resolved")]["fixed_version"] == "1.1.1n-0+deb11u4"
    assert entries[("bullseye", "resolved")]["severity"] == "high"
    assert entries[("buster", "open")]["fixed_version"] is None
    assert entries[("buster", "open")]["severity"] == "unknown"
    assert entries[("stretch", "not_affected")]["severity"] == "negligible"
    # "undetermined" and the "0" sentinel are dropped: neither is a statement
    # anyone can act on, and inventing one would be a false positive.
    assert ("sid", "open") not in entries
    assert not any(release == "bookworm" for release, _ in entries)


def test_normalize_usn_json_emits_source_and_binary_packages() -> None:
    payload = {
        "USN-5051-2": {
            "cves": ["CVE-2021-3711", "not-a-cve"],
            "severity": "High",
            "releases": {
                "focal": {
                    "sources": {"openssl": {"version": "1.1.1f-1ubuntu2.8"}},
                    "binaries": {"libssl1.1": {"version": "1.1.1f-1ubuntu2.8"}},
                }
            },
        },
        "USN-NO-CVE-1": {"cves": [], "releases": {"focal": {"sources": {"x": {"version": "1"}}}}},
    }
    entries = list(ubuntu.normalize_usn_json(payload))
    packages = {entry["source_package"] for entry in entries}
    # Both names are emitted so an inventory that reports the binary package —
    # which is what dpkg reports — still hits the USN.
    assert packages == {"openssl", "libssl1.1"}
    assert all(entry["cve_ids"] == ["CVE-2021-3711"] for entry in entries)
    assert all(entry["severity"] == "high" for entry in entries)


# --------------------------------------------------------------------------
# Fetching — opt-in, bounded, off by default
# --------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self._buffer = payload

    def read(self, size: int) -> bytes:
        chunk, self._buffer = self._buffer[:size], self._buffer[size:]
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


def test_fetch_is_off_by_default(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OCTO_ADVISORY_FETCH_ENABLED", raising=False)
    assert fetch.fetch_enabled() is False
    with pytest.raises(fetch.FetchDisabledError):
        fetch.refresh("ubuntu", path=tmp_path / "out.json")


def test_fetch_refuses_an_unknown_dataset(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    with pytest.raises(ValueError):
        fetch.refresh("gentoo", path=tmp_path / "out.json")


def test_fetch_enforces_the_byte_ceiling_while_streaming() -> None:
    body = b"x" * 4096

    def opener(request, timeout):  # noqa: ARG001 - signature parity with urlopen
        return _FakeResponse(body)

    with pytest.raises(fetch.FetchTooLargeError):
        fetch.fetch_json("https://example.test/f.json", max_bytes=1024, opener=opener)


def test_fetch_writes_a_loadable_dataset(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    payload = json.dumps(
        {
            "USN-6408-1": {
                "cves": ["CVE-2023-38545"],
                "severity": "high",
                "releases": {"focal": {"sources": {"curl": {"version": "7.68.0-1ubuntu2.20"}}}},
            }
        }
    ).encode("utf-8")

    def opener(request, timeout):  # noqa: ARG001 - signature parity with urlopen
        return _FakeResponse(payload)

    out = tmp_path / "ubuntu.json"
    written = fetch.refresh("ubuntu", path=out, opener=opener)
    assert written == 1
    provider = ubuntu.UbuntuAdvisoryProvider(out)
    record = provider.advisories_for(release="focal", source_package="curl")[0]
    assert record.fixed_version == "7.68.0-1ubuntu2.20"
    assert record.advisory_id == "USN-6408-1"
    assert provider.source_label() == "ubuntu-usn"


def test_write_dataset_is_atomic(tmp_path: Path) -> None:
    out = tmp_path / "nested" / "ds.json"
    fetch.write_dataset(out, fetch.build_dataset([], source="s", origin_url="u"))
    assert out.exists()
    assert not list(tmp_path.rglob("*.tmp"))


# --------------------------------------------------------------------------
# Build-time provenance (GET /api/system reads what this writes)
# --------------------------------------------------------------------------


def test_manifest_reports_the_advisory_datasets(tmp_path: Path) -> None:
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    (tmp_path / "advisories").mkdir()
    (tmp_path / "advisories" / "ubuntu-advisories.json").write_text(
        (SEEDS / "ubuntu-advisories.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    manifest = enrichment_manifest.build_manifest(tmp_path, refreshed=set(), failed=set())
    ubuntu_record = manifest["datasets"]["advisories_ubuntu"]
    assert ubuntu_record["required"] is False
    assert ubuntu_record["usable"] is True
    assert ubuntu_record["source"] == "ubuntu-usn-seed"
    assert ubuntu_record["entries"] > 0
    # Absent is a supported configuration for these, unlike the required
    # overlays: the matcher answers "unknown" without one.
    assert manifest["datasets"]["advisories_debian"]["origin"] == "missing"
    assert manifest["datasets"]["advisories_debian"]["degrades"] is False
