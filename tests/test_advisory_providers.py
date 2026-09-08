"""Vendor-advisory providers: dataset loading, normalization, opt-in fetching."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

from api.services import advisories
from api.services.advisories import base, debian, fetch, ubuntu

REPO_ROOT = Path(__file__).resolve().parents[1]
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


def _required_overlays(data_dir: Path) -> None:
    """Lay down the four overlays a build *is* required to ship, so a verdict
    below is a statement about the advisory datasets and not about them."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    for name, (relative, min_entries, required) in enrichment_manifest._JSON_DATASETS.items():
        if not required:
            continue
        path = data_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        entries = {f"CVE-2026-{index:05d}": 0.5 for index in range(min_entries)}
        path.write_text(
            json.dumps({"source": f"{name}-fixture", "updated": "2026-09-01", "entries": entries}),
            encoding="utf-8",
        )


def test_manifest_reports_the_advisory_datasets(tmp_path: Path) -> None:
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    _required_overlays(tmp_path)
    (tmp_path / "advisories").mkdir()
    (tmp_path / "advisories" / "ubuntu-advisories.json").write_text(
        (SEEDS / "ubuntu-advisories.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    manifest = enrichment_manifest.build_manifest(tmp_path, refreshed=set(), failed=set())
    ubuntu_record = manifest["datasets"]["advisories_ubuntu"]
    assert ubuntu_record["required"] is False
    assert ubuntu_record["source"] == "ubuntu-usn-seed"
    assert ubuntu_record["entries"] > 0
    # The seed is a seed: it loads, it matches the handful of packages it
    # covers, and it is *not* advisory coverage. A build carrying ten Ubuntu
    # statements is not carrying USN, and the manifest has to say so — that is
    # what an operator reads off the System page before trusting a clean result.
    assert ubuntu_record["origin"] == "seed"
    assert ubuntu_record["usable"] is False
    assert "expected at least" in (ubuntu_record["error"] or "")
    # Absent is a supported configuration for these, unlike the required
    # overlays: the matcher answers "unknown" without one.
    assert manifest["datasets"]["advisories_debian"]["origin"] == "missing"
    assert manifest["datasets"]["advisories_debian"]["degrades"] is False
    # Neither case fails a build. Only a *required* dataset can do that.
    assert enrichment_manifest.verdict(manifest) != enrichment_manifest.EXIT_NO_DATA


def test_manifest_degrades_when_an_advisory_refresh_fails(tmp_path: Path) -> None:
    """Opting in and then failing is the case #246 exists to make visible.
    Never opting in is not: fetch-enrichment.sh does not run the fetch at all,
    so the dataset is never reported as failed."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    _required_overlays(tmp_path)
    (tmp_path / "advisories").mkdir()
    (tmp_path / "advisories" / "debian-advisories.json").write_text(
        (SEEDS / "debian-advisories.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    manifest = enrichment_manifest.build_manifest(
        tmp_path, refreshed=set(), failed={"advisories_debian"}
    )
    assert manifest["datasets"]["advisories_debian"]["origin"] == "stale"
    assert enrichment_manifest.verdict(manifest) == enrichment_manifest.EXIT_DEGRADED


def test_a_run_that_never_tried_to_fetch_leaves_the_origin_alone(tmp_path: Path) -> None:
    """The API pod's initContainer runs the same script as the CronJob without
    the advisory opt-in, so every API rollout re-inspects datasets the nightly
    job filled and lands in the "neither refreshed nor failed" branch. Calling
    that ``seed`` makes GET /api/system contradict itself — ``origin: seed``
    over four hundred thousand fetched entries — and points the operator at a
    build log with nothing in it. Only a run that *tried* may rewrite an
    origin."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    _required_overlays(tmp_path)
    (tmp_path / "advisories").mkdir()
    (tmp_path / "advisories" / "debian-advisories.json").write_text(
        (SEEDS / "debian-advisories.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    fetched = enrichment_manifest.build_manifest(
        tmp_path, refreshed={"advisories_debian"}, failed=set()
    )
    assert fetched["datasets"]["advisories_debian"]["origin"] == "fetch"
    (tmp_path / enrichment_manifest.MANIFEST_NAME).write_text(
        json.dumps(fetched), encoding="utf-8"
    )

    skipped = enrichment_manifest.build_manifest(tmp_path, refreshed=set(), failed=set())
    assert skipped["datasets"]["advisories_debian"]["origin"] == "fetch"


def test_a_first_run_still_calls_an_unfetched_dataset_a_seed(tmp_path: Path) -> None:
    """The carry-over above only carries what a previous run actually recorded.
    With no manifest beside the data, a dataset nothing fetched is the committed
    seed, which is what it was before and what it still is."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    _required_overlays(tmp_path)
    (tmp_path / "advisories").mkdir()
    (tmp_path / "advisories" / "debian-advisories.json").write_text(
        (SEEDS / "debian-advisories.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    manifest = enrichment_manifest.build_manifest(tmp_path, refreshed=set(), failed=set())
    assert manifest["datasets"]["advisories_debian"]["origin"] == "seed"
    # And a dataset the previous run could not find is not resurrected as one:
    # the floor may have just copied the seed into place since.
    (tmp_path / enrichment_manifest.MANIFEST_NAME).write_text(
        json.dumps({"datasets": {"advisories_debian": {"origin": "missing"}}}), encoding="utf-8"
    )
    again = enrichment_manifest.build_manifest(tmp_path, refreshed=set(), failed=set())
    assert again["datasets"]["advisories_debian"]["origin"] == "seed"


def test_a_fetch_that_lands_under_the_floor_degrades(tmp_path: Path) -> None:
    """The quietest of the three outcomes: the feed answered, the fetch
    "succeeded", and what it published is a stub. ``required`` is False and
    ``fetch`` is neither ``stale`` nor ``missing``, so the verdict used to be
    EXIT_OK — a green CronJob over a dataset that had just been replaced by
    twelve entries."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    _required_overlays(tmp_path)
    (tmp_path / "advisories").mkdir()
    (tmp_path / "advisories" / "debian-advisories.json").write_text(
        (SEEDS / "debian-advisories.json").read_text(encoding="utf-8"), encoding="utf-8"
    )
    for name in ("geoip", "asn"):
        (tmp_path / name).mkdir()
        (tmp_path / name / f"{name}.mmdb").write_bytes(b"\x00" * 32)
    manifest = enrichment_manifest.build_manifest(
        tmp_path,
        refreshed={"advisories_debian", "cvss4", "epss", "kev", "exploit", "geoip", "asn"},
        failed=set(),
    )
    record = manifest["datasets"]["advisories_debian"]
    assert record["origin"] == "fetch"
    assert record["usable"] is False
    assert enrichment_manifest.verdict(manifest) == enrichment_manifest.EXIT_DEGRADED


# --------------------------------------------------------------------------
# Normalization against fragments of the vendors' real dumps
#
# The hand-written payloads above test the shapes the normalizers were written
# for. These test the shapes the *feeds* actually publish, which is a different
# question and the one that had never been asked: until the delivery path
# existed, nothing but the committed seed had ever been through here.
# --------------------------------------------------------------------------


def _normalized_debian_sample() -> list[dict]:
    payload = json.loads((FIXTURES / "debian-tracker-sample.json").read_text(encoding="utf-8"))
    return list(debian.normalize_tracker_json(payload))


def _normalized_usn_sample() -> list[dict]:
    payload = json.loads((FIXTURES / "ubuntu-usn-sample.json").read_text(encoding="utf-8"))
    return list(ubuntu.normalize_usn_json(payload))


def test_debian_tracker_dump_normalizes_every_release_state() -> None:
    entries = {
        (e["source_package"], e["cve_ids"][0], e["release"]): e
        for e in _normalized_debian_sample()
    }
    resolved = entries[("openssl", "CVE-2023-0286", "bullseye")]
    assert resolved["state"] == base.STATE_RESOLVED
    assert resolved["fixed_version"] == "1.1.1n-0+deb11u4"
    # ``nodsa`` means "no DSA will be issued", not "not fixed": the tracker
    # still names the version the fix rode in on, so the statement stands.
    assert entries[("openssl", "CVE-2023-0286", "buster")]["fixed_version"] == "1.1.1n-0+deb10u4"
    # "resolved" with the "0" sentinel is the tracker's way of saying the
    # release was never affected, not a version anything compares against.
    assert ("openssl", "CVE-2023-0286", "stretch") not in entries
    # "undetermined" is not "you are safe" and not "you are exposed".
    assert ("openssl", "CVE-2024-2511", "bullseye") not in entries
    assert entries[("openssl", "CVE-2024-2511", "bookworm")]["state"] == base.STATE_OPEN
    assert entries[("curl", "CVE-2023-38545", "bullseye")]["state"] == base.STATE_NOT_AFFECTED
    # "removed" — the package is gone from that release, so it is not affected.
    assert entries[("linux", "CVE-2019-19070", "jessie")]["state"] == base.STATE_NOT_AFFECTED


def test_debian_tracker_dump_drops_its_internal_temp_ids() -> None:
    """The tracker keys issues it has no CVE for by ``TEMP-0841847-1E6784``.
    Carrying one through would put a string that is not a CVE into
    ``software_cve_matches`` and onto the console as though it were one."""
    cves = {cve for entry in _normalized_debian_sample() for cve in entry["cve_ids"]}
    assert cves
    assert all(cve.startswith("CVE-") for cve in cves)


def test_debian_tracker_dump_maps_the_real_urgency_vocabulary() -> None:
    entries = {
        (e["source_package"], e["cve_ids"][0], e["release"]): e
        for e in _normalized_debian_sample()
    }
    # "high**" — the tracker's flagged-for-review marker, not a severity of
    # its own.
    assert entries[("curl", "CVE-2023-38545", "bookworm")]["severity"] == "high"
    assert entries[("openssl", "CVE-2024-2511", "bookworm")]["severity"] == "negligible"
    assert entries[("openssl", "CVE-2023-0286", "bullseye")]["severity"] == "unknown"


def test_usn_dump_ids_are_normalized_to_the_published_form() -> None:
    """The USN database keys advisories bare — ``"5051-2"`` — while every
    human-facing reference, this project's seed included, says ``USN-5051-2``,
    and that is the form ubuntu.com serves."""
    entries = {e["advisory_id"] for e in _normalized_usn_sample()}
    assert "USN-5051-2" in entries
    assert "5051-2" not in entries
    # Already-prefixed ids are left alone rather than doubled up.
    assert "USN-6408-1" in entries
    assert "USN-USN-6408-1" not in entries
    urls = {e["url"] for e in _normalized_usn_sample()}
    assert "https://ubuntu.com/security/notices/USN-5051-2" in urls


def test_usn_dump_keeps_only_actionable_statements() -> None:
    entries = _normalized_usn_sample()
    by_advisory: dict[str, set[str]] = {}
    for entry in entries:
        by_advisory.setdefault(entry["advisory_id"], set()).add(entry["source_package"])
    # Source and binary names both, so an inventory reporting either one hits.
    assert by_advisory["USN-5051-2"] == {"openssl", "libssl1.1"}
    # A regression fix with no CVE has nothing to match against.
    assert "USN-4796-1" not in by_advisory
    # A release entry with no version cannot be compared against an installed
    # one — ESM-only rows in the real database look exactly like this.
    assert "USN-5101-1" not in by_advisory
    # Launchpad bug URLs sit in the same "cves" list as the CVEs.
    assert all(
        all(cve.startswith("CVE-") for cve in entry["cve_ids"]) for entry in entries
    )


def test_normalized_dumps_round_trip_through_the_loader(tmp_path: Path) -> None:
    """Normalization and loading are two halves of one contract: an entry the
    normalizer emits that ``_coerce_record`` then drops is a silent hole."""
    for name, normalize, sample, provider_cls in (
        ("debian", debian.normalize_tracker_json, "debian-tracker-sample.json", debian.DebianAdvisoryProvider),
        ("ubuntu", ubuntu.normalize_usn_json, "ubuntu-usn-sample.json", ubuntu.UbuntuAdvisoryProvider),
    ):
        payload = json.loads((FIXTURES / sample).read_text(encoding="utf-8"))
        produced = list(normalize(payload))
        out = tmp_path / f"{name}.json"
        fetch.write_dataset(out, fetch.build_dataset(produced, source=name, origin_url="u"))
        provider = provider_cls(out)
        assert provider.entry_count() == len(produced), name


# --------------------------------------------------------------------------
# The lookup index
#
# Eight seed records hide the difference between a dict and a linear scan; a
# real tracker dump is hundreds of thousands of statements looked up once per
# installed package per endpoint.
# --------------------------------------------------------------------------


def test_dataset_is_indexed_by_release_and_source_package(tmp_path: Path) -> None:
    releases = ("bullseye", "bookworm")
    packages = [f"pkg{i:04d}" for i in range(500)]
    entries = [
        {
            "advisory_id": f"CVE-2026-{index:05d}",
            "cve_ids": [f"CVE-2026-{index:05d}"],
            "release": release,
            "source_package": package,
            "fixed_version": "1.0",
            "state": "resolved",
        }
        for release in releases
        for package in packages
        for index in range(2)
    ]
    path = tmp_path / "big.json"
    fetch.write_dataset(path, fetch.build_dataset(entries, source="s", origin_url="u"))

    dataset = debian.DebianAdvisoryProvider(path).dataset()
    assert len(dataset.records) == len(entries)
    # One bucket per (release, source package) pair, built once at load time —
    # not a filter over every record on every lookup.
    assert dataset.index is not None
    assert len(dataset.index) == len(releases) * len(packages)
    assert sum(len(bucket) for bucket in dataset.index.values()) == len(entries)
    assert len(dataset.lookup("bookworm", "pkg0042")) == 2
    assert dataset.lookup("bookworm", "absent") == ()
    assert dataset.lookup("trixie", "pkg0042") == ()


# --------------------------------------------------------------------------
# What the opt-in costs a cluster that did not take it
# --------------------------------------------------------------------------

_ENRICHMENT_K8S = REPO_ROOT / "k8s/shapoclyack/base/enrichment"
_ADVISORY_K8S = REPO_ROOT / "k8s/shapoclyack/base/enrichment-advisories"


def _cronjob_container(document: dict) -> dict:
    spec = document["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return next(c for c in spec["containers"] if c["name"] == "fetch-enrichment")


def test_the_base_enrichment_job_does_not_size_itself_for_the_advisory_feed() -> None:
    """The opt-in is supposed to cost nothing until it is taken, and an
    ``optional: true`` configMapKeyRef genuinely costs nothing — a doubled
    memory limit does not. A namespace under a LimitRange of ``max.memory: 1Gi``,
    an ordinary multi-tenant setting, rejects the pod at admission, and the
    daily refresh of *every* feed stops for a dataset the cluster never asked
    for. The only trace is failedJobsHistoryLimit."""
    document = yaml.safe_load((_ENRICHMENT_K8S / "cronjob.yaml").read_text(encoding="utf-8"))
    assert _cronjob_container(document)["resources"]["limits"]["memory"] == "1Gi"


def test_the_advisory_component_carries_the_flag_and_the_memory_together() -> None:
    """2Gi is real — the Debian tracker document is read, parsed and
    re-serialized whole — so it has to be somewhere. It belongs in the same
    component as the ConfigMap that turns the fetch on, so that a cluster cannot
    take one without the other in either direction: the flag without the memory
    is an OOMKill that takes the four other refreshes with it."""
    component = yaml.safe_load((_ADVISORY_K8S / "kustomization.yaml").read_text(encoding="utf-8"))
    assert component["kind"] == "Component"
    assert component["resources"] == ["configmap.yaml"]
    assert [entry["path"] for entry in component["patches"]] == ["cronjob-memory-patch.yaml"]

    configmap = yaml.safe_load((_ADVISORY_K8S / "configmap.yaml").read_text(encoding="utf-8"))
    assert configmap["metadata"]["name"] == "shapoclyack-enrichment"
    assert configmap["data"]["advisory_fetch_enabled"] == "true"

    patch = yaml.safe_load((_ADVISORY_K8S / "cronjob-memory-patch.yaml").read_text(encoding="utf-8"))
    assert patch["metadata"]["name"] == "enrichment-refresh"
    assert _cronjob_container(patch)["resources"]["limits"]["memory"] == "2Gi"


def test_the_configmap_key_is_the_one_the_cronjob_reads() -> None:
    """Two files, one string. A rename on either side is a ConfigMap nobody
    reads and an opt-in that silently never happens — which is indistinguishable
    from not having opted in."""
    cronjob = yaml.safe_load((_ENRICHMENT_K8S / "cronjob.yaml").read_text(encoding="utf-8"))
    ref = next(
        entry["valueFrom"]["configMapKeyRef"]
        for entry in _cronjob_container(cronjob)["env"]
        if entry["name"] == "OCTO_ADVISORY_FETCH_ENABLED"
    )
    configmap = yaml.safe_load((_ADVISORY_K8S / "configmap.yaml").read_text(encoding="utf-8"))
    assert ref["name"] == configmap["metadata"]["name"]
    assert ref["key"] in configmap["data"]
    assert ref["optional"] is True


# --------------------------------------------------------------------------
# The refresh CLI (scripts/fetch-advisories.py)
# --------------------------------------------------------------------------


# Every spelling of the opt-in flag an operator could plausibly write, including
# the whitespace a YAML tool or a copy-paste leaves behind: a ConfigMap entry
# quoted as ``" true"`` reaches the pod with the space still on it. Whatever
# each of these means, it has to mean the same thing to the script that decides
# whether to fetch and to the service that decides whether to allow it -- the
# two read one variable and there is no third place to reconcile them.
FLAG_SPELLINGS = (
    "true", "TRUE", "True", "1", "yes", "YES", "on", "ON",
    " true", "true ", "\ttrue\t", "true\n", "\n true \n", " 1 ", "\tyes\n", "on\r\n",
    "false", "FALSE", "0", "no", "off", "", " ", "\n",
    "truthy", "tr ue", "true false", "enabled", "2",
)


@pytest.mark.parametrize("raw", FLAG_SPELLINGS)
def test_the_shell_and_the_service_read_the_opt_in_flag_the_same_way(
    raw: str, monkeypatch, tmp_path: Path
) -> None:
    """scripts/fetch-enrichment.sh decides for itself whether to run the fetch
    rather than letting fetch-advisories.py exit 3 into ``run()``. That is only
    sound while the two agree: a value the service accepts and the script does
    not turns into "advisories: skipped" printed at an operator who set the
    flag and gets a seed forever, with nothing in stderr to say why."""
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", raw)
    expected = fetch.fetch_enabled()

    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", "-c",
         f'source "{REPO_ROOT / "scripts" / "fetch-enrichment.sh"}"; advisory_fetch_enabled'],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "OCTO_ADVISORY_FETCH_ENABLED": raw},
    )

    assert (proc.returncode == 0) is expected, (
        f"{raw!r}: shell says {'on' if proc.returncode == 0 else 'off'}, "
        f"fetch_enabled() says {'on' if expected else 'off'}\n{proc.stdout}{proc.stderr}"
    )


def test_sourcing_the_refresh_script_does_not_run_it(tmp_path: Path) -> None:
    """The guard the table test above leans on: sourcing must hand over the
    flag helper and stop, not start downloading GeoIP into the caller's cwd."""
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["bash", "-c",
         f'source "{REPO_ROOT / "scripts" / "fetch-enrichment.sh"}"; echo sourced'],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env={**os.environ, "OCTO_ENRICHMENT_DIR": str(tmp_path / "data")},
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip() == "sourced"
    assert not (tmp_path / "data").exists()



def _fetch_cli():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "fetch_advisories_cli", Path("scripts/fetch-advisories.py")
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_cli_is_off_by_default_and_says_so(monkeypatch, tmp_path: Path) -> None:
    """Distinct from a failure: an installation that never opted in has not had
    a bad day, and fetch-enrichment.sh must not record it as a stale dataset."""
    monkeypatch.delenv("OCTO_ADVISORY_FETCH_ENABLED", raising=False)
    cli = _fetch_cli()
    out = tmp_path / "ubuntu.json"
    monkeypatch.setattr("sys.argv", ["fetch-advisories.py", "ubuntu", "-o", str(out)])
    assert cli.main() == cli.EXIT_DISABLED
    assert not out.exists()


def test_cli_refuses_to_publish_an_empty_feed_over_a_dataset(monkeypatch, tmp_path: Path) -> None:
    """A feed that answers 200 with an empty document is an outage, not a day
    with no advisories, and it must not wipe the data an installation has."""
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    cli = _fetch_cli()
    out = tmp_path / "ubuntu.json"
    out.write_text((SEEDS / "ubuntu-advisories.json").read_text(encoding="utf-8"), encoding="utf-8")
    before = out.read_text(encoding="utf-8")
    monkeypatch.setattr(fetch, "fetch_json", lambda *a, **k: {})
    monkeypatch.setattr("sys.argv", ["fetch-advisories.py", "ubuntu", "-o", str(out)])
    assert cli.main() == cli.EXIT_FAILED
    assert out.read_text(encoding="utf-8") == before
    # Nothing half-written left behind either.
    assert not list(tmp_path.glob("*.fetch"))
    assert not list(tmp_path.glob("*.tmp"))


def test_cli_refuses_a_truncated_feed_over_a_populated_dataset(monkeypatch, tmp_path: Path) -> None:
    """A floor of one only catches the *empty* document. A tracker answering
    200 with a truncated one is the same outage, and it normalizes to a dozen
    statements that clear a floor of one and replace four hundred thousand —
    after which the manifest records ``origin: fetch`` over a stub. The floor
    the manifest already keeps for each dataset is the one to refuse against."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    cli = _fetch_cli()
    payload = json.loads((FIXTURES / "ubuntu-usn-sample.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(fetch, "fetch_json", lambda *a, **k: payload)
    out = tmp_path / "ubuntu.json"
    out.write_text((SEEDS / "ubuntu-advisories.json").read_text(encoding="utf-8"), encoding="utf-8")
    before = out.read_text(encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["fetch-advisories.py", "ubuntu", "-o", str(out)])

    assert cli.main() == cli.EXIT_FAILED
    assert out.read_text(encoding="utf-8") == before
    assert not list(tmp_path.glob("*.fetch"))
    # And the number it refused against is the manifest's, not a second opinion
    # kept in the CLI: one floor per dataset, in one place.
    _, floor, _ = enrichment_manifest._JSON_DATASETS["advisories_ubuntu"]
    assert cli.default_min_entries("ubuntu") == floor


def test_cli_publishes_a_loadable_dataset(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    cli = _fetch_cli()
    payload = json.loads((FIXTURES / "ubuntu-usn-sample.json").read_text(encoding="utf-8"))
    monkeypatch.setattr(fetch, "fetch_json", lambda *a, **k: payload)
    out = tmp_path / "nested" / "ubuntu.json"
    # --min-entries 1 because the fixture is six statements, not a USN dump: the
    # default is the real feed's floor, which is the subject of
    # test_cli_refuses_a_truncated_feed_over_a_populated_dataset below.
    monkeypatch.setattr(
        "sys.argv", ["fetch-advisories.py", "ubuntu", "-o", str(out), "--min-entries", "1"]
    )
    assert cli.main() == cli.EXIT_OK
    provider = ubuntu.UbuntuAdvisoryProvider(out)
    record = provider.advisories_for(release="focal", source_package="openssl")[0]
    assert record.advisory_id == "USN-5051-2"
    assert record.fixed_version == "1.1.1f-1ubuntu2.8"


def test_cli_leaves_the_dataset_alone_when_the_feed_fails(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("OCTO_ADVISORY_FETCH_ENABLED", "true")
    cli = _fetch_cli()
    out = tmp_path / "debian.json"
    out.write_text((SEEDS / "debian-advisories.json").read_text(encoding="utf-8"), encoding="utf-8")
    before = out.read_text(encoding="utf-8")

    def boom(*args, **kwargs):
        raise OSError("connection reset by peer")

    monkeypatch.setattr(fetch, "fetch_json", boom)
    monkeypatch.setattr("sys.argv", ["fetch-advisories.py", "debian", "-o", str(out)])
    assert cli.main() == cli.EXIT_FAILED
    assert out.read_text(encoding="utf-8") == before


def test_usn_dump_emits_one_statement_per_package_and_release() -> None:
    """``sources`` and ``binaries`` overlap — ``curl`` is in both lists of every
    curl USN — so the feed states the same thing twice. Emitting it twice would
    double a tens-of-thousands-entry dataset and put two identical records in
    every lookup bucket for that package."""
    entries = _normalized_usn_sample()
    keys = [(e["advisory_id"], e["release"], e["source_package"]) for e in entries]
    assert len(keys) == len(set(keys))
    # The duplicate is not silently dropped along with the statement: jammy curl
    # is still there, once, and libcurl4 beside it.
    jammy = {
        e["source_package"]
        for e in entries
        if e["advisory_id"] == "USN-6408-1" and e["release"] == "jammy"
    }
    assert jammy == {"curl", "libcurl4"}


# --------------------------------------------------------------------------
# What GET /api/system says about a dataset the build never refreshed
# --------------------------------------------------------------------------


def test_system_status_reports_a_seeded_advisory_dataset_as_unusable(tmp_path, monkeypatch) -> None:
    """A fresh offline install ships the seed, and the seed's mtime is the
    build's — so "present, non-zero entries, zero days old" describes both real
    coverage and eight hand-picked advisories. The manifest already decided
    which one it is against the dataset's floor; the System page has to carry
    that verdict outward or the console renders the seed as ``fresh``."""
    from api.services import system_status

    manifest = tmp_path / "enrichment-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "datasets": {
                    "advisories_debian": {
                        "source": "debian-security-tracker-seed",
                        "origin": "seed",
                        "updated": "2026-08-28",
                        "entries": 8,
                        "required": False,
                        "usable": False,
                    },
                    "advisories_ubuntu": {
                        "source": "debian-security-tracker",
                        "origin": "fetch",
                        "updated": "2026-09-08",
                        "entries": 42_000,
                        "required": False,
                        "usable": True,
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("OCTO_ENRICHMENT_MANIFEST", str(manifest))
    monkeypatch.setenv("OCTO_DEBIAN_ADVISORY_DATABASE", str(SEEDS / "debian-advisories.json"))

    databases = {db["name"]: db for db in system_status.enrichment_status({})}
    seeded = databases["advisories_debian"]
    # Everything that would read as healthy on its own…
    assert seeded["present"] is True
    assert seeded["entries"] == 8
    # …and the one field that says it is not coverage.
    assert seeded["usable"] is False
    assert seeded["origin"] == "seed"
    assert databases["advisories_ubuntu"]["usable"] is True
    # A dataset the manifest says nothing about reports None, not False: "no
    # manifest" is not "this data is bad". Same rule as every other origin field.
    assert databases["epss"]["usable"] is None


# What each feed actually publishes, as of 2026-09, written down here rather
# than read back out of ``_JSON_DATASETS``: a floor checked against a dataset
# generated from that same floor is a tautology — it holds for 10 and for ten
# million, and it held while the Ubuntu dataset roughly halved when the
# sources/binaries duplicate went. These are the independent numbers a floor has
# to stay under, and moving one is a claim about the feed, not about the code.
#
# Debian's tracker: hundreds of thousands of per-release statements.
# Ubuntu's USN database: tens of thousands, post-dedup.
_FEED_SIZES = {
    "advisories_debian": 300_000,
    "advisories_ubuntu": 30_000,
}


@pytest.mark.parametrize("name", sorted(_FEED_SIZES))
def test_manifest_floor_sits_between_the_seed_and_the_real_feed(name: str, tmp_path: Path) -> None:
    """A floor is a claim about two numbers it must sit between: above the
    committed seed, or a seed passes for coverage — the defect the floors were
    added for — and below what a refresh actually brings back, or every
    installation is reported as stubbed forever and no refresh can clear it."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    relative, min_entries, required = enrichment_manifest._JSON_DATASETS[name]
    assert required is False
    assert min_entries <= _FEED_SIZES[name], (
        f"{name}: floor {min_entries} is above the {_FEED_SIZES[name]} entries the feed "
        f"publishes — no refresh could ever clear it"
    )
    # And the committed seed is on the other side of it, which is the whole
    # point: the image ships a seed, not a feed dump.
    seed = enrichment_manifest.inspect_json_dataset(SEEDS / Path(relative).name, min_entries)
    assert seed["present"] is True
    assert seed["usable"] is False
    assert seed["entries"] < min_entries


def test_a_dataset_at_the_floor_is_reported_usable(tmp_path: Path) -> None:
    """The floor is inclusive, and a dataset that clears it reports no error —
    stated separately from the sizing above because it is a statement about
    ``inspect_json_dataset``, not about either feed."""
    import sys

    sys.path.insert(0, "scripts")
    import enrichment_manifest

    entries = [
        {
            "advisory_id": f"USN-{index}-1",
            "cve_ids": [f"CVE-2026-{index:05d}"],
            "release": "jammy",
            "source_package": f"pkg{index}",
            "fixed_version": "1.0",
            "state": "resolved",
        }
        for index in range(100)
    ]
    path = tmp_path / "ubuntu-advisories.json"
    fetch.write_dataset(path, fetch.build_dataset(entries, source="ubuntu-usn", origin_url="u"))
    record = enrichment_manifest.inspect_json_dataset(path, 100)
    assert record["usable"] is True
    assert record["error"] is None
    assert enrichment_manifest.inspect_json_dataset(path, 101)["usable"] is False
