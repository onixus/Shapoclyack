"""Offline enrichment bundles: build, and above all the extractor (#339).

The bundle is the one file that crosses an air gap, which makes its extractor
the one piece of this feature an attacker gets to feed directly: whoever can
drop a file into the inbox volume chooses every byte the loader Job reads. So
most of this module is adversarial — each test hands the installer an archive
that is wrong in one specific way and checks two things: that it is refused,
and that the enrichment directory is byte-for-byte what it was before.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import enrichment_bundle  # noqa: E402 - needs the path above
from enrichment_bundle import BundleError, Limits  # noqa: E402

from tests.test_air_gap_feeds import mirror  # noqa: E402,F401 - the loopback mirror fixture

GEOIP_FIXTURE = REPO_ROOT / "tests" / "data" / "geoip" / "GeoIP2-City-Test.mmdb"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


def _kev(count: int, *, updated: str = "2026-09-20") -> bytes:
    return json.dumps(
        {
            "version": 1,
            "source": "cisa-kev",
            "updated": updated,
            "origin_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "entries": [f"CVE-2026-{i:05d}" for i in range(count)],
        }
    ).encode()


def _epss(count: int) -> bytes:
    return json.dumps(
        {
            "version": 1,
            "source": "first-epss",
            "updated": "2026-09-21",
            "origin_url": "https://epss.cyentia.com/epss_scores-current.csv.gz",
            "entries": {f"CVE-2026-{i:05d}": 0.1 for i in range(count)},
        }
    ).encode()


def _data_dir(root: Path, *, kev_entries: int = 500, geoip: bool = True) -> Path:
    data = root / "connected"
    (data / "kev").mkdir(parents=True)
    (data / "epss").mkdir(parents=True)
    (data / "kev" / "kev-overlay.json").write_bytes(_kev(kev_entries))
    (data / "epss" / "epss-overlay.json").write_bytes(_epss(2000))
    if geoip:
        (data / "geoip").mkdir()
        (data / "geoip" / "geoip.mmdb").write_bytes(GEOIP_FIXTURE.read_bytes())
    return data


@pytest.fixture()
def bundle(tmp_path: Path) -> Path:
    out = tmp_path / "enrichment-bundle.tar.gz"
    enrichment_bundle.build_bundle(_data_dir(tmp_path), out, built_at="2026-09-22T03:00:00+00:00")
    return out


@pytest.fixture()
def site(tmp_path: Path) -> Path:
    """An installation that already has data: every refusal must leave it be."""
    data = tmp_path / "site"
    (data / "kev").mkdir(parents=True)
    (data / "kev" / "kev-overlay.json").write_bytes(_kev(300, updated="2026-08-01"))
    return data


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.name.startswith(".enrichment-bundle.lock")
    }


def _assert_refused(bundle_path: Path, site: Path, match: str, **kwargs) -> None:
    before = _snapshot(site)
    with pytest.raises(BundleError, match=match):
        enrichment_bundle.install(bundle_path, site, **kwargs)
    assert _snapshot(site) == before
    leftovers = [p.name for p in site.iterdir() if p.name.startswith(".enrichment-bundle-")]
    assert leftovers == [".enrichment-bundle.lock"] or leftovers == []
    assert not (site / enrichment_bundle.INSTALLED_RECORD).exists()


def _entry(path: str, data: bytes, dataset: str) -> dict:
    return {
        "path": path,
        "dataset": dataset,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "source": None,
        "source_urls": [],
        "updated": None,
        "fetched_at": "2026-09-22T03:00:00+00:00",
        "origin": "fetch",
        "entries": None,
        "usable": True,
    }


def _manifest(entries: list[dict], **overrides) -> bytes:
    payload = {
        "schema": enrichment_bundle.SCHEMA,
        "schema_version": enrichment_bundle.SCHEMA_VERSION,
        "built_at": "2026-09-22T03:00:00+00:00",
        "files": entries,
    }
    payload.update(overrides)
    return json.dumps(payload).encode()


def _member(name: str, data: bytes = b"", *, kind: bytes = tarfile.REGTYPE, **attrs) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(data) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    info.mtime = 0
    for key, value in attrs.items():
        setattr(info, key, value)
    return info, data


def _tar(members: list[tuple[tarfile.TarInfo, bytes]], *, fmt: int = tarfile.GNU_FORMAT, gz: bool = True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as archive:
        for info, data in members:
            archive.addfile(info, io.BytesIO(data) if info.size else None)
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gz else raw


def _write(tmp_path: Path, payload: bytes, name: str = "evil.tar.gz") -> Path:
    path = tmp_path / name
    path.write_bytes(payload)
    return path


KEV = "kev/kev-overlay.json"


def _kev_bundle(tmp_path: Path, extra: list[tuple[tarfile.TarInfo, bytes]] | None = None, **kwargs) -> Path:
    """A well-formed one-file bundle, plus whatever ``extra`` members follow it."""
    data = _kev(500)
    members = [_member(enrichment_bundle.MANIFEST_MEMBER, _manifest([_entry(KEV, data, "kev")])), _member(KEV, data)]
    return _write(tmp_path, _tar(members + (extra or []), **kwargs))


# --------------------------------------------------------------------------
# Build
# --------------------------------------------------------------------------


def test_the_same_directory_builds_the_same_bytes(tmp_path: Path) -> None:
    """Two people packing one refresh must be able to compare a checksum. The
    timestamp comes from the data (or SOURCE_DATE_EPOCH), never the clock."""
    import time

    data = _data_dir(tmp_path)
    first, second = tmp_path / "a.tar.gz", tmp_path / "b.tar.gz"
    enrichment_bundle.build_bundle(data, first)
    time.sleep(1.1)  # the clock moves past a timestamp's resolution; the bundle must not
    enrichment_bundle.build_bundle(data, second)
    assert first.read_bytes() == second.read_bytes()

    # Likewise once a refresh has described the directory.
    subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(REPO_ROOT / "scripts" / "enrichment_manifest.py"), "--dir", str(data)],
        capture_output=True,
        check=False,
    )
    enrichment_bundle.build_bundle(data, first)
    time.sleep(1.1)
    enrichment_bundle.build_bundle(data, second)
    assert first.read_bytes() == second.read_bytes()


def test_source_date_epoch_pins_the_timestamp(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790000000")
    manifest = enrichment_bundle.build_bundle(_data_dir(tmp_path), tmp_path / "b.tar.gz")
    assert manifest["built_at"] == "2026-09-21T14:13:20+00:00"


def test_the_manifest_is_first_and_describes_every_file(bundle: Path) -> None:
    with tarfile.open(bundle) as archive:
        members = archive.getmembers()
        manifest = json.loads(archive.extractfile(members[0]).read())  # type: ignore[union-attr]
        names = [m.name for m in members]
        payloads = {m.name: archive.extractfile(m).read() for m in members[1:]}  # type: ignore[union-attr]

    assert names[0] == enrichment_bundle.MANIFEST_MEMBER
    # Sorted, regular files, no owner: nothing about the builder's host leaks in.
    assert names[1:] == sorted(names[1:]) == ["epss/epss-overlay.json", "geoip/geoip.mmdb", KEV]
    assert all(m.isreg() and m.uid == 0 and m.uname == "" and m.mode == 0o644 for m in members)
    assert manifest["schema"] == enrichment_bundle.SCHEMA
    assert manifest["schema_version"] == 1
    assert manifest["built_at"] == "2026-09-22T03:00:00+00:00"
    by_path = {entry["path"]: entry for entry in manifest["files"]}
    for name, data in payloads.items():
        assert by_path[name]["sha256"] == hashlib.sha256(data).hexdigest()
        assert by_path[name]["size"] == len(data)
        assert by_path[name]["fetched_at"]
    kev = by_path[KEV]
    assert kev["dataset"] == "kev"
    assert kev["updated"] == "2026-09-20"  # the feed's own date, not the file's
    assert kev["source_urls"] == [
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    ]
    # The .mmdb has no envelope; its data date comes from the database metadata.
    assert by_path["geoip/geoip.mmdb"]["updated"]


def test_a_directory_with_nothing_to_bundle_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(BundleError, match="nothing to bundle"):
        enrichment_bundle.build_bundle(tmp_path / "empty", tmp_path / "b.tar.gz")


def test_a_symlinked_dataset_is_not_followed_into_a_bundle(tmp_path: Path) -> None:
    """The builder runs on the connected host with whatever privileges it has;
    a dataset path that is a link must not pack the file it points at."""
    data = _data_dir(tmp_path, geoip=False)
    secret = tmp_path / "secret.json"
    secret.write_text('{"entries": {}}', encoding="utf-8")
    (data / "epss" / "epss-overlay.json").unlink()
    (data / "epss" / "epss-overlay.json").symlink_to(secret)
    with pytest.raises(BundleError, match="not a regular file"):
        enrichment_bundle.build_bundle(data, tmp_path / "b.tar.gz")


# --------------------------------------------------------------------------
# Install: the happy path and the transaction
# --------------------------------------------------------------------------


def test_install_puts_every_file_in_place_and_records_it(bundle: Path, site: Path) -> None:
    summary = enrichment_bundle.install(bundle, site)

    assert summary["installed"] is True
    assert (site / KEV).read_bytes() == _kev(500)
    assert (site / "geoip" / "geoip.mmdb").read_bytes() == GEOIP_FIXTURE.read_bytes()
    record = json.loads((site / enrichment_bundle.INSTALLED_RECORD).read_text(encoding="utf-8"))
    assert record["bundle_id"] == summary["bundle_id"]
    assert record["built_at"] == "2026-09-22T03:00:00+00:00"
    assert {entry["path"] for entry in record["files"]} == {KEV, "epss/epss-overlay.json", "geoip/geoip.mmdb"}
    manifest = json.loads((site / "enrichment-manifest.json").read_text(encoding="utf-8"))
    assert manifest["datasets"]["kev"]["origin"] == "bundle"
    assert manifest["datasets"]["kev"]["updated"] == "2026-09-20"
    assert manifest["datasets"]["geoip"]["origin"] == "bundle"
    assert manifest["datasets"]["kev"]["path"] == str(site.resolve() / KEV)
    history = (site / enrichment_bundle.HISTORY).read_text(encoding="utf-8").splitlines()
    assert json.loads(history[-1])["bundle_id"] == summary["bundle_id"]
    assert not [p for p in site.iterdir() if p.name.startswith((".enrichment-bundle-staging", ".enrichment-bundle-backup"))]


def test_installing_the_same_bundle_again_changes_nothing(bundle: Path, site: Path) -> None:
    """The loader runs on a schedule against whatever sits in the inbox."""
    enrichment_bundle.install(bundle, site)
    before = _snapshot(site)
    summary = enrichment_bundle.install(bundle, site)
    assert summary["installed"] is False
    assert _snapshot(site) == before


def test_a_dataset_the_bundle_does_not_carry_is_left_alone(tmp_path: Path, site: Path) -> None:
    (site / "cvss4").mkdir()
    (site / "cvss4" / "cvss4.json").write_text('{"entries": {"CVE-1": {}}}', encoding="utf-8")
    bundle_path = _kev_bundle(tmp_path)
    enrichment_bundle.install(bundle_path, site)
    assert (site / "cvss4" / "cvss4.json").read_text(encoding="utf-8") == '{"entries": {"CVE-1": {}}}'


def _is_commit(src, dst) -> bool:
    """A rename out of staging into the live directory — not one inside it."""
    staging = ".enrichment-bundle-staging-"
    return staging in str(src) and staging not in str(dst)


def test_a_failure_mid_commit_rolls_every_file_back(bundle: Path, site: Path, monkeypatch) -> None:
    """Never half a bundle: the third rename fails, and the first two are undone."""
    before = _snapshot(site)
    real_replace = os.replace
    calls = {"n": 0}

    def flaky(src, dst, *args, **kwargs):
        if _is_commit(src, dst):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError("disk full")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(enrichment_bundle.os, "replace", flaky)
    with pytest.raises(OSError, match="disk full"):
        enrichment_bundle.install(bundle, site)
    monkeypatch.setattr(enrichment_bundle.os, "replace", real_replace)

    assert calls["n"] == 3
    assert _snapshot(site) == before
    assert not (site / enrichment_bundle.JOURNAL).exists()


def test_a_crash_mid_commit_is_rolled_back_by_the_next_run(bundle: Path, site: Path, monkeypatch) -> None:
    """A killed pod cannot run its own rollback; the journal is how the next
    one knows what to put back."""
    before = _snapshot(site)
    real_replace = os.replace
    calls = {"n": 0}

    class Killed(BaseException):
        pass

    def dies(src, dst, *args, **kwargs):
        if _is_commit(src, dst):
            calls["n"] += 1
            if calls["n"] == 2:
                raise Killed()
        return real_replace(src, dst, *args, **kwargs)

    # Simulate SIGKILL: the rollback in _commit must not run, so it is disabled.
    monkeypatch.setattr(enrichment_bundle.os, "replace", dies)
    monkeypatch.setattr(enrichment_bundle, "recover", lambda target: False)
    with pytest.raises(Killed):
        enrichment_bundle.install(bundle, site)
    monkeypatch.undo()
    assert (site / enrichment_bundle.JOURNAL).exists()
    assert _snapshot(site) != before  # half-applied on disk, as a crash leaves it

    assert enrichment_bundle.recover(site) is True
    assert {k: v for k, v in _snapshot(site).items() if not k.startswith(".enrichment-bundle-")} == before


def test_an_older_bundle_is_refused_unless_asked_for(tmp_path: Path, site: Path) -> None:
    """Replaying last month's bundle is how last month's KEV comes back."""
    newer = tmp_path / "newer.tar.gz"
    older = tmp_path / "older.tar.gz"
    enrichment_bundle.build_bundle(_data_dir(tmp_path / "n"), newer, built_at="2026-09-22T03:00:00+00:00")
    enrichment_bundle.build_bundle(_data_dir(tmp_path / "o", kev_entries=400), older, built_at="2026-08-01T03:00:00+00:00")
    enrichment_bundle.install(newer, site)

    _assert_refused_after_install(older, site, "before the installed one")
    summary = enrichment_bundle.install(older, site, allow_older=True)
    assert summary["installed"] is True


def _assert_refused_after_install(bundle_path: Path, site: Path, match: str) -> None:
    before = _snapshot(site)
    with pytest.raises(BundleError, match=match):
        enrichment_bundle.install(bundle_path, site)
    assert _snapshot(site) == before


def test_an_unusable_dataset_never_replaces_a_usable_one(tmp_path: Path, site: Path) -> None:
    """The #246 floor at the gap: a truncated feed on the connected side must
    not be carried across and published over a corpus."""
    stub = tmp_path / "stub"
    (stub / "kev").mkdir(parents=True)
    (stub / "kev" / "kev-overlay.json").write_bytes(_kev(3))
    bundle_path = tmp_path / "stub.tar.gz"
    enrichment_bundle.build_bundle(stub, bundle_path, built_at="2026-09-23T00:00:00+00:00")
    _assert_refused(bundle_path, site, "would replace a dataset that is")


def test_a_second_installer_waits_its_turn(bundle: Path, site: Path) -> None:
    import fcntl

    site.mkdir(exist_ok=True)
    with open(site / enrichment_bundle.LOCK, "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(enrichment_bundle.InstallError, match="another bundle install"):
            enrichment_bundle.install(bundle, site)


# --------------------------------------------------------------------------
# Install: adversarial archives
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["../kev-overlay.json", "kev/../../escape.json", "/etc/cron.d/evil", "kev//kev-overlay.json", "./kev/kev-overlay.json"],
)
def test_a_path_that_leaves_the_directory_is_refused(tmp_path: Path, site: Path, name: str) -> None:
    data = b'{"entries": []}'
    manifest = _manifest([_entry(KEV, _kev(500), "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(name, data)])
    _assert_refused(_write(tmp_path, payload), site, "absolute path|path component|not in the manifest")
    assert not (tmp_path / "escape.json").exists()
    assert not (site.parent / "kev-overlay.json").exists()


def test_a_manifest_that_lists_a_path_outside_the_whitelist_is_refused(tmp_path: Path, site: Path) -> None:
    """Even a well-formed, hash-consistent bundle writes only dataset files."""
    script = b"#!/bin/sh\nid\n"
    manifest = _manifest([_entry("kev/run.sh", script, "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member("kev/run.sh", script)])
    _assert_refused(_write(tmp_path, payload), site, "not an enrichment dataset path")


@pytest.mark.parametrize(
    ("kind", "attrs", "label"),
    [
        (tarfile.SYMTYPE, {"linkname": "/etc/passwd"}, "symbolic link"),
        (tarfile.LNKTYPE, {"linkname": "/etc/passwd"}, "hard link"),
        (tarfile.CHRTYPE, {"devmajor": 1, "devminor": 3}, "character device"),
        (tarfile.BLKTYPE, {"devmajor": 8, "devminor": 0}, "block device"),
        (tarfile.FIFOTYPE, {}, "FIFO"),
        (tarfile.DIRTYPE, {}, "directory"),
    ],
)
def test_anything_but_a_regular_file_is_refused(tmp_path: Path, site: Path, kind, attrs, label) -> None:
    """A link named like a dataset is the classic: extracted, it turns the next
    write to that path into a write anywhere."""
    manifest = _manifest([_entry(KEV, _kev(500), "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, kind=kind, **attrs)])
    _assert_refused(_write(tmp_path, payload), site, label)
    assert not (site / KEV).is_symlink()


def test_a_pax_header_is_refused(tmp_path: Path, site: Path) -> None:
    """The builder never writes one, and it is the one header tarfile would
    buffer at an attacker-chosen length."""
    data = _kev(500)
    info, _ = _member(KEV, data)
    info.pax_headers = {"comment": "x" * 100}
    manifest = _manifest([_entry(KEV, data, "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), (info, data)], fmt=tarfile.PAX_FORMAT)
    _assert_refused(_write(tmp_path, payload), site, "pax")


def test_a_hash_mismatch_is_refused(tmp_path: Path, site: Path) -> None:
    good, evil = _kev(500), _kev(500, updated="1999-01-01")
    assert len(good) == len(evil)
    manifest = _manifest([_entry(KEV, good, "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, evil)])
    _assert_refused(_write(tmp_path, payload), site, "sha256")


def test_a_file_the_manifest_does_not_list_is_refused(tmp_path: Path, site: Path) -> None:
    extra = _epss(2000)
    bundle_path = _kev_bundle(tmp_path, extra=[_member("epss/epss-overlay.json", extra)])
    _assert_refused(bundle_path, site, "not in the manifest")


def test_a_member_listed_twice_in_the_archive_is_refused(tmp_path: Path, site: Path) -> None:
    bundle_path = _kev_bundle(tmp_path, extra=[_member(KEV, _kev(500))])
    _assert_refused(bundle_path, site, "appears twice")


def test_a_manifest_listing_a_path_twice_is_refused(tmp_path: Path, site: Path) -> None:
    data = _kev(500)
    manifest = _manifest([_entry(KEV, data, "kev"), _entry(KEV, data, "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, data)])
    _assert_refused(_write(tmp_path, payload), site, "listed twice")


def test_a_size_that_disagrees_with_the_manifest_is_refused(tmp_path: Path, site: Path) -> None:
    data = _kev(500)
    entry = _entry(KEV, data, "kev")
    entry["size"] = len(data) - 1
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, _manifest([entry])), _member(KEV, data)])
    _assert_refused(_write(tmp_path, payload), site, "bytes in the archive")


def test_a_bundle_whose_manifest_is_not_first_is_refused(tmp_path: Path, site: Path) -> None:
    data = _kev(500)
    payload = _tar([_member(KEV, data), _member(enrichment_bundle.MANIFEST_MEMBER, _manifest([_entry(KEV, data, "kev")]))])
    _assert_refused(_write(tmp_path, payload), site, "first member must be")


def test_a_listed_file_missing_from_the_archive_is_refused(tmp_path: Path, site: Path) -> None:
    data = _kev(500)
    manifest = _manifest([_entry(KEV, data, "kev"), _entry("epss/epss-overlay.json", _epss(2000), "epss")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, data)])
    _assert_refused(_write(tmp_path, payload), site, "missing epss/epss-overlay.json")


@pytest.mark.parametrize("keep", [0.25, 0.5, 0.9, 0.999])
def test_a_truncated_gzip_is_refused(bundle: Path, site: Path, tmp_path: Path, keep: float) -> None:
    raw = bundle.read_bytes()
    _assert_refused(_write(tmp_path, raw[: int(len(raw) * keep)], "cut.tar.gz"), site, "truncated|corrupt")


@pytest.mark.parametrize("where", ["in-first-header", "in-a-header", "in-the-data", "before-the-end-marker"])
def test_a_truncated_plain_tar_is_refused(tmp_path: Path, site: Path, where: str) -> None:
    data = _kev(500)
    manifest = _manifest([_entry(KEV, data, "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, data)], gz=False)
    kev_header = 512 + len(manifest) + (-len(manifest)) % 512
    cut = {
        "in-first-header": 100,
        "in-a-header": kev_header + 100,
        "in-the-data": kev_header + 512 + len(data) // 2,
        # Every listed file complete, the end-of-archive marker gone: a copy
        # that stopped a moment early. Still not an archive this tool wrote.
        "before-the-end-marker": kev_header + 512 + len(data) + (-len(data)) % 512,
    }[where]
    _assert_refused(_write(tmp_path, payload[:cut], "cut.tar"), site, "truncated")


def test_a_corrupted_gzip_crc_is_refused(bundle: Path, site: Path, tmp_path: Path) -> None:
    raw = bytearray(bundle.read_bytes())
    raw[-8] ^= 0xFF  # the CRC32 in the gzip trailer
    _assert_refused(_write(tmp_path, bytes(raw)), site, "corrupt")


def test_data_after_the_end_of_the_archive_is_refused(tmp_path: Path, site: Path) -> None:
    data = _kev(500)
    payload = _tar(
        [_member(enrichment_bundle.MANIFEST_MEMBER, _manifest([_entry(KEV, data, "kev")])), _member(KEV, data)],
        gz=False,
    )
    _assert_refused(_write(tmp_path, payload + b"#!/bin/sh\n", "tail.tar"), site, "after the end-of-archive")


def test_a_compression_bomb_is_refused_before_it_is_expanded(tmp_path: Path, site: Path) -> None:
    """64 MiB of zeros gzip to ~64 KiB, a ratio of 1000. The manifest is
    honest about the size, and that is exactly what gives it away — nothing is
    decompressed past the manifest."""
    bomb = bytes(64 * 1024 * 1024)
    manifest = _manifest([_entry(KEV, bomb, "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, bomb)])
    assert len(payload) < 1024 * 1024
    _assert_refused(_write(tmp_path, payload), site, "ratio over")


def test_a_bundle_over_the_size_limit_is_refused(bundle: Path, site: Path) -> None:
    _assert_refused(bundle, site, "over the .* byte limit", limits=Limits(max_bytes=1024))


def test_a_header_that_lies_about_its_size_cannot_outrun_the_budget(tmp_path: Path, site: Path) -> None:
    """The manifest says 10 bytes, the header says 10; the archive then keeps
    going with a second, unlisted, enormous member. The stream is metered
    against what the manifest declared, not against the headers."""
    data = b'{"entries":[]}'
    manifest = _manifest([_entry(KEV, data, "kev")])
    big = bytes(8 * 1024 * 1024)
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, data), _member("epss/epss-overlay.json", big)])
    _assert_refused(_write(tmp_path, payload), site, "not in the manifest|expands past")


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"schema": "something-else"}, "not a shapoclyack.enrichment-bundle"),
        ({"schema_version": 2}, "newer than this release"),
        ({"schema_version": "1"}, "schema_version is missing"),
        ({"built_at": "yesterday"}, "built_at"),
        ({"files": []}, "lists no files"),
    ],
)
def test_a_manifest_this_release_cannot_vouch_for_is_refused(tmp_path: Path, site: Path, overrides, match) -> None:
    data = _kev(500)
    manifest = _manifest([_entry(KEV, data, "kev")], **overrides)
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, data)])
    _assert_refused(_write(tmp_path, payload), site, match)


def test_a_manifest_that_is_not_json_is_refused(tmp_path: Path, site: Path) -> None:
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, b"\x00\xff not json")])
    _assert_refused(_write(tmp_path, payload), site, "not JSON")


def test_a_file_that_is_not_what_its_path_says_is_refused(tmp_path: Path, site: Path) -> None:
    """Hash-consistent is not the same as correct: an HTML page packed as the
    GeoIP database, or a JSON dataset with no entries, is refused on content."""
    page = b"<!DOCTYPE html><html>Attention Required</html>"
    manifest = _manifest([_entry("geoip/geoip.mmdb", page, "geoip")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member("geoip/geoip.mmdb", page)])
    _assert_refused(_write(tmp_path, payload), site, "not a MaxMind DB")

    junk = b'{"hello": "world"}'
    manifest = _manifest([_entry(KEV, junk, "kev")])
    payload = _tar([_member(enrichment_bundle.MANIFEST_MEMBER, manifest), _member(KEV, junk)])
    _assert_refused(_write(tmp_path, payload, "junk.tar.gz"), site, "not an enrichment dataset")


def test_a_bundle_that_is_not_a_regular_file_is_refused(tmp_path: Path, site: Path) -> None:
    """A FIFO in the inbox would hold the loader until its deadline, a device
    stream until it; the check is on what the path resolves to."""
    device = tmp_path / "enrichment-bundle.tar.gz"
    device.symlink_to("/dev/null")
    _assert_refused(device, site, "not a regular file")


def test_a_tampered_journal_cannot_roll_foreign_files_in(tmp_path: Path, site: Path) -> None:
    """The rollback moves files *into* the data directory, so the journal that
    drives it may name only one of our own backup directories."""
    outside = tmp_path / "outside"
    (outside / "kev").mkdir(parents=True)
    (outside / "kev" / "kev-overlay.json").write_text("planted", encoding="utf-8")
    (site / enrichment_bundle.JOURNAL).write_text(
        json.dumps({"backup": "../outside", "files": [{"path": KEV, "had_previous": True}]}),
        encoding="utf-8",
    )
    before = (site / KEV).read_bytes()

    enrichment_bundle.recover(site)

    assert (site / KEV).read_bytes() == before
    assert (outside / "kev" / "kev-overlay.json").read_text(encoding="utf-8") == "planted"
    assert not (site / enrichment_bundle.JOURNAL).exists()


def test_a_symlinked_dataset_directory_on_the_volume_is_not_written_through(bundle: Path, site: Path, tmp_path: Path) -> None:
    """Belt and braces for the volume side: if something replaced ``epss/``
    with a link, the installer refuses rather than writing where it points."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (site / "epss").symlink_to(elsewhere, target_is_directory=True)
    _assert_refused(bundle, site, "not a plain directory")
    assert list(elsewhere.iterdir()) == []


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(REPO_ROOT / "scripts" / "enrichment_bundle.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_build_verify_install_status(tmp_path: Path) -> None:
    data = _data_dir(tmp_path)
    out = tmp_path / "b.tar.gz"
    assert _cli("build", "--dir", str(data), "-o", str(out)).returncode == 0
    verified = _cli("verify", str(out))
    assert verified.returncode == 0, verified.stderr
    assert "OK" in verified.stdout
    installed = _cli("install", str(out), "--dir", str(tmp_path / "site"))
    assert installed.returncode == 0, installed.stderr
    summary = json.loads(installed.stdout.strip().splitlines()[-1])
    assert summary["installed"] is True
    status = _cli("status", "--dir", str(tmp_path / "site"))
    assert json.loads(status.stdout)["bundle_id"] == summary["bundle_id"]


def test_cli_rejects_with_exit_1_and_says_nothing_changed(tmp_path: Path, site: Path) -> None:
    bundle_path = _kev_bundle(tmp_path, extra=[_member("kev/extra.json", b"{}")])
    proc = _cli("install", str(bundle_path), "--dir", str(site))
    assert proc.returncode == enrichment_bundle.EXIT_REJECTED
    assert "nothing under" in proc.stderr
    assert json.loads(proc.stdout.strip())["event"] == "enrichment.bundle.rejected"
    assert _cli("verify", str(bundle_path)).returncode == enrichment_bundle.EXIT_REJECTED


def test_cli_missing_ok_is_how_the_scheduled_loader_idles(tmp_path: Path) -> None:
    proc = _cli("install", str(tmp_path / "absent.tar.gz"), "--dir", str(tmp_path / "site"), "--missing-ok")
    assert proc.returncode == 0
    assert "nothing to do" in proc.stdout
    assert _cli("install", str(tmp_path / "absent.tar.gz"), "--dir", str(tmp_path / "site")).returncode == 2


def test_the_connected_side_builds_a_bundle_from_mirrors_end_to_end(mirror, tmp_path: Path) -> None:  # noqa: F811
    """`make enrichment-bundle`'s script, every feed on a mirror, then the
    install on the other side: the whole round trip, with no internet."""
    from tests.test_air_gap_feeds import _env, _nvd_page

    feeds = tmp_path / "mirror"
    feeds.mkdir()
    csv = "#model_version:v2025.03.14,score_date:2026-09-20T00:00:00+0000\ncve,epss,percentile\n" + "".join(
        f"CVE-2026-{i:05d},0.1,0.5\n" for i in range(1200)
    )
    (feeds / "epss.csv.gz").write_bytes(gzip.compress(csv.encode()))
    (feeds / "kev.json").write_text(
        json.dumps({"dateReleased": "2026-09-19", "vulnerabilities": [{"cveID": f"CVE-2026-{i:05d}"} for i in range(150)]}),
        encoding="utf-8",
    )
    (feeds / "files_exploits.csv").write_text("id,codes\n1,CVE-2026-00001\n", encoding="utf-8")
    (feeds / "msf.json").write_text("{}", encoding="utf-8")
    mirror.files["/nvd"] = _nvd_page()
    work, out = tmp_path / "work", tmp_path / "dist" / "enrichment-bundle.tar.gz"

    proc = subprocess.run(  # noqa: S603 - fixed argv
        ["bash", "scripts/build-enrichment-bundle.sh"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
        env=_env(
            ENRICHMENT_BUILD_DIR=str(work),
            ENRICHMENT_BUNDLE=str(out),
            OCTO_ENRICHMENT_SEED_DIR=str(REPO_ROOT / "scanner" / "data"),
            EPSS_URL=(feeds / "epss.csv.gz").as_uri(),
            KEV_URL=(feeds / "kev.json").as_uri(),
            GEOIP_URL=GEOIP_FIXTURE.as_uri(),
            ASN_URL=GEOIP_FIXTURE.as_uri(),
            NVD_API_URL=f"{mirror.base}/nvd",
            EXPLOITDB_CSV_URL=(feeds / "files_exploits.csv").as_uri(),
            METASPLOIT_MODULES_URL=(feeds / "msf.json").as_uri(),
        ),
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    manifest = json.loads((work / "enrichment-manifest.json").read_text(encoding="utf-8"))
    for name in ("epss", "kev", "cvss4", "exploit", "geoip", "asn"):
        assert manifest["datasets"][name]["origin"] == "fetch", name
    assert manifest["datasets"]["geoip"]["origin_urls"] == [GEOIP_FIXTURE.as_uri()]

    site = tmp_path / "site"
    summary = enrichment_bundle.install(out, site)
    installed = json.loads((site / "enrichment-manifest.json").read_text(encoding="utf-8"))
    assert summary["installed"] is True
    assert installed["datasets"]["epss"]["origin"] == "bundle"
    assert installed["datasets"]["epss"]["updated"] == "2026-09-20"
    assert installed["datasets"]["geoip"]["origin_urls"] == [GEOIP_FIXTURE.as_uri()]
    record = json.loads((site / enrichment_bundle.INSTALLED_RECORD).read_text(encoding="utf-8"))
    by_dataset = {entry["dataset"]: entry for entry in record["files"]}
    assert by_dataset["cvss4"]["source_urls"] == [f"{mirror.base}/nvd"]


def test_padding_past_the_archive_cannot_expand_without_bound(tmp_path: Path, site: Path) -> None:
    """Zeros after the end-of-archive marker are legal tar padding — up to a
    record. 32 MiB of them gzip to almost nothing and would sail under any
    ratio check done on the manifest alone; the metered stream stops them."""
    data = _kev(500)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for info, payload in (
            _member(enrichment_bundle.MANIFEST_MEMBER, _manifest([_entry(KEV, data, "kev")])),
            _member(KEV, data),
        ):
            archive.addfile(info, io.BytesIO(payload))
    padded = raw.getvalue() + bytes(32 * 1024 * 1024)
    _assert_refused(_write(tmp_path, gzip.compress(padded, mtime=0)), site, "expands past")


# --------------------------------------------------------------------------
# The Kubernetes loader
# --------------------------------------------------------------------------


K8S = REPO_ROOT / "k8s" / "shapoclyack"


def _docs(path: Path) -> list[dict]:
    import yaml

    return [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]


def test_the_base_service_accounts_carry_the_registry_pull_secret() -> None:
    """On the ServiceAccounts, so no workload manifest has to name it (#339)."""
    accounts = {doc["metadata"]["name"]: doc for doc in _docs(K8S / "base" / "serviceaccount.yaml")}
    assert set(accounts) == {"scanner", "api"}
    for account in accounts.values():
        assert account["imagePullSecrets"] == [{"name": "shapoclyack-registry"}]
    loader = _docs(K8S / "base" / "enrichment-bundle" / "serviceaccount.yaml")[0]
    assert loader["imagePullSecrets"] == [{"name": "shapoclyack-registry"}]
    assert loader["automountServiceAccountToken"] is False


def _loader_pod() -> dict:
    cronjob = _docs(K8S / "base" / "enrichment-bundle" / "cronjob.yaml")[0]
    return cronjob["spec"]["jobTemplate"]["spec"]["template"]["spec"]


@pytest.mark.parametrize(
    "pod",
    [_loader_pod(), _docs(K8S / "examples" / "enrichment-bundle-inbox.example.yaml")[0]["spec"]],
    ids=["loader-cronjob", "inbox-helper-pod"],
)
def test_the_new_workloads_meet_the_hardened_baseline(pod: dict) -> None:
    assert pod["automountServiceAccountToken"] is False
    assert pod["serviceAccountName"] == "enrichment-bundle"
    assert pod["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    for container in pod["containers"]:
        context = container["securityContext"]
        assert context["allowPrivilegeEscalation"] is False
        assert context["readOnlyRootFilesystem"] is True
        assert context["capabilities"] == {"drop": ["ALL"]}
        assert "@sha256:" in container["image"]
        mounts = {m["mountPath"]: m for m in container["volumeMounts"]}
        assert "/tmp" in mounts  # the writable path a read-only root needs
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert "emptyDir" in volumes["tmp"]


def test_the_loader_reads_the_inbox_read_only_and_idles_without_a_bundle() -> None:
    pod = _loader_pod()
    (container,) = pod["containers"]
    mounts = {m["name"]: m for m in container["volumeMounts"]}
    assert mounts["inbox"]["readOnly"] is True
    assert mounts["enrichment-data"]["mountPath"] == "/app/scanner/data"
    assert container["command"][:3] == ["python3", "scripts/enrichment_bundle.py", "install"]
    assert "--missing-ok" in container["command"]
    volumes = {v["name"]: v for v in pod["volumes"]}
    assert volumes["inbox"]["persistentVolumeClaim"] == {"claimName": "enrichment-bundle-inbox", "readOnly": True}


def test_the_airgap_component_stops_every_online_refresh() -> None:
    """Both online refresh paths would fail offline and then demote the
    bundle's provenance to `stale`: the CronJob is suspended and the API's
    initContainer runs offline."""
    component = K8S / "base" / "enrichment-bundle"
    suspend = _docs(component / "cronjob-refresh-suspend-patch.yaml")[0]
    assert suspend["metadata"]["name"] == "enrichment-refresh"
    assert suspend["spec"]["suspend"] is True
    api = _docs(component / "api-offline-patch.yaml")[0]
    (init,) = api["spec"]["template"]["spec"]["initContainers"]
    assert init["name"] == "fetch-enrichment"
    assert {"name": "OCTO_ENRICHMENT_OFFLINE", "value": "true"} in init["env"]
    overlay = _docs(K8S / "overlays" / "airgap" / "kustomization.yaml")[0]
    assert overlay["components"] == ["../../base/enrichment", "../../base/enrichment-bundle"]
