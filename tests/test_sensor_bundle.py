"""Signed sensor bundle: build, publish, verify, install, roll back (#363).

The update path must not trust a bundle because the configured server sent it.
These tests sign real bundles with a real ECDSA P-256 key generated here (the
algorithm cosign's release key uses), tamper with them byte by byte, and run
the install and its rollback on real directories -- including a process killed
half-way through, in a child process, so the journal is exercised the way a
crash leaves it rather than the way a test would like it left.
"""

from __future__ import annotations

import base64
import contextlib
import http.server
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import tracemalloc
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from agent import logging_setup, update
from agent.worker import AgentClient
from api.services import version_compare
from scripts import sensor_bundle as bundle_builder
from tests.conftest import bearer, configured_client, login, requires_postgres

REPO_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# Helpers: a key, an agent tree, a signed bundle
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def signing_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _sign(key: ec.EllipticCurvePrivateKey, data: bytes) -> str:
    """What ``cosign sign-blob --output-signature`` writes: base64 DER."""
    return base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode("ascii")


def _pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _agent_tree(root: Path, version: str, *, worker: str = "MARKER = 'ok'\n") -> Path:
    source = root / f"src-{version}" / "agent"
    source.mkdir(parents=True)
    (source / "__init__.py").write_text(f'__version__ = "{version}"  # test build\n')
    (source / "worker.py").write_text(worker)
    return source


def _bundle(root: Path, key: ec.EllipticCurvePrivateKey, version: str, **tree: str) -> Path:
    """A signed bundle directory, built by the release script itself."""
    out = root / f"bundle-{version}"
    bundle_builder.build(_agent_tree(root, version, **tree), out, revision="test")
    manifest = (out / update.MANIFEST_NAME).read_bytes()
    (out / update.SIGNATURE_NAME).write_text(_sign(key, manifest) + "\n")
    return out


def _verified(bundle: Path, key: ec.EllipticCurvePrivateKey) -> tuple[update.Manifest, Path]:
    return update._read_bundle_dir(bundle, key.public_key())


def _installed(root: Path, version: str) -> Path:
    """An install directory as scripts/install-agent.sh leaves it: a plain ``agent``."""
    install = root / "install"
    install.mkdir()
    shutil.copytree(_agent_tree(root / "old", version), install / "agent")
    return install


def _live_version(install: Path) -> str:
    return update.read_package_version(install / "agent")


# --------------------------------------------------------------------------
# The pinned key
# --------------------------------------------------------------------------


def test_the_pinned_key_is_the_repositorys_release_key():
    """The sensor pins ``cosign.pub``; a rotation that updates one and not the
    other would ship sensors that refuse every bundle the pipeline signs."""
    pinned = update.RELEASE_PUBLIC_KEY_PEM.decode().split()
    assert pinned == (REPO_ROOT / "cosign.pub").read_text().split()
    assert isinstance(update.load_public_key(), ec.EllipticCurvePublicKey)


def test_a_key_of_another_type_is_not_accepted_as_an_override(tmp_path):
    other = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "other.pub"
    path.write_bytes(other)
    with pytest.raises(update.BundleRefused, match="P-256"):
        update.load_public_key(path)


# --------------------------------------------------------------------------
# Signature and digest
# --------------------------------------------------------------------------


def test_a_signed_bundle_verifies(tmp_path, signing_key):
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.50-1001"), signing_key)
    update.verify_archive(archive, manifest)
    assert manifest.version == "0.50-1001"


def test_one_flipped_byte_in_the_manifest_is_refused(tmp_path, signing_key):
    bundle = _bundle(tmp_path, signing_key, "0.50-1001")
    raw = bytearray((bundle / update.MANIFEST_NAME).read_bytes())
    # The version digit: exactly what a downgrade-by-relabelling would change.
    index = raw.index(b'"0.50-1001"') + 4
    raw[index] ^= 0x01
    (bundle / update.MANIFEST_NAME).write_bytes(bytes(raw))
    with pytest.raises(update.BundleRefused, match="signature does not verify"):
        _verified(bundle, signing_key)


def test_one_flipped_byte_in_the_archive_is_refused(tmp_path, signing_key):
    bundle = _bundle(tmp_path, signing_key, "0.50-1001")
    manifest, archive = _verified(bundle, signing_key)
    raw = bytearray(archive.read_bytes())
    raw[len(raw) // 2] ^= 0x01
    archive.write_bytes(bytes(raw))
    with pytest.raises(update.BundleRefused, match="sha256"):
        update.verify_archive(archive, manifest)


def test_a_bundle_signed_by_another_key_is_refused(tmp_path, signing_key):
    """The attacker's case: they hold the server, not the release key."""
    impostor = ec.generate_private_key(ec.SECP256R1())
    bundle = _bundle(tmp_path, impostor, "0.50-1001")
    with pytest.raises(update.BundleRefused, match="signature does not verify"):
        _verified(bundle, signing_key)


def test_an_empty_or_garbled_signature_is_refused(tmp_path, signing_key):
    bundle = _bundle(tmp_path, signing_key, "0.50-1001")
    for bad in ("", "not base64 at all!", base64.b64encode(b"\x30\x00").decode()):
        (bundle / update.SIGNATURE_NAME).write_text(bad)
        with pytest.raises(update.BundleRefused):
            _verified(bundle, signing_key)


def test_another_document_signed_by_the_release_key_is_not_a_bundle(signing_key):
    """The release key signs image payloads too. A valid signature over some
    other JSON must not read as a bundle manifest."""
    other = json.dumps({"critical": {"type": "cosign container image signature"}}).encode()
    with pytest.raises(update.BundleRefused, match="not a sensor bundle manifest"):
        update.verify_manifest(other, _sign(signing_key, other), signing_key.public_key())


def test_an_archive_name_with_a_path_is_refused_even_when_signed(signing_key):
    manifest = json.dumps(
        {
            "schema": update.SCHEMA,
            "version": "0.50-1001",
            "archive": "../../etc/cron.d/x.tar.gz",
            "sha256": "0" * 64,
            "size": 10,
        }
    ).encode()
    with pytest.raises(update.BundleRefused, match="archive"):
        update.verify_manifest(manifest, _sign(signing_key, manifest), signing_key.public_key())


def test_the_cosign_cli_signature_verifies_here(tmp_path):
    """Interop with the tool the pipeline signs with, not with a re-implementation
    of it: a key made by ``cosign generate-key-pair``, a signature written by
    ``cosign sign-blob``, verified by the sensor's code."""
    cosign = shutil.which("cosign")
    if cosign is None:
        pytest.skip("cosign is not installed")
    env = {**os.environ, "COSIGN_PASSWORD": "test-only"}
    subprocess.run([cosign, "generate-key-pair"], cwd=tmp_path, env=env, check=True, capture_output=True)
    bundle_builder.build(_agent_tree(tmp_path, "0.50-1001"), tmp_path / "b")
    manifest = tmp_path / "b" / update.MANIFEST_NAME
    subprocess.run(
        [cosign, "sign-blob", "--yes", "--key", "cosign.key", "--tlog-upload=false",
         "--use-signing-config=false", "--new-bundle-format=false", "--output-signature", str(tmp_path / "b" / update.SIGNATURE_NAME), str(manifest)],
        cwd=tmp_path, env=env, check=True, capture_output=True,
    )
    key = update.load_public_key(tmp_path / "cosign.pub")
    verified, archive = update._read_bundle_dir(tmp_path / "b", key)
    update.verify_archive(archive, verified)
    manifest.write_bytes(manifest.read_bytes().replace(b"0.50-1001", b"0.50-1002"))
    with pytest.raises(update.BundleRefused):
        update._read_bundle_dir(tmp_path / "b", key)


def test_the_bundle_build_is_reproducible(tmp_path):
    source = _agent_tree(tmp_path, "0.50-1001")
    first = bundle_builder.build(source, tmp_path / "a")
    second = bundle_builder.build(source, tmp_path / "b")
    assert first["sha256"] == second["sha256"]
    with tarfile.open(tmp_path / "a" / first["archive"]) as tar:
        assert sorted(tar.getnames()) == ["agent", "agent/__init__.py", "agent/worker.py"]


# --------------------------------------------------------------------------
# Versions: no downgrade, no install below the floor
# --------------------------------------------------------------------------


def test_a_downgrade_is_refused_even_with_a_valid_signature():
    """A replayed older bundle carries a genuine signature; the version is
    what stops it."""
    with pytest.raises(update.BundleRefused, match="downgrades are refused"):
        update.check_version_policy("0.45-0901", current="0.46-0922", min_versions=[])


def test_the_installed_version_is_nothing_to_do():
    with pytest.raises(update.NothingToDo):
        update.check_version_policy("0.46-0922", current="0.46-0922", min_versions=[])


def test_a_bundle_below_the_minimum_is_refused():
    with pytest.raises(update.BundleRefused, match="below the required minimum 0.48-1001"):
        update.check_version_policy("0.47-0930", current="0.46-0922", min_versions=["", "0.48-1001"])
    update.check_version_policy("0.48-1001", current="0.46-0922", min_versions=["0.48-1001"])


def test_an_unknown_installed_version_refuses_rather_than_assumes():
    with pytest.raises(update.BundleRefused, match="cannot order"):
        update.check_version_policy("0.47-0930", current="", min_versions=[])


@pytest.mark.parametrize(
    ("left", "right"),
    [
        ("0.3.2.1", "0.44-0907"),
        ("0.44-0907", "0.44-0907"),
        ("0.44-0907-beta1", "0.44-0907"),
        ("0.44-0907", "0.45-0101"),
        ("0.46-0922", "0.46-0923"),
        ("1:0.1", "0.99"),
        ("1.0~rc1", "1.0"),
        ("0.44-0907-rc2", "0.44-0907-rc10"),
    ],
)
def test_sensor_ordering_agrees_with_the_api(left, right):
    """The sensor refuses exactly what ``OCTO_AGENT_MIN_VERSION`` refuses on the API."""
    expected = version_compare.compare_dpkg_version(left, right)
    assert update.compare_versions(left, right) == expected
    assert update.compare_versions(right, left) == -expected


# --------------------------------------------------------------------------
# Archive hygiene
# --------------------------------------------------------------------------


def _hostile_archive(path: Path, member: tarfile.TarInfo, data: bytes = b"") -> None:
    import io

    with tarfile.open(path, "w:gz") as tar:
        tar.addfile(member, io.BytesIO(data) if data else None)


@pytest.mark.parametrize(
    "member",
    [
        tarfile.TarInfo("agent/../../escape.py"),
        tarfile.TarInfo("/agent/abs.py"),
        tarfile.TarInfo("scanner/other.py"),
    ],
)
def test_members_outside_the_agent_package_are_refused(tmp_path, member):
    member.size = 1
    _hostile_archive(tmp_path / "x.tar.gz", member, b"x")
    (tmp_path / "dest").mkdir()
    with pytest.raises(update.BundleRefused):
        update.extract_agent_package(tmp_path / "x.tar.gz", tmp_path / "dest")
    assert not (tmp_path / "escape.py").exists()


def test_a_symlink_member_is_refused(tmp_path):
    link = tarfile.TarInfo("agent/worker.py")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/shadow"
    _hostile_archive(tmp_path / "x.tar.gz", link)
    (tmp_path / "dest").mkdir()
    with pytest.raises(update.BundleRefused, match="not a regular file"):
        update.extract_agent_package(tmp_path / "x.tar.gz", tmp_path / "dest")


# --------------------------------------------------------------------------
# Atomic install and rollback, on real directories
# --------------------------------------------------------------------------


def test_install_swaps_in_the_new_release_and_keeps_the_previous(tmp_path, signing_key):
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    update.verify_archive(archive, manifest)

    live = update.Installer(install).install(archive, manifest)

    assert (install / "agent").is_symlink()
    assert os.readlink(install / "agent") == live
    assert _live_version(install) == "0.47-0930"
    # The interpreter the service will start sees the new tree through the link.
    update.import_check(sys.executable, install, "0.47-0930")
    releases = sorted(p.name for p in (install / "releases").iterdir())
    assert len(releases) == 2 and any(name.startswith("legacy-0.46-0922-") for name in releases)
    assert not (install / ".sensor-update.json").exists()


def test_a_failed_health_check_puts_the_previous_release_back(tmp_path, signing_key):
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    restarts: list[str] = []
    seen: list[str] = []

    def unhealthy() -> None:
        seen.append(_live_version(install))
        raise RuntimeError("unit restarted on its own")

    def restart() -> None:
        # The unit is restarted while the tree it ran from is still there.
        new = [p for p in (install / "releases").iterdir() if p.name.startswith("0.47-0930-")]
        restarts.append(f"restart with {len(new)} new tree")

    installer = update.Installer(install, health_check=unhealthy, on_rollback=restart)
    with pytest.raises(update.UpdateFailed, match="rolled back"):
        installer.install(archive, manifest)

    assert seen == ["0.47-0930"]  # the check ran against the new code ...
    assert _live_version(install) == "0.46-0922"  # ... and the old one is back
    assert restarts == ["restart with 1 new tree"]
    assert [p.name for p in (install / "releases").iterdir() if not p.name.startswith("legacy-")] == []
    assert not (install / ".sensor-update.json").exists()


def test_a_release_that_does_not_import_never_goes_live(tmp_path, signing_key):
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(
        _bundle(tmp_path, signing_key, "0.47-0930", worker="raise ImportError('broken')\n"),
        signing_key,
    )
    with pytest.raises(update.UpdateFailed, match="does not import"):
        update.Installer(install).install(archive, manifest)
    assert not (install / "agent").is_symlink()
    assert _live_version(install) == "0.46-0922"


def test_an_archive_whose_package_disagrees_with_the_signed_version_is_refused(tmp_path, signing_key):
    """Signed as 0.47 but built from a 0.45 tree: refused before the swap."""
    install = _installed(tmp_path, "0.46-0922")
    out = tmp_path / "mislabelled"
    built = bundle_builder.build(_agent_tree(tmp_path, "0.45-0901"), out)
    raw = json.dumps({**built, "version": "0.47-0930"}).encode()
    (out / update.MANIFEST_NAME).write_bytes(raw)
    (out / update.SIGNATURE_NAME).write_text(_sign(signing_key, raw))
    manifest, archive = _verified(out, signing_key)
    with pytest.raises(update.BundleRefused, match="version 0.45-0901"):
        update.Installer(install).install(archive, manifest)
    assert _live_version(install) == "0.46-0922"


def test_a_failure_in_the_swap_itself_leaves_the_old_release_live(tmp_path, signing_key, monkeypatch):
    install = _installed(tmp_path, "0.46-0922")
    first, first_archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    update.Installer(install).install(first_archive, first)
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.48-1001"), signing_key)

    real_replace = os.replace
    calls = {"n": 0}

    def failing_replace(src, dst, *args, **kwargs):
        # The first replace onto ``agent`` is the swap to the new release.
        if Path(dst) == install / "agent" and calls["n"] == 0:
            calls["n"] += 1
            raise OSError(28, "No space left on device")
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr(update.os, "replace", failing_replace)
    with pytest.raises(update.UpdateFailed, match="No space left"):
        update.Installer(install).install(archive, manifest)
    assert _live_version(install) == "0.47-0930"
    assert not list(install.glob(".agent.*"))
    assert not (install / ".sensor-update.json").exists()


_CRASH_SCRIPT = """
import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from agent import update
raw = Path(sys.argv[3]).read_bytes()
data = json.loads(raw)
manifest = update.Manifest(version=data["version"], archive=data["archive"],
                           sha256=data["sha256"], size=data["size"], raw=raw)
# Killed after the swap, before the verdict: no except, no finally runs.
update.Installer(Path(sys.argv[2]), health_check=lambda: os._exit(9)).install(
    Path(sys.argv[4]), manifest)
"""


def test_a_process_killed_mid_update_is_rolled_back_by_the_next_run(tmp_path, signing_key):
    install = _installed(tmp_path, "0.46-0922")
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    manifest, archive = _verified(bundle, signing_key)

    crashed = subprocess.run(
        [sys.executable, "-c", _CRASH_SCRIPT, str(REPO_ROOT), str(install),
         str(bundle / update.MANIFEST_NAME), str(archive)],
        capture_output=True, text=True, check=False,
    )
    assert crashed.returncode == 9, crashed.stderr
    # What the crash left: the new code live, and a journal saying what was before.
    assert _live_version(install) == "0.47-0930"
    assert (install / ".sensor-update.json").exists()

    assert update.Installer(install).recover() is True
    assert _live_version(install) == "0.46-0922"
    assert not (install / ".sensor-update.json").exists()
    # And the next attempt goes through from there.
    update.Installer(install).install(archive, manifest)
    assert _live_version(install) == "0.47-0930"


def test_a_journal_naming_a_path_outside_releases_is_not_followed(tmp_path):
    install = _installed(tmp_path, "0.46-0922")
    (install / ".sensor-update.json").write_text(json.dumps({"previous": "../../etc"}))
    with pytest.raises(update.UpdateFailed, match="not a release path"):
        update.Installer(install).recover()


def _unhealthy() -> None:
    raise RuntimeError("unit restarted on its own")


def test_a_failed_release_is_recorded_by_its_signed_digest_not_its_version(tmp_path, signing_key):
    """A bundle re-signed under the same version after a fix is another
    bundle: the first one's failure must not keep ``--auto`` off it."""
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    installer = update.Installer(install, health_check=_unhealthy)
    with pytest.raises(update.UpdateFailed, match="rolled back"):
        installer.install(archive, manifest)
    assert installer.failed_before(manifest)

    respun, _ = _verified(
        _bundle(tmp_path / "respun", signing_key, "0.47-0930", worker="MARKER = 'fixed'\n"),
        signing_key,
    )
    assert (respun.version, respun.sha256 != manifest.sha256) == (manifest.version, True)
    assert not installer.failed_before(respun)


def test_a_release_kept_clears_the_record_of_its_earlier_failure(tmp_path, signing_key):
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    with pytest.raises(update.UpdateFailed):
        update.Installer(install, health_check=_unhealthy).install(archive, manifest)

    installer = update.Installer(install, health_check=lambda: None)
    installer.install(archive, manifest)
    assert _live_version(install) == "0.47-0930"
    assert not installer.failed_before(manifest)
    assert not list(install.glob(".sensor-update-failed*"))


def test_releases_put_back_do_not_pile_up(tmp_path, signing_key):
    """Every failed attempt used to leave a whole release behind until an
    update was kept; one taken out stays only while a process may run it."""
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    counts = []
    for _ in range(4):
        installer = update.Installer(install)
        taken_out = installer.install(archive, manifest, pending=True)
        assert installer.rollback() is True
        assert (install / taken_out).is_dir()  # the unit may still run it
        counts.append(len(list((install / "releases").iterdir())))
    assert counts == [2, 2, 2, 2]
    assert _live_version(install) == "0.46-0922"


def test_a_failed_restart_onto_the_previous_release_keeps_the_new_tree(tmp_path, signing_key, caplog):
    """The tree goes once the unit has left it; a restart that did not happen
    leaves the unit on it, and lazy imports in that process still need it."""
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)

    def restart_fails() -> None:
        raise RuntimeError("systemctl restart shapoclyack-agent.service failed")

    installer = update.Installer(install, health_check=_unhealthy, on_rollback=restart_fails)
    with pytest.raises(update.UpdateFailed, match="rolled back"):
        installer.install(archive, manifest)
    assert _live_version(install) == "0.46-0922"
    assert [p for p in (install / "releases").iterdir() if p.name.startswith("0.47-0930-")]
    assert "Restart after the rollback failed" in caplog.text


def _archive_of(path: Path, files: dict[str, bytes]) -> None:
    import io

    with tarfile.open(path, "w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_an_archive_unpacking_past_the_size_cap_is_refused(tmp_path, monkeypatch):
    """A gzip bomb is small on the wire; the cap is on what it unpacks to."""
    _archive_of(
        tmp_path / "x.tar.gz",
        {"agent/__init__.py": b'__version__ = "1"\n', "agent/big.py": b"#" * 4096},
    )
    monkeypatch.setattr(update, "MAX_UNPACKED_BYTES", 1024)
    (tmp_path / "dest").mkdir()
    with pytest.raises(update.BundleRefused, match="unpacks to more"):
        update.extract_agent_package(tmp_path / "x.tar.gz", tmp_path / "dest")


def test_an_archive_with_too_many_members_is_refused(tmp_path, monkeypatch):
    files = {"agent/__init__.py": b'__version__ = "1"\n'}
    files.update({f"agent/m{index}.py": b"" for index in range(4)})
    _archive_of(tmp_path / "x.tar.gz", files)
    monkeypatch.setattr(update, "MAX_MEMBERS", 3)
    (tmp_path / "dest").mkdir()
    with pytest.raises(update.BundleRefused, match="too many members"):
        update.extract_agent_package(tmp_path / "x.tar.gz", tmp_path / "dest")


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_a_link_or_device_member_is_refused_not_only_a_symlink(tmp_path, kind):
    """Regular files and directories only: a hard link, a FIFO or a device is
    not a symlink and is still not something a release is made of."""
    import io

    path = tmp_path / "x.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        init = b'__version__ = "1"\n'
        info = tarfile.TarInfo("agent/__init__.py")
        info.size = len(init)
        tar.addfile(info, io.BytesIO(init))
        odd = tarfile.TarInfo("agent/odd.py")
        odd.type = kind
        odd.linkname = "agent/__init__.py" if kind == tarfile.LNKTYPE else ""
        tar.addfile(odd)
    (tmp_path / "dest").mkdir()
    with pytest.raises(update.BundleRefused, match="not a regular file"):
        update.extract_agent_package(path, tmp_path / "dest")


def test_the_bytes_hashed_are_the_bytes_unpacked(tmp_path, signing_key, monkeypatch):
    """Whoever can write the download directory swaps the archive between the
    digest check and the unpack. What goes live is still what was verified."""
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    evil = next(_bundle(tmp_path / "evil", signing_key, "0.47-0930", worker="MARKER = 'evil'\n").glob("*.tar.gz"))
    real_read = update.read_verified_archive

    def read_then_swap(path, signed):
        data = real_read(path, signed)
        shutil.copyfile(evil, path)
        return data

    monkeypatch.setattr(update, "read_verified_archive", read_then_swap)
    update.Installer(install).install(archive, manifest)
    assert (install / "agent" / "worker.py").read_text() == "MARKER = 'ok'\n"


def test_the_import_check_ignores_the_callers_pythonpath(tmp_path, signing_key, monkeypatch):
    """A release that imports only because of something on the updater's own
    ``PYTHONPATH`` would not import under the unit."""
    crutch = tmp_path / "crutch"
    crutch.mkdir()
    (crutch / "i363_only_on_pythonpath.py").write_text("")
    monkeypatch.setenv("PYTHONPATH", str(crutch))
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(
        _bundle(tmp_path, signing_key, "0.47-0930", worker="import i363_only_on_pythonpath\n"),
        signing_key,
    )
    with pytest.raises(update.UpdateFailed, match="does not import"):
        update.Installer(install).install(archive, manifest)
    assert _live_version(install) == "0.46-0922"


def test_a_releases_symlink_is_not_installed_through(tmp_path, signing_key):
    install = _installed(tmp_path, "0.46-0922")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (install / "releases").symlink_to(elsewhere)
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    with pytest.raises(update.UpdateFailed, match="is a symlink"):
        update.Installer(install).install(archive, manifest)
    assert list(elsewhere.iterdir()) == []
    assert _live_version(install) == "0.46-0922"


def test_commit_refuses_when_the_live_release_is_not_the_pending_one(tmp_path, signing_key):
    """Something put the old release back between swap and verdict: keeping
    "the pending release" would drop the journal for a release that is not live."""
    install = _installed(tmp_path, "0.46-0922")
    manifest, archive = _verified(_bundle(tmp_path, signing_key, "0.47-0930"), signing_key)
    installer = update.Installer(install)
    installer.install(archive, manifest, pending=True)
    journal = json.loads((install / ".sensor-update.json").read_text())
    installer._point_at(journal["previous"])
    with pytest.raises(update.UpdateFailed, match="not the pending release"):
        installer.commit()
    assert (install / ".sensor-update.json").exists()


# --------------------------------------------------------------------------
# The systemd health check, against a systemctl that behaves like one
# --------------------------------------------------------------------------

_FAKE_SYSTEMCTL = """#!/bin/sh
# A systemctl for one unit. MODE=stable keeps the main PID after a restart;
# MODE=crashloop hands out a new one on every look, as Restart=always does;
# MODE=norestart refuses the restart itself.
state="$FAKE_SYSTEMD_DIR"
case "$1" in
  restart)
    echo restart >> "$state/calls"
    [ "$(cat "$state/mode")" = norestart ] && exit 1
    echo 100 > "$state/pid"; exit 0 ;;
  is-active) [ "$(cat "$state/mode")" = inactive ] && exit 3; exit 0 ;;
  cat) exit 0 ;;
  show)
    pid=$(cat "$state/pid")
    if [ "$(cat "$state/mode")" = crashloop ]; then echo $((pid + 1)) > "$state/pid"; fi
    echo "$pid"; exit 0 ;;
esac
exit 1
"""


def _fake_systemd(tmp_path: Path, monkeypatch, mode: str) -> Path:
    state = tmp_path / "systemd"
    state.mkdir()
    (state / "mode").write_text(mode)
    (state / "pid").write_text("1")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "systemctl").write_text(_FAKE_SYSTEMCTL)
    (bin_dir / "systemctl").chmod(0o755)
    monkeypatch.setenv("FAKE_SYSTEMD_DIR", str(state))
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return state


def test_a_unit_that_stays_up_passes_the_health_check(tmp_path, monkeypatch):
    state = _fake_systemd(tmp_path, monkeypatch, "stable")
    update.systemd_health_check("shapoclyack-agent.service", 1.0)()
    assert (state / "calls").read_text().split() == ["restart"]


def test_a_unit_that_is_not_active_fails_the_health_check(tmp_path, monkeypatch):
    _fake_systemd(tmp_path, monkeypatch, "inactive")
    with pytest.raises(RuntimeError, match="not active"):
        update.systemd_health_check("shapoclyack-agent.service", 1.0)()


def test_a_unit_in_a_restart_loop_fails_the_health_check(tmp_path, monkeypatch):
    """``Restart=always`` keeps a crashing unit "active"; the PID changing is the tell."""
    _fake_systemd(tmp_path, monkeypatch, "crashloop")
    with pytest.raises(RuntimeError, match="restarted on its own"):
        update.systemd_health_check("shapoclyack-agent.service", 1.0)()


# --------------------------------------------------------------------------
# The CLI, end to end from a bundle directory
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _keep_logging_as_it_was(monkeypatch):
    """``update.main`` configures the root logger, as a CLI should. Left in
    place it turns on INFO records for every later test in the session, and
    tests that count ``time.time()`` calls then see logging consume them."""
    monkeypatch.setattr(logging_setup, "configure_logging", lambda **_kwargs: None)


def _cli_install(tmp_path: Path, version: str) -> Path:
    install = _installed(tmp_path, version)
    venv_bin = install / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(sys.executable)
    return install


def _run_cli(install: Path, bundle: Path, key_file: Path, monkeypatch, *extra: str) -> int:
    monkeypatch.setenv(update.PUBKEY_FILE_ENV, str(key_file))
    monkeypatch.setattr(update, "_systemd_unit_present", lambda unit: False)
    return update.main(
        ["--install-dir", str(install), "--env-file", str(install / "missing.env"),
         "--bundle-dir", str(bundle), *extra]
    )


def test_cli_installs_a_signed_upgrade(tmp_path, signing_key, monkeypatch):
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    assert _run_cli(install, _bundle(tmp_path, signing_key, "0.47-0930"), key_file, monkeypatch) == 0
    assert _live_version(install) == "0.47-0930"


def test_cli_refuses_a_downgrade_and_changes_nothing(tmp_path, signing_key, monkeypatch):
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    assert _run_cli(install, _bundle(tmp_path, signing_key, "0.45-0901"), key_file, monkeypatch) == 1
    assert _live_version(install) == "0.46-0922"
    assert not (install / "agent").is_symlink()


def test_cli_refuses_a_bundle_below_the_local_floor(tmp_path, signing_key, monkeypatch):
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    monkeypatch.setenv(update.MIN_VERSION_ENV, "0.48-1001")
    assert _run_cli(install, _bundle(tmp_path, signing_key, "0.47-0930"), key_file, monkeypatch) == 1
    assert _live_version(install) == "0.46-0922"


def test_cli_refuses_a_bundle_the_pinned_key_did_not_sign(tmp_path, signing_key, monkeypatch):
    """No override: the key compiled into the package is the one that counts,
    and the test key is not the release key."""
    install = _cli_install(tmp_path, "0.46-0922")
    monkeypatch.delenv(update.PUBKEY_FILE_ENV, raising=False)
    monkeypatch.setattr(update, "_systemd_unit_present", lambda unit: False)
    code = update.main(
        ["--install-dir", str(install), "--env-file", str(install / "missing.env"),
         "--bundle-dir", str(_bundle(tmp_path, signing_key, "0.47-0930"))]
    )
    assert code == 1
    assert _live_version(install) == "0.46-0922"


def test_auto_mode_does_nothing_unless_opted_in(tmp_path, signing_key, monkeypatch):
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    monkeypatch.delenv(update.AUTO_UPDATE_ENV, raising=False)
    assert _run_cli(install, bundle, key_file, monkeypatch, "--auto") == 0
    assert _live_version(install) == "0.46-0922"
    monkeypatch.setenv(update.AUTO_UPDATE_ENV, "true")
    assert _run_cli(install, bundle, key_file, monkeypatch, "--auto") == 0
    assert _live_version(install) == "0.47-0930"


def test_a_crashed_update_is_rolled_back_even_when_the_bundle_is_still_current(
    tmp_path, signing_key, monkeypatch
):
    """The common crash: the run dies during the health check, and the server
    still offers the version that was swapped in. "Nothing to do" must not be
    the answer that leaves an unverified release live."""
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    manifest, archive = _verified(bundle, signing_key)
    installer = update.Installer(install)
    interrupted = installer.install(archive, manifest, pending=True)  # swapped, verdict never came
    assert _live_version(install) == "0.47-0930"

    # --check changes nothing, this included; it says what it found.
    assert _run_cli(install, bundle, key_file, monkeypatch, "--check") == 1
    assert _live_version(install) == "0.47-0930"
    # The next real run puts the previous release back first, and stops there
    # to have the service restarted onto it: that process still runs the
    # interrupted release, whose tree is therefore left in place.
    assert _run_cli(install, bundle, key_file, monkeypatch, "--pending") == update.EXIT_RECOVERED
    assert _live_version(install) == "0.46-0922"
    assert not (install / ".sensor-update.json").exists()
    assert (install / interrupted).is_dir()


def test_a_second_update_waits_for_the_first(tmp_path):
    install = _installed(tmp_path, "0.46-0922")
    with update.update_lock(install):
        with pytest.raises(update.UpdateFailed, match="another sensor update"):
            with update.update_lock(install):
                pass


def test_the_env_file_cannot_steer_the_root_side(tmp_path, signing_key, monkeypatch):
    """agent.env belongs to the sensor's account. A key override, a key file
    and a loader variable written there are not taken."""
    install = _cli_install(tmp_path, "0.46-0922")
    impostor = ec.generate_private_key(ec.SECP256R1())
    evil_key = tmp_path / "evil.pub"
    evil_key.write_bytes(_pem(impostor))
    env_file = tmp_path / "agent.env"
    env_file.write_text(
        f"{update.PUBKEY_FILE_ENV}={evil_key}\n"
        "OCTO_AGENT_PROVISIONING_KEY_FILE=/etc/shadow\n"
        "LD_PRELOAD=/tmp/x.so\n"
    )
    for name in (update.PUBKEY_FILE_ENV, "OCTO_AGENT_PROVISIONING_KEY_FILE", "LD_PRELOAD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(update, "_systemd_unit_present", lambda unit: False)
    code = update.main(
        ["--install-dir", str(install), "--env-file", str(env_file),
         "--bundle-dir", str(_bundle(tmp_path, impostor, "0.47-0930"))]
    )
    assert code == 1  # verified against the pinned key, not the planted one
    assert _live_version(install) == "0.46-0922"
    for name in (update.PUBKEY_FILE_ENV, "OCTO_AGENT_PROVISIONING_KEY_FILE", "LD_PRELOAD"):
        assert name not in os.environ


def test_the_server_floor_refuses_a_bundle_below_it(tmp_path, signing_key, monkeypatch):
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    archive = next(bundle.glob("*.tar.gz")).read_bytes()
    monkeypatch.setenv(update.PUBKEY_FILE_ENV, str(key_file))
    monkeypatch.setenv("OCTO_AGENT_TOKEN", "sensor-token")
    monkeypatch.delenv(update.MIN_VERSION_ENV, raising=False)
    monkeypatch.setattr(update, "_systemd_unit_present", lambda unit: False)
    with _fake_api(_metadata(bundle, min_version="0.48-1001"), archive) as url:
        monkeypatch.setenv("OCTO_API_URL", url)
        code = update.main(["--install-dir", str(install), "--env-file", str(tmp_path / "none")])
    assert code == 1
    assert _live_version(install) == "0.46-0922"


def test_root_will_not_run_the_update_over_a_tree_another_account_owns(tmp_path, signing_key, monkeypatch):
    """The accident guard: ``sudo python -m agent.update`` by hand, on a tree
    the sensor's account owns, stops before it touches anything."""
    install = _cli_install(tmp_path, "0.46-0922")
    assert install.stat().st_uid != 0
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    state = _fake_systemd(tmp_path, monkeypatch, "stable")
    monkeypatch.setenv(update.PUBKEY_FILE_ENV, str(key_file))
    monkeypatch.setattr(update.os, "geteuid", lambda: 0)
    code = update.main(
        ["--install-dir", str(install), "--env-file", str(install / "missing.env"),
         "--bundle-dir", str(_bundle(tmp_path, signing_key, "0.47-0930")), "--health-seconds", "1"]
    )
    assert code == 2
    assert _live_version(install) == "0.46-0922"
    assert not (state / "calls").exists()


def _systemd_cli(install: Path, bundle: Path, key_file: Path, monkeypatch, *extra: str) -> int:
    """``python -m agent.update`` as an operator running it with a unit present."""
    monkeypatch.setenv(update.PUBKEY_FILE_ENV, str(key_file))
    monkeypatch.setattr(update, "_systemd_unit_present", lambda unit: True)
    return update.main(
        ["--install-dir", str(install), "--env-file", str(install / "missing.env"),
         "--bundle-dir", str(bundle), "--health-seconds", "1", *extra]
    )


def test_cli_restarts_the_unit_onto_a_release_it_put_back(tmp_path, signing_key, monkeypatch):
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    state = _fake_systemd(tmp_path, monkeypatch, "stable")
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    manifest, archive = _verified(bundle, signing_key)
    update.Installer(install).install(archive, manifest, pending=True)

    assert _systemd_cli(install, bundle, key_file, monkeypatch) == 0
    # Onto the release put back first, then onto the one installed and checked.
    assert (state / "calls").read_text().split() == ["restart", "restart"]
    assert _live_version(install) == "0.47-0930"


def test_cli_stops_when_the_unit_does_not_restart_onto_a_release_it_put_back(
    tmp_path, signing_key, monkeypatch, caplog
):
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    state = _fake_systemd(tmp_path, monkeypatch, "norestart")
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    manifest, archive = _verified(bundle, signing_key)
    interrupted = update.Installer(install).install(archive, manifest, pending=True)

    assert _systemd_cli(install, bundle, key_file, monkeypatch) == 1
    assert "did not restart" in caplog.text
    assert _live_version(install) == "0.46-0922"
    # Nothing installed on top of a unit in an unknown state, and the tree it
    # may still run from is there.
    assert (state / "calls").read_text().split() == ["restart"]
    assert (install / interrupted).is_dir()


def test_abort_puts_an_interrupted_release_back_without_calling_it_failed(tmp_path, signing_key, monkeypatch):
    """What update-agent.sh runs when it is interrupted: the release was not
    judged, so ``--auto`` must not hold it against the next run."""
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    manifest, archive = _verified(bundle, signing_key)
    update.Installer(install).install(archive, manifest, pending=True)

    assert _run_cli(install, bundle, key_file, monkeypatch, "--abort") == update.EXIT_RECOVERED
    assert _live_version(install) == "0.46-0922"
    assert not (install / ".sensor-update.json").exists()
    assert not update.Installer(install).failed_before(manifest)
    assert _run_cli(install, bundle, key_file, monkeypatch, "--abort") == 0


@pytest.mark.parametrize("killed_in", ["_prune", "_clear_journal"])
def test_a_recovery_killed_half_way_still_asks_for_the_restart(tmp_path, signing_key, monkeypatch, killed_in):
    """The release is put back, and the run doing it dies before it can say
    so -- pruning old trees, or removing the journal. The unit still runs the
    release taken out, so the next ``--abort`` has to answer "restart" again,
    although ``agent`` already points where it should."""
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    manifest, archive = _verified(bundle, signing_key)
    update.Installer(install).install(archive, manifest, pending=True)

    def killed(*_args, **_kwargs):
        raise KeyboardInterrupt

    with monkeypatch.context() as patched:
        patched.setattr(update.Installer, killed_in, killed)
        with pytest.raises(KeyboardInterrupt):
            update.Installer(install).recover()
    assert _live_version(install) == "0.46-0922"

    assert _run_cli(install, bundle, key_file, monkeypatch, "--abort") == update.EXIT_RECOVERED
    assert not (install / ".sensor-update.json").exists()
    assert _run_cli(install, bundle, key_file, monkeypatch, "--abort") == 0


def test_commit_with_nothing_pending_is_not_a_success(tmp_path, monkeypatch):
    install = _cli_install(tmp_path, "0.46-0922")
    monkeypatch.setattr(update, "_systemd_unit_present", lambda unit: False)
    code = update.main(
        ["--install-dir", str(install), "--env-file", str(install / "missing.env"), "--commit"]
    )
    assert code == update.EXIT_NOTHING_TO_DO


# --------------------------------------------------------------------------
# scripts/update-agent.sh: root restarts, the account installs
# --------------------------------------------------------------------------

_FAKE_RUNUSER = """#!/bin/sh
# runuser -u USER -- CMD...: record who and what the command is attached to,
# then run CMD as ourselves.
echo "$2" >> "$FAKE_SYSTEMD_DIR/runuser"
"$FAKE_PYTHON" -c "$ATTACHMENT_PROBE"
shift 3
exec "$@"
"""

_FAKE_SU = """#!/bin/sh
# BusyBox su -s /bin/sh USER -c CMD: the same record, then CMD as ourselves.
echo "$3" >> "$FAKE_SYSTEMD_DIR/runuser"
"$FAKE_PYTHON" -c "$ATTACHMENT_PROBE"
exec /bin/sh -c "$5"
"""

#: What the sensor's process is attached to: its session, and what fds 0-2 are.
_ATTACHMENT_PROBE = """
import os, stat
null = os.stat(os.devnull).st_rdev
def kind(fd):
    st = os.fstat(fd)
    if stat.S_ISCHR(st.st_mode) and st.st_rdev == null:
        return "null"
    if os.isatty(fd):
        return "tty"
    return "fifo" if stat.S_ISFIFO(st.st_mode) else "file"
with open(os.path.join(os.environ["FAKE_SYSTEMD_DIR"], "attached"), "a") as out:
    print(os.getsid(0), kind(0), kind(1), kind(2), file=out)
"""

#: macOS has no setsid(1); this does what util-linux's does, -w included.
_FAKE_SETSID = """#!{python}
import os, sys
args = sys.argv[1:]
if args and args[0] in ("-w", "--wait"):
    args = args[1:]
if os.getpgrp() == os.getpid():
    child = os.fork()
    if child:
        sys.exit(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]))
os.setsid()
os.execvp(args[0], args)
"""


#: macOS has no flock(1) either. ``flock -n FD`` locks the open file the
#: script's descriptor names, so the lock stays when this process exits.
_FAKE_FLOCK = """#!{python}
import fcntl, sys
try:
    fcntl.flock(int(sys.argv[-1]), fcntl.LOCK_EX | (fcntl.LOCK_NB if "-n" in sys.argv else 0))
except BlockingIOError:
    sys.exit(1)
"""


def _real_agent_tree(root: Path, version: str) -> Path:
    tree = root / f"real-{version}" / "agent"
    shutil.copytree(REPO_ROOT / "agent", tree, ignore=shutil.ignore_patterns("__pycache__"))
    init = tree / "__init__.py"
    init.write_text(
        update._PACKAGE_VERSION_RE.sub(f'__version__ = "{version}"', init.read_text(), count=1)
    )
    return tree


def _script_stand(tmp_path: Path, monkeypatch, mode: str, key: ec.EllipticCurvePrivateKey):
    state = _fake_systemd(tmp_path, monkeypatch, mode)
    bin_dir = tmp_path / "bin"
    (bin_dir / "runuser").write_text(_FAKE_RUNUSER)
    (bin_dir / "runuser").chmod(0o755)
    if shutil.which("setsid") is None:
        (bin_dir / "setsid").write_text(_FAKE_SETSID.format(python=sys.executable))
        (bin_dir / "setsid").chmod(0o755)
    if shutil.which("flock") is None:
        (bin_dir / "flock").write_text(_FAKE_FLOCK.format(python=sys.executable))
        (bin_dir / "flock").chmod(0o755)
    install = tmp_path / "install"
    shutil.copytree(_real_agent_tree(tmp_path / "old", "0.46-0922"), install / "agent")
    venv_bin = install / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    # A wrapper, not a symlink: the venv is found from the path it is run by.
    (venv_bin / "python").write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n')
    (venv_bin / "python").chmod(0o755)
    conf = tmp_path / "etc"
    conf.mkdir()
    (conf / "agent.env").write_text("OCTO_API_URL=http://127.0.0.1:9\n")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(key))
    bundle = tmp_path / "bundle"
    bundle_builder.build(_real_agent_tree(tmp_path / "new", "0.47-0930"), bundle)
    manifest = (bundle / update.MANIFEST_NAME).read_bytes()
    (bundle / update.SIGNATURE_NAME).write_text(_sign(key, manifest))
    env = {
        **os.environ,
        "INSTALL_DIR": str(install),
        "CONF_DIR": str(conf),
        "HEALTH_SECONDS": "1",
        "LOCK_FILE": str(tmp_path / "update-agent.lock"),
        update.PUBKEY_FILE_ENV: str(key_file),
        "FAKE_PYTHON": sys.executable,
        "ATTACHMENT_PROBE": _ATTACHMENT_PROBE,
    }
    return install, bundle, state, env


def _run_script(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "update-agent.sh"), *args],
        env=env, capture_output=True, text=True, check=False, timeout=120,
    )


def test_auto_without_the_opt_in_restarts_nothing(tmp_path, signing_key, monkeypatch):
    """The timer left in place after ``OCTO_AGENT_AUTO_UPDATE`` was taken out
    of agent.env: every tick must be a no-op, not a restart mid-scan."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env.pop(update.AUTO_UPDATE_ENV, None)
    for _tick in range(2):
        done = _run_script(env, "--auto", "--bundle-dir", str(bundle))
        assert done.returncode == 0, done.stdout + done.stderr
        assert "kept" not in done.stdout + done.stderr
    assert not (state / "calls").exists()
    assert _live_version(install) == "0.46-0922"


def test_update_script_keeps_a_release_the_unit_stays_up_on(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert _live_version(install) == "0.47-0930"
    assert not (install / ".sensor-update.json").exists()
    assert (state / "calls").read_text().split() == ["restart"]
    # Every python the script started ran as the sensor's account.
    assert set((state / "runuser").read_text().split()) == {"shapoclyack"}
    # What changed is the agent package; scanner/ and the venv are not in the bundle.
    assert "agent package updated to 0.47-0930" in done.stdout


def test_update_script_puts_the_previous_release_back_on_a_crash_loop(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "crashloop", signing_key)
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 1
    assert "previous release is back" in done.stderr
    assert _live_version(install) == "0.46-0922"
    assert not (install / ".sensor-update.json").exists()
    # Restarted onto the new code, then onto the old one again. The new tree
    # stays until the next update that is kept: the unit ran from it until
    # that second restart, and lazy imports in a running process need it.
    assert (state / "calls").read_text().split() == ["restart", "restart"]
    assert not os.readlink(install / "agent").startswith("releases/0.47")


def test_update_script_restarts_nothing_for_a_refused_bundle(tmp_path, signing_key, monkeypatch):
    impostor = ec.generate_private_key(ec.SECP256R1())
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", impostor)
    env[update.PUBKEY_FILE_ENV] = str(tmp_path / "trusted.pub")
    (tmp_path / "trusted.pub").write_bytes(_pem(signing_key))
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 1
    assert "signature does not verify" in done.stdout + done.stderr
    assert _live_version(install) == "0.46-0922"
    assert not (state / "calls").exists()


def test_update_script_refuses_the_unsigned_bundle_url(tmp_path, signing_key, monkeypatch):
    _install, _bundle_dir, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    done = _run_script(env, "--bundle-url", "http://example.invalid/agent.tar.gz")
    assert done.returncode == 1
    assert "--bundle-url is gone" in done.stderr


@pytest.mark.parametrize("runner", ["runuser", "su"])
def test_update_script_detaches_the_sensors_code_from_roots_terminal(
    tmp_path, signing_key, monkeypatch, runner
):
    """``sudo update-agent.sh`` from an interactive shell must not hand the
    sensor's account root's terminal: with it, a planted ``venv/bin/python``
    pushes keystrokes into root's shell with TIOCSTI (the CVE-2016-2779
    class). Every process run as the account is in a session of its own, reads
    /dev/null and writes into a pipe -- checked here with the script's own
    stdio on plain files, so none of that is inherited by accident."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    if runner == "su":
        if any(Path(d, "runuser").exists() for d in ("/usr/bin", "/bin")):
            pytest.skip("runuser is installed in /usr/bin here; the BusyBox path is not reachable")
        (tmp_path / "bin" / "runuser").unlink()
        (tmp_path / "bin" / "su").write_text(_FAKE_SU)
        (tmp_path / "bin" / "su").chmod(0o755)
        env["PATH"] = f"{tmp_path / 'bin'}{os.pathsep}/usr/bin{os.pathsep}/bin"
    stdin = tmp_path / "stdin"
    stdin.write_text("")
    with stdin.open() as source, (tmp_path / "out").open("w") as out, (tmp_path / "err").open("w") as err:
        done = subprocess.run(
            ["bash", str(REPO_ROOT / "scripts" / "update-agent.sh"), "--bundle-dir", str(bundle)],
            env=env, stdin=source, stdout=out, stderr=err, check=False, timeout=120,
        )
    assert done.returncode == 0, (tmp_path / "out").read_text() + (tmp_path / "err").read_text()
    assert _live_version(install) == "0.47-0930"
    assert set((state / "runuser").read_text().split()) == {"shapoclyack"}
    attached = [line.split() for line in (state / "attached").read_text().splitlines()]
    assert len(attached) >= 3  # the import probe, --pending, --commit
    for sid, fd0, fd1, fd2 in attached:
        assert int(sid) != os.getsid(0)
        assert (fd0, fd1, fd2) == ("null", "fifo", "fifo")


def _interrupted(install: Path, bundle: Path, key: ec.EllipticCurvePrivateKey) -> str:
    """What a script killed between restart and ``--commit`` leaves: the new
    release live and running, and the journal naming the one before."""
    manifest, archive = _verified(bundle, key)
    live = update.Installer(install).install(archive, manifest, pending=True)
    assert _live_version(install) == "0.47-0930"
    return live


def test_update_script_restarts_onto_a_release_it_put_back(tmp_path, signing_key, monkeypatch):
    """The review's case: the interrupted release is rolled back, and then the
    bundle is refused. The unit is still running the code that was taken out;
    it has to be restarted onto what is live again."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    interrupted = _interrupted(install, bundle, signing_key)
    env[update.PUBKEY_FILE_ENV] = str(tmp_path / "other.pub")
    (tmp_path / "other.pub").write_bytes(_pem(ec.generate_private_key(ec.SECP256R1())))
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 1  # the bundle itself is refused ...
    assert _live_version(install) == "0.46-0922"
    assert (state / "calls").read_text().split() == ["restart"]  # ... after the restart
    assert not (install / ".sensor-update.json").exists()
    # The tree the old process was running from is still there for it.
    assert (install / interrupted).is_dir()


def test_update_script_installs_again_after_putting_an_interrupted_release_back(
    tmp_path, signing_key, monkeypatch
):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    interrupted = _interrupted(install, bundle, signing_key)
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert _live_version(install) == "0.47-0930"
    # Restarted onto the release put back, then onto the verified install.
    assert (state / "calls").read_text().split() == ["restart", "restart"]
    assert os.readlink(install / "agent") != interrupted
    assert not (install / interrupted).parent.exists()  # pruned once committed


def test_check_reports_an_interrupted_update_and_changes_nothing(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    interrupted = _interrupted(install, bundle, signing_key)
    done = _run_script(env, "--check", "--bundle-dir", str(bundle))
    assert done.returncode == 1
    assert "interrupted update" in done.stdout + done.stderr
    assert os.readlink(install / "agent") == interrupted
    assert (install / ".sensor-update.json").exists()
    assert not (state / "calls").exists()


def test_auto_does_not_retry_a_release_that_failed_here(tmp_path, signing_key, monkeypatch):
    """A genuine release that crash-loops on this host: the timer must not
    install it, restart into the loop and roll back again on every tick."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "crashloop", signing_key)
    with (tmp_path / "etc" / "agent.env").open("a") as handle:
        handle.write("OCTO_AGENT_AUTO_UPDATE=true\n")
    first = _run_script(env, "--auto", "--bundle-dir", str(bundle))
    assert first.returncode == 1
    assert (state / "calls").read_text().split() == ["restart", "restart"]

    again = _run_script(env, "--auto", "--bundle-dir", str(bundle))
    assert again.returncode == 0, again.stdout + again.stderr
    assert "failed its health check" in again.stdout + again.stderr
    assert (state / "calls").read_text().split() == ["restart", "restart"]
    assert _live_version(install) == "0.46-0922"

    # An operator running it by hand means it: the release is tried again,
    # and once it stays up the record of its failure goes.
    (state / "mode").write_text("stable")
    manual = _run_script(env, "--bundle-dir", str(bundle))
    assert manual.returncode == 0, manual.stdout + manual.stderr
    assert _live_version(install) == "0.47-0930"
    assert not list(install.glob(".sensor-update-failed*"))
    # The tree of the failed attempt went with that update.
    assert len(list((install / "releases").iterdir())) == 2


#: BusyBox 1.37's setsid, as Alpine has it next to the `runuser` package when
#: util-linux-misc is not installed: no -w, and for a process-group leader it
#: forks and the parent exits 0 at once.
_BUSYBOX_SETSID = """#!{python}
import os, sys
args = sys.argv[1:]
if args and args[0].startswith("-"):
    sys.stderr.write("setsid: unrecognized option: " + args[0].lstrip("-") + "\\n")
    sys.exit(1)
if os.getpgrp() == os.getpid() and os.fork():
    sys.exit(0)
os.setsid()
os.execvp(args[0], args)
"""


def test_update_script_works_with_a_setsid_that_has_no_wait(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    (tmp_path / "bin" / "setsid").write_text(_BUSYBOX_SETSID.format(python=sys.executable))
    (tmp_path / "bin" / "setsid").chmod(0o755)
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert _live_version(install) == "0.47-0930"
    for line in (state / "attached").read_text().splitlines():
        assert int(line.split()[0]) != os.getsid(0)


def test_update_script_shows_why_the_verifier_would_not_start(tmp_path, signing_key, monkeypatch):
    install, bundle, _state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    (install / "venv" / "bin" / "python").write_text(
        "#!/bin/sh\necho 'ModuleNotFoundError: No module named cryptography' >&2\nexit 1\n"
    )
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 1
    assert "No module named cryptography" in done.stdout + done.stderr


def test_update_script_passes_no_control_characters_to_roots_terminal(tmp_path, signing_key, monkeypatch):
    """A pipe alone is no filter: escape sequences a terminal answers (title
    reports, DECRQSS) would still reach root's terminal byte for byte."""
    install, bundle, _state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    (install / "venv" / "bin" / "python").write_text(
        "#!/bin/sh\n"
        "printf 'planted\\033]0;pwn\\007\\033[21t\\033P$q\"p\\033\\\\\\r\\n' >&2\n"
        f'exec "{sys.executable}" "$@"\n'
    )
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    seen = done.stdout + done.stderr
    assert "planted]0;pwn[21t" in seen  # the text arrives ...
    for sequence in ("\x1b]", "\x07", "\x1b[21t", "\x1bP", "\r"):
        assert sequence not in seen  # ... the controls do not


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _interrupt_script(env: dict, sig: int, ready, *args: str) -> tuple[int | None, float, str]:
    """Start the script as an operator's foreground job would be, signal its
    process group once ``ready()`` -- ^C, a dropped SSH session, a kill -- and
    return its status (``None`` if it was still running 20 s later)."""
    proc = subprocess.Popen(
        ["bash", str(REPO_ROOT / "scripts" / "update-agent.sh"), *args],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )
    deadline = time.monotonic() + 60
    while not ready():
        if proc.poll() is not None or time.monotonic() > deadline:
            proc.kill()
            pytest.fail("the script never got there:\n" + proc.communicate()[0])
        time.sleep(0.05)
    os.killpg(proc.pid, sig)
    started = time.monotonic()
    try:
        out, _ = proc.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        return None, time.monotonic() - started, proc.communicate()[0]
    return proc.returncode, time.monotonic() - started, out


def test_ctrl_c_stops_the_verifier_and_puts_the_previous_release_back(tmp_path, signing_key, monkeypatch):
    """The sensor's process runs in a session of its own, so ^C at root's
    terminal does not reach it: the script has to pass it on, and then undo
    a swap that no verdict will follow."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    # The swap is done and the process is still there, as a slow exit would be.
    (install / "venv" / "bin" / "python").write_text(
        "#!/bin/sh\n"
        f'"{sys.executable}" "$@"; rc=$?\n'
        'case "$*" in *--pending*) echo $$ > "$FAKE_SYSTEMD_DIR/lingering"; sleep 30 ;; esac\n'
        "exit $rc\n"
    )
    status, took, out = _interrupt_script(
        env, signal.SIGINT, lambda: (state / "lingering").exists(), "--bundle-dir", str(bundle)
    )
    lingering = int((state / "lingering").read_text())
    left_running = _alive(lingering)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(lingering, signal.SIGKILL)

    assert (status, left_running) == (130, False), out
    assert took < 10, out
    assert _live_version(install) == "0.46-0922", out
    assert not (install / ".sensor-update.json").exists()
    assert not list(install.glob(".sensor-update-failed*"))  # interrupted, not judged


def test_the_script_waits_for_the_verifier_to_go_before_putting_anything_back(
    tmp_path, signing_key, monkeypatch
):
    """The signal ends the shell's ``wait`` at once; the verifier, told to
    stop, may take a while. Putting the release back under it would race the
    process that still holds the update lock and may still be swapping."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    (install / "venv" / "bin" / "python").write_text(
        "#!/bin/sh\n"
        f'"{sys.executable}" "$@"; rc=$?\n'
        'case "$*" in *--pending*)\n'
        # Its output closed first: the FIFO's end is no sign it has gone.
        "  trap 'exec >/dev/null 2>&1; sleep 4; touch \"$FAKE_SYSTEMD_DIR/verifier-gone\"; exit 143' TERM\n"
        '  echo $$ > "$FAKE_SYSTEMD_DIR/lingering"; sleep 30 ;;\n'
        "esac\n"
        "exit $rc\n"
    )
    status, _took, out = _interrupt_script(
        env, signal.SIGINT, lambda: (state / "lingering").exists(), "--bundle-dir", str(bundle)
    )
    gone_when_the_script_exited = (state / "verifier-gone").exists()
    with contextlib.suppress(ProcessLookupError):
        os.killpg(int((state / "lingering").read_text()), signal.SIGKILL)
    assert status == 130, out
    assert gone_when_the_script_exited, out
    assert _live_version(install) == "0.46-0922", out


def test_a_signal_during_the_health_check_puts_the_previous_release_back(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env["HEALTH_SECONDS"] = "30"
    status, _took, out = _interrupt_script(
        env, signal.SIGTERM, lambda: (state / "calls").exists(), "--bundle-dir", str(bundle)
    )
    assert status == 143, out
    assert _live_version(install) == "0.46-0922", out
    assert not (install / ".sensor-update.json").exists()
    # Restarted onto the new release, then onto the one put back.
    assert (state / "calls").read_text().split() == ["restart", "restart"]
    assert not list(install.glob(".sensor-update-failed*"))


def test_a_hangup_during_the_health_check_puts_the_previous_release_back(tmp_path, signing_key, monkeypatch):
    """A dropped SSH session: SIGHUP to the foreground group."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env["HEALTH_SECONDS"] = "30"
    status, _took, out = _interrupt_script(
        env, signal.SIGHUP, lambda: (state / "calls").exists(), "--bundle-dir", str(bundle)
    )
    assert status == 129, out
    assert _live_version(install) == "0.46-0922", out
    assert (state / "calls").read_text().split() == ["restart", "restart"]


def _verifier(install: Path, body: str) -> None:
    """Replace the venv's python with a shell wrapper; ``$PY`` runs the real one."""
    (install / "venv" / "bin" / "python").write_text(f'#!/bin/sh\nPY="{sys.executable}"\n{body}')


def _signal_twice(env: dict, sig: int, first, second, *args: str) -> tuple[int | None, str]:
    """``_interrupt_script`` with a second signal once ``second()`` holds."""
    proc = subprocess.Popen(
        ["bash", str(REPO_ROOT / "scripts" / "update-agent.sh"), *args],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )
    for ready in (first, second):
        deadline = time.monotonic() + 60
        while not ready():
            if proc.poll() is not None or time.monotonic() > deadline:
                proc.kill()
                pytest.fail("the script never got there:\n" + proc.communicate()[0])
            time.sleep(0.05)
        os.killpg(proc.pid, sig)
    try:
        out, _ = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        return None, proc.communicate()[0]
    return proc.returncode, out


def test_an_interruption_after_the_recovery_still_restarts_the_unit(tmp_path, signing_key, monkeypatch):
    """The review's lost restart: an earlier run died after its restart, so
    the unit runs the release its journal names as new. This run's ``--pending``
    puts the previous one back -- which removes the journal -- and is stopped
    before the restart that has to follow. The journal no longer says so; the
    unit still needs it."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    _interrupted(install, bundle, signing_key)
    _verifier(
        install,
        '"$PY" "$@"; rc=$?\n'
        'case "$*" in *--pending*) [ "$rc" -eq 4 ] && { touch "$FAKE_SYSTEMD_DIR/recovered"; sleep 30; } ;; esac\n'
        "exit $rc\n",
    )
    status, _took, out = _interrupt_script(
        env, signal.SIGTERM, lambda: (state / "recovered").exists(), "--bundle-dir", str(bundle)
    )
    assert status == 143, out
    assert _live_version(install) == "0.46-0922", out
    assert (state / "calls").read_text().split() == ["restart"], out


def test_an_interruption_after_the_rollback_still_restarts_the_unit(tmp_path, signing_key, monkeypatch):
    """The health check failed and ``--rollback`` has put the previous release
    back -- removing the journal -- when the signal comes, before its process
    has gone. The unit still runs the release that failed; nothing on disk
    says so any more, so the script has to remember the restart it owes."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "crashloop", signing_key)
    _verifier(
        install,
        '"$PY" "$@"; rc=$?\n'
        'case "$*" in *--rollback*) touch "$FAKE_SYSTEMD_DIR/rolled"; sleep 30 ;; esac\n'
        "exit $rc\n",
    )
    status, _took, out = _interrupt_script(
        env, signal.SIGINT, lambda: (state / "rolled").exists(), "--bundle-dir", str(bundle)
    )
    assert status == 130, out
    assert _live_version(install) == "0.46-0922", out
    assert not (install / ".sensor-update.json").exists(), out
    # Onto the new release, then onto the one put back.
    assert (state / "calls").read_text().split() == ["restart", "restart"], out


def test_an_interruption_before_anything_changed_restarts_nothing(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    _verifier(
        install,
        'case "$*" in *--pending*) touch "$FAKE_SYSTEMD_DIR/started"; sleep 30 ;; esac\n'
        'exec "$PY" "$@"\n',
    )
    status, _took, out = _interrupt_script(
        env, signal.SIGINT, lambda: (state / "started").exists(), "--bundle-dir", str(bundle)
    )
    assert status == 130, out
    assert _live_version(install) == "0.46-0922", out
    assert not (state / "calls").exists(), out


def test_an_interruption_during_check_changes_nothing(tmp_path, signing_key, monkeypatch):
    """``--check`` never changes anything, an interrupted one included: the
    interrupted update it found stays for a real run to put back."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    interrupted = _interrupted(install, bundle, signing_key)
    _verifier(
        install,
        'case "$*" in *--check*) touch "$FAKE_SYSTEMD_DIR/checking"; sleep 30 ;; esac\n'
        'exec "$PY" "$@"\n',
    )
    status, _took, out = _interrupt_script(
        env, signal.SIGTERM, lambda: (state / "checking").exists(),
        "--check", "--bundle-dir", str(bundle),
    )
    assert status == 143, out
    assert os.readlink(install / "agent") == interrupted
    assert (install / ".sensor-update.json").exists()
    assert not (state / "calls").exists(), out


def test_an_interruption_after_the_commit_says_the_release_was_kept(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    _verifier(
        install,
        '"$PY" "$@"; rc=$?\n'
        'case "$*" in *--commit*) touch "$FAKE_SYSTEMD_DIR/committed"; sleep 30 ;; esac\n'
        "exit $rc\n",
    )
    status, _took, out = _interrupt_script(
        env, signal.SIGINT, lambda: (state / "committed").exists(), "--bundle-dir", str(bundle)
    )
    assert status == 130, out
    assert _live_version(install) == "0.47-0930", out
    assert "putting the previous release back" not in out
    assert "Nothing was waiting for a verdict" in out
    assert (state / "calls").read_text().split() == ["restart"], out


def test_a_commit_that_kept_nothing_is_not_reported_as_kept(tmp_path, signing_key, monkeypatch):
    """Whatever took the journal away -- another run, a hand -- the script must
    not log "kept" for a release it did not keep."""
    install, bundle, _state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    _verifier(
        install,
        'case "$*" in *--commit*) rm -f "$INSTALL_DIR/.sensor-update.json" ;; esac\n'
        'exec "$PY" "$@"\n',
    )
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 1, done.stdout + done.stderr
    assert "kept." not in done.stdout
    assert "was not kept" in done.stderr


def test_a_second_run_stops_while_the_first_is_in_its_health_check(tmp_path, signing_key, monkeypatch):
    """The review's race: a timer firing during a manual run's health check
    took that run's journal, and the manual run's rollback then recorded the
    timer's healthy install as failed. The lock is held for the whole run."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    with (tmp_path / "etc" / "agent.env").open("a") as handle:
        handle.write("OCTO_AGENT_AUTO_UPDATE=true\n")
    first = subprocess.Popen(
        ["bash", str(REPO_ROOT / "scripts" / "update-agent.sh"), "--bundle-dir", str(bundle)],
        env={**env, "HEALTH_SECONDS": "6"}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    deadline = time.monotonic() + 60
    while not (state / "calls").exists():
        assert first.poll() is None and time.monotonic() < deadline, first.communicate()[0]
        time.sleep(0.05)
    second = _run_script(env, "--auto", "--bundle-dir", str(bundle))
    out = first.communicate(timeout=60)[0]

    assert second.returncode == 1, second.stdout + second.stderr
    assert "Another sensor update is running" in second.stderr
    assert first.returncode == 0, out
    assert "kept." in out
    assert _live_version(install) == "0.47-0930"
    assert (state / "calls").read_text().split() == ["restart"]
    assert not list(install.glob(".sensor-update-failed*"))


def test_the_sensors_processes_do_not_inherit_the_lock(tmp_path, signing_key, monkeypatch):
    """A process of the account holding the descriptor could keep every later
    run out, or release the lock under the run that holds it."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    _verifier(
        install,
        '{ : >&9; } 2>/dev/null && echo "$*" >> "$FAKE_SYSTEMD_DIR/fd9"\n'
        'exec "$PY" "$@"\n',
    )
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert not (state / "fd9").exists(), (state / "fd9").read_text()


def test_no_other_account_can_open_the_lock(tmp_path, signing_key, monkeypatch):
    """flock(2) takes LOCK_EX on a descriptor opened read-only: a lock file
    other accounts can read lets any of them keep every update out."""
    _install, bundle, _state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    lock = Path(env["LOCK_FILE"])
    done = _run_script(env, "--check", "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600
    # One left behind readable, by an older script or by hand, is tightened.
    lock.chmod(0o644)
    done = _run_script(env, "--check", "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert stat.S_IMODE(lock.stat().st_mode) == 0o600


_SLOW_SECOND_RESTART = """#!/bin/sh
state="$FAKE_SYSTEMD_DIR"
case "$1" in
  restart)
    n=$(cat "$state/calls" 2>/dev/null | wc -l)
    echo restart >> "$state/calls"
    if [ "$n" -ge 1 ]; then touch "$state/restarting"; sleep 3; echo done >> "$state/calls"; fi
    echo 100 > "$state/pid"; exit 0 ;;
  is-active|cat) exit 0 ;;
  show) cat "$state/pid"; exit 0 ;;
esac
exit 1
"""


def test_a_second_ctrl_c_does_not_cut_the_restart_after_the_rollback_short(
    tmp_path, signing_key, monkeypatch
):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    (tmp_path / "bin" / "systemctl").write_text(_SLOW_SECOND_RESTART)
    env["HEALTH_SECONDS"] = "30"
    status, out = _signal_twice(
        env, signal.SIGINT,
        lambda: (state / "calls").exists(), lambda: (state / "restarting").exists(),
        "--bundle-dir", str(bundle),
    )
    assert status == 130, out
    assert _live_version(install) == "0.46-0922", out
    assert (state / "calls").read_text().split() == ["restart", "restart", "done"], out
    assert "did not restart" not in out


@pytest.mark.parametrize("first_during", ["health check", "verifier"])
def test_a_second_signal_does_not_stop_the_verifier_putting_the_release_back(
    tmp_path, signing_key, monkeypatch, first_during
):
    """Interrupted during the health check, the clean-up runs inside the
    first signal's trap, where bash holds the same signal back anyway.
    Interrupted while the verifier runs, it runs after the trap has returned,
    and only the clean-up's own ``trap ':'`` keeps the second one off it."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env["HEALTH_SECONDS"] = "30"
    _verifier(
        install,
        'case "$*" in\n'
        '  *--abort*) touch "$FAKE_SYSTEMD_DIR/aborting"; sleep 2 ;;\n'
        '  *--pending*) "$PY" "$@"; rc=$?; touch "$FAKE_SYSTEMD_DIR/swapped"; sleep 10; exit $rc ;;\n'
        "esac\n"
        'exec "$PY" "$@"\n',
    )
    first = "calls" if first_during == "health check" else "swapped"
    status, out = _signal_twice(
        env, signal.SIGTERM,
        lambda: (state / first).exists(), lambda: (state / "aborting").exists(),
        "--bundle-dir", str(bundle),
    )
    assert status == 143, out
    assert _live_version(install) == "0.46-0922", out
    assert not (install / ".sensor-update.json").exists()
    # The health check's restart, if it got that far, and the one onto the
    # release put back.
    restarts = ["restart", "restart"] if first_during == "health check" else ["restart"]
    assert (state / "calls").read_text().split() == restarts, out


def test_a_verifier_that_ignores_sigterm_is_killed(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env["STOP_SECONDS"] = "2"
    _verifier(
        install,
        'case "$*" in *--pending*)\n'
        "  trap '' TERM\n"
        '  "$PY" "$@"; echo $$ > "$FAKE_SYSTEMD_DIR/lingering"; sleep 60 ;;\n'
        "esac\n"
        'exec "$PY" "$@"\n',
    )
    status, took, out = _interrupt_script(
        env, signal.SIGINT, lambda: (state / "lingering").exists(), "--bundle-dir", str(bundle)
    )
    lingering = int((state / "lingering").read_text())
    left_running = _alive(lingering)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(lingering, signal.SIGKILL)
    assert (status, left_running) == (130, False), out
    assert took < 10, out
    assert _live_version(install) == "0.46-0922", out


def test_what_ignores_sigterm_is_killed_after_the_verifier_itself_went(
    tmp_path, signing_key, monkeypatch
):
    """runuser and su go on SIGTERM and leave their child to it: one ignoring
    SIGTERM stays behind in the verifier's process group, which is what gets
    SIGKILL -- not only while the process the script started is alive."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env["STOP_SECONDS"] = "2"
    _verifier(
        install,
        'case "$*" in *--pending*)\n'
        '  "$PY" "$@"\n'
        "  sh -c 'trap \"\" TERM; echo $$ > \"$FAKE_SYSTEMD_DIR/lingering\"; exec sleep 60' &\n"
        "  wait ;;\n"
        "esac\n"
        'exec "$PY" "$@"\n',
    )
    status, took, out = _interrupt_script(
        env, signal.SIGINT, lambda: (state / "lingering").exists(), "--bundle-dir", str(bundle)
    )
    lingering = int((state / "lingering").read_text())
    time.sleep(0.5)
    left_running = _alive(lingering)
    with contextlib.suppress(ProcessLookupError):
        os.kill(lingering, signal.SIGKILL)
    assert (status, left_running) == (130, False), out
    assert took < 10, out
    assert _live_version(install) == "0.46-0922", out


def test_a_process_left_holding_the_output_does_not_hold_the_script(tmp_path, signing_key, monkeypatch):
    """The verifier exits and leaves a process behind with its output open:
    its reader would wait for that one's end, for ever."""
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env["DRAIN_SECONDS"] = "2"
    _verifier(
        install,
        'case "$*" in *--pending*) sleep 60 & echo $! > "$FAKE_SYSTEMD_DIR/holder" ;; esac\n'
        'exec "$PY" "$@"\n',
    )
    try:
        done = _run_script(env, "--bundle-dir", str(bundle))
    finally:
        with contextlib.suppress(OSError, ValueError):
            os.kill(int((state / "holder").read_text()), signal.SIGKILL)
    assert done.returncode == 0, done.stdout + done.stderr
    assert _live_version(install) == "0.47-0930"


def test_a_signal_while_the_output_drains_ends_the_wait(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    env["DRAIN_SECONDS"] = "60"
    _verifier(
        install,
        '"$PY" "$@"; rc=$?\n'
        'case "$*" in *--pending*)\n'
        '  sleep 60 & echo $! > "$FAKE_SYSTEMD_DIR/holder"; touch "$FAKE_SYSTEMD_DIR/draining" ;;\n'
        "esac\n"
        "exit $rc\n",
    )
    try:
        status, took, out = _interrupt_script(
            env, signal.SIGINT, lambda: (state / "draining").exists(), "--bundle-dir", str(bundle)
        )
    finally:
        with contextlib.suppress(OSError, ValueError):
            os.kill(int((state / "holder").read_text()), signal.SIGKILL)
    assert status == 130, out
    assert took < 10, out
    assert _live_version(install) == "0.46-0922", out


def test_the_verifiers_last_words_come_before_the_scripts_next_ones(tmp_path, signing_key, monkeypatch):
    """Its output is read to the end before the script goes on, so what it
    printed last is not lost behind, or after, the verdict."""
    install, bundle, _state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    _verifier(
        install,
        '"$PY" "$@"; rc=$?\n'
        'case "$*" in *--pending*) (sleep 3; echo "late line from the verifier") & ;; esac\n'
        "exit $rc\n",
    )
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "late line from the verifier" in done.stdout
    assert done.stdout.index("late line from the verifier") < done.stdout.index("stayed up")


# --------------------------------------------------------------------------
# The sensor's HTTP path, against a server that lies
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _fake_api(metadata: dict, archive: bytes, *, seen: list[str] | None = None):
    """A stand-in API on a real socket, so ``AgentClient`` runs as it does on a host.
    ``seen`` collects the paths asked for."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802 - http.server's naming
            if seen is not None:
                seen.append(self.path)
            if self.headers.get("Authorization") != "Bearer sensor-token":
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps(metadata).encode() if self.path == "/api/agent/bundle" else archive
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _metadata(bundle: Path, **overrides: object) -> dict:
    manifest = (bundle / update.MANIFEST_NAME).read_bytes()
    data = json.loads(manifest)
    return {
        "version": data["version"],
        "manifest": base64.b64encode(manifest).decode(),
        "signature": (bundle / update.SIGNATURE_NAME).read_text().strip(),
        "min_version": None,
        **overrides,
    }


def _from_server(tmp_path: Path, monkeypatch, url: str, key: ec.EllipticCurvePrivateKey):
    monkeypatch.setenv("OCTO_API_URL", url)
    monkeypatch.setenv("OCTO_AGENT_TOKEN", "sensor-token")
    monkeypatch.delenv("OCTO_AGENT_PROVISIONING_KEY", raising=False)
    monkeypatch.delenv("OCTO_AGENT_PROVISIONING_KEY_FILE", raising=False)
    work = tmp_path / "download"
    work.mkdir(exist_ok=True)
    client, manifest, floor = update._server_manifest(key.public_key())
    client.download_bundle(work / manifest.archive, max_bytes=manifest.size)
    return manifest, work / manifest.archive, floor


def test_the_sensor_downloads_and_verifies_over_http(tmp_path, signing_key, monkeypatch):
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    archive = next(bundle.glob("*.tar.gz")).read_bytes()
    with _fake_api(_metadata(bundle, min_version="0.46-0922"), archive) as url:
        manifest, path, floor = _from_server(tmp_path, monkeypatch, url, signing_key)
    update.verify_archive(path, manifest)
    assert (manifest.version, floor) == ("0.47-0930", "0.46-0922")


def test_server_metadata_that_disagrees_with_the_signed_version_is_refused(tmp_path, signing_key, monkeypatch):
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    archive = next(bundle.glob("*.tar.gz")).read_bytes()
    with _fake_api(_metadata(bundle, version="9.99-1231"), archive) as url:
        with pytest.raises(update.BundleRefused, match="signed manifest"):
            _from_server(tmp_path, monkeypatch, url, signing_key)


def test_oversized_bundle_metadata_is_not_read_into_memory(tmp_path, signing_key, monkeypatch):
    """The metadata is unsigned until it has been read; a server answering it
    with an endless body must not get to decide how much memory that takes."""
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    archive = next(bundle.glob("*.tar.gz")).read_bytes()
    padded = _metadata(bundle, padding="x" * (2 * 1024 * 1024))
    with _fake_api(padded, archive) as url:
        with pytest.raises(RuntimeError, match="more than"):
            _from_server(tmp_path, monkeypatch, url, signing_key)


def test_a_server_streaming_more_than_the_signed_size_is_cut_off(tmp_path, signing_key, monkeypatch):
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    archive = next(bundle.glob("*.tar.gz")).read_bytes()
    with _fake_api(_metadata(bundle), archive + b"\0" * (2 * 1024 * 1024)) as url:
        with pytest.raises(RuntimeError, match="more bytes than the signed"):
            _from_server(tmp_path, monkeypatch, url, signing_key)


def _auto_from_server(install: Path, url: str, key_file: Path, monkeypatch) -> int:
    monkeypatch.setenv(update.PUBKEY_FILE_ENV, str(key_file))
    monkeypatch.setenv(update.AUTO_UPDATE_ENV, "true")
    monkeypatch.setenv("OCTO_API_URL", url)
    monkeypatch.setenv("OCTO_AGENT_TOKEN", "sensor-token")
    monkeypatch.delenv("OCTO_AGENT_PROVISIONING_KEY", raising=False)
    monkeypatch.delenv("OCTO_AGENT_PROVISIONING_KEY_FILE", raising=False)
    monkeypatch.setattr(update, "_systemd_unit_present", lambda unit: False)
    return update.main(
        ["--install-dir", str(install), "--env-file", str(install / "missing.env"), "--auto"]
    )


def test_auto_skips_a_release_that_failed_here_before_downloading_it(tmp_path, signing_key, monkeypatch):
    """The signed manifest names the digest; a timer tick that is going to
    skip the release has no reason to fetch 64 MiB of it first."""
    install = _cli_install(tmp_path, "0.46-0922")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    manifest, archive = _verified(bundle, signing_key)
    with pytest.raises(update.UpdateFailed):
        update.Installer(install, health_check=_unhealthy).install(archive, manifest)

    seen: list[str] = []
    with _fake_api(_metadata(bundle), archive.read_bytes(), seen=seen) as url:
        assert _auto_from_server(install, url, key_file, monkeypatch) == 0
    assert seen == ["/api/agent/bundle"]
    assert _live_version(install) == "0.46-0922"


def test_a_bundle_already_installed_is_not_downloaded(tmp_path, signing_key, monkeypatch):
    install = _cli_install(tmp_path, "0.47-0930")
    key_file = tmp_path / "release.pub"
    key_file.write_bytes(_pem(signing_key))
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    seen: list[str] = []
    with _fake_api(_metadata(bundle), next(bundle.glob("*.tar.gz")).read_bytes(), seen=seen) as url:
        assert _auto_from_server(install, url, key_file, monkeypatch) == 0
    assert seen == ["/api/agent/bundle"]


_FLOOD_BYTES = 32 * 1024 * 1024


@contextlib.contextmanager
def _flooding_api(status: int):
    """An API that answers anything with ``status`` and 32 MiB of body."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _flood(self):
            self.send_response(status)
            self.send_header("Content-Length", str(_FLOOD_BYTES))
            self.end_headers()
            chunk = b"x" * 65536
            with contextlib.suppress(OSError):
                for _ in range(_FLOOD_BYTES // len(chunk)):
                    self.wfile.write(chunk)

        do_GET = do_POST = _flood  # noqa: N815 - http.server's naming

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


_SENSOR_CALLS = {
    "bundle metadata": lambda client, tmp: client.bundle_info(),
    "credential exchange": lambda client, tmp: client.exchange_provisioning_key("pk_test"),
    "bundle download": lambda client, tmp: client.download_bundle(tmp / "b.tar.gz", max_bytes=1024),
}


@pytest.mark.parametrize("status", [200, 500])
@pytest.mark.parametrize("call", sorted(_SENSOR_CALLS))
def test_how_much_of_an_answer_is_read_is_decided_by_the_sensor(tmp_path, call, status):
    """What the updater reads from the API before anything is verified -- an
    error body included, and the text of the error it is logged as -- is
    bounded here, whatever length the server announces or sends."""
    with _flooding_api(status) as url:
        client = AgentClient(url, "sensor-token")
        tracemalloc.start()
        try:
            with pytest.raises(RuntimeError) as refused:
                _SENSOR_CALLS[call](client, tmp_path)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
    assert len(str(refused.value)) < 8 * 1024
    assert peak < 8 * 1024 * 1024
    if status != 200:
        assert str(refused.value).endswith("[truncated]")


@contextlib.contextmanager
def _redirecting_api(seen: list[tuple[str, str | None]]):
    """An API answering everything with a 302 to another origin and 32 MiB
    of body; ``seen`` collects what that other origin is asked, and with
    which ``Authorization``."""

    class Elsewhere(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _answer(self):
            seen.append((self.path, self.headers.get("Authorization")))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST = _answer  # noqa: N815 - http.server's naming

    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Elsewhere)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _redirect(self):
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{other.server_address[1]}/steal")
            self.send_header("Content-Length", str(_FLOOD_BYTES))
            self.end_headers()
            chunk = b"x" * 65536
            with contextlib.suppress(OSError):
                for _ in range(_FLOOD_BYTES // len(chunk)):
                    self.wfile.write(chunk)

        do_GET = do_POST = _redirect  # noqa: N815 - http.server's naming

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    for srv in (server, other):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        for srv in (server, other):
            srv.shutdown()
            srv.server_close()


@pytest.mark.parametrize("call", sorted(_SENSOR_CALLS))
def test_a_redirect_is_not_followed_with_the_token_or_read_to_its_end(tmp_path, call):
    """urllib's own redirect handler takes the bearer token to whatever host
    the Location names, and reads the 3xx body to its end before it does."""
    seen: list[tuple[str, str | None]] = []
    with _redirecting_api(seen) as url:
        client = AgentClient(url, "sensor-token")
        tracemalloc.start()
        try:
            with pytest.raises(RuntimeError, match="-> 302: redirect to .* not followed") as refused:
                _SENSOR_CALLS[call](client, tmp_path)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
    assert seen == []
    assert peak < 8 * 1024 * 1024
    assert len(str(refused.value)) < 8 * 1024


# --------------------------------------------------------------------------
# The API: GET /api/agent/bundle and /download
# --------------------------------------------------------------------------


AGENT = {"Authorization": "Bearer test-agent-token"}


def _api(tmp_path: Path, monkeypatch, **overrides: object):
    return configured_client(tmp_path, monkeypatch, job_execution_mode="agent", **overrides)


@requires_postgres
def test_no_bundle_configured_is_404(tmp_path, monkeypatch):
    client = _api(tmp_path, monkeypatch)
    response = client.get("/api/agent/bundle", headers=AGENT)
    assert response.status_code == 404
    assert "OCTO_AGENT_BUNDLE_DIR" in response.json()["detail"]


@requires_postgres
def test_the_bundle_route_needs_a_sensor_credential(tmp_path, monkeypatch, signing_key):
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    client = _api(tmp_path, monkeypatch, agent_bundle_dir=str(bundle))
    assert client.get("/api/agent/bundle").status_code == 401
    assert client.get("/api/agent/bundle/download").status_code == 401
    operator = login(client, "operator")
    assert client.get("/api/agent/bundle", headers=bearer(operator)).status_code == 401


@requires_postgres
def test_the_served_metadata_verifies_on_the_sensor(tmp_path, monkeypatch, signing_key):
    """What the route returns is exactly what the sensor checks: the signed
    bytes, the signature, and the archive the signature's digest names."""
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    client = _api(tmp_path, monkeypatch, agent_bundle_dir=str(bundle), agent_min_version="0.46-0922")
    info = client.get("/api/agent/bundle", headers=AGENT)
    assert info.status_code == 200, info.text
    body = info.json()
    assert body["version"] == "0.47-0930"
    assert body["min_version"] == "0.46-0922"
    manifest = update.verify_manifest(
        base64.b64decode(body["manifest"]), body["signature"], signing_key.public_key()
    )
    download = client.get(body["download_path"], headers=AGENT)
    assert download.status_code == 200
    archive = tmp_path / "downloaded.tar.gz"
    archive.write_bytes(download.content)
    update.verify_archive(archive, manifest)


@requires_postgres
def test_an_inconsistent_bundle_directory_is_503(tmp_path, monkeypatch, signing_key):
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    archive = next(bundle.glob("*.tar.gz"))
    raw = bytearray(archive.read_bytes())
    raw[100] ^= 0x01
    archive.write_bytes(bytes(raw))
    client = _api(tmp_path, monkeypatch, agent_bundle_dir=str(bundle))
    response = client.get("/api/agent/bundle", headers=AGENT)
    assert response.status_code == 503
    assert "sha256" in response.json()["detail"]


@requires_postgres
def test_an_endpoint_agent_is_not_handed_the_sensor_bundle(tmp_path, monkeypatch, signing_key):
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    client = _api(tmp_path, monkeypatch, agent_token="", agent_bundle_dir=str(bundle))
    admin = login(client, "admin")
    key = client.post(
        "/api/tenants/default/provisioning-keys", headers=bearer(admin), json={"label": "bundle"}
    ).json()["key"]
    tokens = {}
    for agent_id, kind in (("sensor_1", "scanner"), ("lariska_1", "endpoint")):
        token = client.post(
            "/api/auth/agent/token", json={"provisioning_key": key, "agent_id": agent_id}
        ).json()["access_token"]
        registered = client.post(
            "/api/agent/register",
            headers=bearer(token),
            json={"agent_id": agent_id, "hostname": agent_id, "version": "0.46-0922", "agent_kind": kind},
        )
        assert registered.status_code == 200, registered.text
        tokens[kind] = token
    assert client.get("/api/agent/bundle", headers=bearer(tokens["scanner"])).status_code == 200
    refused = client.get("/api/agent/bundle", headers=bearer(tokens["endpoint"]))
    assert refused.status_code == 403
    assert client.get("/api/agent/bundle/download", headers=bearer(tokens["endpoint"])).status_code == 403



def test_a_sensor_of_another_tenant_is_not_handed_the_bundle(tmp_path, monkeypatch, signing_key):
    """The route's own tenant check, without a database: the agent row the
    request resolves to belongs to another tenant than the credential."""
    from types import SimpleNamespace

    from fastapi import HTTPException

    from api.auth import AgentPrincipal
    from api.routes import agents as agent_routes
    from api.schemas import AgentInfo

    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    settings = SimpleNamespace(agent_bundle_dir=str(bundle))
    principal = AgentPrincipal(tenant_id="ten_a", agent_id="sensor_1")
    rows = {"ten_a": AgentInfo(agent_id="sensor_1", tenant_id="ten_a")}
    monkeypatch.setattr(agent_routes, "_agent_for_request", lambda _r, _p, _id: rows["current"])

    rows["current"] = rows["ten_a"]
    assert agent_routes._published_bundle(None, principal, settings).version == "0.47-0930"
    rows["current"] = AgentInfo(agent_id="sensor_1", tenant_id="ten_b")
    with pytest.raises(HTTPException) as refused:
        agent_routes._published_bundle(None, principal, settings)
    assert refused.value.status_code == 403
