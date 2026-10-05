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
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from agent import logging_setup, update
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

    installer = update.Installer(
        install, health_check=unhealthy, on_rollback=lambda: restarts.append("restart")
    )
    with pytest.raises(update.UpdateFailed, match="rolled back"):
        installer.install(archive, manifest)

    assert seen == ["0.47-0930"]  # the check ran against the new code ...
    assert _live_version(install) == "0.46-0922"  # ... and the old one is back
    assert restarts == ["restart"]
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


# --------------------------------------------------------------------------
# The systemd health check, against a systemctl that behaves like one
# --------------------------------------------------------------------------

_FAKE_SYSTEMCTL = """#!/bin/sh
# A systemctl for one unit. MODE=stable keeps the main PID after a restart;
# MODE=crashloop hands out a new one on every look, as Restart=always does.
state="$FAKE_SYSTEMD_DIR"
case "$1" in
  restart) echo restart >> "$state/calls"; echo 100 > "$state/pid"; exit 0 ;;
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
    installer.install(archive, manifest, pending=True)  # swapped, verdict never came
    assert _live_version(install) == "0.47-0930"

    assert _run_cli(install, bundle, key_file, monkeypatch, "--check") == 0
    assert _live_version(install) == "0.46-0922"
    assert not (install / ".sensor-update.json").exists()


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


# --------------------------------------------------------------------------
# scripts/update-agent.sh: root restarts, the account installs
# --------------------------------------------------------------------------

_FAKE_RUNUSER = """#!/bin/sh
# runuser -u USER -- CMD...: record who, run CMD as ourselves.
echo "$2" >> "$FAKE_SYSTEMD_DIR/runuser"
shift 3
exec "$@"
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
    (tmp_path / "bin" / "runuser").write_text(_FAKE_RUNUSER)
    (tmp_path / "bin" / "runuser").chmod(0o755)
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
        update.PUBKEY_FILE_ENV: str(key_file),
    }
    return install, bundle, state, env


def _run_script(env: dict, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(REPO_ROOT / "scripts" / "update-agent.sh"), *args],
        env=env, capture_output=True, text=True, check=False, timeout=120,
    )


def test_update_script_keeps_a_release_the_unit_stays_up_on(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "stable", signing_key)
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 0, done.stdout + done.stderr
    assert _live_version(install) == "0.47-0930"
    assert not (install / ".sensor-update.json").exists()
    assert (state / "calls").read_text().split() == ["restart"]
    # Every python the script started ran as the sensor's account.
    assert set((state / "runuser").read_text().split()) == {"shapoclyack"}


def test_update_script_puts_the_previous_release_back_on_a_crash_loop(tmp_path, signing_key, monkeypatch):
    install, bundle, state, env = _script_stand(tmp_path, monkeypatch, "crashloop", signing_key)
    done = _run_script(env, "--bundle-dir", str(bundle))
    assert done.returncode == 1
    assert "previous release is back" in done.stderr
    assert _live_version(install) == "0.46-0922"
    assert not (install / ".sensor-update.json").exists()
    # Restarted onto the new code, then onto the old one again.
    assert (state / "calls").read_text().split() == ["restart", "restart"]
    assert not [p for p in (install / "releases").iterdir() if p.name.startswith("0.47")]


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


# --------------------------------------------------------------------------
# The sensor's HTTP path, against a server that lies
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _fake_api(metadata: dict, archive: bytes):
    """A stand-in API on a real socket, so ``AgentClient`` runs as it does on a host."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802 - http.server's naming
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
    return update._download_from_server(work, key.public_key())


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


def test_a_server_streaming_more_than_the_signed_size_is_cut_off(tmp_path, signing_key, monkeypatch):
    bundle = _bundle(tmp_path, signing_key, "0.47-0930")
    archive = next(bundle.glob("*.tar.gz")).read_bytes()
    with _fake_api(_metadata(bundle), archive + b"\0" * (2 * 1024 * 1024)) as url:
        with pytest.raises(RuntimeError, match="more bytes than the signed"):
            _from_server(tmp_path, monkeypatch, url, signing_key)


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
