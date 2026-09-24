"""scripts/verify-pulse-image.py: the customer-side check of the Pulse binary (#340).

The pin in ``scripts/pulse-pinned.sha256`` is a digest of the GenDec release
*tarball*; the image holds only the binary that came out of it. The verifier
bridges the two either through the install record the image build writes, or
independently through the pinned tarball. These tests build image filesystems
by hand (and, for ``--image``, serve them through a fake ``docker``), so every
failure mode can be staged without a registry, a daemon or GenDec access.

The contract with the real image layout -- where the Dockerfiles put the
binary and the record -- is checked against the Dockerfiles themselves at the
bottom; the contract with the installer that writes the record is exercised
end to end in tests/test_pulse_supply_chain.py.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import re
import subprocess
import sys
import tarfile
import threading
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "scripts" / "verify-pulse-image.py"

_spec = importlib.util.spec_from_file_location("verify_pulse_image", VERIFIER)
assert _spec is not None and _spec.loader is not None
verify_pulse_image = importlib.util.module_from_spec(_spec)
# Registered first: @dataclass resolves the module's string annotations through it.
sys.modules[_spec.name] = verify_pulse_image
_spec.loader.exec_module(verify_pulse_image)

VERSION = "v9.9.9"
PLATFORM = "linux-amd64"
BINARY = b"\x7fELF pretend pulse 9.9.9\n"
# What the fake engine says it resolved the reference to.
IMAGE_ID = "sha256:" + "1" * 64
REPO_DIGEST = "ghcr.io/example/shapoclyack-scanner@sha256:" + "2" * 64


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tarball(path: Path, *, members: list[tuple[str, bytes | None, str]] | None = None) -> Path:
    """A release tarball. ``members`` is ``(name, content, kind)``; kind is
    ``file`` or ``symlink`` (content is then the link target)."""
    members = members if members is not None else [("pulse", BINARY, "file")]
    with tarfile.open(path, "w:gz") as archive:
        for name, content, kind in members:
            info = tarfile.TarInfo(name)
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = (content or b"").decode()
                archive.addfile(info)
            else:
                info.size = len(content or b"")
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(content or b""))
    return path


def _pins(entries: dict[tuple[str, str], str]) -> str:
    return "# test pins\n" + "".join(f"{v}  {p}  {d}\n" for (v, p), d in entries.items())


def _record(**overrides: str) -> str:
    fields = {
        "version": VERSION,
        "platform": PLATFORM,
        "verified": "pin",
        "tarball": f"pulse-{VERSION}-{PLATFORM}.tar.gz",
        "tarball_sha256": "",
        "binary_sha256": _sha(BINARY),
    }
    fields.update(overrides)
    return "# written by the test\n" + "".join(f"{k}={v}\n" for k, v in fields.items())


@pytest.fixture
def release(tmp_path: Path):
    """The pinned tarball, and a pin file (the customer's checkout) pinning it."""
    tarball = _tarball(tmp_path / f"pulse-{VERSION}-{PLATFORM}.tar.gz")
    pin = _sha(tarball.read_bytes())
    pins = tmp_path / "pulse-pinned.sha256"
    pins.write_text(_pins({(VERSION, PLATFORM): pin, (VERSION, "linux-arm64"): "b" * 64}))
    return tarball, pin, pins


def _rootfs(
    tmp_path: Path,
    *,
    binary: bytes | None = BINARY,
    record: str | None = None,
    image_pins: str | None = None,
) -> Path:
    root = tmp_path / "rootfs"
    if binary is not None:
        (root / "usr/local/bin").mkdir(parents=True, exist_ok=True)
        (root / "usr/local/bin/pulse").write_bytes(binary)
    if record is not None:
        (root / "usr/local/share/shapoclyack").mkdir(parents=True, exist_ok=True)
        (root / "usr/local/share/shapoclyack/pulse-install.txt").write_text(record)
    if image_pins is not None:
        (root / "app/scripts").mkdir(parents=True, exist_ok=True)
        (root / "app/scripts/pulse-pinned.sha256").write_text(image_pins)
    root.mkdir(exist_ok=True)
    return root


def _run(*args: str | Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VERIFIER), *map(str, args)],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )


# --- the install record ------------------------------------------------------


def test_a_pinned_install_record_verifies(tmp_path, release):
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin), image_pins=pins.read_text())
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFIED against install record" in proc.stdout
    # Said out loud: the record is unsigned and lives in the image it describes.
    assert "only as good as the image digest you verified" in proc.stdout


def test_a_binary_changed_after_the_install_is_caught(tmp_path, release):
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, binary=BINARY + b"backdoor", record=_record(tarball_sha256=pin))
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert "changed after the install" in proc.stdout
    assert "NOT VERIFIED" in proc.stdout


def test_a_record_of_a_tarball_other_than_the_pinned_one_fails(tmp_path, release):
    """The build installed *something* it called pinned, but not the bytes this
    checkout pins: a different pin file, or a build that lied."""
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256="c" * 64))
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert f"{'c' * 64} vs pin {pin}" in proc.stdout


@pytest.mark.parametrize(
    ("verified", "explanation"),
    [
        ("checksums", "only against that release's own checksums.txt"),
        ("none", "PULSE_SKIP_CHECKSUM=1"),
        ("source", "built from source"),
    ],
)
def test_an_install_that_did_not_check_the_pin_fails(tmp_path, release, verified, explanation):
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(verified=verified, tarball_sha256=pin))
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert f"verified={verified}" in proc.stdout
    assert explanation in proc.stdout


def test_a_pin_file_from_another_tag_says_which_one_to_use(tmp_path, release):
    _tarball_path, pin, _pins_file = release
    other = tmp_path / "other-tag.sha256"
    other.write_text(_pins({("v1.0.0", PLATFORM): "d" * 64}))
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin))
    proc = _run("--rootfs", root, "--pins", other)
    assert proc.returncode == 1
    assert f"pins no {VERSION} {PLATFORM}" in proc.stdout
    assert "release tag this image was built from" in proc.stdout


def test_an_image_built_from_other_pins_fails(tmp_path, release):
    """The record agrees with the customer's pin, but the pin file the build
    itself carried says otherwise -- so the record and the build disagree."""
    _tarball_path, pin, pins = release
    root = _rootfs(
        tmp_path,
        record=_record(tarball_sha256=pin),
        image_pins=_pins({(VERSION, PLATFORM): "e" * 64}),
    )
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert "the image was not built from these pins" in proc.stdout


def test_a_platform_other_than_the_one_asked_for_fails(tmp_path, release):
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin))
    proc = _run("--rootfs", root, "--pins", pins, "--platform", "linux/arm64")
    assert proc.returncode == 1
    assert "vs requested linux/arm64" in proc.stdout


@pytest.mark.parametrize(
    "record",
    [
        _record() + "extra=1\n",
        _record() + f"version={VERSION}\n",
        _record(verified="trusted"),
        _record(binary_sha256="not-a-digest"),
        "version=v9.9.9\n",
    ],
    ids=["unknown-key", "duplicate-key", "unknown-verified", "bad-digest", "incomplete"],
)
def test_a_malformed_record_is_not_guessed_at(tmp_path, release, record):
    _tarball_path, _pin, pins = release
    root = _rootfs(tmp_path, record=record)
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert "install record:" in proc.stdout


def test_a_consistently_rewritten_record_is_not_detected_and_the_output_says_so(tmp_path, release):
    """Whoever can replace the binary in an image -- a re-pushed tag, a derived
    image -- can rewrite the unsigned record next to it. No check here can see
    that, so the verdict must not claim more than the record can carry: it is
    as good as the image digest that was verified (review round 1, #2)."""
    _tarball_path, pin, pins = release
    trojan = b"\x7fELF not the pinned pulse\n"
    root = _rootfs(
        tmp_path,
        binary=trojan,
        record=_record(tarball_sha256=pin, binary_sha256=_sha(trojan)),
        image_pins=pins.read_text(),
    )
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 0
    assert "VERIFIED against install record" in proc.stdout
    assert "only as good as the image digest you verified" in proc.stdout
    assert "--tarball" in proc.stdout


def test_a_record_without_the_image_pin_file_fails(tmp_path, release):
    """Every build that writes the record also copies scripts/ into the image,
    pin file included; a record without it is an altered image, and the
    contract says the comparison is required (review round 1, #6)."""
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin))
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert "FAIL  the image carries an install record but no /app/scripts/pulse-pinned.sha256" in proc.stdout


def test_an_image_without_its_pin_file_says_the_comparison_was_not_made(tmp_path, release):
    """Images of 0.45-0916 and earlier predate the pin file. The tarball check
    still stands on its own, but the output has to say what it did not compare."""
    tarball, _pin, pins = release
    proc = _run("--rootfs", _rootfs(tmp_path), "--pins", pins, "--tarball", tarball)
    assert proc.returncode == 0, proc.stdout
    assert "not compared: the image has no /app/scripts/pulse-pinned.sha256" in proc.stdout


def test_an_image_without_a_record_is_not_verified_by_default(tmp_path, release):
    """Every image published before #340: the binary is there, and nothing in
    the image says which tarball it came from."""
    _tarball_path, _pin, pins = release
    root = _rootfs(tmp_path, image_pins=pins.read_text())
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert "no install record" in proc.stdout
    assert "--tarball" in proc.stdout


def test_an_image_without_pulse_is_reported_as_such(tmp_path, release):
    _tarball_path, _pin, pins = release
    root = _rootfs(tmp_path, binary=None)
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 3
    assert "INSTALL_PULSE=0" in proc.stdout


def test_a_symlinked_binary_is_not_followed(tmp_path, release):
    """A link in an unpacked image resolves against the host doing the check.
    Pointed at a file with exactly the recorded digest, following it would
    "verify" whatever the image really runs."""
    _tarball_path, pin, pins = release
    host_copy = tmp_path / "host-pulse"
    host_copy.write_bytes(BINARY)
    root = _rootfs(tmp_path, binary=None, record=_record(tarball_sha256=pin))
    (root / "usr/local/bin").mkdir(parents=True)
    (root / "usr/local/bin/pulse").symlink_to(host_copy)
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert "is a symlink; refusing to follow it" in proc.stdout


def test_a_symlinked_directory_on_the_way_is_not_followed(tmp_path, release):
    _tarball_path, _pin, pins = release
    outside = tmp_path / "outside"
    (outside / "bin").mkdir(parents=True)
    (outside / "bin/pulse").write_bytes(BINARY)
    root = _rootfs(tmp_path, binary=None)
    (root / "usr").mkdir()
    (root / "usr/local").symlink_to(outside)
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 1
    assert "resolves outside" in proc.stdout


# --- the independent check: the pinned tarball -------------------------------


def test_the_pinned_tarball_verifies_an_image_that_predates_the_record(tmp_path, release):
    tarball, _pin, pins = release
    root = _rootfs(tmp_path, image_pins=pins.read_text())
    proc = _run("--rootfs", root, "--pins", pins, "--tarball", tarball)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFIED against pinned tarball" in proc.stdout
    assert "only as good as the image digest" not in proc.stdout


def test_record_and_tarball_together_verify_both_chains(tmp_path, release):
    tarball, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin), image_pins=pins.read_text())
    proc = _run("--rootfs", root, "--pins", pins, "--tarball", tarball)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFIED against install record and pinned tarball" in proc.stdout


def test_a_tarball_that_is_not_pinned_proves_nothing(tmp_path, release):
    """Same binary inside, different archive: whoever repacked it could have
    put anything next to it. Only the pinned bytes count."""
    _tarball_path, _pin, pins = release
    stray = _tarball(
        tmp_path / "stray.tar.gz",
        members=[("pulse", BINARY, "file"), ("README", b"repacked\n", "file")],
    )
    root = _rootfs(tmp_path)
    proc = _run("--rootfs", root, "--pins", pins, "--tarball", stray)
    assert proc.returncode == 1
    assert "matches no pin(s)" in proc.stdout
    # Its binary would match -- and is never looked at (review round 1, #7).
    assert "'pulse' in the tarball" not in proc.stdout


def test_an_unpinned_tarball_is_never_parsed(tmp_path, release):
    """An unpinned file is untrusted input; handing it to the tar/gzip parser
    first and checking the pin afterwards exposes the parser for nothing
    (review round 1, #7). The pin decides before anything is parsed."""
    _tarball_path, _pin, pins = release
    garbage = tmp_path / "garbage.tar.gz"
    garbage.write_bytes(b"\x1f\x8b not really gzip")
    proc = _run("--rootfs", _rootfs(tmp_path), "--pins", pins, "--tarball", garbage)
    assert proc.returncode == 1
    assert "matches no pin(s)" in proc.stdout
    assert "not a readable .tar.gz" not in proc.stdout


def test_the_tarball_is_read_exactly_once(tmp_path, release):
    """The digest that is checked must be of the bytes that are parsed. Served
    through a FIFO, a second read has no writer and never returns: a verifier
    that hashes the file and then reopens it to parse it hangs here, and one
    that could be handed different bytes the second time is the TOCTOU the
    review found (round 1, #7)."""
    tarball, _pin, pins = release
    data = tarball.read_bytes()
    fifo = tmp_path / "served.tar.gz"
    os.mkfifo(fifo)

    def serve_once() -> None:
        with fifo.open("wb") as handle:
            handle.write(data)

    writer = threading.Thread(target=serve_once, daemon=True)
    writer.start()
    root = _rootfs(tmp_path, image_pins=pins.read_text())
    try:
        proc = subprocess.run(
            [sys.executable, str(VERIFIER), "--rootfs", str(root), "--pins", str(pins), "--tarball", str(fifo)],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("the verifier opened the tarball a second time")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "VERIFIED against pinned tarball" in proc.stdout


def test_record_and_tarball_that_name_different_pins_do_not_verify(tmp_path, release):
    """Both chains can pass on their own and still contradict each other: the
    record names the amd64 tarball, the tarball handed in is a different pinned
    one that happens to contain the same binary. Two accounts of one image that
    disagree are not a verification (review round 1, #9)."""
    tarball, pin, pins = release
    other = _tarball(
        tmp_path / "other.tar.gz",
        members=[("pulse", BINARY, "file"), ("NOTES", b"another build\n", "file")],
    )
    pins.write_text(_pins({(VERSION, PLATFORM): pin, (VERSION, "linux-arm64"): _sha(other.read_bytes())}))
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin), image_pins=pins.read_text())
    proc = _run("--rootfs", root, "--pins", pins, "--tarball", other)
    assert proc.returncode == 1, proc.stdout
    assert "FAIL  install record names the same tarball" in proc.stdout


def test_a_tarball_larger_than_any_release_is_refused_unread(tmp_path, release, monkeypatch, capsys):
    tarball, _pin, pins = release
    monkeypatch.setattr(verify_pulse_image, "MAX_TARBALL_BYTES", 16)
    code = verify_pulse_image.main(
        ["--rootfs", str(_rootfs(tmp_path)), "--pins", str(pins), "--tarball", str(tarball)]
    )
    assert code == 1
    assert "larger than 16 bytes" in capsys.readouterr().out


def test_a_member_claiming_more_than_the_limit_is_refused_before_it_is_read(monkeypatch, tmp_path):
    data = _tarball(tmp_path / "t.tar.gz").read_bytes()
    monkeypatch.setattr(verify_pulse_image, "MAX_MEMBER_BYTES", len(BINARY) - 1)
    opened: list[str] = []
    real = tarfile.TarFile.extractfile
    monkeypatch.setattr(
        tarfile.TarFile, "extractfile", lambda self, member: opened.append(member) or real(self, member)
    )
    with pytest.raises(verify_pulse_image.EvidenceError, match="claims"):
        verify_pulse_image.tarball_binary_sha256(data, "t.tar.gz")
    assert opened == []


def test_the_member_is_hashed_under_a_bound_whatever_its_header_says(monkeypatch, tmp_path):
    """Defence in depth: the header's size was checked, but the hash itself
    still stops at the limit if the reader hands back more than that."""
    data = _tarball(tmp_path / "t.tar.gz").read_bytes()
    monkeypatch.setattr(verify_pulse_image, "MAX_MEMBER_BYTES", len(BINARY))
    monkeypatch.setattr(tarfile.TarFile, "extractfile", lambda self, member: io.BytesIO(BINARY + b"x" * 64))
    with pytest.raises(verify_pulse_image.EvidenceError, match="more than"):
        verify_pulse_image.tarball_binary_sha256(data, "t.tar.gz")


def test_a_binary_that_is_not_the_one_in_the_pinned_tarball_fails(tmp_path, release):
    """The pinned tarball is genuine; the image runs something else. With no
    record in the image, this is the only check that can see it."""
    tarball, _pin, pins = release
    root = _rootfs(tmp_path, binary=b"something else entirely")
    proc = _run("--rootfs", root, "--pins", pins, "--tarball", tarball)
    assert proc.returncode == 1
    assert "DIFFERS from the binary in the image" in proc.stdout


@pytest.mark.parametrize(
    "members",
    [
        [("pulse", b"/usr/bin/true", "symlink")],
        [("pulse", BINARY, "file"), ("./pulse", BINARY, "file")],
        [("../pulse", BINARY, "file")],
        [("bin/pulse", BINARY, "file")],
    ],
    ids=["symlink", "two-candidates", "traversal", "nested"],
)
def test_a_tarball_with_an_unexpected_layout_is_refused_without_unpacking(tmp_path, release, members):
    _tarball_path, _pin, pins = release
    hostile = _tarball(tmp_path / "hostile.tar.gz", members=members)
    # Pinned, so the refusal is about the layout and not about the digest.
    pins.write_text(pins.read_text() + f"v0.0.1  {PLATFORM}  {_sha(hostile.read_bytes())}\n")
    root = _rootfs(tmp_path)
    workdir = tmp_path / "cwd"
    workdir.mkdir()
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), "--rootfs", str(root), "--pins", str(pins), "--tarball", str(hostile)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=workdir,
    )
    assert proc.returncode == 1
    assert "tarball:" in proc.stdout
    assert list(workdir.iterdir()) == [], "the verifier unpacked something"
    assert not (tmp_path / "pulse").exists()


def test_a_corrupt_tarball_is_a_failure_not_a_crash(tmp_path, release):
    _tarball_path, _pin, pins = release
    broken = tmp_path / "broken.tar.gz"
    broken.write_bytes(b"\x1f\x8b not really gzip")
    # Pinned, so that it gets as far as the parser.
    pins.write_text(pins.read_text() + f"v0.0.1  {PLATFORM}  {_sha(broken.read_bytes())}\n")
    proc = _run("--rootfs", _rootfs(tmp_path), "--pins", pins, "--tarball", broken)
    assert proc.returncode == 1
    assert "not a readable .tar.gz" in proc.stdout


# --- the trusted pin file -----------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        f"{VERSION} {PLATFORM}\n",
        f"{VERSION} {PLATFORM} {'a' * 63}\n",
        f"{VERSION} {PLATFORM} {'a' * 64}\n{VERSION} {PLATFORM} {'b' * 64}\n",
    ],
    ids=["missing-digest", "short-digest", "duplicate"],
)
def test_an_ambiguous_pin_file_is_refused(tmp_path, text):
    pins = tmp_path / "pins"
    pins.write_text(text)
    proc = _run("--rootfs", _rootfs(tmp_path), "--pins", pins)
    assert proc.returncode == 2
    assert "cannot read the pin file" in proc.stderr


def test_the_default_pin_file_is_the_one_next_to_the_script():
    assert verify_pulse_image.DEFAULT_PINS == REPO_ROOT / "scripts" / "pulse-pinned.sha256"
    # And it parses under the verifier's stricter reading, or the default
    # invocation would fail on every image.
    assert verify_pulse_image.parse_pins(verify_pulse_image.DEFAULT_PINS.read_text())


# --- an environment that cannot answer is exit 2, never a traceback -------------
#
# Exit 1 means "the evidence says no". A file this process cannot read, a
# filesystem it cannot walk, or a temp directory it cannot create is no evidence
# either way, and the contract promises exit 2 for it (review round 1, #8).


def test_a_symlink_loop_in_the_image_filesystem_is_an_environment_error(tmp_path, release):
    _tarball_path, _pin, pins = release
    root = _rootfs(tmp_path, binary=None)
    (root / "usr").mkdir()
    (root / "usr/local").symlink_to("local2")
    (root / "usr/local2").symlink_to("local")
    proc = _run("--rootfs", root, "--pins", pins)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "Traceback" not in proc.stderr
    assert "cannot read" in proc.stderr


def test_an_unreadable_binary_is_an_environment_error(tmp_path, release, monkeypatch, capsys):
    """As root the permission bits do not bite, so the read itself is made to fail."""
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin), image_pins=pins.read_text())

    def denied(path):
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(verify_pulse_image, "sha256_file", denied)
    assert verify_pulse_image.main(["--rootfs", str(root), "--pins", str(pins)]) == 2
    assert "Permission denied" in capsys.readouterr().err


def test_an_unreadable_tarball_is_an_environment_error(tmp_path, release):
    _tarball_path, _pin, pins = release
    proc = _run("--rootfs", _rootfs(tmp_path), "--pins", pins, "--tarball", tmp_path / "missing.tar.gz")
    assert proc.returncode == 2
    assert "cannot read --tarball" in proc.stderr


def test_rootfs_mode_needs_no_temporary_directory(tmp_path, release, monkeypatch):
    """A read-only /tmp must not stop a check that never needed it."""
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin), image_pins=pins.read_text())

    def no_tmp(*args, **kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(verify_pulse_image.tempfile, "TemporaryDirectory", no_tmp)
    assert verify_pulse_image.main(["--rootfs", str(root), "--pins", str(pins)]) == 0


def test_image_mode_without_a_temporary_directory_is_an_environment_error(tmp_path, release, monkeypatch, capsys):
    _tarball_path, _pin, pins = release

    def no_tmp(*args, **kwargs):
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(verify_pulse_image.tempfile, "TemporaryDirectory", no_tmp)
    assert verify_pulse_image.main(["--image", "img:any", "--pins", str(pins)]) == 2
    assert "Read-only file system" in capsys.readouterr().err


# --- --image: a created, never started, container ------------------------------


@pytest.fixture
def fake_engine(tmp_path: Path):
    """A `docker` that serves `cp` out of a rootfs directory and logs every call."""
    bindir = tmp_path / "engine-bin"
    bindir.mkdir()
    log = tmp_path / "engine.log"

    def make(root: Path, *, cp_error: str | None = None) -> dict[str, str]:
        failing = (
            f'  echo "{cp_error}" >&2; exit 1\n' if cp_error else ""
        )
        (bindir / "docker").write_text(
            "#!/usr/bin/env bash\n"
            f'printf "%s\\n" "$*" >> "{log}"\n'
            'case "$1" in\n'
            '  create) echo "Unable to find image locally" >&2; echo cid0123; exit 0 ;;\n'
            f'  inspect) echo "{IMAGE_ID}"; exit 0 ;;\n'
            f"  image) echo '[\"{REPO_DIGEST}\"]'; exit 0 ;;\n"
            "  cp)\n"
            f"{failing}"
            '    src="${2#cid0123:}"\n'
            f'    if [[ -e "{root}$src" || -L "{root}$src" ]]; then cp -P "{root}$src" "$3"; exit 0; fi\n'
            '    echo "Error response from daemon: Could not find the file $src in container cid0123" >&2; exit 1 ;;\n'
            "  rm) exit 0 ;;\n"
            '  *) echo "unexpected: $*" >&2; exit 99 ;;\n'
            "esac\n"
        )
        (bindir / "docker").chmod(0o755)
        return dict(os.environ, PATH=f"{bindir}{os.pathsep}{os.environ['PATH']}")

    make.log = log  # type: ignore[attr-defined]
    return make


def test_image_mode_copies_out_of_a_container_it_never_starts(tmp_path, release, fake_engine):
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin), image_pins=pins.read_text())
    env = fake_engine(root)
    proc = _run(
        "--image", "ghcr.io/example/shapoclyack-scanner:test", "--platform", "linux/amd64", "--pins", pins,
        env=env,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = fake_engine.log.read_text().splitlines()
    assert calls[0] == "create --platform linux/amd64 ghcr.io/example/shapoclyack-scanner:test"
    assert calls[1:3] == [
        "inspect --format {{.Image}} cid0123",
        f"image inspect --format {{{{json .RepoDigests}}}} {IMAGE_ID}",
    ]
    assert [c.split()[0] for c in calls[3:]] == ["cp", "cp", "cp", "rm"]
    # The images declare VOLUMEs, and `create` makes an anonymous volume for
    # each; without -v every run would leave four behind (review round 1, #3).
    assert calls[-1] == "rm -f -v cid0123"
    assert not any(c.split()[0] in {"run", "start", "exec"} for c in calls)


def test_image_mode_names_the_image_it_examined(tmp_path, release, fake_engine):
    """A tag can be re-pushed between two pulls. What was verified is the image
    the engine resolved, so the output names it -- the ID and the repository
    digest to compare with the one you trust (review round 1, #2)."""
    _tarball_path, pin, pins = release
    root = _rootfs(tmp_path, record=_record(tarball_sha256=pin), image_pins=pins.read_text())
    proc = _run("--image", "ghcr.io/example/shapoclyack-scanner:test", "--pins", pins, env=fake_engine(root))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert f"image id {IMAGE_ID}" in proc.stdout
    assert REPO_DIGEST in proc.stdout


def test_image_mode_never_hands_the_engine_an_option_as_the_image(tmp_path, release, fake_engine):
    _tarball_path, _pin, pins = release
    env = fake_engine(_rootfs(tmp_path))
    proc = _run("--image=--privileged", "--pins", pins, env=env)
    assert proc.returncode == 2
    assert not fake_engine.log.exists()


def test_image_mode_reports_an_image_without_pulse(tmp_path, release, fake_engine):
    _tarball_path, _pin, pins = release
    env = fake_engine(_rootfs(tmp_path, binary=None))
    proc = _run("--image", "img:nopulse", "--pins", pins, env=env)
    assert proc.returncode == 3
    assert "INSTALL_PULSE=0" in proc.stdout


def test_image_mode_tells_a_daemon_error_from_a_missing_file(tmp_path, release, fake_engine):
    """A daemon that cannot answer must not read as "this image has no Pulse" --
    that is exit 3, an answer; this is exit 2, no answer. The container is
    removed either way."""
    _tarball_path, _pin, pins = release
    env = fake_engine(_rootfs(tmp_path), cp_error="Cannot connect to the Docker daemon")
    proc = _run("--image", "img:any", "--pins", pins, env=env)
    assert proc.returncode == 2
    assert "Cannot connect to the Docker daemon" in proc.stderr
    assert fake_engine.log.read_text().splitlines()[-1] == "rm -f -v cid0123"


def test_image_mode_does_not_follow_a_symlink_the_image_ships(tmp_path, release, fake_engine):
    _tarball_path, pin, pins = release
    host_copy = tmp_path / "host-pulse"
    host_copy.write_bytes(BINARY)
    root = _rootfs(tmp_path, binary=None, record=_record(tarball_sha256=pin))
    (root / "usr/local/bin").mkdir(parents=True)
    (root / "usr/local/bin/pulse").symlink_to(host_copy)
    proc = _run("--image", "img:link", "--pins", pins, env=fake_engine(root))
    assert proc.returncode == 1
    assert "refusing to follow it" in proc.stdout


# --- the image layout the verifier assumes -------------------------------------


def _pulse_bin_stage(dockerfile: Path) -> tuple[str, str]:
    """(pulse-bin stage text, final stage text) of a Dockerfile."""
    text = dockerfile.read_text()
    start = text.index("AS pulse-bin")
    end = text.index("\nFROM ", start)
    return text[start:end], text[end:]


@pytest.mark.parametrize("dockerfile", ["Dockerfile", "Dockerfile.allinone"])
def test_the_image_puts_pulse_and_its_record_where_the_verifier_looks(dockerfile):
    """The verifier reads fixed paths out of the image. The Dockerfile decides
    them in two places -- PULSE_DEST/PULSE_RECORD under /out, and the COPYs that
    map /out into the final stage -- so both have to agree with it."""
    stage, final = _pulse_bin_stage(REPO_ROOT / dockerfile)
    dest = re.search(r"PULSE_DEST=(\S+)", stage)
    record = re.search(r"PULSE_RECORD=(\S+)", stage)
    assert dest and record, f"{dockerfile}: the pulse-bin stage must pass PULSE_DEST and PULSE_RECORD"
    copies = [
        (src.rstrip("/") + "/", dst.rstrip("/") + "/")
        for src, dst in re.findall(r"^COPY --from=pulse-bin (\S+) (\S+)$", final, re.MULTILINE)
    ]
    assert copies, f"{dockerfile}: no COPY --from=pulse-bin in the final stage"

    def landed(path: str) -> str:
        matches = [(src, dst) for src, dst in copies if path.startswith(src)]
        assert len(matches) == 1, f"{path} is copied by {len(matches)} of {copies}"
        src, dst = matches[0]
        return (dst + path.removeprefix(src)).lstrip("/")

    assert landed(dest.group(1)) == verify_pulse_image.IMAGE_BINARY
    assert landed(record.group(1)) == verify_pulse_image.IMAGE_RECORD
    # The build must fail rather than ship a binary with no record.
    assert f"test -s {record.group(1)}" in stage
    assert "COPY scripts /app/scripts" in final
    assert verify_pulse_image.IMAGE_PINS == "app/scripts/pulse-pinned.sha256"


@pytest.mark.parametrize("dockerfile", ["Dockerfile", "Dockerfile.allinone"])
def test_the_pulse_copies_touch_only_the_directories_they_fill(dockerfile):
    """COPY of a directory also applies that directory's metadata to the target.
    /out/ onto /usr/local/ would restamp /usr/local itself from a scratch stage;
    one COPY per subdirectory keeps it to bin/ and share/ (review round 1, #10).
    Both sources must exist even when INSTALL_PULSE=0 leaves them empty, or the
    COPY fails -- so they are created before that early exit."""
    stage, final = _pulse_bin_stage(REPO_ROOT / dockerfile)
    targets = [dst.rstrip("/") for _src, dst in re.findall(r"^COPY --from=pulse-bin (\S+) (\S+)$", final, re.MULTILINE)]
    assert targets == ["/usr/local/bin", "/usr/local/share"], targets
    mkdir = stage.index("mkdir -p /out/bin /out/share")
    assert mkdir < stage.index('if [ "${INSTALL_PULSE}" != "1" ]; then')


def test_the_ci_smoke_runs_the_verifier_inside_the_built_image():
    """The Jenkins Smoke stage is the only place a real image build meets the
    verifier; without that line the Dockerfile wiring above is checked by text
    alone (review round 1, #9)."""
    jenkinsfile = (REPO_ROOT / "Jenkinsfile").read_text()
    start = jenkinsfile.index("stage('Smoke')")
    smoke = jenkinsfile[start : jenkinsfile.index("stage(", start + 1)]
    run = smoke[smoke.index("docker run") :]
    script = run[run.index("-c '") : run.index("\n              '\n")]
    lines = [line.strip() for line in script.splitlines()]
    assert "set -e" in lines
    assert "python scripts/verify-pulse-image.py --rootfs /" in lines
    assert lines.index("python scripts/verify-pulse-image.py --rootfs /") > lines.index("set -e")
