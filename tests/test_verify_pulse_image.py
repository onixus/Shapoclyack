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
    # Said out loud: the record is the build's own account of itself.
    assert "does not rest on the build" in proc.stdout


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
    assert "does not rest on the build" not in proc.stdout


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
    assert "matches the binary in the image" in proc.stdout


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
    assert [c.split()[0] for c in calls] == ["create", "cp", "cp", "cp", "rm"]
    assert calls[-1] == "rm -f cid0123"
    assert not any(c.split()[0] in {"run", "start", "exec"} for c in calls)


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
    assert fake_engine.log.read_text().splitlines()[-1] == "rm -f cid0123"


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
    them in two places -- PULSE_DEST/PULSE_RECORD under /out, and the COPY that
    maps /out into the final stage -- so both have to agree with it."""
    stage, final = _pulse_bin_stage(REPO_ROOT / dockerfile)
    dest = re.search(r"PULSE_DEST=(\S+)", stage)
    record = re.search(r"PULSE_RECORD=(\S+)", stage)
    assert dest and record, f"{dockerfile}: the pulse-bin stage must pass PULSE_DEST and PULSE_RECORD"
    copy = re.search(r"^COPY --from=pulse-bin (\S+) (\S+)$", final, re.MULTILINE)
    assert copy, f"{dockerfile}: no COPY --from=pulse-bin in the final stage"
    src, dst = copy.group(1).rstrip("/") + "/", copy.group(2).rstrip("/") + "/"

    def landed(path: str) -> str:
        assert path.startswith(src), f"{path} is outside the copied {src}"
        return (dst + path.removeprefix(src)).lstrip("/")

    assert landed(dest.group(1)) == verify_pulse_image.IMAGE_BINARY
    assert landed(record.group(1)) == verify_pulse_image.IMAGE_RECORD
    # The build must fail rather than ship a binary with no record.
    assert f"test -s {record.group(1)}" in stage
    assert "COPY scripts /app/scripts" in final
    assert verify_pulse_image.IMAGE_PINS == "app/scripts/pulse-pinned.sha256"
