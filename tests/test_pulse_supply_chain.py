"""Supply-chain checks for the Pulse binary the scanner runs.

The Pulse CLI comes from a GenDec GitHub Release and is granted
``cap_net_raw,cap_net_admin`` in the images, so a swapped binary is
root-equivalent on a sensor host. ``scripts/pulse-pinned.sha256`` is what makes
that a reviewed decision instead of a trusted download: these tests drive the
real installer script offline (a fake ``curl`` serves a local release) and
assert that a tarball which does not match the pinned digest is refused, and
that no environment knob turns the check off.

They also fail on the drift this is actually vulnerable to in practice: a
``PULSE_VERSION`` bump in one file and not the others, or a bump with no
matching pin.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install-pulse.sh"
PINS = REPO_ROOT / "scripts" / "pulse-pinned.sha256"

# Kept in step with the case statement in install-pulse.sh.
_PLATFORMS = {
    ("linux", "x86_64"): "linux-amd64",
    ("linux", "aarch64"): "linux-arm64",
    ("linux", "arm64"): "linux-arm64",
    ("darwin", "arm64"): "darwin-arm64",
    ("darwin", "x86_64"): "darwin-amd64",
}


def _host_platform() -> str:
    key = (platform.system().lower(), platform.machine().lower())
    if key not in _PLATFORMS:
        pytest.skip(f"install-pulse.sh does not support {key}")
    return _PLATFORMS[key]


def _parse_pins(text: str) -> dict[tuple[str, str], str]:
    pins: dict[tuple[str, str], str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        version, plat, digest = line.split()
        pins[(version, plat)] = digest.lower()
    return pins


def _default_arg(path: Path, name: str) -> str:
    """The default of `ARG <name>=…` / `<name>="${<name>:-…}"` in a build file."""
    text = path.read_text()
    for pattern in (
        rf"^ARG {name}=(\S+)$",
        rf'^\w+="\$\{{{name}:-(v?[0-9][^}}"]*)\}}"',
        rf"^def {name} = '([^']+)'$",
    ):
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            return match.group(1)
    raise AssertionError(f"no default for {name} in {path}")


# --- version/pin consistency -------------------------------------------------


def test_pinned_version_matches_every_build_file():
    """A PULSE_VERSION bump that misses one file builds a different binary than
    the one reviewed here; the image and the host install then disagree."""
    declared = {
        "scripts/install-pulse.sh": _default_arg(INSTALLER, "PULSE_VERSION"),
        "Dockerfile": _default_arg(REPO_ROOT / "Dockerfile", "PULSE_VERSION"),
        "Dockerfile.allinone": _default_arg(
            REPO_ROOT / "Dockerfile.allinone", "PULSE_VERSION"
        ),
        "Jenkinsfile.publish": _default_arg(
            REPO_ROOT / "Jenkinsfile.publish", "PULSE_VERSION"
        ),
    }
    assert len(set(declared.values())) == 1, declared


def test_default_version_is_pinned_for_every_supported_platform():
    """The whole point of the pin file: the version that builds by default must
    not fall through to the release's own checksums.txt on any platform."""
    version = _default_arg(REPO_ROOT / "Dockerfile", "PULSE_VERSION")
    pins = _parse_pins(PINS.read_text())
    missing = [
        plat for plat in sorted(set(_PLATFORMS.values())) if (version, plat) not in pins
    ]
    assert not missing, f"{version} has no pinned digest for {missing}"


def test_pins_are_full_sha256_values():
    pins = _parse_pins(PINS.read_text())
    assert pins
    for key, digest in pins.items():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{key} -> {digest!r}"


# --- the installer, driven offline against a fake release --------------------


@pytest.fixture
def fake_release(tmp_path: Path):
    """A local stand-in for a GenDec release plus a `curl` that serves it.

    Returns a callable: run(version, *, pin, skip_checksum, corrupt) -> CompletedProcess.
    """
    if shutil.which("bash") is None:  # pragma: no cover - bash is a hard dep here
        pytest.skip("bash not available")

    asset = _host_platform()
    release = tmp_path / "release"
    release.mkdir()

    payload = tmp_path / "pulse"
    payload.write_text("#!/bin/sh\necho 'pulse 9.9.9'\n")
    payload.chmod(0o755)

    def _tarball(version: str) -> tuple[str, str]:
        name = f"pulse-{version}-{asset}.tar.gz"
        path = release / name
        if not path.exists():
            # Built once and reused: gzip embeds an mtime, so a rebuild would
            # change the digest a previous call in the same test just learned.
            with tarfile.open(path, "w:gz") as tar:
                tar.add(payload, arcname="pulse")
        return name, hashlib.sha256(path.read_bytes()).hexdigest()

    # A `curl` that answers from the release directory and nowhere else, so a
    # test that accidentally reaches the network fails instead of passing.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    curl = bindir / "curl"
    curl.write_text(
        "#!/usr/bin/env bash\n"
        "dest=''; url=''\n"
        "while [[ $# -gt 0 ]]; do\n"
        '  case "$1" in\n'
        '    -o) dest="$2"; shift 2 ;;\n'
        "    -w|-H) shift 2 ;;\n"
        "    -*) shift ;;\n"
        '    *) url="$1"; shift ;;\n'
        "  esac\n"
        "done\n"
        'src="' + str(release) + '/$(basename "$url")"\n'
        'if [[ -f "$src" ]]; then cp "$src" "$dest"; echo 200; else echo 404; fi\n'
    )
    curl.chmod(0o755)

    def run(
        version: str,
        *,
        pins: str | None,
        skip_checksum: bool = False,
        corrupt: bool = False,
        checksums: bool = True,
    ):
        name, digest = _tarball(version)
        served = digest
        if corrupt:
            # Same name, different bytes: exactly the "release was rewritten
            # after review" case the pin exists to catch. checksums.txt is
            # regenerated from the new bytes, because whoever can rewrite the
            # tarball can rewrite the checksum file sitting next to it.
            path = release / name
            path.write_bytes(path.read_bytes() + b"\x00")
            served = hashlib.sha256(path.read_bytes()).hexdigest()
        if checksums:
            (release / "checksums.txt").write_text(f"{served}  dist/{name}\n")
        dest = tmp_path / "out" / "pulse"
        dest.unlink(missing_ok=True)
        pin_file = tmp_path / "pins"
        pin_file.write_text(pins if pins is not None else "")
        env = dict(os.environ)
        env.update(
            PATH=f"{bindir}{os.pathsep}{env['PATH']}",
            PULSE_DEST=str(tmp_path / "out" / "pulse"),
            PULSE_VERSION=version,
            PULSE_PINS=str(pin_file),
            PULSE_SKIP_CHECKSUM="1" if skip_checksum else "0",
        )
        env.pop("GITHUB_TOKEN", None)
        env.pop("GH_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(INSTALLER)],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc, digest, dest

    run.asset = asset  # type: ignore[attr-defined]
    return run


def test_matching_pin_installs(fake_release):
    asset = fake_release.asset
    # Two passes: the tarball's digest is only known once it has been built, so
    # build once to learn it, then again with that value pinned.
    _proc, digest, _dest = fake_release("v9.9.9", pins=None)
    proc, _digest, dest = fake_release("v9.9.9", pins=f"v9.9.9 {asset} {digest}")
    assert proc.returncode == 0, proc.stderr
    assert "verified against pinned digest" in proc.stdout
    assert dest.exists()


def test_pin_mismatch_refuses_to_install(fake_release):
    asset = fake_release.asset
    wrong = "0" * 64
    proc, _digest, dest = fake_release("v9.9.9", pins=f"v9.9.9 {asset} {wrong}")
    assert proc.returncode != 0
    assert "sha256 mismatch" in proc.stderr
    assert "not the bytes this repository was reviewed against" in proc.stderr
    assert not dest.exists()


def test_rewritten_release_is_caught_even_though_checksums_txt_agrees(fake_release):
    """checksums.txt travels with the tarball, so an attacker who can rewrite
    one rewrites both. The pin is the only value they do not control."""
    asset = fake_release.asset
    proc, digest, dest = fake_release("v9.9.9", pins=None)
    assert proc.returncode == 0, proc.stderr  # unpinned: checksums.txt is enough
    proc, _d, dest = fake_release(
        "v9.9.9", pins=f"v9.9.9 {asset} {digest}", corrupt=True
    )
    assert proc.returncode != 0
    assert "sha256 mismatch" in proc.stderr
    assert not dest.exists()


def test_skip_checksum_cannot_bypass_a_pin(fake_release):
    asset = fake_release.asset
    wrong = "0" * 64
    proc, _digest, dest = fake_release(
        "v9.9.9", pins=f"v9.9.9 {asset} {wrong}", skip_checksum=True
    )
    assert proc.returncode != 0
    assert "PULSE_SKIP_CHECKSUM=1 ignored" in proc.stderr
    assert "sha256 mismatch" in proc.stderr
    assert not dest.exists()


def test_unpinned_version_warns_and_falls_back_to_checksums_txt(fake_release):
    asset = fake_release.asset
    proc, _digest, dest = fake_release("v9.9.9", pins=f"v1.0.0 {asset} {'a' * 64}")
    assert proc.returncode == 0, proc.stderr
    assert "is not pinned" in proc.stderr
    assert "sha256 verified: pulse-v9.9.9" in proc.stdout
    assert dest.exists()


def test_unpinned_version_without_checksums_txt_still_refuses(fake_release):
    proc, _digest, dest = fake_release("v9.9.9", pins=None, checksums=False)
    assert proc.returncode != 0
    assert "refusing to install an unverified binary" in proc.stderr
    assert not dest.exists()


# --- the pin helper: where the signature actually gates something ------------
#
# install-pulse.sh does not check a signature, on purpose: on the pinned path
# the digest committed here is strictly stronger than anything fetched from the
# release being installed. The signature's job is to gate the moment a *new*
# digest enters this repository, which is scripts/pulse-pin.sh.

PIN_HELPER = REPO_ROOT / "scripts" / "pulse-pin.sh"


@pytest.fixture
def fake_pin_release(tmp_path: Path):
    """A release served to scripts/pulse-pin.sh, with or without a signature."""
    release = tmp_path / "release"
    release.mkdir()

    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "curl").write_text(
        "#!/usr/bin/env bash\n"
        "dest=''; url=''\n"
        "while [[ $# -gt 0 ]]; do\n"
        '  case "$1" in\n'
        '    -o) dest="$2"; shift 2 ;;\n'
        "    -w|-H) shift 2 ;;\n"
        "    -*) shift ;;\n"
        '    *) url="$1"; shift ;;\n'
        "  esac\n"
        "done\n"
        'src="' + str(release) + '/$(basename "$url")"\n'
        'if [[ -f "$src" ]]; then cp "$src" "$dest"; echo 200; else echo 404; fi\n'
    )
    (bindir / "curl").chmod(0o755)

    def run(
        *,
        signed: bool,
        allow_unsigned: bool = False,
        cosign_ok: bool = True,
        version: str = "v9.9.9",
    ):
        lines = [
            f"{'a' * 64}  dist/pulse-{version}-{plat}.tar.gz"
            for plat in ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64")
        ]
        (release / "checksums.txt").write_text("\n".join(lines) + "\n")
        bundle = release / "checksums.txt.cosign.bundle"
        if signed:
            bundle.write_text("{}\n")
        else:
            bundle.unlink(missing_ok=True)
        # A cosign that records that it was called, and with which identity.
        called = tmp_path / "cosign-args"
        called.unlink(missing_ok=True)
        (bindir / "cosign").write_text(
            "#!/usr/bin/env bash\n"
            'printf "%s\\n" "$@" > '
            + str(called)
            + "\n"
            + (
                "exit 0\n"
                if cosign_ok
                else 'echo "signature not verified" >&2\nexit 1\n'
            )
        )
        (bindir / "cosign").chmod(0o755)

        env = dict(os.environ)
        env.update(
            PATH=f"{bindir}{os.pathsep}{env['PATH']}",
            PULSE_PIN_ALLOW_UNSIGNED="1" if allow_unsigned else "0",
        )
        env.pop("GITHUB_TOKEN", None)
        env.pop("GH_TOKEN", None)
        proc = subprocess.run(
            ["bash", str(PIN_HELPER), version],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        args = called.read_text().splitlines() if called.exists() else []
        return proc, args

    return run


def test_pin_helper_refuses_an_unsigned_release(fake_pin_release):
    proc, cosign_args = fake_pin_release(signed=False)
    assert proc.returncode != 0
    assert "nothing to verify" in proc.stderr
    assert proc.stdout == ""
    assert cosign_args == []


def test_pin_helper_allows_an_unsigned_release_only_on_request(fake_pin_release):
    proc, _ = fake_pin_release(signed=False, allow_unsigned=True)
    assert proc.returncode == 0, proc.stderr
    assert "WARNING" in proc.stderr
    assert "only as good as this download" in proc.stderr


def test_pin_helper_constrains_the_signer_identity(fake_pin_release):
    """cosign verify-blob with no --certificate-identity accepts a signature
    from anybody, which would make the whole exercise decorative."""
    proc, cosign_args = fake_pin_release(signed=True)
    assert proc.returncode == 0, proc.stderr
    assert "verify-blob" in cosign_args
    identity = cosign_args[cosign_args.index("--certificate-identity") + 1]
    assert identity == (
        "https://github.com/onixus/GenDec/.github/workflows/release.yml"
        "@refs/tags/v9.9.9"
    ), "identity must pin the workflow and the tag, not just the repository"
    issuer = cosign_args[cosign_args.index("--certificate-oidc-issuer") + 1]
    assert issuer == "https://token.actions.githubusercontent.com"


def test_pin_helper_prints_nothing_when_the_signature_fails(fake_pin_release):
    proc, _ = fake_pin_release(signed=True, cosign_ok=False)
    assert proc.returncode != 0
    assert proc.stdout == ""


def test_pin_helper_output_is_parsed_by_the_pin_reader(fake_pin_release):
    """The helper's stdout is pasted into pulse-pinned.sha256 verbatim, so the
    two formats have to stay the same one."""
    proc, _ = fake_pin_release(signed=True)
    assert proc.returncode == 0, proc.stderr
    pins = _parse_pins(proc.stdout)
    assert set(pins) == {("v9.9.9", plat) for plat in set(_PLATFORMS.values())}
    assert set(pins.values()) == {"a" * 64}
