#!/usr/bin/env python3
"""Check the Pulse binary inside a Shapoclyack image against the reviewed pin (#340).

The images carry ``/usr/local/bin/pulse`` with ``cap_net_raw,cap_net_admin``,
and it is the default service-probe engine, so "which Pulse is this?" is a
question a customer's review has to be able to answer from the outside. What
this repository pins is the SHA-256 of the GenDec release *tarball*
(``scripts/pulse-pinned.sha256``), while the image keeps only the binary that
came out of it. Two ways bridge that gap:

* ``--tarball``: the pinned tarball itself, read once into memory. Its digest
  must be in the pin file before anything in it is parsed; then the ``pulse``
  member is hashed (never unpacked to disk) and compared with the binary in
  the image. This does not rest on anything the image says about itself, and
  it works for every published image. It needs the tarball, which today only a
  holder of a GenDec token can download -- see
  docs/adr/0001-pulse-distribution-model.md.
* The install record ``/usr/local/share/shapoclyack/pulse-install.txt`` that
  ``scripts/install-pulse.sh`` writes in images built after #340: which tarball
  was installed, which check it passed and what the binary hashed to. It is
  unsigned and lives in the same image as the binary, so it catches a binary
  replaced *without* its record -- a later layer, a patched image -- and says
  the build installed the pinned tarball by its own account. Against someone
  who rewrites both, it is only as good as the image digest you verified:
  check an image by ``...@sha256:<digest>`` you trust, and use ``--tarball``
  for a check that does not depend on the image at all.

The pin file to trust is the one **at the release tag the image was built
from**, in your own clone. This script is newer than most releases, so run it
from ``main`` (or a newer release) and hand it that tag's pins:

    git show shapoclyack-0.46-0922:scripts/pulse-pinned.sha256 > pins-0.46-0922.sha256
    scripts/verify-pulse-image.py --pins pins-0.46-0922.sha256 --platform linux/amd64 \\
        --image ghcr.io/onixus/shapoclyack-scanner@sha256:<digest> [--tarball pulse-v1.1.0-linux-amd64.tar.gz]
    scripts/verify-pulse-image.py --pins ... --rootfs ./unpacked-image [--tarball ...]

The copy inside the image is only compared against that file: a disagreement
means the image was built from different pins than the tag says.

``--image`` uses ``docker create`` + ``docker cp`` (``--engine podman`` works
too), never starts the container, and removes it with its anonymous volumes;
nothing from the image under review is executed. It prints the image ID and
repository digests the engine resolved, which is what was actually checked.
Python 3.9 or later, standard library only.

Exit status: 0 verified; 1 not verified (a check failed, or nothing ties the
binary to a pin); 2 usage or environment error (a file that cannot be read, no
engine, no temporary directory); 3 the image contains no Pulse.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Where the Dockerfiles put things; kept in step by tests/test_verify_pulse_image.py.
IMAGE_BINARY = "usr/local/bin/pulse"
IMAGE_RECORD = "usr/local/share/shapoclyack/pulse-install.txt"
IMAGE_PINS = "app/scripts/pulse-pinned.sha256"
DEFAULT_PINS = Path(__file__).resolve().with_name("pulse-pinned.sha256")

# OCI platform -> the asset suffix install-pulse.sh and the pin file use.
PLATFORMS = {"linux/amd64": "linux-amd64", "linux/arm64": "linux-arm64"}

# The Pulse binary and its tarball are a few MB. Anything larger than these is
# not a Pulse release, and reading it would only be a way to make this tool hang
# or exhaust memory: the tarball is held in memory so that the bytes whose
# digest is checked are the bytes that are parsed.
MAX_TARBALL_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_RECORD_KEYS = ("version", "platform", "verified", "tarball", "tarball_sha256", "binary_sha256")
# What each `verified=` value in a record means, for the message when it is not "pin".
_UNPINNED = {
    "checksums": "installed from a release that is not pinned, checked only against that release's own checksums.txt",
    "none": "installed from a release that is not pinned, with PULSE_SKIP_CHECKSUM=1 -- no check at all",
    "source": "built from source, not installed from the pinned release tarball",
}

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_NO_PULSE = 0, 1, 2, 3


class EvidenceError(Exception):
    """A file this check reads is present but cannot be trusted as-is."""


def parse_pins(text: str) -> dict[tuple[str, str], str]:
    """``<version> <platform> <sha256>`` lines, strictly.

    install-pulse.sh reads the same file more leniently (first match wins); here
    a malformed or duplicated line is an error, because a verifier that guesses
    which of two pins was meant has stopped verifying.
    """
    pins: dict[tuple[str, str], str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or not _SHA256.fullmatch(fields[2].lower()):
            raise EvidenceError(f"pin file line {number} is not '<version> <platform> <sha256>': {line!r}")
        key = (fields[0], fields[1])
        if key in pins:
            raise EvidenceError(f"pin file pins {key[0]} {key[1]} twice (line {number})")
        pins[key] = fields[2].lower()
    return pins


def parse_record(text: str) -> dict[str, str]:
    record: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or key not in _RECORD_KEYS:
            raise EvidenceError(f"install record line {number} is not a known 'key=value': {line!r}")
        if key in record:
            raise EvidenceError(f"install record sets {key} twice (line {number})")
        record[key] = value
    missing = [key for key in _RECORD_KEYS if key not in record]
    if missing:
        raise EvidenceError(f"install record is missing {', '.join(missing)}")
    if record["verified"] != "pin" and record["verified"] not in _UNPINNED:
        raise EvidenceError(f"install record has an unknown verified={record['verified']!r}")
    for key in ("tarball_sha256", "binary_sha256"):
        if record[key] and not _SHA256.fullmatch(record[key]):
            raise EvidenceError(f"install record {key} is not a sha256: {record[key]!r}")
    if not record["binary_sha256"]:
        raise EvidenceError("install record has no binary_sha256")
    return record


def _sha256_stream(stream, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    while chunk := stream.read(1 << 20):
        total += len(chunk)
        if limit is not None and total > limit:
            raise EvidenceError(f"more than {limit} bytes")
        digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return _sha256_stream(handle)


def read_bounded(path: Path, limit: int) -> bytes:
    """The whole file, read once; more than ``limit`` bytes is refused.

    Read once so that nothing can swap the file between the digest check and
    the parse (a second open of the same path is a second, different read).
    """
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise EvidenceError(f"{path.name} is larger than {limit} bytes; no Pulse release tarball is")
    return data


def tarball_binary_sha256(data: bytes, name: str) -> str:
    """SHA-256 of the ``pulse`` member of a release tarball held in memory.

    Called only on bytes whose digest is already pinned. Nothing is extracted
    to disk, so a hostile archive (``../`` names, links, devices) has nothing
    to write. The member must be the one regular file named ``pulse`` at the
    top of the archive -- the layout install-pulse.sh unpacks and installs.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            matches = [m for m in archive.getmembers() if m.name.removeprefix("./") == "pulse"]
            if len(matches) != 1:
                raise EvidenceError(f"{name} has {len(matches)} top-level 'pulse' entries, expected exactly one")
            member = matches[0]
            if not member.isreg():
                raise EvidenceError(f"'pulse' in {name} is not a regular file")
            if member.size > MAX_MEMBER_BYTES:
                raise EvidenceError(f"'pulse' in {name} claims {member.size} bytes")
            handle = archive.extractfile(member)
            if handle is None:  # pragma: no cover - isreg() already excludes this
                raise EvidenceError(f"'pulse' in {name} cannot be read")
            with handle:
                return _sha256_stream(handle, MAX_MEMBER_BYTES)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise EvidenceError(f"{name} is not a readable .tar.gz: {exc}") from exc


def _regular_or_none(path: Path, rel: str) -> Path | None:
    """``path`` if it is a regular file, None if absent; a link is refused.

    A symlink is not followed: in an unpacked image it would resolve against
    the host running this check, and hashing a host binary would "verify" the
    wrong thing.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        kind = "a symlink" if stat.S_ISLNK(info.st_mode) else "not a regular file"
        raise EvidenceError(f"/{rel} in the image is {kind}; refusing to follow it")
    return path


@dataclass
class Evidence:
    binary: Path | None
    record: Path | None
    image_pins: Path | None
    # What the engine resolved --image to; None for --rootfs.
    identity: str | None = None


def evidence_from_rootfs(root: Path) -> Evidence:
    found: list[Path | None] = []
    try:
        base = root.resolve()
        for rel in (IMAGE_BINARY, IMAGE_RECORD, IMAGE_PINS):
            candidate = base / rel
            # A directory on the way that is a symlink could lead out of the
            # tree; the leaf itself is checked by _regular_or_none.
            if not candidate.parent.resolve().is_relative_to(base):
                raise EvidenceError(f"/{rel} resolves outside {root}; refusing to follow it")
            found.append(_regular_or_none(candidate, rel))
    except RuntimeError as exc:
        # A symlink loop: RuntimeError up to Python 3.12, OSError from 3.13.
        raise OSError(f"cannot read the image filesystem under {root}: {exc}") from exc
    return Evidence(*found)


_ABSENT = ("no such container:path", "could not find the file", "no such file or directory")


def evidence_from_image(image: str, platform: str | None, engine: str, workdir: Path) -> Evidence:
    """Copy the three files out of a created -- never started -- container."""

    def call(*argv: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run([engine, *argv], capture_output=True, text=True, check=False)  # noqa: S603
        except FileNotFoundError as exc:
            raise OSError(f"{engine} not found; install it or unpack the image and use --rootfs") from exc

    create = ["create", *(["--platform", platform] if platform else []), image]
    created = call(*create)
    if created.returncode != 0:
        raise OSError(f"{engine} create {image} failed: {created.stderr.strip()}")
    output = created.stdout.strip().splitlines()
    if not output:
        raise OSError(f"{engine} create {image} printed no container id")
    container = output[-1]
    try:
        # The ID and repository digests of what the engine actually resolved
        # the reference to: a tag can be re-pushed between two pulls, and a
        # verdict is only worth something next to the digest it was about.
        image_id = call("inspect", "--format", "{{.Image}}", container)
        if image_id.returncode != 0 or not image_id.stdout.strip():
            raise OSError(f"{engine} inspect {container} failed: {image_id.stderr.strip()}")
        ident = image_id.stdout.strip()
        digests = call("image", "inspect", "--format", "{{json .RepoDigests}}", ident)
        if digests.returncode != 0:
            raise OSError(f"{engine} image inspect {ident} failed: {digests.stderr.strip()}")
        identity = f"image id {ident}, repository digests {digests.stdout.strip() or '[]'}"
        found: list[Path | None] = []
        for index, rel in enumerate((IMAGE_BINARY, IMAGE_RECORD, IMAGE_PINS)):
            dest = workdir / f"{index}-{Path(rel).name}"
            copied = call("cp", f"{container}:/{rel}", str(dest))
            if copied.returncode != 0:
                if any(marker in copied.stderr.lower() for marker in _ABSENT):
                    found.append(None)
                    continue
                raise OSError(f"{engine} cp /{rel} failed: {copied.stderr.strip()}")
            found.append(_regular_or_none(dest, rel))
        return Evidence(*found, identity=identity)
    finally:
        # -v: the images declare VOLUMEs, and `create` made an anonymous
        # volume for each of them.
        call("rm", "-f", "-v", container)


@dataclass
class Report:
    lines: list[tuple[bool, str]] = field(default_factory=list)

    def check(self, ok: bool, message: str) -> bool:
        self.lines.append((ok, message))
        return ok

    @property
    def failed(self) -> bool:
        return any(not ok for ok, _ in self.lines)


def verify(
    evidence: Evidence,
    anchor: dict[tuple[str, str], str],
    *,
    anchor_name: str,
    platform: str | None,
    tarball: tuple[str, bytes] | None,
) -> tuple[Report, list[str]]:
    """Run every check that the evidence allows; returns the report and what passed.

    The second value names the chains that fully passed ("install record",
    "pinned tarball"). An empty list with no failure means nothing tied the
    binary to a pin, which is reported as a failure too.
    """
    report = Report()
    chains: list[str] = []
    if evidence.binary is None:
        raise ValueError("verify() needs a binary; an image without one has nothing to verify")
    if evidence.identity is not None:
        report.check(True, f"examined {evidence.identity}")
    actual = sha256_file(evidence.binary)
    report.check(True, f"pulse binary in the image: sha256 {actual}")
    key: tuple[str, str] | None = None

    record: dict[str, str] | None = None
    if evidence.record is not None:
        try:
            record = parse_record(evidence.record.read_text(encoding="utf-8"))
        except (EvidenceError, UnicodeDecodeError) as exc:
            report.check(False, f"install record: {exc}")
    if record is not None:
        key = (record["version"], record["platform"])
        ok = report.check(
            record["verified"] == "pin",
            f"install record: {record['tarball'] or 'no tarball'}, verified={record['verified']}"
            + ("" if record["verified"] == "pin" else f" -- {_UNPINNED[record['verified']]}"),
        )
        if platform is not None:
            ok &= report.check(
                record["platform"] == PLATFORMS.get(platform, platform),
                f"install record platform {record['platform']} vs requested {platform}",
            )
        pin = anchor.get(key)
        if pin is None:
            ok &= report.check(
                False,
                f"{anchor_name} pins no {key[0]} {key[1]}: use the pin file of the release tag this image was built from",
            )
        else:
            ok &= report.check(
                record["tarball_sha256"] == pin,
                f"install record tarball sha256 {record['tarball_sha256'] or '(none)'} vs pin {pin} in {anchor_name}",
            )
        ok &= report.check(
            record["binary_sha256"] == actual,
            "binary matches the install record" if record["binary_sha256"] == actual
            else f"binary does not match the install record ({record['binary_sha256']}): changed after the install",
        )
        if ok:
            chains.append("install record")

    if tarball is not None:
        name, data = tarball
        tar_sha = hashlib.sha256(data).hexdigest()
        pinned_as = [k for k, v in anchor.items() if v == tar_sha]
        ok = report.check(
            len(pinned_as) == 1,
            f"tarball {name} sha256 {tar_sha} "
            + (
                f"is pinned in {anchor_name} as {' '.join(pinned_as[0])}"
                if len(pinned_as) == 1
                else f"matches {len(pinned_as) or 'no'} pin(s) in {anchor_name}; its contents are not examined"
            ),
        )
        if record is not None:
            ok &= report.check(
                record["tarball_sha256"] == tar_sha,
                f"install record names the same tarball ({record['tarball_sha256'] or '(none)'})",
            )
        # Parsed only once the pin has vouched for these exact bytes: an
        # unpinned archive is untrusted input and proves nothing either way.
        if len(pinned_as) == 1:
            key = key or pinned_as[0]
            try:
                member_sha = tarball_binary_sha256(data, name)
            except EvidenceError as exc:
                ok &= report.check(False, f"tarball: {exc}")
            else:
                ok &= report.check(
                    member_sha == actual,
                    f"'pulse' in the tarball: sha256 {member_sha} "
                    + ("matches the binary in the image" if member_sha == actual else "DIFFERS from the binary in the image"),
                )
        if ok:
            chains.append("pinned tarball")

    if evidence.image_pins is None:
        if record is not None:
            # Every build that writes the record also runs `COPY scripts
            # /app/scripts`; a record without the pins it was checked against
            # is an altered image, and the comparison is a required one.
            report.check(
                False,
                f"the image carries an install record but no /{IMAGE_PINS}; "
                "the build's own pins cannot be compared",
            )
        else:
            report.check(
                True,
                f"not compared: the image has no /{IMAGE_PINS} "
                "(images of shapoclyack-0.45-0916 and earlier predate it)",
            )
    elif key is not None and key in anchor:
        try:
            inside = parse_pins(evidence.image_pins.read_text(encoding="utf-8")).get(key)
        except (EvidenceError, UnicodeDecodeError) as exc:
            report.check(False, f"pin file inside the image: {exc}")
        else:
            report.check(
                inside == anchor[key],
                f"pin file inside the image agrees with {anchor_name} for {key[0]} {key[1]}"
                if inside == anchor[key]
                else f"pin file inside the image has {inside or 'no entry'} for {key[0]} {key[1]}, "
                f"{anchor_name} has {anchor[key]}: the image was not built from these pins",
            )

    if not chains and not report.failed:
        report.check(
            False,
            "nothing ties this binary to a pin: the image has no install record (built before #340); "
            "pass --tarball with the pinned release tarball",
        )
    return report, ([] if report.failed else chains)


def _collect(args: argparse.Namespace, workdir: Path | None) -> Evidence:
    if args.image:
        if workdir is None:  # pragma: no cover - main() always passes one
            raise ValueError("--image needs a working directory")
        return evidence_from_image(args.image, args.platform, args.engine, workdir)
    return evidence_from_rootfs(args.rootfs)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check the Pulse binary in a Shapoclyack image against scripts/pulse-pinned.sha256 (#340).",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--image", help="image reference; read with `<engine> create` + `cp`, never started")
    source.add_argument("--rootfs", type=Path, help="an image filesystem already unpacked into this directory")
    parser.add_argument("--platform", help=f"image platform, one of {', '.join(PLATFORMS)}")
    parser.add_argument("--engine", default="docker", help="container CLI for --image (docker, podman)")
    parser.add_argument(
        "--pins", type=Path, default=DEFAULT_PINS,
        help="the trusted pin file: the one at the release tag the image was built from, e.g. "
        "`git show <tag>:scripts/pulse-pinned.sha256 > pins` (default: the file next to this script)",
    )
    parser.add_argument("--tarball", type=Path, help="the pinned GenDec release tarball, for the independent check")
    args = parser.parse_args(argv)

    if args.image is not None and args.image.startswith("-"):
        # It goes to `<engine> create` as one argument; one that starts with a
        # dash would be read as an option of the engine, not as an image.
        parser.error("--image must be an image reference, not an option")
    if args.platform is not None and args.platform not in PLATFORMS:
        parser.error(f"--platform must be one of {', '.join(PLATFORMS)}")
    try:
        anchor = parse_pins(args.pins.read_text(encoding="utf-8"))
    except (OSError, EvidenceError, UnicodeDecodeError) as exc:
        print(f"cannot read the pin file {args.pins}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.rootfs is not None and not args.rootfs.is_dir():
        print(f"--rootfs {args.rootfs} is not a directory", file=sys.stderr)
        return EXIT_USAGE
    where = args.image or str(args.rootfs)

    tarball: tuple[str, bytes] | None = None
    if args.tarball is not None:
        try:
            tarball = (args.tarball.name, read_bounded(args.tarball, MAX_TARBALL_BYTES))
        except EvidenceError as exc:
            print(f"  FAIL  tarball: {exc}\nNOT VERIFIED")
            return EXIT_FAILED
        except OSError as exc:
            print(f"cannot read --tarball {args.tarball}: {exc}", file=sys.stderr)
            return EXIT_USAGE

    # Any read of the image below can fail on the host doing the check -- an
    # unreadable file, a symlink loop, no temporary directory. That is no
    # evidence either way: exit 2, not a verdict and not a traceback.
    try:
        if args.image:
            # Only --image copies anything out, so only it needs a directory.
            with tempfile.TemporaryDirectory(prefix="verify-pulse-") as workdir:
                return _judge(_collect(args, Path(workdir)), anchor, args, tarball, where)
        return _judge(_collect(args, None), anchor, args, tarball, where)
    except EvidenceError as exc:
        print(f"NOT VERIFIED: {exc}")
        return EXIT_FAILED
    except OSError as exc:
        print(f"cannot read what was to be verified: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _judge(
    evidence: Evidence,
    anchor: dict[tuple[str, str], str],
    args: argparse.Namespace,
    tarball: tuple[str, bytes] | None,
    where: str,
) -> int:
    if evidence.binary is None:
        print(
            f"{where} contains no /{IMAGE_BINARY}. A Shapoclyack image built with INSTALL_PULSE=0 "
            "looks like this: it has no service-probe backend of its own, and a run with "
            "service_probe.backend: pulse fails (docs/pulse-backend.md). Nothing to verify."
        )
        return EXIT_NO_PULSE

    report, chains = verify(evidence, anchor, anchor_name=args.pins.name, platform=args.platform, tarball=tarball)
    for ok, message in report.lines:
        print(f"  {'ok  ' if ok else 'FAIL'}  {message}")
    if chains:
        print(f"VERIFIED against {' and '.join(chains)}")
        if chains == ["install record"]:
            print(
                "  (the record is unsigned and lives in the image it describes: it is only as good as "
                "the image digest you verified. --tarball checks the binary without relying on the image.)"
            )
        return EXIT_OK
    print("NOT VERIFIED")
    return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
