#!/usr/bin/env python3
"""Check the Pulse binary inside a Shapoclyack image against the reviewed pin (#340).

The images carry ``/usr/local/bin/pulse`` with ``cap_net_raw,cap_net_admin``,
and it is the default service-probe engine, so "which Pulse is this?" is a
question a customer's review has to be able to answer from the outside. What
this repository pins is the SHA-256 of the GenDec release *tarball*
(``scripts/pulse-pinned.sha256``), while the image keeps only the binary that
came out of it. Two ways bridge that gap:

* ``--tarball``: the pinned tarball itself. Its digest is looked up in the pin
  file, the ``pulse`` member is hashed in memory (never unpacked to disk) and
  compared with the binary in the image. This does not rest on anything the
  image says about itself, and it works for every published image. It needs
  the tarball, which today only a holder of a GenDec token can download --
  see docs/adr/0001-pulse-distribution-model.md.
* The install record ``/usr/local/share/shapoclyack/pulse-install.txt`` that
  ``scripts/install-pulse.sh`` writes in images built after #340: which tarball
  was installed, which check it passed and what the binary hashed to. It is
  written by the build it describes, so it proves the image was not changed
  after that build and that the build used the pinned tarball *by its own
  account* -- not that the build was honest. Use it with a signature on the
  image (#313) or with ``--tarball``.

The pin file to trust is the one from **your** checkout of the release tag the
image was built from (the default is the file next to this script). The copy
inside the image is only compared against it: a disagreement means the image
was built from different pins than the tag says.

    git checkout shapoclyack-0.47-MMDD
    scripts/verify-pulse-image.py --image ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.47-MMDD \\
        --platform linux/amd64 [--tarball pulse-v1.1.0-linux-amd64.tar.gz]
    scripts/verify-pulse-image.py --rootfs ./unpacked-image [--tarball …]

``--image`` uses ``docker create`` + ``docker cp`` (``--engine podman`` works
too) and never starts the container, so nothing from the image under review is
executed. Only the Python standard library is used.

Exit status: 0 verified; 1 not verified (a check failed, or nothing ties the
binary to a pin); 2 usage or environment error; 3 the image contains no Pulse
(an ``INSTALL_PULSE=0`` build, which has no service-probe backend of its own).
"""

from __future__ import annotations

import argparse
import hashlib
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

# The Pulse binary is a few MB. A tarball member claiming more than this is not
# a Pulse release, and hashing it would only be a way to make this tool hang.
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


def tarball_binary_sha256(tarball: Path) -> str:
    """SHA-256 of the ``pulse`` member of a release tarball, read in memory.

    Nothing is extracted to disk, so a hostile archive (``../`` names, links,
    devices) has nothing to write. The member must be the one regular file
    named ``pulse`` at the top of the archive -- the layout install-pulse.sh
    unpacks and installs.
    """
    try:
        with tarfile.open(tarball, "r:gz") as archive:
            matches = [m for m in archive.getmembers() if m.name.removeprefix("./") == "pulse"]
            if len(matches) != 1:
                raise EvidenceError(f"{tarball.name} has {len(matches)} top-level 'pulse' entries, expected exactly one")
            member = matches[0]
            if not member.isreg():
                raise EvidenceError(f"'pulse' in {tarball.name} is not a regular file")
            if member.size > MAX_MEMBER_BYTES:
                raise EvidenceError(f"'pulse' in {tarball.name} claims {member.size} bytes")
            handle = archive.extractfile(member)
            if handle is None:  # pragma: no cover - isreg() already excludes this
                raise EvidenceError(f"'pulse' in {tarball.name} cannot be read")
            with handle:
                return _sha256_stream(handle, MAX_MEMBER_BYTES)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise EvidenceError(f"{tarball.name} is not a readable .tar.gz: {exc}") from exc


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


def evidence_from_rootfs(root: Path) -> Evidence:
    base = root.resolve()
    found: list[Path | None] = []
    for rel in (IMAGE_BINARY, IMAGE_RECORD, IMAGE_PINS):
        candidate = base / rel
        # A directory on the way that is a symlink could lead out of the tree;
        # the leaf itself is checked by _regular_or_none.
        if not candidate.parent.resolve().is_relative_to(base):
            raise EvidenceError(f"/{rel} resolves outside {root}; refusing to follow it")
        found.append(_regular_or_none(candidate, rel))
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
        return Evidence(*found)
    finally:
        call("rm", "-f", container)


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
    tarball: Path | None,
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
        try:
            tar_sha = sha256_file(tarball)
            member_sha = tarball_binary_sha256(tarball)
        except (EvidenceError, OSError) as exc:
            report.check(False, f"tarball: {exc}")
        else:
            pinned_as = [k for k, v in anchor.items() if v == tar_sha]
            ok = report.check(
                len(pinned_as) == 1,
                f"tarball {tarball.name} sha256 {tar_sha} "
                + (
                    f"is pinned in {anchor_name} as {' '.join(pinned_as[0])}"
                    if len(pinned_as) == 1
                    else f"matches {len(pinned_as) or 'no'} pin(s) in {anchor_name}"
                ),
            )
            if len(pinned_as) == 1:
                key = key or pinned_as[0]
            if record is not None:
                ok &= report.check(
                    record["tarball_sha256"] == tar_sha,
                    f"install record names the same tarball ({record['tarball_sha256'] or '(none)'})",
                )
            ok &= report.check(
                member_sha == actual,
                f"'pulse' in the tarball: sha256 {member_sha} "
                + ("matches the binary in the image" if member_sha == actual else "DIFFERS from the binary in the image"),
            )
            if ok:
                chains.append("pinned tarball")

    if evidence.image_pins is not None and key is not None and key in anchor:
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
        help="the trusted pin file: from your checkout of the release tag (default: next to this script)",
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

    with tempfile.TemporaryDirectory(prefix="verify-pulse-") as workdir:
        try:
            if args.image:
                evidence = evidence_from_image(args.image, args.platform, args.engine, Path(workdir))
                where = args.image
            else:
                if not args.rootfs.is_dir():
                    print(f"--rootfs {args.rootfs} is not a directory", file=sys.stderr)
                    return EXIT_USAGE
                evidence = evidence_from_rootfs(args.rootfs)
                where = str(args.rootfs)
        except EvidenceError as exc:
            print(f"NOT VERIFIED: {exc}")
            return EXIT_FAILED
        except OSError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_USAGE

        if evidence.binary is None:
            print(
                f"{where} contains no /{IMAGE_BINARY}: built with INSTALL_PULSE=0, so it has no "
                "service-probe backend of its own and a run with service_probe.backend: pulse fails "
                "(docs/pulse-backend.md). Nothing to verify."
            )
            return EXIT_NO_PULSE

        report, chains = verify(
            evidence, anchor, anchor_name=args.pins.name, platform=args.platform, tarball=args.tarball
        )

    for ok, message in report.lines:
        print(f"  {'ok  ' if ok else 'FAIL'}  {message}")
    if chains:
        print(f"VERIFIED against {' and '.join(chains)}")
        if chains == ["install record"]:
            print(
                "  (the record is the build's own account; pair it with the image signature "
                "or --tarball for a check that does not rest on the build)"
            )
        return EXIT_OK
    print("NOT VERIFIED")
    return EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
