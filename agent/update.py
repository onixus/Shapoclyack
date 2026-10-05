"""Install a signed sensor bundle, or refuse it (#363).

``python -m agent.update`` replaces the ``agent`` package of a *native* sensor
(``scripts/install-agent.sh`` without ``--docker``) with the bundle the API
publishes at ``GET /api/agent/bundle``. A container sensor is upgraded by its
image and never runs this.

**The server is not trusted to vouch for the bundle.** Installing code is remote
code execution by construction, and the API is the thing an attacker who got
into it would use to reach every sensor at once. So what the API sends is
treated as transport only:

* the manifest -- version, archive name, sha256 and size -- must carry a valid
  signature by the release key pinned *in this package*
  (:data:`RELEASE_PUBLIC_KEY_PEM`, the repository's ``cosign.pub``), checked
  before a byte of it is parsed. ``cosign sign-blob`` produces it in the publish
  pipeline (``scripts/build-sensor-bundle.sh``), with the same key that signs
  the images, and an ECDSA P-256 / SHA-256 signature is what that is;
* the archive must match the *signed* digest and size;
* the version that decides anything is the *signed* one: below the version
  installed here is a downgrade and is refused, the same version is nothing to
  do, and below ``OCTO_AGENT_MIN_VERSION`` -- the API's floor, or this host's
  own if it sets one -- is refused too. A replayed older bundle carries a valid
  signature, which is why the version check is not optional.

The manifest's ``schema`` is checked as well: the release key also signs image
payloads, and a signature over some other JSON document must not read as a
bundle.

**Install is a symlink swap.** Releases are unpacked under
``<install dir>/releases/<version>-<random>/agent``, and ``<install dir>/agent``
-- which the unit imports from, ``WorkingDirectory`` being the install dir --
becomes a symlink to one of them, replaced with ``rename(2)``. Before the swap
the staged tree has to import in a fresh interpreter and report the signed
version; after it, the service is restarted and has to stay up. Either failing
puts the previous release back. A journal written before the swap lets the next
run put it back too, if this process dies half-way.

**Root runs none of this.** The install directory belongs to the sensor's
account, so ``scripts/update-agent.sh`` runs this module as that account with
``--pending``, detached from root's terminal, restarts the unit itself, and
answers with ``--commit`` or ``--rollback``. Started as root by hand over a
tree another account owns, it stops -- a guard against the accident, not a
boundary: by the time it runs, root is already executing code that account can
rewrite. Only the names in :data:`ENV_FILE_NAMES` are taken from ``agent.env``.

**Automatic updates are off.** Nothing calls this on its own. ``--auto`` exists
for an operator's timer and does nothing unless ``OCTO_AGENT_AUTO_UPDATE=true``.
See docs/operations.md § Sensor bundle updates.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import fcntl
import hashlib
import io
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key

if TYPE_CHECKING:
    from agent.worker import AgentClient

LOG = logging.getLogger("octo-agent.update")

#: What a sensor bundle manifest says it is. Checked after the signature, so a
#: document the release key signed for another purpose is not a bundle.
SCHEMA = "shapoclyack.sensor-bundle/v1"
MANIFEST_NAME = "sensor-bundle.json"
SIGNATURE_NAME = "sensor-bundle.json.sig"

#: The release key's public half: ``cosign.pub`` at the repository root, which
#: is what customers verify the images with. Pinned here rather than fetched,
#: because a key that arrives with the bundle vouches for nothing.
#: ``tests/test_sensor_bundle.py`` fails if the two differ. A bundle signed by
#: the current key may carry a different one, which is how the key rotates.
RELEASE_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpO6pJNpabngln0/4v5wRRKeMEiNV
ZHAVyu6JYmkyN8hweYzBJIpTuzL+oP0vOJPHykglHMm5Z+Swrya+QbKqfw==
-----END PUBLIC KEY-----
"""

#: A different public key, for an installation that builds and signs its own
#: bundles. Read from this host's environment only, never from the API.
PUBKEY_FILE_ENV = "OCTO_AGENT_BUNDLE_PUBKEY_FILE"
AUTO_UPDATE_ENV = "OCTO_AGENT_AUTO_UPDATE"
MIN_VERSION_ENV = "OCTO_AGENT_MIN_VERSION"

DEFAULT_INSTALL_DIR = Path("/opt/shapoclyack-agent")
DEFAULT_ENV_FILE = Path("/etc/shapoclyack/agent.env")
DEFAULT_UNIT = "shapoclyack-agent.service"

MAX_MANIFEST_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_UNPACKED_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 4096

_JOURNAL = ".sensor-update.json"
#: The release whose health check last failed here, so ``--auto`` does not
#: install it, crash, and roll it back again on every timer tick.
_FAILED = ".sensor-update-failed.json"
_LOCK = ".sensor-update.lock"
_RELEASES = "releases"
_LIVE = "agent"
_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~:-]{0,63}$")
_ARCHIVE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\.tar\.gz$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RELEASE_NAME_RE = re.compile(r"^(?:legacy-)?[0-9A-Za-z._+~-]{1,64}-[0-9a-f]{8}$")
_UNSAFE_NAME_CHARS_RE = re.compile(r"[^0-9A-Za-z._+~-]")
_PACKAGE_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"', re.MULTILINE)


class BundleRefused(Exception):
    """The bundle is not one this sensor may install. Nothing was changed."""


class NothingToDo(Exception):
    """The bundle is the version already installed."""


class UpdateFailed(RuntimeError):
    """The install was attempted and undone; the previous release is live."""


@dataclass(frozen=True)
class Manifest:
    """A manifest whose signature has been checked. ``raw`` is what was signed."""

    version: str
    archive: str
    sha256: str
    size: int
    raw: bytes


# --------------------------------------------------------------------------
# Signature
# --------------------------------------------------------------------------


def load_public_key(path: Path | None = None) -> ec.EllipticCurvePublicKey:
    """The pinned release key, or the one in ``path`` (``OCTO_AGENT_BUNDLE_PUBKEY_FILE``).

    Only an ECDSA P-256 key is accepted: that is what ``cosign generate-key-pair``
    makes and what the release key is, and taking whatever type the file holds
    would let an override quietly change the algorithm the signature is held to.
    """
    pem = path.read_bytes() if path else RELEASE_PUBLIC_KEY_PEM
    try:
        key = load_pem_public_key(pem)
    except ValueError as exc:
        raise BundleRefused(f"the bundle public key is not a PEM public key: {exc}") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise BundleRefused("the bundle public key must be an ECDSA P-256 key (cosign)")
    return key


def _decode_signature(signature: str | bytes) -> bytes:
    """cosign's ``--output-signature`` file: base64 of the DER signature."""
    text = signature.strip() if isinstance(signature, bytes) else signature.strip().encode("ascii", "replace")
    if not text or len(text) > MAX_SIGNATURE_BYTES:
        raise BundleRefused("the bundle signature is empty or oversized")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleRefused("the bundle signature is not base64") from exc


def verify_manifest(
    manifest_bytes: bytes,
    signature: str | bytes,
    public_key: ec.EllipticCurvePublicKey,
) -> Manifest:
    """Check the signature over ``manifest_bytes``, then parse them.

    In that order: nothing in an unsigned document is read, so a parser quirk
    is not reachable by whoever controls the server.
    """
    if not manifest_bytes or len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise BundleRefused("the bundle manifest is empty or oversized")
    try:
        public_key.verify(_decode_signature(signature), manifest_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise BundleRefused(
            "the bundle manifest's signature does not verify against the pinned release key"
        ) from exc
    try:
        data = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleRefused("the signed manifest is not JSON") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise BundleRefused(f"the signed document is not a sensor bundle manifest ({SCHEMA})")
    version = data.get("version")
    archive = data.get("archive")
    digest = data.get("sha256")
    size = data.get("size")
    if not isinstance(version, str) or not _VERSION_RE.match(version):
        raise BundleRefused("the signed manifest names no usable version")
    if not isinstance(archive, str) or not _ARCHIVE_RE.match(archive):
        raise BundleRefused("the signed manifest names no usable archive")
    if not isinstance(digest, str) or not _SHA256_RE.match(digest):
        raise BundleRefused("the signed manifest names no sha256")
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_BUNDLE_BYTES:
        raise BundleRefused("the signed manifest names no usable size")
    return Manifest(version=version, archive=archive, sha256=digest, size=size, raw=manifest_bytes)


def read_verified_archive(path: Path, manifest: Manifest) -> bytes:
    """The archive's bytes, if they are the ones the signed manifest describes.

    Read once and returned, so what is unpacked is what was hashed: checking a
    path and then opening it again by name leaves a window for whoever can
    write that directory to put something else there.
    """
    with path.open("rb") as handle:
        data = handle.read(manifest.size + 1)
    if len(data) != manifest.size:
        raise BundleRefused(
            f"the bundle archive is not the {manifest.size} bytes the signed manifest says"
        )
    if hashlib.sha256(data).hexdigest() != manifest.sha256:
        raise BundleRefused("the bundle archive's sha256 does not match the signed manifest")
    return data


def verify_archive(path: Path, manifest: Manifest) -> None:
    """The archive is the one the signed manifest describes, byte for byte."""
    read_verified_archive(path, manifest)


# --------------------------------------------------------------------------
# Versions
# --------------------------------------------------------------------------
#
# dpkg ordering, transcribed from ``api/services/version_compare.py`` -- the
# grammar ``OCTO_AGENT_MIN_VERSION`` is already judged by on the API side, so
# the sensor refuses exactly what the API would refuse. A copy because the
# ``api`` package is not on a sensor host; ``tests/test_sensor_bundle.py``
# holds the two to the same answers.


class VersionError(ValueError):
    """Not a version this module can order."""


def _split(raw: str) -> tuple[int, str, str]:
    text = (raw or "").strip()
    if not text:
        raise VersionError("empty version string")
    head, sep, tail = text.partition(":")
    epoch, rest = (int(head), tail) if sep and head.isdigit() else (0, text)
    if not rest:
        raise VersionError(f"version {raw!r} has an epoch but no version")
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        upstream, revision = rest, ""
    if not upstream:
        raise VersionError(f"version {raw!r} has an empty upstream part")
    return epoch, upstream, revision


def _order(char: str) -> int:
    if "0" <= char <= "9":
        return 0
    if ("a" <= char <= "z") or ("A" <= char <= "Z"):
        return ord(char)
    if char == "~":
        return -1
    if char:
        return ord(char) + 256
    return 0


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    len_a, len_b = len(a), len(b)
    while i < len_a or j < len_b:
        first_diff = 0
        while (i < len_a and not a[i].isdigit()) or (j < len_b and not b[j].isdigit()):
            ac = _order(a[i]) if i < len_a else 0
            bc = _order(b[j]) if j < len_b else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len_a and a[i] == "0":
            i += 1
        while j < len_b and b[j] == "0":
            j += 1
        while i < len_a and j < len_b and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len_a and a[i].isdigit():
            return 1
        if j < len_b and b[j].isdigit():
            return -1
        if first_diff:
            return -1 if first_diff < 0 else 1
    return 0


def compare_versions(left: str, right: str) -> int:
    """``-1``/``0``/``1`` like ``cmp``; :class:`VersionError` when unparsable."""
    if not left.isascii() or not right.isascii():
        raise VersionError("versions are ASCII")
    a, b = _split(left), _split(right)
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    return _verrevcmp(a[1], b[1]) or _verrevcmp(a[2], b[2])


def check_version_policy(candidate: str, *, current: str, min_versions: list[str]) -> None:
    """Refuse a downgrade and anything below a floor; say so when already current.

    ``current`` is what is installed here. An unknown one is refused rather than
    assumed old: a host that cannot say what it runs cannot say an install is
    not a downgrade, and this is the check a replayed old bundle has to pass.
    """
    try:
        order = compare_versions(candidate, current)
    except VersionError as exc:
        raise BundleRefused(
            f"cannot order bundle version {candidate!r} against installed {current!r}: {exc}"
        ) from exc
    if order < 0:
        raise BundleRefused(
            f"bundle version {candidate} is older than the installed {current}; "
            "downgrades are refused"
        )
    if order == 0:
        raise NothingToDo(f"version {current} is already installed")
    for floor in min_versions:
        floor = (floor or "").strip()
        if not floor:
            continue
        try:
            below = compare_versions(candidate, floor) < 0
        except VersionError as exc:
            raise BundleRefused(f"cannot order bundle version against minimum {floor!r}: {exc}") from exc
        if below:
            raise BundleRefused(
                f"bundle version {candidate} is below the required minimum {floor}"
            )


def read_package_version(agent_dir: Path) -> str:
    """The ``__version__`` literal in ``agent_dir/__init__.py``, read, never imported."""
    try:
        text = (agent_dir / "__init__.py").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""
    match = _PACKAGE_VERSION_RE.search(text)
    return match.group(1) if match else ""


# --------------------------------------------------------------------------
# Archive
# --------------------------------------------------------------------------


def extract_agent_package(archive: Path | bytes, dest: Path) -> Path:
    """Unpack the ``agent/`` tree of ``archive`` into ``dest``; return ``dest/agent``.

    Run only on an archive whose digest matched the signed manifest, and still
    strict, because a signed archive built from a wrong tree is a mistake worth
    refusing too: regular files and directories only (no links, devices or
    FIFOs), every name under ``agent/``, no absolute path and no ``..``, a cap
    on members and unpacked size. Modes are set here, not taken from the
    archive.
    """
    members = 0
    unpacked = 0
    root = dest.resolve()
    try:
        source_file = io.BytesIO(archive) if isinstance(archive, bytes) else None
        with tarfile.open(
            archive if source_file is None else None, mode="r:gz", fileobj=source_file
        ) as tar:
            for member in tar:
                members += 1
                if members > MAX_MEMBERS:
                    raise BundleRefused("the bundle archive has too many members")
                name = member.name
                parts = Path(name).parts
                if (
                    name.startswith("/")
                    or not parts
                    or parts[0] != _LIVE
                    or any(part in ("..", "") for part in parts)
                ):
                    raise BundleRefused(f"the bundle archive member {name!r} is outside agent/")
                target = dest.joinpath(*parts)
                if root not in target.resolve().parents and target.resolve() != root / _LIVE:
                    raise BundleRefused(f"the bundle archive member {name!r} escapes the release")
                if member.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    os.chmod(target, 0o755)
                    continue
                if not member.isreg():
                    raise BundleRefused(f"the bundle archive member {name!r} is not a regular file")
                unpacked += member.size
                if unpacked > MAX_UNPACKED_BYTES:
                    raise BundleRefused("the bundle archive unpacks to more than the limit")
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise BundleRefused(f"the bundle archive member {name!r} has no data")
                with source, open(target, "xb") as out:
                    shutil.copyfileobj(source, out)
                    out.flush()
                    os.fsync(out.fileno())
                os.chmod(target, 0o644)
    except (tarfile.TarError, EOFError, OSError) as exc:
        if isinstance(exc, FileExistsError):
            raise BundleRefused("the bundle archive names a file twice") from exc
        raise BundleRefused(f"the bundle archive cannot be read: {exc}") from exc
    package = dest / _LIVE
    if not (package / "__init__.py").is_file():
        raise BundleRefused("the bundle archive holds no agent package")
    return package


# --------------------------------------------------------------------------
# Atomic install
# --------------------------------------------------------------------------


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def import_check(python: str, root: Path, expected_version: str, *, timeout: float = 120.0) -> None:
    """Import ``agent.worker`` from ``root`` in a fresh, isolated interpreter.

    ``-I`` keeps the caller's ``PYTHONPATH``, user site and working directory
    out of it, so what is imported is the tree under ``root`` and the venv's
    dependencies, and nothing that happens to be lying around.
    """
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "import agent, agent.worker; print(agent.__version__)"
    )
    try:
        result = subprocess.run(
            [python, "-I", "-c", code, str(root)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateFailed(f"could not run {python} to check the release: {exc}") from exc
    if result.returncode != 0:
        tail = (result.stderr or "").strip().splitlines()[-5:]
        raise UpdateFailed("the release does not import: " + " | ".join(tail))
    reported = (result.stdout or "").strip()
    if reported != expected_version:
        raise UpdateFailed(
            f"the release reports version {reported!r}, the signed manifest {expected_version!r}"
        )


class Installer:
    """Releases under ``<install_dir>/releases``, one of them live via ``agent``.

    ``health_check`` runs after the swap -- the CLI restarts the service and
    watches it -- and raising from it undoes the swap; ``on_rollback`` then
    runs, to restart the service onto the code that is live again. ``python`` is the
    interpreter the staged tree is import-checked with: the sensor's own venv,
    so its dependencies are the ones the service will have.
    """

    def __init__(
        self,
        install_dir: Path,
        *,
        python: str | None = None,
        health_check: Callable[[], None] | None = None,
        on_rollback: Callable[[], None] | None = None,
    ) -> None:
        self.install_dir = install_dir
        self.python = python or sys.executable
        self.health_check = health_check
        self.on_rollback = on_rollback
        self.live = install_dir / _LIVE
        self.releases = install_dir / _RELEASES
        self.journal = install_dir / _JOURNAL
        self.failed = install_dir / _FAILED

    # -- journal -----------------------------------------------------------

    def _write_journal(self, payload: dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.install_dir, prefix=f"{_JOURNAL}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.journal)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        _fsync_dir(self.install_dir)

    def _clear_journal(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.journal.unlink()
        _fsync_dir(self.install_dir)

    def _release_path(self, relative: str) -> Path:
        """``releases/<name>/agent`` and nothing else -- a journal or a link
        naming anything outside the releases directory is not followed."""
        parts = Path(relative).parts
        if (
            len(parts) != 3
            or parts[0] != _RELEASES
            or parts[2] != _LIVE
            or not _RELEASE_NAME_RE.match(parts[1])
        ):
            raise UpdateFailed(f"{relative!r} is not a release path; fix {self.install_dir} by hand")
        return self.install_dir / relative

    # -- swap --------------------------------------------------------------

    def _point_at(self, relative: str) -> None:
        """Make ``agent`` a symlink to ``relative``, atomically.

        A new link next to it, then ``rename(2)`` over it: at every instant
        ``agent`` is the old tree or the new one, never missing.
        """
        self._release_path(relative)
        tmp = self.install_dir / f".{_LIVE}.{secrets.token_hex(4)}"
        os.symlink(relative, tmp)
        try:
            os.replace(tmp, self.live)
        except BaseException:
            with contextlib.suppress(OSError):
                tmp.unlink()
            raise
        _fsync_dir(self.install_dir)

    def current(self) -> str | None:
        """The release ``agent`` points at, or ``None`` for a plain directory."""
        if not self.live.is_symlink():
            return None
        target = os.readlink(self.live)
        self._release_path(target)
        return target

    def pending(self) -> bool:
        """Whether a journal says a swap is waiting for its verdict."""
        return self.journal.exists()

    def recover(self) -> bool:
        """Finish what a killed run left: put back the release its journal names.

        Returns whether the service has to be restarted: the journal named a
        release swapped in, so the service may still run it. That is decided
        by the journal and not by where ``agent`` points, because a recovery
        killed after the link went back but before the journal did leaves the
        link on the previous release and the service on the other one; the
        journal goes last, so the next recovery still says so. The tree taken
        out is kept for the same reason; every other release but the one put
        back goes, so failed attempts do not pile up between updates that are
        kept.
        """
        try:
            payload = json.loads(self.journal.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return False
        except (OSError, ValueError) as exc:
            raise UpdateFailed(f"{self.journal} is unreadable ({exc}); fix it by hand") from exc
        previous = str(payload.get("previous") or "")
        previous_path = self._release_path(previous)
        taken_out = str(payload.get("new") or "")
        if not self.live.is_symlink() and self.live.is_dir():
            # Killed while adopting a plain directory, before it moved: the
            # live tree is still where it was and nothing needs putting back.
            with contextlib.suppress(OSError):
                previous_path.parent.rmdir()
            self._clear_journal()
            return False
        if not previous_path.is_dir():
            raise UpdateFailed(
                f"the journal names {previous} as the release to restore and it is missing; "
                f"fix {self.install_dir} by hand"
            )
        keep = {previous}
        if taken_out:
            # A journal naming something that is no release keeps nothing.
            with contextlib.suppress(UpdateFailed):
                self._release_path(taken_out)
                keep.add(taken_out)
        restart = len(keep) == 2
        if self.current() != previous:
            self._point_at(previous)
            LOG.warning("An interrupted update was rolled back to %s", previous)
            restart = True
        self._prune(keep=keep)
        self._clear_journal()
        return restart

    def rollback(self) -> bool:
        """``--rollback``: the restarted service did not stay up on the pending
        release. Remember it as failed here, then put the previous one back."""
        try:
            payload = json.loads(self.journal.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            payload = {}
        new = str(payload.get("new") or "") if isinstance(payload, dict) else ""
        if new:
            self._remember_failed(new)
        return self.recover()

    def _remember_failed(self, relative: str) -> None:
        """Record the signed manifest of a release that failed its health check.

        Fail-soft: the record only spares ``--auto`` a retry, and an error
        writing it must not stand in the way of the rollback it accompanies.
        """
        try:
            raw = (self._release_path(relative).parent / "manifest.json").read_bytes()
            data = json.loads(raw)
            record = {"version": str(data["version"]), "sha256": str(data["sha256"])}
            fd, tmp = tempfile.mkstemp(dir=self.install_dir, prefix=f"{_FAILED}.")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(record, handle)
                os.replace(tmp, self.failed)
            except OSError:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except (OSError, ValueError, KeyError, TypeError, UpdateFailed) as exc:
            LOG.warning("Could not record %s as failed: %s", relative, exc)

    def failed_before(self, manifest: Manifest) -> bool:
        """Whether this very bundle (by its signed digest) failed here before."""
        try:
            record = json.loads(self.failed.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return isinstance(record, dict) and record.get("sha256") == manifest.sha256

    def _forget_failed(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self.failed.unlink()

    def _adopt_live(self) -> str:
        """The live release as a ``releases/…`` path, moving a plain directory there.

        The installer leaves ``agent`` as a plain directory. It is moved under
        ``releases/`` and linked back -- journaled first, so a run killed
        between the move and the link is put back by :meth:`recover`.
        """
        current = self.current()
        if current is not None:
            if not self._release_path(current).is_dir():
                raise UpdateFailed(f"{self.live} points at {current}, which is missing")
            return current
        if not self.live.is_dir():
            raise UpdateFailed(f"there is no installed agent package at {self.live}")
        version = read_package_version(self.live)
        version = _UNSAFE_NAME_CHARS_RE.sub("_", version)[:64] or "unknown"
        name = f"legacy-{version}-{secrets.token_hex(4)}"
        relative = f"{_RELEASES}/{name}/{_LIVE}"
        (self.releases / name).mkdir(mode=0o755)
        self._write_journal({"previous": relative, "new": None})
        os.rename(self.live, self.install_dir / relative)
        self._point_at(relative)
        self._clear_journal()
        return relative

    def _stage(self, archive: bytes, manifest: Manifest) -> str:
        staging = Path(tempfile.mkdtemp(prefix=".staging-", dir=self.releases))
        try:
            os.chmod(staging, 0o755)
            package = extract_agent_package(archive, staging)
            unpacked = read_package_version(package)
            if unpacked != manifest.version:
                raise BundleRefused(
                    f"the archive's agent package is version {unpacked or 'unknown'}, "
                    f"the signed manifest says {manifest.version}"
                )
            (staging / "manifest.json").write_bytes(manifest.raw)
            import_check(self.python, staging, manifest.version)
            name = f"{_UNSAFE_NAME_CHARS_RE.sub('_', manifest.version)}-{secrets.token_hex(4)}"
            for directory in sorted(staging.rglob("*"), reverse=True):
                if directory.is_dir() and not directory.is_symlink():
                    _fsync_dir(directory)
            os.rename(staging, self.releases / name)
            _fsync_dir(self.releases)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return f"{_RELEASES}/{name}/{_LIVE}"

    def install(self, archive: Path, manifest: Manifest, *, pending: bool = False) -> str:
        """Stage, check, swap, health-check; undo the swap if anything after it fails.

        The archive is read once and checked against the signed digest here,
        whatever the caller checked before. Returns the release now live.

        ``pending`` stops after the swap and leaves the journal in place: the
        caller restarts the service and then calls :meth:`commit` or
        :meth:`recover`. ``scripts/update-agent.sh`` does that, so the restart
        is root's and the code that runs as root is none of this tree's.
        Callers hold :func:`update_lock`.
        """
        self.recover()
        data = read_verified_archive(archive, manifest)
        if self.releases.is_symlink():
            raise UpdateFailed(f"{self.releases} is a symlink; refusing to install through it")
        self.releases.mkdir(mode=0o755, exist_ok=True)
        new = self._stage(data, manifest)
        try:
            previous = self._adopt_live()
        except BaseException:
            shutil.rmtree(self._release_path(new).parent, ignore_errors=True)
            raise
        self._write_journal({"previous": previous, "new": new})
        checking = False
        try:
            self._point_at(new)
            if pending:
                return new
            if self.health_check is not None:
                checking = True
                self.health_check()
        except BaseException as exc:
            if checking and isinstance(exc, Exception):
                self._remember_failed(new)
            self._point_at(previous)
            self._clear_journal()
            restarted = True
            if self.on_rollback is not None:
                try:
                    self.on_rollback()
                except Exception as hook_exc:  # noqa: BLE001 - the rollback itself is done
                    # The previous release is live on disk either way; failing
                    # to restart onto it is reported alongside, not instead of,
                    # the reason the update was undone.
                    restarted = False
                    LOG.error("Restart after the rollback failed: %s", hook_exc)
            # The new tree goes once the service has left it: until the
            # restart it runs from there, and after a failed one it still does.
            self._prune(keep={previous} if restarted else {previous, new})
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise UpdateFailed(f"rolled back to {previous}: {exc}") from exc
        self._clear_journal()
        self._forget_failed()
        self._prune(keep={new, previous})
        return new

    def commit(self) -> str | None:
        """Keep the release a ``pending`` install swapped in; return it."""
        try:
            payload = json.loads(self.journal.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            raise UpdateFailed(f"{self.journal} is unreadable ({exc}); fix it by hand") from exc
        previous = str(payload.get("previous") or "")
        new = str(payload.get("new") or "")
        self._release_path(previous)
        if self.current() != new:
            raise UpdateFailed(f"{self.live} is not the pending release {new}; not committing")
        self._clear_journal()
        self._forget_failed()
        self._prune(keep={new, previous})
        return new

    def _prune(self, *, keep: set[str]) -> None:
        """Remove every release but those in ``keep``, and staging leftovers.

        After an update that is kept, that is the live release and the one
        before it; after one put back, the live release and the one taken out.
        """
        kept = {Path(relative).parts[1] for relative in keep}
        for entry in self.releases.iterdir():
            if entry.name in kept or entry.is_symlink() or not entry.is_dir():
                continue
            if _RELEASE_NAME_RE.match(entry.name) or entry.name.startswith(".staging-"):
                shutil.rmtree(entry, ignore_errors=True)


@contextlib.contextmanager
def update_lock(install_dir: Path):
    """One update at a time, from the journal check to the verdict.

    A timer firing during a manual run would otherwise recover the other run's
    journal under it, or prune its staging directory.
    """
    with open(install_dir / _LOCK, "a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise UpdateFailed("another sensor update is running") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


# --------------------------------------------------------------------------
# Service health
# --------------------------------------------------------------------------


def _systemctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, check=False)


def _restart_unit(unit: str) -> None:
    """``systemctl restart unit``; a refusal raises instead of being a return code."""
    restarted = _systemctl("restart", unit)
    if restarted.returncode != 0:
        raise RuntimeError(f"systemctl restart {unit} failed: {restarted.stderr.strip()}")


def _main_pid(unit: str) -> str:
    return _systemctl("show", "-p", "MainPID", "--value", unit).stdout.strip()


def systemd_health_check(unit: str, seconds: float) -> Callable[[], None]:
    """Restart ``unit`` and require it to stay up, as one process, for ``seconds``.

    ``Type=simple`` makes a unit "active" the moment it forks, and
    ``Restart=always`` brings a crashing one back every five seconds, so
    neither "active" nor "active again later" proves the new code runs. The
    main PID changing while it is watched is what a crash loop looks like.
    """

    def check() -> None:
        _restart_unit(unit)
        time.sleep(1.0)
        pid = _main_pid(unit)
        deadline = time.monotonic() + seconds
        while True:
            if _systemctl("is-active", "--quiet", unit).returncode != 0:
                raise RuntimeError(f"{unit} is not active after the restart")
            now_pid = _main_pid(unit)
            if not pid or pid == "0" or now_pid != pid:
                raise RuntimeError(f"{unit} restarted on its own (pid {pid} -> {now_pid})")
            if time.monotonic() >= deadline:
                return
            time.sleep(1.0)

    return check


def _systemd_unit_present(unit: str) -> bool:
    if shutil.which("systemctl") is None:
        return False
    return _systemctl("cat", unit).returncode == 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def read_env_file(path: Path) -> dict[str, str]:
    """``KEY=value`` lines, parsed and never sourced: the file holds the key."""
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        name = name.strip()
        if name.startswith("export "):
            name = name[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[name] = value
    return values


#: What the updater takes from ``agent.env``. That file belongs to the
#: sensor's own account, so anything else in it -- ``LD_PRELOAD``, a key file
#: path pointing at ``/etc/shadow``, a public-key override replacing the
#: release key -- would be the service account choosing what this process
#: does. ``OCTO_AGENT_BUNDLE_PUBKEY_FILE`` is read from the process
#: environment only, for the same reason.
ENV_FILE_NAMES = frozenset(
    {
        "OCTO_API_URL",
        "OCTO_AGENT_PROVISIONING_KEY",
        "OCTO_AGENT_TOKEN",
        "OCTO_AGENT_ID",
        AUTO_UPDATE_ENV,
        MIN_VERSION_ENV,
        "OCTO_HTTP_PROXY",
        "OCTO_HTTPS_PROXY",
        "OCTO_NO_PROXY",
        "OCTO_CA_BUNDLE",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "NO_PROXY",
        "no_proxy",
    }
)


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def _server_manifest(public_key: ec.EllipticCurvePublicKey) -> tuple[AgentClient, Manifest, str]:
    """Fetch the signed manifest with the sensor's own credential, and verify it.

    The archive is fetched separately (``client.download_bundle``), once the
    signed manifest has said it is worth fetching.
    """
    from agent.worker import AgentClient

    api_url = os.environ.get("OCTO_API_URL", "").strip()
    if not api_url:
        raise UpdateFailed("OCTO_API_URL is not set (in the environment or the env file)")
    client = AgentClient(api_url, os.environ.get("OCTO_AGENT_TOKEN", "").strip())
    key_file = os.environ.get("OCTO_AGENT_PROVISIONING_KEY_FILE", "").strip()
    key = Path(key_file).read_text(encoding="utf-8").strip() if key_file else ""
    key = key or os.environ.get("OCTO_AGENT_PROVISIONING_KEY", "").strip()
    if key:
        exchanged = client.exchange_provisioning_key(
            key, agent_id=os.environ.get("OCTO_AGENT_ID", "").strip() or None
        )
        client.set_token(str(exchanged["access_token"]))
    elif not client.token:
        raise UpdateFailed("no sensor credential (OCTO_AGENT_PROVISIONING_KEY[_FILE] or OCTO_AGENT_TOKEN)")

    info = client.bundle_info()
    try:
        manifest_bytes = base64.b64decode(str(info.get("manifest") or ""), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleRefused("the server's manifest field is not base64") from exc
    manifest = verify_manifest(manifest_bytes, str(info.get("signature") or ""), public_key)
    if info.get("version") != manifest.version:
        raise BundleRefused(
            f"the server says version {info.get('version')!r}, the signed manifest {manifest.version!r}"
        )
    return client, manifest, str(info.get("min_version") or "")


def _read_bundle_dir(bundle_dir: Path, public_key: ec.EllipticCurvePublicKey) -> tuple[Manifest, Path]:
    manifest = verify_manifest(
        (bundle_dir / MANIFEST_NAME).read_bytes(),
        (bundle_dir / SIGNATURE_NAME).read_bytes(),
        public_key,
    )
    return manifest, bundle_dir / manifest.archive


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent.update",
        description="Install the signed sensor bundle, or refuse it (#363).",
    )
    parser.add_argument("--install-dir", type=Path, default=DEFAULT_INSTALL_DIR)
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_FILE,
        help="Sensor env file to read OCTO_API_URL and the credential from (parsed, not sourced)",
    )
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        help=f"Install from {MANIFEST_NAME}, {SIGNATURE_NAME} and the archive in this "
        "directory instead of the API (air-gapped hosts). Verified the same way",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Verify and report; install nothing")
    mode.add_argument(
        "--pending",
        action="store_true",
        help="Swap the release in and stop: the caller restarts the service and then "
        f"runs --commit or --rollback. Exit {EXIT_NOTHING_TO_DO} when there is nothing to install",
    )
    mode.add_argument(
        "--commit",
        action="store_true",
        help=f"Keep the pending release. Exit {EXIT_NOTHING_TO_DO} when none was pending",
    )
    mode.add_argument("--rollback", action="store_true", help="Put the previous release back")
    mode.add_argument(
        "--abort",
        action="store_true",
        help="The caller was interrupted: put the previous release back without recording "
        f"the pending one as failed. Exit {EXIT_RECOVERED} when something was put back",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help=f"For a timer: do nothing unless {AUTO_UPDATE_ENV}=true",
    )
    parser.add_argument("--unit", default=DEFAULT_UNIT, help="systemd unit to restart and watch")
    parser.add_argument(
        "--health-seconds",
        type=float,
        default=20.0,
        help="How long the restarted unit must stay up before the update is kept",
    )
    return parser


#: ``--pending`` found the bundle already installed; the caller restarts nothing.
#: ``--commit`` found no pending release to keep.
EXIT_NOTHING_TO_DO = 3
#: ``--pending`` found an interrupted update and put the previous release back,
#: and stopped there: the service still runs the release taken out, so the
#: caller restarts it and runs ``--pending`` again.
EXIT_RECOVERED = 4


def _owned_by_someone_else(path: Path) -> bool:
    return os.geteuid() == 0 and path.stat().st_uid != 0


def main(argv: list[str] | None = None) -> int:  # noqa: C901 - one CLI, its modes in a row
    args = build_parser().parse_args(argv)
    from agent import logging_setup

    logging_setup.configure_logging()
    # The env file fills in what the environment does not set, and only for
    # the names in ENV_FILE_NAMES: the proxy and CA variables reach
    # agent.egress this way, as they do for the service.
    for name, value in read_env_file(args.env_file).items():
        if name in ENV_FILE_NAMES:
            os.environ.setdefault(name, value)

    if args.auto and not _truthy(os.environ.get(AUTO_UPDATE_ENV)):
        LOG.info("Automatic sensor updates are off (%s is not true); nothing to do", AUTO_UPDATE_ENV)
        return 0

    install_dir: Path = args.install_dir
    venv_python = install_dir / "venv" / "bin" / "python"
    if not venv_python.is_file():
        LOG.error(
            "%s has no venv: this is not a native sensor install. A container sensor "
            "is upgraded by its image",
            install_dir,
        )
        return 2
    use_systemd = not args.pending and _systemd_unit_present(args.unit)
    if use_systemd and _owned_by_someone_else(install_dir):
        # Root running code from a tree the sensor's account can rewrite is that
        # account's way to root. This stops the accident -- ``sudo python -m
        # agent.update`` typed by hand -- and is no boundary: it runs inside
        # that very code. scripts/update-agent.sh runs this as the owner and
        # keeps only the restart for itself.
        LOG.error(
            "Not updating %s as root: it belongs to another account, whose code this "
            "would run. Use scripts/update-agent.sh",
            install_dir,
        )
        return 2

    try:
        with update_lock(install_dir):
            installer = Installer(install_dir, python=str(venv_python))
            if args.commit:
                kept = installer.commit()
                if kept:
                    LOG.info(
                        "Sensor agent package updated to %s (%s); scanner/ and the venv "
                        "are not part of the bundle",
                        read_package_version(install_dir / _LIVE),
                        kept,
                    )
                    return 0
                # Not a success to report as one: the caller judged a restart
                # onto a release that is not pending any more.
                LOG.error("Kept nothing: no update was pending")
                return EXIT_NOTHING_TO_DO
            if args.rollback:
                LOG.info("Rolled back" if installer.rollback() else "No pending update to roll back")
                return 0
            if args.abort:
                # scripts/update-agent.sh was interrupted. Whatever it swapped
                # in got no verdict, so it is put back, and not held against
                # the release the way a failed health check is.
                return EXIT_RECOVERED if installer.recover() else 0
            if args.check and installer.pending():
                # --check changes nothing; putting the release back is a
                # change, and one that needs the restart --check does not do.
                LOG.error(
                    "An interrupted update left %s live without a verdict; run the "
                    "update without --check to put the previous release back",
                    installer.current(),
                )
                return 1
            # Before anything else, including "nothing to do": a run killed
            # between swap and verdict left an unverified release live, and the
            # server offering that same version must not leave it there.
            if installer.recover():
                if args.pending:
                    return EXIT_RECOVERED
                if use_systemd:
                    try:
                        _restart_unit(args.unit)
                    except RuntimeError as exc:
                        LOG.error(
                            "%s did not restart onto the release put back and may still run "
                            "the one taken out; not installing over it: %s",
                            args.unit, exc,
                        )
                        return 1
                else:
                    LOG.warning("Restart the sensor process yourself: it may run the release put back")

            key_path = os.environ.get(PUBKEY_FILE_ENV, "").strip()
            public_key = load_public_key(Path(key_path) if key_path else None)
            current = read_package_version(install_dir / _LIVE)
            with tempfile.TemporaryDirectory(prefix=".download-", dir=install_dir) as tmp:
                client = None
                if args.bundle_dir:
                    manifest, archive = _read_bundle_dir(args.bundle_dir, public_key)
                    server_floor = ""
                else:
                    client, manifest, server_floor = _server_manifest(public_key)
                    archive = Path(tmp) / manifest.archive
                # Decided by the signed manifest alone, so a bundle that is
                # not going to be installed is not downloaded either.
                check_version_policy(
                    manifest.version,
                    current=current,
                    min_versions=[server_floor, os.environ.get(MIN_VERSION_ENV, "")],
                )
                if args.auto and not args.check and installer.failed_before(manifest):
                    LOG.warning(
                        "Bundle %s failed its health check on this host before; --auto does "
                        "not retry it. Run the update by hand to try it again",
                        manifest.version,
                    )
                    return EXIT_NOTHING_TO_DO if args.pending else 0
                if client is not None:
                    client.download_bundle(archive, max_bytes=manifest.size)
                verify_archive(archive, manifest)
                if args.check:
                    LOG.info("Bundle %s verifies and would replace %s", manifest.version, current)
                    return 0
                installer.health_check = (
                    systemd_health_check(args.unit, args.health_seconds)
                    if use_systemd
                    else (lambda: import_check(str(venv_python), install_dir, manifest.version))
                )
                if use_systemd:
                    installer.on_rollback = lambda: _restart_unit(args.unit)
                live = installer.install(archive, manifest, pending=args.pending)
    except NothingToDo as exc:
        LOG.info("Nothing to update: %s", exc)
        return EXIT_NOTHING_TO_DO if args.pending else 0
    except BundleRefused as exc:
        LOG.error("Sensor bundle refused: %s", exc)
        return 1
    except UpdateFailed as exc:
        LOG.error("Sensor update failed: %s", exc)
        return 1
    except RuntimeError as exc:
        # AgentClient's own errors: the exchange or a request was refused.
        LOG.error("Sensor update could not reach the bundle: %s", exc)
        return 1
    if args.pending:
        LOG.info(
            "Sensor agent package %s swapped in for %s (%s); waiting for the verdict",
            manifest.version, current, live,
        )
        return 0
    LOG.info(
        "Sensor agent package updated to %s from %s (%s); scanner/ and the venv are not "
        "part of the bundle",
        manifest.version, current, live,
    )
    if not use_systemd:
        LOG.warning(
            "No systemd unit %s here: restart the sensor process yourself to run the new version",
            args.unit,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
