"""What an artifact store is, and what a key means.

Scan artifacts -- run directories, screenshots, generated reports, the input
files a job hands its executor -- were files on one shared volume. That volume
is `scanner-data`, requested ReadWriteOnce, and a CSI driver attaches an RWO
volume to exactly one node: a second API replica scheduled elsewhere never
leaves ContainerCreating. Artifacts on a filesystem are therefore what caps the
API at one replica (#336, blocking #335).

This module defines the seam. A store addresses **bytes by key**, and a key is
a POSIX-style relative path built by :mod:`api.services.artifact_store.keys` --
never assembled ad hoc at a call site, so that the day run keys gain a tenant
segment (#311) there is one function to change.

Two backends implement it: ``local`` maps keys onto the directories the product
has always used, byte for byte, so an installation that upgrades and changes
nothing sees no difference at all; ``s3`` puts them in object storage and the
shared volume stops being needed.

The interface is deliberately small. Everything the product does with an
artifact is one of: write it, read it whole, stream it to a client, ask whether
it is there, list a prefix, or delete a prefix. Anything richer (random access,
append, rename) would be a promise object storage cannot keep.
"""

from __future__ import annotations

import abc
import posixpath
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path


class ArtifactStoreError(RuntimeError):
    """A store operation failed for a reason the caller cannot fix.

    Deliberately not an ``OSError``: callers that used to wrap filesystem
    access in ``except OSError`` would otherwise swallow a misconfigured
    bucket, an expired credential and a network partition as though they were
    a missing file, and an installation would look empty rather than broken.
    """


class ArtifactNotFound(ArtifactStoreError):
    """Asked for a key that is not in the store."""


@dataclass(frozen=True)
class ArtifactEntry:
    """One object in a listing.

    ``modified`` is epoch seconds. It is what retention sweeps compare against
    a cutoff, so it has to mean the same thing on both backends: the local
    store reports ``st_mtime`` and S3 reports ``LastModified``. Neither is the
    moment the scan ran -- a restored backup or a re-uploaded object is young
    again -- which is why retention is documented as "age in the store".
    """

    key: str
    size: int
    modified: float


def normalize_key(key: str) -> str:
    """Return ``key`` as a safe relative POSIX path, or raise.

    Every public method runs its argument through this. The check is not
    theoretical: run ids and report filenames reach the store having passed
    through URLs, and a key of ``../../etc/passwd`` against the local backend
    is a filesystem write outside the artifact root. Refusing here means each
    backend does not have to remember to.
    """
    if not isinstance(key, str) or not key.strip():
        raise ValueError("artifact key must be a non-empty string")
    cleaned = key.replace("\\", "/").strip("/")
    if not cleaned:
        raise ValueError("artifact key must name an object, not the root")
    parts = [part for part in cleaned.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise ValueError(f"artifact key escapes the store: {key!r}")
    if any("\x00" in part for part in parts):
        raise ValueError("artifact key contains a NUL byte")
    normalized = posixpath.join(*parts) if parts else ""
    if not normalized:
        raise ValueError("artifact key must name an object, not the root")
    return normalized


def normalize_prefix(prefix: str) -> str:
    """Like :func:`normalize_key`, for an argument that names a subtree.

    Kept separate because a prefix has a trailing-slash meaning a key does
    not: ``runs/2026`` must not match ``runs/2026-old``, so listings and
    deletions compare against ``prefix + "/"``.
    """
    return normalize_key(prefix)


class ArtifactStore(abc.ABC):
    """Bytes by key, on whatever the installation has.

    Implementations must be safe to share across threads: one instance is
    cached per process and the API serves requests, retention sweeps and the
    report worker from several of them at once.
    """

    #: Short name of the backend, for logs and ``/api/system`` diagnostics.
    backend: str = "unknown"

    @abc.abstractmethod
    def put_bytes(self, key: str, data: bytes, *, content_type: str | None = None) -> None:
        """Write ``data`` at ``key``, replacing whatever was there."""

    @abc.abstractmethod
    def get_bytes(self, key: str) -> bytes:
        """Read the whole object, or raise :class:`ArtifactNotFound`."""

    @abc.abstractmethod
    def stream(self, key: str, *, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        """Yield the object in chunks, or raise :class:`ArtifactNotFound`.

        Separate from :meth:`get_bytes` because a download response must not
        require the whole artifact in the API's memory: a run archive or a PDF
        report is unbounded by anything the API controls, and holding one per
        concurrent download is how a replica dies of a large report rather
        than a large load.
        """

    @abc.abstractmethod
    def exists(self, key: str) -> bool:
        """Whether ``key`` is in the store."""

    @abc.abstractmethod
    def size(self, key: str) -> int | None:
        """Bytes at ``key``, or ``None`` when it is absent."""

    @abc.abstractmethod
    def stat(self, key: str) -> ArtifactEntry | None:
        """Size and modification time of one object, or ``None``.

        One round trip for both, which is what retention needs: asking a
        listing for a single object's timestamp costs a walk of its whole
        neighbourhood.
        """

    @abc.abstractmethod
    def list_prefix(self, prefix: str) -> Iterable[ArtifactEntry]:
        """Every object under ``prefix``, in no guaranteed order."""

    @abc.abstractmethod
    def list_children(self, prefix: str) -> Iterable[str]:
        """The immediate child *names* under ``prefix``, files and folders alike.

        This is what makes a run listing affordable: enumerating run ids must
        not read every object in every run. On S3 it is a delimited listing; on
        the filesystem it is ``iterdir``.
        """

    @abc.abstractmethod
    def delete(self, key: str) -> bool:
        """Remove one object. ``False`` when it was not there."""

    @abc.abstractmethod
    def delete_prefix(self, prefix: str) -> int:
        """Remove every object under ``prefix``; answer how many went."""

    @abc.abstractmethod
    def upload_tree(self, prefix: str, source: Path) -> int:
        """Copy a local directory to ``prefix``; answer how many files went.

        Trees exist because a run is produced as a directory by a scanner that
        knows nothing about object storage, and is consumed by API code that
        reads two dozen JSON files out of it.
        """

    @abc.abstractmethod
    def download_tree(self, prefix: str, dest: Path) -> int:
        """Materialise ``prefix`` into ``dest``; answer how many files arrived."""

    def presigned_url(
        self,
        key: str,
        *,
        expires_seconds: int,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> str | None:
        """A URL a browser can fetch directly, when the backend offers one.

        ``None`` means "stream it through the API instead", which is what the
        local backend always answers. Callers must handle ``None`` rather than
        require presigning: it is an optimisation that takes the artifact bytes
        off the API's event loop, not the mechanism downloads depend on.

        ``filename`` and ``content_type`` are carried into the signed URL so a
        browser that follows the redirect still saves ``report.pdf`` rather
        than the opaque key -- signed, so neither can be tampered with in the
        URL bar.
        """
        return None

    def healthy(self) -> tuple[bool, str]:
        """Cheap reachability probe for ``/api/system``: ``(ok, detail)``."""
        return True, "ok"
