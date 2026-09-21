"""The filesystem backend: the layout this product has always written.

Nothing here is new behaviour. A key maps onto the path the same bytes
occupied before :mod:`api.services.artifact_store` existed -- ``runs/<id>/...``
under ``OCTO_OUTPUT_DIR``, ``job_inputs/<job>/...`` under ``OCTO_STATE_DIR``
-- so an installation that upgrades and sets nothing keeps reading and writing
the files it already has. That is the point of having a default backend at all:
object storage is an option an operator takes, not a migration they are handed.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable, Iterator
from pathlib import Path

from .base import (
    ArtifactEntry,
    ArtifactNotFound,
    ArtifactStore,
    ArtifactStoreError,
    normalize_key,
    normalize_prefix,
)
from .keys import LOCAL_ROOT_BY_FAMILY


class LocalArtifactStore(ArtifactStore):
    """Keys under one of two directory roots.

    Two rather than one because the product has always kept run output and
    scratch state apart, and an operator has always been able to point them at
    different volumes. Collapsing them here would silently relocate every
    existing job input on upgrade.
    """

    backend = "local"

    def __init__(self, *, output_root: Path, state_root: Path) -> None:
        self._roots = {"output": Path(output_root), "state": Path(state_root)}

    # -- paths ------------------------------------------------------------

    def _root_for(self, key: str) -> Path:
        family, _, _ = key.partition("/")
        return self._roots[LOCAL_ROOT_BY_FAMILY.get(family, "output")]

    def path_for(self, key: str) -> Path:
        """Absolute path of ``key``.

        Public because the local backend's whole value is that a caller *can*
        still be handed a real path: a run directory is read by code that opens
        two dozen files out of it, and forcing that through byte APIs would buy
        nothing on an installation that has no object storage.
        """
        normalized = normalize_key(key)
        root = self._root_for(normalized)
        # normalize_key has already refused `..`, so this join stays inside the
        # root. Resolved anyway: a symlinked root is legitimate (an operator
        # pointing output_dir at a mounted volume), and comparing unresolved
        # paths would make the check below fail on a correct installation.
        target = (root / normalized).resolve()
        root_resolved = root.resolve()
        if root_resolved != target and root_resolved not in target.parents:
            raise ArtifactStoreError(f"artifact key escapes its root: {key!r}")
        return target

    # -- bytes ------------------------------------------------------------

    def put_bytes(self, key: str, data: bytes, *, content_type: str | None = None) -> None:
        target = self.path_for(key)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Written beside the target and renamed: a reader on another thread --
        # a retention sweep, a download, the run listing -- must never observe
        # half an artifact, and rename is atomic within a directory.
        tmp = target.with_name(f".{target.name}.tmp{os.getpid()}")
        try:
            tmp.write_bytes(data)
            tmp.replace(target)
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise ArtifactStoreError(f"could not write {key}: {exc}") from exc

    def get_bytes(self, key: str) -> bytes:
        target = self.path_for(key)
        try:
            return target.read_bytes()
        except FileNotFoundError as exc:
            raise ArtifactNotFound(key) from exc
        except IsADirectoryError as exc:
            raise ArtifactNotFound(key) from exc
        except OSError as exc:
            raise ArtifactStoreError(f"could not read {key}: {exc}") from exc

    def stream(self, key: str, *, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        target = self.path_for(key)
        try:
            handle = target.open("rb")
        except FileNotFoundError as exc:
            raise ArtifactNotFound(key) from exc
        except IsADirectoryError as exc:
            raise ArtifactNotFound(key) from exc
        except OSError as exc:
            raise ArtifactStoreError(f"could not read {key}: {exc}") from exc

        def chunks() -> Iterator[bytes]:
            with handle:
                while True:
                    block = handle.read(chunk_size)
                    if not block:
                        return
                    yield block

        return chunks()

    def exists(self, key: str) -> bool:
        return self.path_for(key).is_file()

    def size(self, key: str) -> int | None:
        target = self.path_for(key)
        try:
            stat = target.stat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            raise ArtifactStoreError(f"could not stat {key}: {exc}") from exc
        # A directory is not an object. S3 has no such thing to report a size
        # for, and a caller that gets 4096 back for `runs/<id>` would believe
        # the run is a file.
        return None if os.path.isdir(target) else stat.st_size

    def stat(self, key: str) -> ArtifactEntry | None:
        target = self.path_for(key)
        try:
            info = target.stat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        except OSError as exc:
            raise ArtifactStoreError(f"could not stat {key}: {exc}") from exc
        if os.path.isdir(target):
            return None
        return ArtifactEntry(key=normalize_key(key), size=info.st_size, modified=info.st_mtime)

    # -- listings ---------------------------------------------------------

    def list_prefix(self, prefix: str) -> Iterable[ArtifactEntry]:
        normalized = normalize_prefix(prefix)
        root = self._root_for(normalized)
        base = self.path_for(normalized)
        if not base.is_dir():
            if base.is_file():
                stat = base.stat()
                return [ArtifactEntry(key=normalized, size=stat.st_size, modified=stat.st_mtime)]
            return []
        entries: list[ArtifactEntry] = []
        for path in base.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                stat = path.stat()
            except OSError:
                # Swept out from under us by retention mid-walk. A listing that
                # raced a deletion should be short one entry, not an error.
                continue
            entries.append(
                ArtifactEntry(
                    key=path.relative_to(root).as_posix(),
                    size=stat.st_size,
                    modified=stat.st_mtime,
                )
            )
        return entries

    def list_children(self, prefix: str) -> Iterable[str]:
        base = self.path_for(normalize_prefix(prefix))
        if not base.is_dir():
            return []
        try:
            return sorted(child.name for child in base.iterdir())
        except OSError as exc:
            raise ArtifactStoreError(f"could not list {prefix}: {exc}") from exc

    # -- removal ----------------------------------------------------------

    def delete(self, key: str) -> bool:
        target = self.path_for(key)
        try:
            target.unlink()
            return True
        except FileNotFoundError:
            return False
        except IsADirectoryError:
            return False
        except OSError as exc:
            raise ArtifactStoreError(f"could not delete {key}: {exc}") from exc

    def delete_prefix(self, prefix: str) -> int:
        base = self.path_for(normalize_prefix(prefix))
        if base.is_file():
            return 1 if self.delete(normalize_prefix(prefix)) else 0
        if not base.is_dir():
            return 0
        removed = sum(1 for path in base.rglob("*") if path.is_file())
        try:
            shutil.rmtree(base)
        except OSError as exc:
            raise ArtifactStoreError(f"could not delete {prefix}: {exc}") from exc
        return removed

    # -- trees ------------------------------------------------------------

    def upload_tree(self, prefix: str, source: Path, *, written: list[str] | None = None) -> int:
        """Copy ``source`` to ``prefix``.

        A no-op when they are already the same directory, which is the normal
        case: the local backend's "publish this run" is the run having been
        written where it belongs in the first place. Copying it to itself would
        be a needless doubling of every run's bytes -- and nothing is appended
        to ``written`` for it, because nothing was written and a rollback that
        removed those keys would delete the run itself.
        """
        normalized = normalize_prefix(prefix)
        target = self.path_for(normalized)
        source = Path(source)
        if not source.is_dir():
            return 0
        if source.resolve() == target:
            return sum(1 for path in source.rglob("*") if path.is_file())
        count = 0
        for path in sorted(source.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(source).as_posix()
            key = f"{normalized}/{relative}"
            self.put_bytes(key, path.read_bytes())
            if written is not None:
                written.append(normalize_key(key))
            count += 1
        return count

    def download_tree(self, prefix: str, dest: Path) -> int:
        normalized = normalize_prefix(prefix)
        base = self.path_for(normalized)
        dest = Path(dest)
        if not base.is_dir():
            return 0
        if dest.exists() and dest.resolve() == base:
            # Already materialised: on this backend the store *is* the
            # filesystem the caller wanted it copied to.
            return sum(1 for path in base.rglob("*") if path.is_file())
        count = 0
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            out = dest / path.relative_to(base)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, out)
            count += 1
        return count

    def healthy(self) -> tuple[bool, str]:
        for name, root in self._roots.items():
            if not root.exists():
                # Not an error: a fresh install has written no artifacts yet
                # and the directory appears with the first one.
                continue
            if not os.access(root, os.W_OK):
                return False, f"{name} root {root} is not writable"
        return True, "ok"
