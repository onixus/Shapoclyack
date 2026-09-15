"""The S3 backend: artifacts in object storage, so the API can have replicas.

Anything that speaks S3 -- AWS, MinIO, Ceph RGW, Wasabi, Yandex Object Storage
-- works through the same ``endpoint_url``/``region`` pair the Postgres backup
CronJob already uses, on purpose: an installation that has somewhere to put a
database dump has somewhere to put its artifacts, and the operator does not
learn a second vocabulary.

``boto3`` is imported lazily. It is a large dependency for an installation that
never leaves the filesystem, and a missing one must say *which* setting asked
for it rather than failing at process import with a bare ModuleNotFoundError.
"""

from __future__ import annotations

import logging
import mimetypes
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .base import (
    ArtifactEntry,
    ArtifactNotFound,
    ArtifactStore,
    ArtifactStoreError,
    normalize_key,
    normalize_prefix,
)

LOG = logging.getLogger("shapoclyack.artifacts")

#: How many objects a tree transfer moves at once. A run directory is hundreds
#: of small JSON files, and moving them one round trip at a time makes the end
#: of every scan wait on latency rather than bandwidth. Bounded low: this runs
#: inside the API process, next to request handling.
_TREE_CONCURRENCY = 8


@dataclass(frozen=True)
class S3Config:
    bucket: str
    prefix: str = ""
    endpoint_url: str = ""
    region: str = ""
    access_key_id: str = ""
    secret_access_key: str = ""
    session_token: str = ""
    #: MinIO and most self-hosted gateways serve path-style
    #: (``host/bucket/key``); AWS deprecates it in favour of virtual-host
    #: style. Default "auto" leaves boto3's own choice alone.
    addressing_style: str = "auto"
    presign_expires_seconds: int = 900
    #: Whether a download may be answered with a redirect to object storage
    #: instead of bytes through the API. Off unless asked for: see
    #: ``Settings.artifact_presign_enabled``.
    presign_enabled: bool = False
    verify_tls: bool = True


class S3ArtifactStore(ArtifactStore):
    backend = "s3"

    def __init__(self, config: S3Config) -> None:
        if not config.bucket.strip():
            raise ArtifactStoreError(
                "OCTO_ARTIFACT_S3_BUCKET is required when OCTO_ARTIFACT_BACKEND=s3"
            )
        self._config = config
        self._prefix = config.prefix.strip("/")
        self._client: Any | None = None

    # -- client -----------------------------------------------------------

    @property
    def client(self) -> Any:
        """The boto3 client, built once.

        Built lazily rather than in ``__init__`` so that constructing the store
        -- which happens at settings time, including in tests that never touch
        object storage -- does not require credentials or a reachable endpoint.
        """
        if self._client is None:
            self._client = self._build_client()
        return self._client

    def _build_client(self) -> Any:
        try:
            import boto3
            from botocore.config import Config as BotoConfig
        except ImportError as exc:  # pragma: no cover - depends on the install
            raise ArtifactStoreError(
                "OCTO_ARTIFACT_BACKEND=s3 needs boto3, which is not installed. "
                "Install requirements-api.txt, or set OCTO_ARTIFACT_BACKEND=local."
            ) from exc

        cfg = self._config
        boto_config = BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": cfg.addressing_style},
            retries={"max_attempts": 5, "mode": "standard"},
        )
        kwargs: dict[str, Any] = {"config": boto_config}
        if cfg.endpoint_url:
            kwargs["endpoint_url"] = cfg.endpoint_url
        if cfg.region:
            kwargs["region_name"] = cfg.region
        # Credentials left unset fall through to boto3's own chain -- instance
        # role, IRSA, ~/.aws. That is the preferred shape on a cloud cluster
        # and the reason these are not required settings.
        if cfg.access_key_id and cfg.secret_access_key:
            kwargs["aws_access_key_id"] = cfg.access_key_id
            kwargs["aws_secret_access_key"] = cfg.secret_access_key
            if cfg.session_token:
                kwargs["aws_session_token"] = cfg.session_token
        if not cfg.verify_tls:
            kwargs["verify"] = False
        return boto3.client("s3", **kwargs)

    # -- key mapping ------------------------------------------------------

    def _object_key(self, key: str) -> str:
        normalized = normalize_key(key)
        return f"{self._prefix}/{normalized}" if self._prefix else normalized

    def _object_prefix(self, prefix: str) -> str:
        normalized = normalize_prefix(prefix)
        return f"{self._prefix}/{normalized}" if self._prefix else normalized

    def _logical_key(self, object_key: str) -> str:
        if self._prefix and object_key.startswith(f"{self._prefix}/"):
            return object_key[len(self._prefix) + 1 :]
        return object_key

    @staticmethod
    def _is_missing(exc: Exception) -> bool:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        status = getattr(exc, "response", {}).get("ResponseMetadata", {}).get("HTTPStatusCode")
        return code in {"NoSuchKey", "404", "NotFound"} or status == 404

    # -- bytes ------------------------------------------------------------

    def put_bytes(self, key: str, data: bytes, *, content_type: str | None = None) -> None:
        guessed = content_type or mimetypes.guess_type(key)[0] or "application/octet-stream"
        try:
            self.client.put_object(
                Bucket=self._config.bucket,
                Key=self._object_key(key),
                Body=data,
                ContentType=guessed,
            )
        except Exception as exc:  # noqa: BLE001 - botocore raises its own tree
            raise ArtifactStoreError(f"could not write {key}: {exc}") from exc

    def get_bytes(self, key: str) -> bytes:
        try:
            response = self.client.get_object(
                Bucket=self._config.bucket, Key=self._object_key(key)
            )
            return response["Body"].read()
        except Exception as exc:  # noqa: BLE001
            if self._is_missing(exc):
                raise ArtifactNotFound(key) from exc
            raise ArtifactStoreError(f"could not read {key}: {exc}") from exc

    def stream(self, key: str, *, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:
        try:
            response = self.client.get_object(
                Bucket=self._config.bucket, Key=self._object_key(key)
            )
        except Exception as exc:  # noqa: BLE001
            if self._is_missing(exc):
                raise ArtifactNotFound(key) from exc
            raise ArtifactStoreError(f"could not read {key}: {exc}") from exc

        body = response["Body"]

        def chunks() -> Iterator[bytes]:
            try:
                while True:
                    block = body.read(chunk_size)
                    if not block:
                        return
                    yield block
            finally:
                body.close()

        return chunks()

    def exists(self, key: str) -> bool:
        return self.size(key) is not None

    def size(self, key: str) -> int | None:
        try:
            head = self.client.head_object(Bucket=self._config.bucket, Key=self._object_key(key))
        except Exception as exc:  # noqa: BLE001
            if self._is_missing(exc):
                return None
            raise ArtifactStoreError(f"could not stat {key}: {exc}") from exc
        return int(head.get("ContentLength", 0))

    # -- listings ---------------------------------------------------------

    def _paginate(self, **kwargs: Any) -> Iterator[dict[str, Any]]:
        try:
            paginator = self.client.get_paginator("list_objects_v2")
            yield from paginator.paginate(Bucket=self._config.bucket, **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise ArtifactStoreError(f"could not list {kwargs.get('Prefix')}: {exc}") from exc

    def list_prefix(self, prefix: str) -> Iterable[ArtifactEntry]:
        # The trailing slash is what keeps `runs/2026-09-15` from matching
        # `runs/2026-09-15-retry`: S3 prefixes are string prefixes, not paths.
        search = f"{self._object_prefix(prefix)}/"
        entries: list[ArtifactEntry] = []
        for page in self._paginate(Prefix=search):
            for item in page.get("Contents", []):
                entries.append(
                    ArtifactEntry(
                        key=self._logical_key(item["Key"]),
                        size=int(item.get("Size", 0)),
                        modified=item["LastModified"].timestamp(),
                    )
                )
        # An object stored at the prefix itself, rather than under it, is not
        # matched by `prefix/` and would otherwise be invisible to a sweep --
        # every family is a subtree today, but a store whose listing silently
        # skips a key it holds is a trap waiting for the first one that is not. Its timestamp comes from a HEAD rather than
        # being invented: a retention sweep compares `modified` against a
        # cutoff, and a placeholder zero would mean "delete on the next pass".
        exact = self.stat(prefix)
        if exact is not None:
            entries.append(exact)
        return entries

    def stat(self, key: str) -> ArtifactEntry | None:
        """One object's entry, or ``None`` when it is not there."""
        try:
            head = self.client.head_object(Bucket=self._config.bucket, Key=self._object_key(key))
        except Exception as exc:  # noqa: BLE001
            if self._is_missing(exc):
                return None
            raise ArtifactStoreError(f"could not stat {key}: {exc}") from exc
        modified = head.get("LastModified")
        return ArtifactEntry(
            key=normalize_key(key),
            size=int(head.get("ContentLength", 0)),
            modified=modified.timestamp() if modified is not None else 0.0,
        )

    def list_children(self, prefix: str) -> Iterable[str]:
        search = f"{self._object_prefix(prefix)}/"
        names: set[str] = set()
        for page in self._paginate(Prefix=search, Delimiter="/"):
            for common in page.get("CommonPrefixes", []):
                names.add(common["Prefix"][len(search) :].rstrip("/"))
            for item in page.get("Contents", []):
                names.add(item["Key"][len(search) :])
        return sorted(name for name in names if name)

    # -- removal ----------------------------------------------------------

    def delete(self, key: str) -> bool:
        present = self.exists(key)
        try:
            self.client.delete_object(Bucket=self._config.bucket, Key=self._object_key(key))
        except Exception as exc:  # noqa: BLE001
            raise ArtifactStoreError(f"could not delete {key}: {exc}") from exc
        return present

    def delete_prefix(self, prefix: str) -> int:
        keys = [entry.key for entry in self.list_prefix(prefix)]
        removed = 0
        # delete_objects takes a thousand keys per call; a long-retained run
        # can exceed that on screenshots alone.
        for start in range(0, len(keys), 1000):
            batch = keys[start : start + 1000]
            try:
                response = self.client.delete_objects(
                    Bucket=self._config.bucket,
                    Delete={
                        "Objects": [{"Key": self._object_key(key)} for key in batch],
                        "Quiet": True,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                raise ArtifactStoreError(f"could not delete {prefix}: {exc}") from exc
            errors = response.get("Errors") or []
            if errors:
                raise ArtifactStoreError(
                    f"could not delete {len(errors)} object(s) under {prefix}: "
                    f"{errors[0].get('Code')} {errors[0].get('Key')}"
                )
            removed += len(batch)
        return removed

    # -- trees ------------------------------------------------------------

    def upload_tree(self, prefix: str, source: Path) -> int:
        source = Path(source)
        if not source.is_dir():
            return 0
        normalized = normalize_prefix(prefix)
        files = [
            path
            for path in sorted(source.rglob("*"))
            if path.is_file() and not path.is_symlink()
        ]
        if not files:
            return 0

        def send(path: Path) -> None:
            relative = path.relative_to(source).as_posix()
            self.put_bytes(f"{normalized}/{relative}", path.read_bytes())

        with ThreadPoolExecutor(max_workers=_TREE_CONCURRENCY) as pool:
            # list() so an exception in any worker is raised here rather than
            # dropped: a partially uploaded run must fail the publish, not be
            # reported as complete and read back short a summary.
            list(pool.map(send, files))
        return len(files)

    def download_tree(self, prefix: str, dest: Path) -> int:
        dest = Path(dest)
        entries = list(self.list_prefix(prefix))
        if not entries:
            return 0
        normalized = normalize_prefix(prefix)

        def receive(entry: ArtifactEntry) -> None:
            relative = entry.key[len(normalized) + 1 :] if entry.key != normalized else entry.key
            out = dest / relative
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(self.get_bytes(entry.key))

        dest.mkdir(parents=True, exist_ok=True)
        with ThreadPoolExecutor(max_workers=_TREE_CONCURRENCY) as pool:
            list(pool.map(receive, entries))
        return len(entries)

    # -- extras -----------------------------------------------------------

    def presigned_url(
        self,
        key: str,
        *,
        expires_seconds: int,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> str | None:
        if not self._config.presign_enabled:
            return None
        params: dict[str, Any] = {"Bucket": self._config.bucket, "Key": self._object_key(key)}
        if filename:
            # Quoted and stripped of anything that could end the header value:
            # the filename reaches here from a report row and a run's own
            # artifact names, and a response header is not the place to find
            # out one of them contains a quote or a newline.
            safe = "".join(ch for ch in filename if ch.isprintable() and ch not in '"\\;')
            params["ResponseContentDisposition"] = f'attachment; filename="{safe}"'
        if content_type:
            params["ResponseContentType"] = content_type
        try:
            return self.client.generate_presigned_url(
                "get_object",
                Params=params,
                ExpiresIn=max(1, expires_seconds),
            )
        except Exception:  # noqa: BLE001
            # Falling back to streaming is always correct, so a gateway that
            # cannot presign degrades in speed rather than in function.
            LOG.warning("Could not presign %s; falling back to streaming", key, exc_info=True)
            return None

    def healthy(self) -> tuple[bool, str]:
        try:
            self.client.head_bucket(Bucket=self._config.bucket)
        except Exception as exc:  # noqa: BLE001
            return False, f"bucket {self._config.bucket} unreachable: {exc}"
        return True, "ok"
