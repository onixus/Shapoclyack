"""Artifact storage: bytes by key, on a filesystem or in object storage (#336).

Import from here, not from the backend modules::

    from api.services import artifact_store

    store = artifact_store.get_store(settings)
    store.put_bytes(artifact_store.keys.report_key(tenant_id, filename), data)

``get_store`` is memoised on the settings that describe the backend, so the
boto3 client and its connection pool are built once per process rather than
once per request, and a test that swaps settings still gets its own store.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

from . import keys
from .base import (
    ArtifactEntry,
    ArtifactNotFound,
    ArtifactStore,
    ArtifactStoreError,
    normalize_key,
    normalize_prefix,
)
from .local import LocalArtifactStore
from .s3 import S3ArtifactStore, S3Config

if TYPE_CHECKING:  # pragma: no cover
    from api.settings import Settings

LOG = logging.getLogger("shapoclyack.artifacts")

BACKEND_LOCAL = "local"
BACKEND_S3 = "s3"
SUPPORTED_BACKENDS = (BACKEND_LOCAL, BACKEND_S3)

__all__ = [
    "ArtifactEntry",
    "ArtifactNotFound",
    "ArtifactStore",
    "ArtifactStoreError",
    "BACKEND_LOCAL",
    "BACKEND_S3",
    "LocalArtifactStore",
    "S3ArtifactStore",
    "S3Config",
    "SUPPORTED_BACKENDS",
    "build_store",
    "get_store",
    "is_remote",
    "keys",
    "normalize_key",
    "normalize_prefix",
    "reset_cache",
]

_LOCK = threading.Lock()
_CACHE: dict[tuple[Any, ...], ArtifactStore] = {}


def _fingerprint(settings: Settings) -> tuple[Any, ...]:
    """Everything that changes which store a caller should get.

    The secret is included by identity, not by value, so that a rotated
    credential produces a new client instead of a cached one signing with a
    key the gateway no longer accepts.
    """
    return (
        settings.artifact_backend,
        str(settings.output_dir),
        str(settings.state_dir),
        settings.artifact_s3_bucket,
        settings.artifact_s3_prefix,
        settings.artifact_s3_endpoint_url,
        settings.artifact_s3_region,
        settings.artifact_s3_access_key_id,
        settings.artifact_s3_secret_access_key,
        settings.artifact_s3_session_token,
        settings.artifact_s3_addressing_style,
        settings.artifact_s3_verify_tls,
        settings.artifact_presign_enabled,
        settings.artifact_presign_expires_seconds,
    )


def build_store(settings: Settings) -> ArtifactStore:
    """A store for these settings, without consulting the cache."""
    backend = (settings.artifact_backend or BACKEND_LOCAL).strip().lower()
    if backend == BACKEND_LOCAL:
        return LocalArtifactStore(output_root=settings.output_dir, state_root=settings.state_dir)
    if backend == BACKEND_S3:
        return S3ArtifactStore(
            S3Config(
                bucket=settings.artifact_s3_bucket,
                prefix=settings.artifact_s3_prefix,
                endpoint_url=settings.artifact_s3_endpoint_url,
                region=settings.artifact_s3_region,
                access_key_id=settings.artifact_s3_access_key_id,
                secret_access_key=settings.artifact_s3_secret_access_key,
                session_token=settings.artifact_s3_session_token,
                addressing_style=settings.artifact_s3_addressing_style,
                presign_expires_seconds=settings.artifact_presign_expires_seconds,
                presign_enabled=settings.artifact_presign_enabled,
                verify_tls=settings.artifact_s3_verify_tls,
            )
        )
    # Reached only through a typo in OCTO_ARTIFACT_BACKEND. Refused rather than
    # defaulted to local: an operator who asked for object storage and got a
    # filesystem would find out when the second replica failed to see the
    # first one's runs, which is the failure this whole module exists to end.
    raise ArtifactStoreError(
        f"OCTO_ARTIFACT_BACKEND={backend!r} is not one of {', '.join(SUPPORTED_BACKENDS)}"
    )


def get_store(settings: Settings) -> ArtifactStore:
    fingerprint = _fingerprint(settings)
    with _LOCK:
        store = _CACHE.get(fingerprint)
        if store is None:
            store = build_store(settings)
            _CACHE[fingerprint] = store
            LOG.info("Artifact store backend: %s", store.backend)
        return store


def reset_cache() -> None:
    """Drop cached stores. For tests, and for a settings reload."""
    with _LOCK:
        _CACHE.clear()


def is_remote(settings: Settings) -> bool:
    """Whether artifacts live somewhere other than this pod's filesystem.

    The question callers actually ask: a remote store needs a run materialised
    before it can be read as files, and a local one is already there.
    """
    return (settings.artifact_backend or BACKEND_LOCAL).strip().lower() != BACKEND_LOCAL
