"""Bounded live readiness tied to an independently pinned startup manifest."""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from time import monotonic

import httpx

from .config import OperatorConfig

MAX_MANIFEST_BYTES = 16384
MAX_STATUS_BYTES = 65536


def _read_json(client, url, deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise ValueError("readiness deadline")
    with client.stream("GET", url, headers={"Accept-Encoding": "identity"}, timeout=min(3.0, remaining)) as response:
        response.raise_for_status()
        if response.headers.get("content-encoding", "identity") != "identity":
            raise ValueError("encoded response")
        raw = bytearray()
        for chunk in response.iter_bytes():
            if monotonic() > deadline:
                raise ValueError("readiness deadline")
            raw.extend(chunk)
            if len(raw) > MAX_STATUS_BYTES:
                raise ValueError("status too large")
    return json.loads(raw)


def probe(settings, *, transport=None):
    empty = {"runtime_status": "not_checked", "runtime_verified": False,
             "model_integrity": "not_checked"}
    path = getattr(settings, "operator_runtime_manifest_path", None)
    expected = getattr(settings, "operator_runtime_manifest_sha256", "")
    if path is None:
        return empty
    try:
        path = Path(path)
        if path.is_symlink() or not re.fullmatch(r"[a-f0-9]{64}", expected):
            raise ValueError("invalid manifest")
        with path.open("rb") as handle:
            raw = handle.read(MAX_MANIFEST_BYTES + 1)
        if len(raw) > MAX_MANIFEST_BYTES or hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("untrusted manifest")
        manifest = json.loads(raw)
        config = OperatorConfig.from_settings(settings)
        if (manifest["schema_version"] != 1 or config.provider != "local"
                or manifest["model"] != config.model or manifest["context_tokens"] != 8192
                or manifest["parallel"] != 1 or manifest["profile"] != "mac-arm64-cpu"
                or not re.fullmatch(r"[a-f0-9]{64}", manifest["model_sha256"])
                or not re.fullmatch(r"[a-f0-9]{40}", manifest["runtime_revision"])
                or not re.fullmatch(r"ghcr\.io/ggml-org/llama\.cpp:server@sha256:[a-f0-9]{64}", manifest["runtime_image"])):
            raise ValueError("manifest configuration mismatch")
        datetime.fromisoformat(manifest["verified_at"].replace("Z", "+00:00"))
        deadline = monotonic() + 6.0
        with httpx.Client(timeout=3.0, trust_env=False, follow_redirects=False, transport=transport) as client:
            root = config.base_url.rstrip("/").removesuffix("/v1")
            if _read_json(client, root + "/health", deadline).get("status") != "ok":
                raise ValueError("runtime not healthy")
            models = _read_json(client, config.base_url.rstrip("/") + "/models", deadline)
            selected = [value for value in models.get("data", []) if value.get("id") == config.model]
            if len(selected) != 1 or selected[0].get("meta", {}).get("n_ctx") != manifest["context_tokens"]:
                raise ValueError("live model mismatch")
            if settings.operator_embeddings_enabled:
                from .embeddings import EmbeddingConfig
                embeddings = EmbeddingConfig.from_settings(settings)
                if (manifest["embedding_revision"] != embeddings.revision
                        or manifest["embedding_sha256"] != embeddings.model_sha256
                        or manifest["embedding_dimensions"] != embeddings.dimensions):
                    raise ValueError("embedding manifest mismatch")
                endpoint = embeddings.base_url.rstrip("/").removesuffix("/v1")
                if _read_json(client, endpoint + "/health", deadline).get("status") != "ok":
                    raise ValueError("embedding runtime unavailable")
        return {"runtime_status": "ready", "runtime_verified": True,
                "model_integrity": "verified_at_startup", "model_sha256": manifest["model_sha256"],
                "runtime_revision": manifest["runtime_revision"], "runtime_image": manifest["runtime_image"],
                "context_tokens": manifest["context_tokens"], "parallel": manifest["parallel"],
                "verified_at": manifest["verified_at"], "profile": manifest["profile"]}
    except (KeyError, ValueError, TypeError, AttributeError, OSError, httpx.HTTPError, RecursionError):
        # Neither paths nor upstream response bodies belong in status/errors.
        return {**empty, "runtime_status": "unavailable"}
