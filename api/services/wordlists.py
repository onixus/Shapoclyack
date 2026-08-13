"""Tenant-uploaded brute-force wordlists (Phase 8.2, UI-managed).

The subdomain and cloud-bucket brute-force stages both take a
``wordlist_file`` path (``scanner/pipeline/hostnames.py`` /
``cloud_discovery.py``), which only an operator with filesystem access to the
scanner can set. This module lets a tenant upload a wordlist through the API
instead: the body is normalized to the exact shape the scanner's own
``_load_wordlist`` would produce (lowercased, de-duplicated, blank lines and
``#`` comments stripped) and stored in Postgres, so it survives restarts and is
visible to every replica.

Nothing here touches the scanner. At local scan start
``config_override.materialize_wordlist`` writes the stored body to a file under
the state dir and points the job's effective config at it — see
``api/services/jobs.py``.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select

from api.db import models
from api.db.engine import get_session
from api.settings import Settings

LOG = logging.getLogger("shapoclyack.wordlists")

KINDS = ("subdomain", "bucket")

_settings: Settings | None = None


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _require_settings() -> Settings:
    assert _settings is not None, "wordlists.configure() not called"
    return _settings


def normalize(raw: str, *, max_words: int) -> tuple[str, int]:
    """Reduce an uploaded body to the scanner's on-disk wordlist shape.

    Mirrors ``hostnames._load_wordlist`` / ``cloud_discovery._load_wordlist``
    exactly (``line.strip().lower()``, drop blanks and ``#`` comments) and
    additionally de-duplicates while preserving first-seen order, so the stored
    body is what the scanner will actually iterate. Raises ``ValueError`` if the
    result is empty or exceeds ``max_words``.
    """
    words: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        word = line.strip().lower()
        if not word or word.startswith("#"):
            continue
        if word in seen:
            continue
        seen.add(word)
        words.append(word)
    if not words:
        raise ValueError("wordlist has no usable entries")
    if len(words) > max_words:
        raise ValueError(f"wordlist has {len(words)} entries; the limit is {max_words}")
    return "\n".join(words), len(words)


def _to_info(row: models.Wordlist) -> dict[str, Any]:
    """Public view — never includes the wordlist body, only its metadata."""
    return {
        "wordlist_id": row.wordlist_id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "kind": row.kind,
        "line_count": row.line_count,
        "sha256": row.sha256,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "created_by": row.created_by,
    }


def create_wordlist(
    *,
    tenant_id: str,
    name: str,
    kind: str,
    raw_content: str,
    username: str | None = None,
) -> dict[str, Any]:
    """Create or replace (by tenant+name) a wordlist. Raises ``ValueError`` on
    an unknown kind, an empty name, or a body that fails ``normalize``."""
    settings = _require_settings()
    name = (name or "").strip()
    if not name:
        raise ValueError("name must not be empty")
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {list(KINDS)}")
    content, line_count = normalize(raw_content, max_words=settings.wordlist_max_words)
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()

    with get_session(settings.postgres_url) as session:
        existing = session.scalar(
            select(models.Wordlist).where(
                models.Wordlist.tenant_id == tenant_id,
                models.Wordlist.name == name,
            )
        )
        if existing is not None:
            # Re-uploading under the same name is an update, not a duplicate —
            # the unique (tenant, name) constraint makes that the only sane
            # resolution and keeps the id stable for any scan referencing it.
            existing.kind = kind
            existing.content = content
            existing.line_count = line_count
            existing.sha256 = sha
            existing.created_at = datetime.now(UTC)
            existing.created_by = username
            row = existing
        else:
            row = models.Wordlist(
                wordlist_id=uuid.uuid4().hex[:12],
                tenant_id=tenant_id,
                name=name,
                kind=kind,
                content=content,
                line_count=line_count,
                sha256=sha,
                created_at=datetime.now(UTC),
                created_by=username,
            )
            session.add(row)
        session.flush()
        return _to_info(row)


def list_wordlists(tenant_id: str | None) -> list[dict[str, Any]]:
    """Metadata for a tenant's wordlists (bodies excluded). ``None`` tenant_id
    lists every tenant's — for an unscoped platform admin, as the other
    services do."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        stmt = select(models.Wordlist).order_by(models.Wordlist.created_at.desc())
        if tenant_id is not None:
            stmt = stmt.where(models.Wordlist.tenant_id == tenant_id)
        return [_to_info(row) for row in session.scalars(stmt).all()]


def get_wordlist(wordlist_id: str) -> dict[str, Any] | None:
    """Metadata for one wordlist, or ``None``. Body excluded — use
    ``get_content`` for the body (scan start only)."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Wordlist, wordlist_id)
        return _to_info(row) if row is not None else None


def get_content(wordlist_id: str, *, tenant_id: str) -> str | None:
    """The normalized body for one of the tenant's wordlists, or ``None`` when
    it does not exist or belongs to another tenant."""
    resolved = get_for_scan(wordlist_id, tenant_id=tenant_id)
    return resolved[1] if resolved is not None else None


def get_for_scan(wordlist_id: str, *, tenant_id: str) -> tuple[str, str] | None:
    """``(kind, content)`` for one of the tenant's wordlists, or ``None`` when
    it does not exist or belongs to another tenant. The tenant check here is
    the scan-start authorization: a job cannot brute-force with a list it does
    not own. Called from ``api/services/jobs.py`` at local scan start."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        row = session.get(models.Wordlist, wordlist_id)
        if row is None or row.tenant_id != tenant_id:
            return None
        return row.kind, row.content


def delete_wordlist(wordlist_id: str) -> bool:
    """Delete one wordlist by id. Returns whether a row was removed."""
    settings = _require_settings()
    with get_session(settings.postgres_url) as session:
        result = session.execute(
            delete(models.Wordlist).where(models.Wordlist.wordlist_id == wordlist_id)
        )
        return bool(result.rowcount)
