"""Tenant registry + provisioning keys (Phase 2 MSSP). Persisted as JSON until Postgres."""

from __future__ import annotations

import json
import secrets
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from passlib.context import CryptContext

from api.settings import Settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
DEFAULT_TENANT_ID = "default"

_lock = threading.Lock()
_tenants: dict[str, dict[str, Any]] = {}
_keys: dict[str, dict[str, Any]] = {}
_settings: Settings | None = None


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def _tenants_path() -> Path:
    assert _settings is not None
    return _settings.state_dir / "api_tenants.json"


def _keys_path() -> Path:
    assert _settings is not None
    return _settings.state_dir / "api_provisioning_keys.json"


def _persist_tenants_unlocked() -> None:
    path = _tenants_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(list(_tenants.values()), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _persist_keys_unlocked() -> None:
    path = _keys_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never persist plaintext keys.
    safe = []
    for item in _keys.values():
        row = dict(item)
        row.pop("plaintext", None)
        safe.append(row)
    path.write_text(json.dumps(safe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def load_tenants(settings: Settings) -> None:
    configure(settings)
    tpath = _tenants_path()
    kpath = _keys_path()
    with _lock:
        _tenants.clear()
        _keys.clear()
        if tpath.is_file():
            try:
                raw = json.loads(tpath.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict) and item.get("tenant_id"):
                            _tenants[str(item["tenant_id"])] = item
            except (OSError, json.JSONDecodeError):
                pass
        if kpath.is_file():
            try:
                raw = json.loads(kpath.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, dict) and item.get("key_id"):
                            _keys[str(item["key_id"])] = item
            except (OSError, json.JSONDecodeError):
                pass
        # Ensure lab default tenant always exists.
        if DEFAULT_TENANT_ID not in _tenants:
            _tenants[DEFAULT_TENANT_ID] = {
                "tenant_id": DEFAULT_TENANT_ID,
                "name": "Default",
                "status": "active",
                "created_at": _now_iso(),
            }
            _persist_tenants_unlocked()


def reset_for_tests() -> None:
    with _lock:
        _tenants.clear()
        _keys.clear()


def list_tenants() -> list[dict[str, Any]]:
    with _lock:
        items = [dict(t) for t in _tenants.values()]
    items.sort(key=lambda t: str(t.get("name") or t.get("tenant_id")).lower())
    return items


def get_tenant(tenant_id: str) -> dict[str, Any] | None:
    with _lock:
        item = _tenants.get(tenant_id)
        return dict(item) if item else None


def create_tenant(*, name: str, tenant_id: str | None = None) -> dict[str, Any]:
    name = name.strip()
    if not name:
        raise ValueError("tenant name required")
    tid = (tenant_id or "").strip() or f"ten_{uuid.uuid4().hex[:12]}"
    with _lock:
        if tid in _tenants:
            raise ValueError(f"tenant_id already exists: {tid}")
        record = {
            "tenant_id": tid,
            "name": name,
            "status": "active",
            "created_at": _now_iso(),
        }
        _tenants[tid] = record
        _persist_tenants_unlocked()
        return dict(record)


def create_provisioning_key(*, tenant_id: str, label: str = "") -> dict[str, Any]:
    """Mint a provisioning key. Returns record including one-time ``key`` plaintext."""
    with _lock:
        tenant = _tenants.get(tenant_id)
        if tenant is None:
            raise LookupError("tenant not found")
        if tenant.get("status") != "active":
            raise ValueError("tenant is not active")
        key_id = f"pk_{uuid.uuid4().hex[:16]}"
        plaintext = f"octo-pk-{secrets.token_urlsafe(32)}"
        record = {
            "key_id": key_id,
            "tenant_id": tenant_id,
            "label": label.strip(),
            "key_hash": pwd_context.hash(plaintext),
            "created_at": _now_iso(),
            "revoked_at": None,
            "last_used_at": None,
        }
        _keys[key_id] = record
        _persist_keys_unlocked()
        out = dict(record)
        out.pop("key_hash", None)
        out["key"] = plaintext
        return out


def list_provisioning_keys(tenant_id: str | None = None) -> list[dict[str, Any]]:
    with _lock:
        items = []
        for item in _keys.values():
            if tenant_id and item.get("tenant_id") != tenant_id:
                continue
            row = {k: v for k, v in item.items() if k != "key_hash"}
            items.append(row)
    items.sort(key=lambda r: str(r.get("created_at") or ""), reverse=True)
    return items


def revoke_provisioning_key(key_id: str) -> dict[str, Any] | None:
    with _lock:
        item = _keys.get(key_id)
        if item is None:
            return None
        item["revoked_at"] = _now_iso()
        _persist_keys_unlocked()
        return {k: v for k, v in item.items() if k != "key_hash"}


def resolve_provisioning_key(plaintext: str) -> dict[str, Any] | None:
    """Find active key matching plaintext; update last_used_at."""
    with _lock:
        for item in _keys.values():
            if item.get("revoked_at"):
                continue
            stored = str(item.get("key_hash") or "")
            if not stored:
                continue
            if pwd_context.verify(plaintext, stored):
                tenant = _tenants.get(str(item.get("tenant_id")))
                if tenant is None or tenant.get("status") != "active":
                    return None
                item["last_used_at"] = _now_iso()
                _persist_keys_unlocked()
                return {
                    "key_id": str(item["key_id"]),
                    "tenant_id": str(item["tenant_id"]),
                    "label": str(item.get("label") or ""),
                }
    return None
