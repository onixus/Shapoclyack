"""Remote agent registry (Phase 3)."""

from __future__ import annotations

import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from api.schemas import AgentInfo
from api.settings import Settings

_lock = threading.Lock()
_agents: dict[str, dict[str, Any]] = {}
_settings: Settings | None = None


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _agents_path() -> Path:
    assert _settings is not None
    return _settings.state_dir / "api_agents.json"


def configure(settings: Settings) -> None:
    global _settings
    _settings = settings


def load_agents(settings: Settings) -> None:
    configure(settings)
    path = _agents_path()
    if not path.is_file():
        return
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(raw, list):
        return
    with _lock:
        _agents.clear()
        for item in raw:
            if isinstance(item, dict) and item.get("agent_id"):
                _agents[str(item["agent_id"])] = item


def _persist_unlocked() -> None:
    path = _agents_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(list(_agents.values()), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _is_online(agent: dict[str, Any]) -> bool:
    assert _settings is not None
    last = agent.get("last_seen_at")
    if not last:
        return False
    try:
        seen = datetime.fromisoformat(str(last).replace("Z", "+00:00"))
    except ValueError:
        return False
    age = (datetime.now(UTC) - seen.astimezone(UTC)).total_seconds()
    return age <= _settings.agent_stale_seconds


def _to_info(agent: dict[str, Any]) -> AgentInfo:
    online = _is_online(agent)
    status = str(agent.get("status") or "idle")
    if not online:
        status = "stale"
    return AgentInfo(
        agent_id=str(agent["agent_id"]),
        hostname=str(agent.get("hostname") or ""),
        version=str(agent.get("version") or ""),
        labels=dict(agent.get("labels") or {}),
        status=status,  # type: ignore[arg-type]
        current_job_id=agent.get("current_job_id"),
        detail=agent.get("detail"),
        registered_at=agent.get("registered_at"),
        last_seen_at=agent.get("last_seen_at"),
        online=online,
    )


def register_agent(
    *,
    agent_id: str | None = None,
    hostname: str = "",
    version: str = "",
    labels: dict[str, str] | None = None,
) -> AgentInfo:
    now = _now_iso()
    with _lock:
        if agent_id and agent_id in _agents:
            agent = _agents[agent_id]
            agent["hostname"] = hostname or agent.get("hostname") or ""
            agent["version"] = version or agent.get("version") or ""
            if labels is not None:
                agent["labels"] = dict(labels)
            agent["last_seen_at"] = now
            if agent.get("status") == "stale":
                agent["status"] = "idle"
            _persist_unlocked()
            return _to_info(agent)

        new_id = (agent_id or "").strip() or uuid.uuid4().hex
        agent = {
            "agent_id": new_id,
            "hostname": hostname or "",
            "version": version or "",
            "labels": dict(labels or {}),
            "status": "idle",
            "current_job_id": None,
            "detail": None,
            "registered_at": now,
            "last_seen_at": now,
        }
        _agents[new_id] = agent
        _persist_unlocked()
        return _to_info(agent)


def heartbeat(
    agent_id: str,
    *,
    status: str = "idle",
    current_job_id: str | None = None,
    detail: str | None = None,
) -> AgentInfo | None:
    with _lock:
        agent = _agents.get(agent_id)
        if agent is None:
            return None
        agent["last_seen_at"] = _now_iso()
        agent["status"] = status
        agent["current_job_id"] = current_job_id
        agent["detail"] = detail
        _persist_unlocked()
        return _to_info(agent)


def list_agents() -> list[AgentInfo]:
    with _lock:
        items = [_to_info(agent) for agent in _agents.values()]
    items.sort(key=lambda a: (a.hostname or a.agent_id).lower())
    return items


def get_agent(agent_id: str) -> AgentInfo | None:
    with _lock:
        agent = _agents.get(agent_id)
        if agent is None:
            return None
        return _to_info(agent)


def touch_job(agent_id: str, job_id: str | None, *, status: str = "busy") -> None:
    with _lock:
        agent = _agents.get(agent_id)
        if agent is None:
            return
        agent["last_seen_at"] = _now_iso()
        agent["current_job_id"] = job_id
        agent["status"] = status if job_id else "idle"
        _persist_unlocked()
