"""The worker's credentials stay the worker's (#338 review).

In the Kubernetes executor the provisioning key used to arrive as an
environment variable, which every process the worker starts inherits: the
scanner, and through it nmap, naabu, httpx and nuclei — whose templates are
third-party content. And a Secret rotated under a running pod changed nothing
until somebody restarted it, because the key was read once, from the
environment, at start.

The key can now come from a file that is read again on every exchange, and the
scan subprocess is started without the worker's own variables.
"""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from typing import Any

from agent import worker


def _args(**overrides: Any) -> argparse.Namespace:
    base = {
        "api_url": "http://127.0.0.1:8080",
        "token": "",
        "timeout": 1.0,
        "provisioning_key": "",
        "provisioning_key_file": "",
        "jwt_refresh_seconds": 0,
        "agent_id": "shapoclyack-scanner-executor-0",
        "hostname": "edge-1",
        "label": None,
        "nats_url": "",
        "poll_interval": 0.01,
        "config": "scanner/config/default.yaml",
        "output_dir": "out",
        "scan_timeout": 1.0,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_a_rotated_key_file_is_used_on_the_next_exchange(monkeypatch, tmp_path):
    """What the kubelet does to a mounted Secret after an ExternalSecret
    refresh: the file changes under the running process. The next exchange —
    the refresh, or the one forced by the old key's revocation — has to send
    the new key, or the pod keeps presenting a revoked one until restarted."""
    key_file = tmp_path / "provisioning_key"
    key_file.write_text("key-one\n", encoding="utf-8")
    exchanges: list[str] = []
    beats = 0

    class _Client:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def set_token(self, token: str) -> None:
            pass

        def exchange_provisioning_key(self, provisioning_key: str, *, agent_id=None):
            exchanges.append(provisioning_key)
            # Rotated between the two exchanges, as the kubelet would.
            key_file.write_text("key-two\n", encoding="utf-8")
            return {
                "access_token": f"tok-{len(exchanges)}",
                "tenant_id": "default",
                "agent_id": agent_id,
                "expires_in": 3600,
            }

        def register(self, **kwargs: Any) -> dict[str, Any]:
            return {"agent_id": kwargs.get("agent_id"), "tenant_id": "default"}

        def heartbeat(self, agent_id: str, **kwargs: Any) -> dict[str, Any]:
            nonlocal beats
            beats += 1
            if beats == 1:
                # The old key was revoked, so the token minted from it is refused.
                raise worker.AgentTokenRejected("POST /api/agent/heartbeat -> 401: revoked")
            raise KeyboardInterrupt

        def claim(self, agent_id: str, **kwargs: Any) -> None:
            return None

    monkeypatch.setattr(worker, "AgentClient", _Client)
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: None)

    assert worker.run_loop(_args(provisioning_key_file=str(key_file))) == 0
    assert exchanges == ["key-one", "key-two"]


def test_a_key_file_alone_is_enough_to_start(monkeypatch, tmp_path):
    key_file = tmp_path / "provisioning_key"
    key_file.write_text("key-one", encoding="utf-8")
    monkeypatch.delenv("OCTO_AGENT_PROVISIONING_KEY", raising=False)
    monkeypatch.delenv("OCTO_AGENT_TOKEN", raising=False)
    monkeypatch.setenv("OCTO_AGENT_PROVISIONING_KEY_FILE", str(key_file))
    started: list[argparse.Namespace] = []
    monkeypatch.setattr(worker, "run_loop", lambda args: started.append(args) or 0)

    assert worker.main([]) == 0
    assert started and started[0].provisioning_key_file == str(key_file)


def test_the_scan_does_not_inherit_the_workers_credentials(monkeypatch, tmp_path):
    """The scanner and every tool under it get the environment the scan
    needs — the operator's NVD or HIBP key included — and not the worker's
    own: its enrollment key, its token, its broker credentials."""
    monkeypatch.setenv("OCTO_AGENT_PROVISIONING_KEY", "enrollment-key")
    monkeypatch.setenv("OCTO_AGENT_TOKEN", "legacy-token")
    monkeypatch.setenv("OCTO_AGENT_PROVISIONING_KEY_FILE", "/var/run/secrets/key")
    monkeypatch.setenv("OCTO_NATS_URL", "nats://agent:broker-password@nats:4222")
    monkeypatch.setenv("OCTO_NATS_TLS_KEY", "/etc/nats/tls.key")
    monkeypatch.setenv("NVD_API_KEY", "operator-nvd-key")
    seen: dict[str, Any] = {}

    class _Proc:
        pid = 4242
        returncode = 0

        def communicate(self, timeout=None):
            return "", ""

        def poll(self):
            return 0

    def fake_popen(command, **kwargs):
        seen.update(kwargs)
        return _Proc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    worker._run_scan(
        config=Path("scanner/config/default.yaml"),
        job={"job_id": "j1", "run_id": "r1", "inputs": {}},
        workdir=tmp_path,
        output_dir=tmp_path / "out",
        timeout=5.0,
    )

    env = seen.get("env")
    assert env is not None, "the scan inherits the worker's whole environment"
    leaked = sorted(k for k in env if k.startswith(("OCTO_AGENT_", "OCTO_NATS_")))
    assert not leaked, leaked
    assert env.get("NVD_API_KEY") == "operator-nvd-key"
    assert env.get("PATH")


def test_the_key_file_wins_over_the_environment(tmp_path):
    """The manifests set both while the pinned image predates the file
    (review round 2); a current worker must use the file, which is the one
    that follows a rotation."""
    key_file = tmp_path / "provisioning_key"
    key_file.write_text("from-file\n", encoding="utf-8")
    args = _args(provisioning_key="from-env", provisioning_key_file=str(key_file))
    assert worker._provisioning_key(args) == "from-file"
