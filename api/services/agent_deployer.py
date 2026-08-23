"""UI-Driven Remote SSH Agent Deployer Service.

Allows operators to remotely push and install the Shapoclyack Agent onto
Linux target hosts via SSH directly from the Web UI.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from api.schemas import AgentDeploySSHRequest, AgentDeployStatusResponse
from api.services import agents as agents_service
from api.services import tenants as tenants_service

LOG = logging.getLogger("shapoclyack.agent-deployer")

# In-memory registry of deployment runs: deploy_id -> run dict
_deployments: dict[str, dict[str, Any]] = {}
_deployments_lock = threading.Lock()
_MAX_HISTORY = 100


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def get_deployment_status(deploy_id: str) -> AgentDeployStatusResponse | None:
    with _deployments_lock:
        data = _deployments.get(deploy_id)
        if not data:
            return None
        return AgentDeployStatusResponse(
            deploy_id=deploy_id,
            status=data["status"],
            stage=data["stage"],
            progress_percent=data["progress_percent"],
            logs=list(data["logs"]),
            agent_id=data.get("agent_id"),
            error=data.get("error"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
        )


def _append_log(deploy_id: str, message: str) -> None:
    timestamp = datetime.now(UTC).strftime("%H:%M:%S")
    formatted = f"[{timestamp}] {message}"
    with _deployments_lock:
        if deploy_id in _deployments:
            _deployments[deploy_id]["logs"].append(formatted)


def _update_stage(
    deploy_id: str,
    *,
    status: str | None = None,
    stage: str | None = None,
    progress_percent: int | None = None,
    error: str | None = None,
    agent_id: str | None = None,
) -> None:
    with _deployments_lock:
        if deploy_id in _deployments:
            entry = _deployments[deploy_id]
            if status:
                entry["status"] = status
            if stage:
                entry["stage"] = stage
            if progress_percent is not None:
                entry["progress_percent"] = progress_percent
            if error:
                entry["error"] = error
            if agent_id:
                entry["agent_id"] = agent_id
            if status in ("completed", "failed"):
                entry["completed_at"] = _now_iso()


def _execute_ssh_command(
    req: AgentDeploySSHRequest,
    command: str,
    *,
    timeout: int = 120,
) -> tuple[int, str, str]:
    """Execute a remote shell command via Paramiko (if available) or OpenSSH CLI fallback."""
    # Attempt paramiko first
    try:
        import io
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        pkey = None
        if req.private_key and req.private_key.strip():
            key_str = req.private_key.strip()
            key_file = io.StringIO(key_str)
            for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
                try:
                    key_file.seek(0)
                    pkey = key_cls.from_private_key(key_file)
                    break
                except Exception:
                    continue

        client.connect(
            hostname=req.host,
            port=req.port,
            username=req.username,
            password=req.password,
            pkey=pkey,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        client.close()
        return exit_code, out, err
    except ImportError:
        pass
    except Exception as exc:
        return 1, "", f"Paramiko SSH failed: {exc}"

    # Fallback to OpenSSH CLI
    key_file_path = None
    try:
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=15",
            "-p", str(req.port),
        ]
        if req.private_key and req.private_key.strip():
            fd, key_file_path = tempfile.mkstemp(prefix="ssh_key_")
            with os.fdopen(fd, "w") as f:
                f.write(req.private_key.strip() + "\n")
            os.chmod(key_file_path, 0o600)
            cmd.extend(["-i", key_file_path])

        target = f"{req.username}@{req.host}"
        cmd.append(target)
        cmd.append(command)

        # If password is provided and sshpass exists
        if req.password and shutil.which("sshpass"):
            cmd = ["sshpass", "-p", req.password] + cmd

        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        return res.returncode, res.stdout, res.stderr
    finally:
        if key_file_path and os.path.exists(key_file_path):
            with contextlib.suppress(OSError):
                os.remove(key_file_path)


def _deploy_worker(deploy_id: str, req: AgentDeploySSHRequest, server_url: str) -> None:
    try:
        _update_stage(deploy_id, status="connecting", stage="Connecting to remote host", progress_percent=15)
        _append_log(deploy_id, f"Initiating SSH connection to {req.username}@{req.host}:{req.port}...")

        # Test remote connectivity
        code, out, err = _execute_ssh_command(req, "uname -s -m && id -u", timeout=20)
        if code != 0:
            err_msg = f"SSH connection failed (exit code {code}): {err.strip() or out.strip()}"
            _append_log(deploy_id, f"[ERROR] {err_msg}")
            _update_stage(deploy_id, status="failed", stage="Connection failed", error=err_msg)
            return

        remote_info = out.strip().replace("\n", " ")
        _append_log(deploy_id, f"Connected to host successfully: {remote_info}")

        # Provisioning Key
        _update_stage(deploy_id, status="installing", stage="Minting provisioning credentials", progress_percent=30)
        _append_log(deploy_id, f"Generating provisioning key for tenant '{req.tenant_id}'...")
        key_res = tenants_service.create_provisioning_key(
            tenant_id=req.tenant_id,
            label=f"SSH Remote Deploy on {req.host}",
        )
        provisioning_key = key_res["key"]
        agent_id = req.agent_id or f"agent-{req.host.replace('.', '-').replace(':', '-')}-{uuid.uuid4().hex[:6]}"
        _append_log(deploy_id, f"Provisioned agent_id: {agent_id}")

        # Run remote installer
        _update_stage(deploy_id, status="installing", stage="Running remote agent installation", progress_percent=55)
        clean_server = server_url.rstrip("/")
        install_url = f"{clean_server}/api/agent/install.sh"
        _append_log(deploy_id, f"Fetching installer script from {install_url}...")

        sudo_prefix = "sudo " if req.username != "root" else ""
        docker_flag = "--docker " if req.use_docker else ""
        install_cmd = (
            f"curl -sSL {install_url} | {sudo_prefix}bash -s -- "
            f"--server {clean_server} "
            f"--key {provisioning_key} "
            f"--tenant {req.tenant_id} "
            f"--agent-id {agent_id} "
            f"{docker_flag}"
        )

        _append_log(deploy_id, "Executing installation payload on remote host...")
        code, out, err = _execute_ssh_command(req, install_cmd, timeout=300)

        # Log lines from remote output
        for line in out.splitlines():
            if line.strip():
                _append_log(deploy_id, f"[REMOTE] {line.strip()}")
        for line in err.splitlines():
            if line.strip():
                _append_log(deploy_id, f"[REMOTE ERR] {line.strip()}")

        if code != 0:
            err_msg = f"Remote installer exited with code {code}"
            _append_log(deploy_id, f"[ERROR] {err_msg}")
            _update_stage(deploy_id, status="failed", stage="Installation failed", error=err_msg)
            return

        # Verification step
        _update_stage(deploy_id, status="verifying", stage="Verifying agent heartbeat registration", progress_percent=85)
        _append_log(deploy_id, f"Waiting for agent {agent_id} to send initial heartbeat...")

        registered = False
        for _ in range(15):
            time.sleep(2)
            info = agents_service.get_agent(agent_id, tenant_id=req.tenant_id)
            if info and info.online:
                registered = True
                _append_log(deploy_id, f"Agent {agent_id} is ONLINE! Version: {info.version}, Hostname: {info.hostname}")
                break

        if not registered:
            _append_log(deploy_id, "[WARN] Agent service started, but heartbeat verification timed out (agent may take a moment).")

        _update_stage(
            deploy_id,
            status="completed",
            stage="Deployment successfully completed",
            progress_percent=100,
            agent_id=agent_id,
        )
        _append_log(deploy_id, f"Deployment completed successfully for agent {agent_id}.")

    except Exception as exc:
        LOG.exception("Unexpected error in agent SSH deployer")
        err_msg = f"Unexpected deployment error: {exc}"
        _append_log(deploy_id, f"[FATAL] {err_msg}")
        _update_stage(deploy_id, status="failed", stage="Fatal error", error=err_msg)


def start_ssh_deployment(req: AgentDeploySSHRequest, server_url: str) -> str:
    """Queue and start an asynchronous SSH push deployment."""
    deploy_id = f"dep_{uuid.uuid4().hex[:12]}"
    now_str = _now_iso()

    with _deployments_lock:
        if len(_deployments) > _MAX_HISTORY:
            # Drop oldest entry
            oldest_key = next(iter(_deployments))
            _deployments.pop(oldest_key, None)

        _deployments[deploy_id] = {
            "deploy_id": deploy_id,
            "status": "queued",
            "stage": "Queued for deployment",
            "progress_percent": 5,
            "logs": [f"[{datetime.now(UTC).strftime('%H:%M:%S')}] Deployment initialized for target {req.host}"],
            "agent_id": req.agent_id,
            "error": None,
            "started_at": now_str,
            "completed_at": None,
        }

    thread = threading.Thread(
        target=_deploy_worker,
        args=(deploy_id, req, server_url),
        daemon=True,
        name=f"agent-deploy-{deploy_id}",
    )
    thread.start()
    return deploy_id
