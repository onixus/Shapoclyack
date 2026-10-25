#!/usr/bin/env python3
"""Provision an isolated, authenticated loopback operator development stand.

Secrets remain in chmod-600 ignored files. No secret value is printed and no
existing database, cluster, scan job or Docker volume is modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
PRIVATE = ROOT / ".operator-local"
COMPOSE = ROOT / "compose.operator-console.yml"
PROJECT = "shapo-operator-console"
URL = "http://127.0.0.1:8083"
IMAGES = ("sha256:d0c3811794d5e8ba0ab27e32705c34410ca7e6208c6a34d32a57a9ef6af387bf",
          "sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea")


def private_write(path, content):
    if path.is_symlink():
        raise SystemExit("Refusing symlink in private stand configuration")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(content)
    path.chmod(0o600)


def initialize():
    if PRIVATE.is_symlink():
        raise SystemExit("Refusing symlink for stand credentials directory")
    PRIVATE.mkdir(mode=0o700, exist_ok=True)
    PRIVATE.chmod(0o700)
    for directory in ("state", "output"):
        target = PRIVATE / directory
        if target.is_symlink():
            raise SystemExit("Refusing symlink for stand data")
        target.mkdir(mode=0o777, exist_ok=True)
        # The private parent stays 0700 on macOS; container UID 1000 receives
        # this directory alone, never credentials or its sibling database.
        target.chmod(0o777)
    postgres_data = PRIVATE / "postgres-data"
    if postgres_data.is_symlink():
        raise SystemExit("Refusing symlink for stand database")
    postgres_data.mkdir(mode=0o700, exist_ok=True)
    runtime_dir = PRIVATE / "runtime"
    if runtime_dir.is_symlink():
        raise SystemExit("Refusing symlink for runtime metadata")
    runtime_dir.mkdir(mode=0o755, exist_ok=True)
    runtime_dir.chmod(0o755)
    credentials_path = PRIVATE / "credentials"
    if credentials_path.is_symlink():
        raise SystemExit("Refusing symlink for stand credentials")
    if credentials_path.exists():
        credentials = json.loads(credentials_path.read_text())
        credentials_path.chmod(0o600)
    else:
        credentials = {"username": "operator-local", "password": secrets.token_urlsafe(32),
                       "postgres_password": secrets.token_hex(32), "jwt_secret": secrets.token_hex(32),
                       "master_key": secrets.token_hex(32)}
        private_write(credentials_path, json.dumps(credentials, indent=2) + "\n")
    postgres = {"POSTGRES_USER": "operator_console", "POSTGRES_DB": "operator_console",
                "POSTGRES_PASSWORD": credentials["postgres_password"]}
    config = {
        "OCTO_ENV": "dev", "OCTO_API_HOST": "0.0.0.0", "OCTO_API_PORT": "8080",
        "OCTO_OUTPUT_DIR": "/app/scanner/output", "OCTO_STATE_DIR": "/app/scanner/state",
        "OCTO_POSTGRES_URL": "postgresql+psycopg://operator_console:"
        + credentials["postgres_password"] + "@postgres:5432/operator_console",
        "OCTO_API_USERS": json.dumps([{"username": credentials["username"],
                                      "password": credentials["password"], "role": "admin"}]),
        "OCTO_JWT_SECRET": credentials["jwt_secret"], "OCTO_MASTER_KEY": credentials["master_key"],
        "OCTO_API_CORS": URL + ",http://localhost:8083", "OCTO_PUBLIC_BASE_URL": URL,
        "OCTO_REFRESH_COOKIE_SECURE": "false", "OCTO_WEB_DIST": "/app/web/dist",
        "OCTO_ALLOW_SCAN_START": "false", "OCTO_JOB_EXECUTION_MODE": "agent",
        "OCTO_OPERATOR_ENABLED": "true", "OCTO_OPERATOR_WORKER_ENABLED": "true",
        "OCTO_OPERATOR_PROVIDER": "local", "OCTO_OPERATOR_ALLOW_EXTERNAL": "false",
        "OCTO_OPERATOR_BASE_URL": "http://172.30.83.2:8082/v1",
        "OCTO_OPERATOR_MODEL": "Qwen3.5-9B-Q4_K_M", "OCTO_OPERATOR_MAX_OUTPUT_TOKENS": "512",
        "OCTO_OPERATOR_TIMEOUT_SECONDS": "120", "OCTO_OPERATOR_WORKER_LEASE_SECONDS": "180",
        "OCTO_OPERATOR_QUEUE_LIMIT": "5", "OCTO_MCP_ENABLED": "false",
        "OCTO_OPERATOR_EMBEDDINGS_ENABLED": "true",
        "OCTO_OPERATOR_EMBEDDINGS_BASE_URL": "http://172.30.83.5:8084/v1",
        "OCTO_OPERATOR_EMBEDDINGS_MODEL": "Qwen3-Embedding-0.6B",
        "OCTO_OPERATOR_EMBEDDINGS_REVISION": "370f27d7550e0def9b39c1f16d3fbaa13aa67728",
        "OCTO_OPERATOR_EMBEDDINGS_MODEL_SHA256": "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439",
        "OCTO_OPERATOR_EMBEDDINGS_DIMENSIONS": "1024",
    }
    runtime_record = PRIVATE / "runtime/verification.json"
    if runtime_record.is_file() and not runtime_record.is_symlink():
        config["OCTO_OPERATOR_RUNTIME_MANIFEST_PATH"] = "/run/operator/verification.json"
        config["OCTO_OPERATOR_RUNTIME_MANIFEST_SHA256"] = hashlib.sha256(runtime_record.read_bytes()).hexdigest()
    # Disable unrelated dispatchers; an unavailable model cannot launch scans,
    # mail, webhooks or tracker work in this demonstration database.
    for feature in ("NATS_OUTBOX", "CH_INGEST", "SCHEDULER_DISPATCH", "REPORT_DISPATCH", "REPORTS",
                    "SOFTWARE_MATCH", "RETRO_MATCH", "SLA_ESCALATION", "JOB_REAPER",
                    "RUN_PUBLICATION_WORKER", "WEBHOOKS", "WEBHOOK_DISPATCH", "WEBHOOK_FANOUT",
                    "TICKET_SYNC", "ENDPOINT_NATS_EVENTS", "NOTIFICATION_CHANNELS"):
        config["OCTO_" + feature + "_ENABLED"] = "false"
    private_write(PRIVATE / "postgres.env", "".join(f"{key}={value}\n" for key, value in postgres.items()))
    private_write(PRIVATE / "console.env", "".join(f"{key}={value}\n" for key, value in config.items()))
    return credentials


def compose(*args):
    return subprocess.run(["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), *args], cwd=ROOT, check=True)


def smoke():
    credentials = json.loads((PRIVATE / "credentials").read_text())
    payload = json.dumps({key: credentials[key] for key in ("username", "password")}).encode()
    request = urllib.request.Request(URL + "/api/auth/login", data=payload,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        token = json.load(response)["access_token"]
    request = urllib.request.Request(URL + "/api/operator/status?tenant_id=default",
                                     headers={"Authorization": "Bearer " + token})
    with urllib.request.urlopen(request, timeout=15) as response:
        status = json.load(response)
    with urllib.request.urlopen(URL + "/operator", timeout=15) as response:
        assert response.status == 200 and b"/_next/" in response.read()
    print(json.dumps({"console": URL + "/operator", "authenticated": True,
                      "provider": status["provider"], "model": status["model"],
                      "runtime_status": status["runtime_status"],
                      "task_submission_enabled": status["task_submission_enabled"],
                      "scan_dispatch_enabled": False, "quality_status": status["quality_status"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("init", "up", "down", "ps", "smoke"), default="up", nargs="?")
    args = parser.parse_args()
    if args.action in {"init", "up"}:
        initialize()
    if args.action == "init":
        print("Private stand configuration created; secret values were not printed.")
    elif args.action == "up":
        if not (ROOT / "web-next/out/operator.html").is_file():
            raise SystemExit("Build web-next before starting this development stand")
        for image in IMAGES:
            subprocess.run(["docker", "image", "inspect", image], check=True, stdout=subprocess.DEVNULL)
        network = json.loads(subprocess.check_output(["docker", "network", "inspect", "shapo-operator-offline"]))[0]
        if not network.get("Internal") or not any(entry.get("Subnet") == "172.30.83.0/24"
                                                   for entry in network["IPAM"]["Config"]):
            raise SystemExit("Inference network must be internal with the documented private subnet")
        compose("up", "-d", "--pull", "never")
        for _ in range(30):
            try:
                with urllib.request.urlopen(URL + "/api/health", timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(1)
        smoke()
    elif args.action in {"down", "ps"}:
        compose(args.action)
    else:
        smoke()


if __name__ == "__main__":
    main()
