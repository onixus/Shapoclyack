#!/usr/bin/env python3
"""Install the published Shapoclyack appliance; Python standard library only."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from urllib.parse import urlsplit

DEFAULT_IMAGE = (
    "ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.46-0922"
    "@sha256:40a7312b39b46d2fce7e529a2ce7003834b32f880f8579ffff5850c5e2b0b161"
)
# The database is pinned the same way as the application (#313): a tag alone
# lets the next `compose pull` start a Postgres nobody tested this with. One
# line, so Renovate's regex manager can propose the refresh.
POSTGRES_IMAGE = "postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea"


def origin(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.path not in ("", "/")
            or parsed.query or parsed.fragment
            or not re.fullmatch(r"https://[A-Za-z0-9.:[\]-]+/?", value)):
        raise argparse.ArgumentTypeError("Use an HTTPS origin, e.g. https://scan.example.com")
    try:
        parsed.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    return value.rstrip("/")


def image_ref(value: str) -> str:
    if not re.fullmatch(r"[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}", value):
        raise argparse.ArgumentTypeError("Image must be pinned as registry/image:tag@sha256:<64 hex digits>")
    return value


def manifest(image: str, url: str, port: int, password: str) -> dict:
    db_password = secrets.token_hex(32)
    log = {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}}
    return {
        "services": {
            "postgres": {
                "image": POSTGRES_IMAGE, "restart": "unless-stopped",
                "environment": {"POSTGRES_DB": "shapoclyack", "POSTGRES_USER": "octo",
                                "POSTGRES_PASSWORD": db_password},
                "volumes": ["postgres:/var/lib/postgresql/data"],
                "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U octo -d shapoclyack"],
                                "interval": "5s", "timeout": "5s", "retries": 30},
                "logging": log,
            },
            "api": {
                "image": image, "restart": "unless-stopped", "init": True,
                "ports": [f"127.0.0.1:{port}:8080"],
                "cap_drop": ["ALL"], "cap_add": ["NET_RAW", "NET_ADMIN"],
                "environment": {
                    "OCTO_ENV": "prod", "OCTO_PUBLIC_BASE_URL": url, "OCTO_API_CORS": url,
                    "OCTO_JWT_SECRET": secrets.token_hex(32),
                    "OCTO_MASTER_KEY": secrets.token_hex(32),
                    "OCTO_API_USERS": json.dumps([
                        {"username": "admin", "password": password, "role": "admin"}
                    ]),
                    "OCTO_POSTGRES_URL": f"postgresql+psycopg://octo:{db_password}@postgres:5432/shapoclyack",
                    "OCTO_ALLOW_SCAN_START": "true", "OCTO_JOB_EXECUTION_MODE": "local",
                    # Same synchronous result path as the default Kubernetes installation.
                    "OCTO_NATS_URL": "", "OCTO_CLICKHOUSE_URL": "",
                },
                "volumes": ["output:/app/scanner/output", "state:/app/scanner/state",
                            "config:/app/scanner/config", "inputs:/app/scanner/inputs"],
                "depends_on": {"postgres": {"condition": "service_healthy"}},
                "healthcheck": {
                    "test": ["CMD", "python", "-c",
                             "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=4)"],
                    "interval": "10s", "timeout": "5s", "start_period": "60s", "retries": 18,
                },
                "stop_grace_period": "60s", "logging": log,
            },
        },
        "volumes": {name: {} for name in ("postgres", "output", "state", "config", "inputs")},
    }


def write_private(path: Path, data: str) -> None:
    # Exclusive creation: never overwrite an existing installation's keys.
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(data)


def prepare(directory: Path, args: argparse.Namespace) -> None:
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("Installation directory must be empty; use start for an existing installation")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    password = secrets.token_hex(16)
    config = manifest(args.image, args.url, args.port, password)
    # Random, persisted project ID prevents volume collisions between installations.
    config["name"] = "shapoclyack-" + secrets.token_hex(6)
    write_private(directory / "compose.json", json.dumps(config, indent=2) + "\n")
    write_private(directory / "access.json", json.dumps(
        {"url": args.url, "username": "admin", "password": password}, indent=2) + "\n")
    print(f"Configuration: {directory / 'compose.json'}")
    print(f"Initial credentials: {directory / 'access.json'} (not printed to logs)")


def compose(directory: Path, *args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "--project-directory", str(directory),
         "-f", str(directory / "compose.json"), *args], check=True, **kwargs,
    )


def preflight(directory: Path) -> None:
    if not (directory / "compose.json").is_file():
        raise ValueError("No installation found. Run prepare or install first.")
    subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL)
    compose(directory, "config", "--quiet")
    for command in ("up", "run"):
        help_text = compose(directory, command, "--help", capture_output=True, text=True).stdout
        required = "--wait" if command == "up" else "--pull"
        if required not in help_text:
            raise ValueError("Docker Compose v2 with up --wait and run --pull is required")


def backup(directory: Path) -> Path:
    backups = directory / "backups"
    backups.mkdir(exist_ok=True, mode=0o700)
    target = backups / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
                        + "-" + secrets.token_hex(3) + ".dump")
    try:
        with target.open("xb") as stream:
            compose(directory, "exec", "-T", "postgres", "pg_dump", "-U", "octo",
                    "-d", "shapoclyack", "-Fc", stdout=stream)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    print(f"PostgreSQL backup: {target}")
    return target


def start(directory: Path, timeout: int) -> None:
    # Pull failures must leave the existing application running.
    compose(directory, "pull")
    compose(directory, "up", "-d", "--no-build", "--wait", "--wait-timeout", str(timeout), "postgres")
    compose(directory, "stop", "api")
    backup(directory)
    # Explicit migration on every start, protected by the application's DB lock.
    # A failure leaves the API stopped and the backup available for recovery.
    compose(directory, "run", "--rm", "--no-deps", "--pull", "never", "api",
            "python", "-m", "api.db.migrate")
    compose(directory, "up", "-d", "--no-build", "--wait", "--wait-timeout", str(timeout), "api")
    print("Ready. Configure your HTTPS reverse proxy to the loopback port in compose.json.")
    print("Sign in using access.json, change the password, and approve the tenant scanning scope.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "install", "start", "status", "logs", "stop", "backup"])
    parser.add_argument("--directory", type=Path, default=Path("/opt/shapoclyack"))
    parser.add_argument("--url", type=origin, help="Public HTTPS origin (TLS reverse proxy required)")
    parser.add_argument("--image", type=image_ref, default=DEFAULT_IMAGE)
    parser.add_argument("--port", type=int, default=8080, help="Loopback HTTP port")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)
    if args.command in ("prepare", "install") and not args.url:
        parser.error("--url is required for prepare/install")
    if not 1 <= args.port <= 65535 or args.timeout <= 0:
        parser.error("Port must be 1..65535 and timeout must be positive")
    os.umask(0o077)
    directory = args.directory.expanduser().resolve()
    try:
        if args.command in ("prepare", "install"):
            prepare(directory, args)
        if args.command == "prepare":
            return 0
        preflight(directory)
        # Read-only inspection remains available during a slow migration/start.
        if args.command == "status":
            compose(directory, "ps")
        elif args.command == "logs":
            compose(directory, "logs", "--tail", "100", "-f")
        else:
            with (directory / ".installer.lock").open("a") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise ValueError("Another installer operation is already running") from exc
                if args.command in ("install", "start"):
                    start(directory, args.timeout)
                elif args.command == "backup":
                    backup(directory)
                elif args.command == "stop":
                    compose(directory, "stop")
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Installation failed: {exc}\nConfiguration and data are retained in {directory}. "
              "After fixing the cause, use start; inspect logs for startup errors.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
