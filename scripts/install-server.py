#!/usr/bin/env python3
"""Install the published Shapoclyack appliance; Python standard library only."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
from urllib.parse import urlsplit

DEFAULT_IMAGE = (
    "ghcr.io/onixus/shapoclyack-aio:shapoclyack-0.48-1021"
    "@sha256:70ac7f954fa68de9c99025cc584817fc35db71fd1f4dc6c4a7118066c66d10d4"
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


BDU_MOUNT = "/var/lib/shapoclyack/bdu"
BDU_FILES = ("bdu-overlay.json", "threats-overlay.json")


def resolve_bdu(path: Path | None) -> Path | None:
    """Absolute host directory that already holds both overlays.

    install does not fetch the catalogues. The compose file bind-mounts this
    directory, so the files remain after the container is recreated.
    """
    if not path:
        return None
    resolved = Path(path).expanduser().resolve()
    missing = [name for name in BDU_FILES if not (resolved / name).is_file()]
    if missing:
        raise ValueError(f"{resolved} must already contain {', '.join(BDU_FILES)}")
    return resolved


def manifest(
    image: str,
    url: str,
    port: int,
    password: str,
    *,
    bdu_host: Path | None = None,
) -> dict:
    db_password = secrets.token_hex(32)
    log = {"driver": "json-file", "options": {"max-size": "10m", "max-file": "3"}}
    api_env = {
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
    }
    volumes = ["output:/app/scanner/output", "state:/app/scanner/state",
               "config:/app/scanner/config", "inputs:/app/scanner/inputs"]
    vol_names = ["postgres", "output", "state", "config", "inputs"]

    if bdu_host is not None:
        api_env["OCTO_BDU_FSTEC_DATABASE"] = f"{BDU_MOUNT}/bdu-overlay.json"
        api_env["OCTO_BDU_THREATS_DATABASE"] = f"{BDU_MOUNT}/threats-overlay.json"
        volumes.append(f"{bdu_host}:{BDU_MOUNT}:ro")

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
                "environment": api_env,
                "volumes": volumes,
                "depends_on": {"postgres": {"condition": "service_healthy"}},
                "healthcheck": {
                    "test": ["CMD", "python", "-c",
                             "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/readyz', timeout=4)"],
                    "interval": "10s", "timeout": "5s", "start_period": "60s", "retries": 18,
                },
                "stop_grace_period": "60s", "logging": log,
            },
        },
        "volumes": {name: {} for name in vol_names},
    }


def write_private(path: Path, data: str) -> None:
    # Exclusive creation: never overwrite an existing installation's keys.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(data)


def _name_window(preview: list[str], name: str) -> None:
    """Keep the five lexicographically first names, independent of readdir order."""
    if len(preview) < 5:
        preview.append(name)
    elif name < preview[-1]:
        preview[-1] = name
    else:
        return
    preview.sort()


def _occupancy(directory: Path) -> tuple[int, list[str]] | None:
    """Entries already in directory, or None when it is missing or empty."""
    if not directory.exists():
        return None
    preview: list[str] = []
    total = 0
    try:
        for item in directory.iterdir():
            total += 1
            _name_window(preview, item.name)
    except FileNotFoundError:
        if total == 0:
            return None
    if total == 0 or not directory.exists():
        return None
    return total, preview


def _occupied_message(directory: Path, total: int, preview: list[str]) -> str:
    shown = ", ".join(repr(name) for name in preview)
    if total > len(preview):
        shown += ", ..."
    quoted_dir = shlex.quote(str(directory))
    script = shlex.quote(str(Path(__file__).resolve()))
    has_compose = (directory / "compose.json").is_file()
    has_access = (directory / "access.json").is_file()
    lines = [
        (
            f"Installation directory {quoted_dir} already exists and is not empty "
            f"({total} entries; compose.json: {'yes' if has_compose else 'no'}; "
            f"access.json: {'yes' if has_access else 'no'}; names: {shown})."
        ),
        "To start the existing installation, run:",
        f"  python3 {script} start --directory {quoted_dir}",
    ]
    if has_compose:
        compose = shlex.quote(str(directory / "compose.json"))
        lines.extend([
            (
                "Deleting this directory does not stop containers or remove named "
                "volumes. It destroys compose.json (the project name and keys) and "
                "backups stored here, after which start and stop can no longer see "
                "this installation."
            ),
            "A full wipe, only while compose.json still exists, destroys the database:",
            f"  docker compose --project-directory {quoted_dir} -f {compose} down -v",
            "Then remove the directory:",
            f"  rm -rf {quoted_dir}",
        ])
    else:
        lines.append(
            "Choose an empty directory. This path has no compose.json, so it is not "
            "an installation and must not be deleted in order to reinstall."
        )
    return "\n".join(lines)


def prepare(directory: Path, args: argparse.Namespace) -> None:
    occupied = _occupancy(directory)
    if occupied is not None:
        raise ValueError(_occupied_message(directory, *occupied))
    bdu_host = resolve_bdu(getattr(args, "bdu", None))
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    password = secrets.token_hex(16)
    config = manifest(args.image, args.url, args.port, password, bdu_host=bdu_host)
    # Random, persisted project ID prevents volume collisions between installations.
    config["name"] = "shapoclyack-" + secrets.token_hex(6)
    write_private(directory / "compose.json", json.dumps(config, indent=2) + "\n")
    write_private(directory / "access.json", json.dumps(
        {"url": args.url, "username": "admin", "password": password}, indent=2) + "\n")
    print(f"Configuration: {directory / 'compose.json'}")
    print(f"Initial credentials: {directory / 'access.json'} (not printed to logs)")
    if bdu_host is not None:
        print(f"BDU catalogues mounted from {bdu_host}. install does not download them.")


def compose(directory: Path, *args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "--project-directory", str(directory),
         "-f", str(directory / "compose.json"), *args], check=True, **kwargs,
    )


def preflight(directory: Path, *, starting: bool = False) -> None:
    if not (directory / "compose.json").is_file():
        raise ValueError("No installation found. Run prepare or install first.")
    subprocess.run(["docker", "info"], check=True, stdout=subprocess.DEVNULL)
    compose(directory, "config", "--quiet")
    if not starting:
        return
    for command in ("up", "run"):
        help_text = compose(directory, command, "--help", capture_output=True, text=True).stdout
        required = "--wait" if command == "up" else "--pull"
        if required not in help_text:
            raise ValueError("Docker Compose v2 with up --wait and run --pull is required")


@contextmanager
def operation_lock(directory: Path):
    """Serialize operations that change containers or create a backup."""
    with (directory / ".installer.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("Another installer operation is already running") from exc
        yield


def backup(directory: Path) -> Path:
    backups = directory / "backups"
    backups.mkdir(exist_ok=True, mode=0o700)
    target = backups / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
                        + "-" + secrets.token_hex(3) + ".dump")
    # Failed exclusive creation must not remove somebody else's dump.
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
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
    parser.add_argument(
        "--bdu",
        type=Path,
        metavar="DIR",
        help=(
            "Host directory that already holds bdu-overlay.json and threats-overlay.json. "
            "Mounted read-only into the API container. Does not download the catalogues "
            "or enable a feed refresh."
        ),
    )
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
        preflight(directory, starting=args.command in ("install", "start"))
        # Read-only inspection remains available during a slow migration/start.
        if args.command == "status":
            compose(directory, "ps")
        elif args.command == "logs":
            compose(directory, "logs", "--tail", "100", "-f")
        else:
            with operation_lock(directory):
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
