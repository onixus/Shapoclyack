from __future__ import annotations

import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any


def setup_logging(log_file: Path, max_bytes: int = 10_485_760, backup_count: int = 5) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    stream_handler = logging.StreamHandler()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[file_handler, stream_handler],
    )


def load_yaml(path: Path) -> dict[str, Any]:
    import yaml

    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def run_command(
    command: list[str],
    timeout: int,
    retries: int,
    check: bool = True,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    last_exc: Exception | None = None
    for attempt in range(1, retries + 2):
        try:
            logging.info("Running command (attempt %s): %s", attempt, " ".join(map(shlex.quote, command)))
            completed = subprocess.run(
                command,
                text=True,
                capture_output=capture_output,
                timeout=timeout,
                check=check,
            )
            if capture_output:
                if completed.stdout and completed.stdout.strip():
                    logging.info("stdout: %s", completed.stdout.strip()[:1000])
                if completed.stderr and completed.stderr.strip():
                    logging.info("stderr: %s", completed.stderr.strip()[:1000])
            return completed
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            logging.warning("Command failed on attempt %s: %s", attempt, exc)
            if attempt <= retries:
                time.sleep(min(2 * attempt, 10))
    assert last_exc is not None
    raise last_exc


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    values: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        values.append(line)
    return values


def write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    unique = sorted(set(lines))
    path.write_text("\n".join(unique) + ("\n" if unique else ""), encoding="utf-8")


def is_ip_or_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False


_FQDN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def is_fqdn(value: str) -> bool:
    if is_ip_or_cidr(value):
        return False
    return bool(_FQDN_RE.match(value))


def load_json(path: Path, fallback: Any) -> Any:
    if not path.exists():
        return fallback
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
