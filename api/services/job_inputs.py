"""Materialization and cleanup of per-job scanner inputs.

Queue persistence and execution do not need to know how target files, scope,
policy snapshots or local wordlists are laid out. This module owns that
filesystem/object-store boundary.
"""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from api.schemas import StartScanRequest
from api.services import artifact_store
from api.services import scan_scopes
from api.services import wordlists as wordlists_service
from api.services.targets import parse_target_payload
from api.settings import Settings

_log = logging.getLogger(__name__)

SCAN_SCOPE_INPUT = "scan_scope.json"
PROMOTED_DOMAINS_INPUT = "promoted_domains.txt"
SCAN_POLICY_INPUT = "scan_policy.json"
JOB_INPUT_FILES = (
    "ranges.txt",
    "domains.txt",
    "ports.txt",
    "ports_udp.txt",
    SCAN_SCOPE_INPUT,
    PROMOTED_DOMAINS_INPUT,
    SCAN_POLICY_INPUT,
)


def _write_lines(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(lines)
    if body:
        body += "\n"
    path.write_text(body, encoding="utf-8")


def job_inputs_dir(settings: Settings, job_id: str) -> Path:
    return settings.state_dir / "job_inputs" / job_id


def prepare_target_inputs(
    settings: Settings,
    job_id: str,
    request: StartScanRequest,
    *,
    tenant_id: str,
    promoted: list[str] | None = None,
    scope: scan_scopes.ScanScope | None = None,
    policy: dict[str, Any] | None = None,
) -> tuple[Path | None, dict[str, int] | None, list[str]]:
    """Write target, scope and policy files for one admitted job."""
    if scope is None:
        scope = scan_scopes.load_scope(settings, tenant_id)
    parsed = parse_target_payload(
        scope=scope,
        ranges_text=request.ranges,
        domains_text=request.domains,
        ports_text=request.ports,
        ports_udp_text=request.ports_udp,
    )

    inputs_dir = job_inputs_dir(settings, job_id)
    inputs_dir.mkdir(parents=True, exist_ok=True)
    scope_path = inputs_dir / SCAN_SCOPE_INPUT
    scope_path.write_text(
        json.dumps(scope.to_document(), indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    extra: list[str] = ["--scan-scope", str(scope_path)]
    counts: dict[str, int] = {}

    if policy is not None:
        extra.extend(["--scan-policy", str(_write_policy_input(inputs_dir, policy))])

    if promoted:
        promoted_path = inputs_dir / PROMOTED_DOMAINS_INPUT
        _write_lines(promoted_path, promoted)
        extra.extend(["--promoted-domains", str(promoted_path)])
        counts["promoted_domains"] = len(promoted)

    if parsed is None:
        return inputs_dir, counts or None, extra

    if parsed.ranges is not None and parsed.domains is not None:
        ranges_path = inputs_dir / "ranges.txt"
        domains_path = inputs_dir / "domains.txt"
        _write_lines(ranges_path, parsed.ranges)
        _write_lines(domains_path, parsed.domains)
        extra.extend(["--ranges", str(ranges_path), "--domains", str(domains_path)])
        counts["ranges"] = len(parsed.ranges)
        counts["domains"] = len(parsed.domains)

    if parsed.ports is not None:
        ports_path = inputs_dir / "ports.txt"
        _write_lines(ports_path, parsed.ports)
        extra.extend(["--ports-file", str(ports_path)])
        counts["ports"] = len(parsed.ports)

    if parsed.ports_udp is not None:
        ports_udp_path = inputs_dir / "ports_udp.txt"
        _write_lines(ports_udp_path, parsed.ports_udp)
        extra.extend(["--ports-udp-file", str(ports_udp_path)])
        counts["ports_udp"] = len(parsed.ports_udp)

    return inputs_dir, counts or None, extra


def _write_policy_input(inputs_dir: Path, policy: dict[str, Any]) -> Path:
    inputs_dir.mkdir(parents=True, exist_ok=True)
    path = inputs_dir / SCAN_POLICY_INPUT
    path.write_text(
        json.dumps(policy, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def publish(settings: Settings, job_id: str) -> None:
    """Mirror job inputs to remote artifact storage when configured."""
    if not artifact_store.is_remote(settings):
        return
    directory = job_inputs_dir(settings, job_id)
    if not directory.is_dir():
        return
    artifact_store.get_store(settings).upload_tree(
        artifact_store.keys.job_inputs_prefix(job_id), directory
    )


def ensure_local(settings: Settings, job_id: str) -> Path:
    """Materialize remote job inputs on this replica if needed."""
    directory = job_inputs_dir(settings, job_id)
    if directory.is_dir() or not artifact_store.is_remote(settings):
        return directory
    try:
        artifact_store.get_store(settings).download_tree(
            artifact_store.keys.job_inputs_prefix(job_id), directory
        )
    except artifact_store.ArtifactStoreError:
        _log.warning("Could not fetch the input files for job %s", job_id, exc_info=True)
    return directory


def discard(settings: Settings, job_id: str) -> None:
    """Best-effort removal of job-scoped input material."""
    if artifact_store.is_remote(settings):
        try:
            artifact_store.get_store(settings).delete_prefix(
                artifact_store.keys.job_inputs_prefix(job_id)
            )
        except artifact_store.ArtifactStoreError:
            _log.warning("Could not remove stored inputs for job %s", job_id, exc_info=True)
    try:
        shutil.rmtree(job_inputs_dir(settings, job_id), ignore_errors=False)
    except FileNotFoundError:
        pass
    except OSError:
        _log.warning("Could not remove input files for job %s", job_id, exc_info=True)


def wordlist_file_for_job(settings: Settings, job_id: str) -> Path:
    return settings.state_dir / "wordlists" / f"{job_id}.txt"


def discard_wordlist(settings: Settings, job_id: str) -> None:
    try:
        wordlist_file_for_job(settings, job_id).unlink(missing_ok=True)
    except OSError:
        _log.warning("Could not remove wordlist scratch file for job %s", job_id, exc_info=True)


def wordlist_overrides(
    settings: Settings, job_id: str, tenant_id: str, wordlist_id: str | None
) -> tuple[dict, dict] | None:
    """Materialize a selected tenant wordlist and return config/provenance."""
    if not wordlist_id:
        return None
    resolved = wordlists_service.get_for_scan(wordlist_id, tenant_id=tenant_id)
    if resolved is None:
        raise ValueError(f"Unknown wordlist_id: {wordlist_id}")

    dest = wordlist_file_for_job(settings, job_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(resolved.content + "\n", encoding="utf-8")
    path = str(dest)

    if resolved.kind == "bucket":
        stage = {"cloud": {"enabled": True, "wordlist_file": path}}
    else:
        stage = {
            "ct": {
                "enabled": True,
                "brute_force": {"enabled": True, "wordlist_file": path},
            }
        }
    provenance = {
        "wordlist_id": wordlist_id,
        "wordlist_name": resolved.name,
        "wordlist_kind": resolved.kind,
        "wordlist_sha256": resolved.sha256,
        "wordlist_entries": resolved.line_count,
    }
    return {"discovery": stage}, provenance
