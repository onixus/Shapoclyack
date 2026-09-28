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

from api.services import artifact_store
from api.services import scan_scopes
from api.services.targets import ParsedTargets
from api.services import wordlists as wordlists_service
from api.settings import Settings
from scanner.pipeline import config_overlay

_log = logging.getLogger(__name__)

SCAN_SCOPE_INPUT = "scan_scope.json"
PROMOTED_DOMAINS_INPUT = "promoted_domains.txt"
SCAN_POLICY_INPUT = "scan_policy.json"
CONFIG_OVERLAY_INPUT = config_overlay.INPUT_NAME
JOB_INPUT_FILES = (
    "ranges.txt",
    "domains.txt",
    "ports.txt",
    "ports_udp.txt",
    SCAN_SCOPE_INPUT,
    PROMOTED_DOMAINS_INPUT,
    SCAN_POLICY_INPUT,
    CONFIG_OVERLAY_INPUT,
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
    *,
    tenant_id: str,
    parsed: ParsedTargets | None,
    promoted: list[str] | None = None,
    scope: scan_scopes.ScanScope | None = None,
    policy: dict[str, Any] | None = None,
) -> tuple[Path | None, dict[str, int] | None, list[str]]:
    """Write target, scope and policy files for one already-admitted job.

    Returns (inputs_dir, target_counts, extra_cli_args).

    Takes the parsed targets rather than the request: deciding whether a
    target is well-formed and in scope is admission's job (scan_admission,
    the first of the two #226 barriers), and doing it here would mean a
    refusal had already created this job's scratch directory.

    The scope document is written for *every* job, including one that carries
    no target overrides at all (#244). That is the case the API cannot check
    any other way: such a run reads the installation's own target files, which
    the API never opens, so the only thing #226 could ask was whether the
    tenant had a scope — not whether the files agree with it. The scanner
    opens them, and now has the scope in hand when it does.
    """
    if scope is None:
        scope = scan_scopes.load_scope(settings, tenant_id)

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
        # Written for the local runner and read back for the agent's claim
        # response by ``job_control._read_job_inputs``, so both executors are
        # handed the same document by the same mechanism — a policy only one
        # of the two paths applied would be a ceiling that depends on where
        # the scan happened to run.
        extra.extend(["--scan-policy", str(write_policy_input(inputs_dir, policy))])

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


def write_policy_input(inputs_dir: Path, policy: dict[str, Any]) -> Path:
    inputs_dir.mkdir(parents=True, exist_ok=True)
    path = inputs_dir / SCAN_POLICY_INPUT
    path.write_text(
        json.dumps(policy, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def write_config_overlay_input(
    settings: Settings, job_id: str, overlay: dict[str, Any]
) -> list[str]:
    """Write the agent job's config overlay; return the scanner arguments.

    ``to_document`` checks every path against the scanner's own allow-list, so
    a setting an executor would refuse fails this request rather than the
    scan, on a host the operator may not be able to read the log of.
    """
    document = config_overlay.to_document(overlay)
    inputs_dir = job_inputs_dir(settings, job_id)
    inputs_dir.mkdir(parents=True, exist_ok=True)
    path = inputs_dir / CONFIG_OVERLAY_INPUT
    path.write_text(
        json.dumps(document, indent=2, ensure_ascii=True, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return ["--config-overlay", str(path)]


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
            # Same best-effort contract as the local removal below: a
            # finished scan must not be reported as failed because its
            # scratch directory outlived it. The retention sweep collects it
            # later.
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
    """Materialize a tenant's selected brute-force wordlist to a job-scoped
    file and return ``(config_override, provenance)``.

    Returns ``None`` when no wordlist was requested. Raises ``ValueError``
    when the id is unknown or belongs to another tenant — selecting a wordlist
    that cannot be found must fail the scan request, not run it without one.

    The override is nested under ``discovery`` because that is where the
    scanner's ``AppConfig`` actually holds these stages. A top-level ``ct``/
    ``cloud`` key validates cleanly (the schema does not forbid extras) and is
    then ignored, so the scan would run with the stage still disabled and
    succeed — a silent no-op rather than an error. The scan-start tests assert
    through ``load_config`` for exactly this reason.

    Selecting a *subdomain* list turns on the CT/brute-force discovery stage
    (``ct.enabled`` + ``ct.brute_force.enabled``) with the uploaded list; a
    *bucket* list turns on cloud discovery. Enabling ``ct`` also lets its
    configured providers run (default ``crtsh``, a passive third-party CT-log
    query) — brute force is nested under that stage and cannot run without it.
    """
    if not wordlist_id:
        return None
    resolved = wordlists_service.get_for_scan(wordlist_id, tenant_id=tenant_id)
    if resolved is None:
        raise ValueError(f"Unknown wordlist_id: {wordlist_id}")

    dest = wordlist_file_for_job(settings, job_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    # Written to this pod's disk and deliberately NOT to the artifact store,
    # unlike the job's other inputs (#336). Nothing else would ever read it:
    # the only consumer is the scanner subprocess, started by ``start_scan``
    # in the same process that writes this file, and a job retried after a
    # restart comes back through here and rewrites it. The list itself is a
    # row in Postgres, which every replica already reads. A copy in the bucket
    # would be storage nothing fetches and the retention worker then sweeps.
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
    # Recorded on the job so a completed run can still answer "which
    # dictionary produced this?" after the wordlist is renamed or deleted.
    provenance = {
        "wordlist_id": wordlist_id,
        "wordlist_name": resolved.name,
        "wordlist_kind": resolved.kind,
        "wordlist_sha256": resolved.sha256,
        "wordlist_entries": resolved.line_count,
    }
    return {"discovery": stage}, provenance
