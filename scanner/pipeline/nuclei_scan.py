"""Nuclei template-based vulnerability/misconfig scanning.

Runs against already-discovered open web ports (``open_ports.txt``) -- same
candidate-endpoint selection as ``fingerprint.py``, no new port scan. Shells
out to the ``nuclei`` binary (built from source at a pinned version tag, see
``Dockerfile``) against a pinned ``nuclei-templates`` checkout, and parses
its JSONL output.

CVE-tagged matches (``info.classification.cve-id``) are split out as
``cve_findings`` in a shape compatible with ``report.py``'s
``vulnerabilities.json`` rows (``host``/``port``/``cve``/``cvss``/``severity``/
``script_id``, tagged ``source: "nuclei"``), so the caller
(``scanner/main.py``) can merge them into the same list that
``nmap-vulners``/``vulscan`` findings populate -- CVSS4/EPSS/KEV enrichment
and risk scoring then treat them identically. Non-CVE matches (exposed
panels, misconfig, tech detection) are reported only in ``nuclei.json``.

SAFETY: enabled by default since Phase 4.2 (``nuclei.enabled = true``) as the
web-CVE companion to Pulse ``--cve``. Set ``nuclei.enabled: false`` to opt out.
Template scope is
capped by ``severities``/``exclude_tags`` (conservative by default -- see
``NucleiConfig``), and the candidate endpoint list is capped by
``max_targets`` -- past the cap, remaining endpoints are skipped and the run
is flagged "truncated". Never raises: a missing ``templates_dir``, missing
``nuclei`` binary, or a failed/timed-out invocation all degrade to a clean
``skipped_reason`` rather than failing the scan (same fail-soft convention
as ``fingerprint.py``/``tls_posture.py``).

OAST: off unless ``nuclei.interactsh_server`` names a server the operator
runs. Off means ``-no-interactsh``, and nuclei then skips every template that
needs an interactsh URL. See ``NucleiConfig`` and
``docs/network-requirements.md`` for why the default is not nuclei's own.

COVERAGE: ``nuclei.json`` carries a ``coverage`` block -- whether nuclei was
actually run and exited cleanly, the URLs it was given, and, for a run pinned
to ``nuclei.template_ids`` (a verification re-scan), which of those ids were
found under the template directories and which were not. The API closes a
finding as machine-verified on the strength of this block
(``api/services/verification_coverage.py``), so it records what happened, not
what was configured: an empty finding list next to ``ran: false`` is a scan
that did not look, and is not read as a clean one.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from .config_schema import NucleiConfig
from .dns_resolvers import host_port, scan_resolvers
from .protocol import is_ipv6, parse_endpoint
from .utils import run_command, save_json, write_lines

LOG = logging.getLogger("shapoclyack.nuclei")

#: Token for a self-hosted interactsh server started with ``-auth``/``-token``.
#: Read from the environment rather than the scan config, and handed to nuclei
#: in a private ``-config`` file rather than as ``-interactsh-token``:
#: ``run_command`` writes argv into ``scan.log``, which is uploaded with the
#: run, and argv is readable in ``/proc`` by anything else in the container.
INTERACTSH_TOKEN_ENV = "OCTO_INTERACTSH_TOKEN"

#: What nuclei v3.11.1 logs at INFO once its interactsh client has registered.
#: Registration is lazy (the first template that asks for a URL), and a failed
#: one is logged nowhere below -v, so this line is the only evidence either way.
_INTERACTSH_REGISTERED = "Using Interactsh Server:"

_SEVERITY_CVSS_FLOOR = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.0,
}

#: How much of a template file is read to find its ``id``. nuclei-templates
#: puts ``id:`` on the first line of every file; the slack is for a comment
#: header above it. Reading the head and not the file is what keeps the index
#: cheap over a ~10k-file checkout.
_TEMPLATE_HEAD_BYTES = 2048

#: What nuclei v3.11.1 prints at INFO (stderr, hidden by -silent), checked
#: live in the aio image: how many templates the run really loaded, and each
#: target it gave up on ("... found unresponsive permanently: ..." for a
#: refused port, "... found unresponsive N times" after -max-host-error).
_TEMPLATES_LOADED = re.compile(r"Templates loaded for current scan: (\d+)")
_TARGET_SKIPPED = re.compile(r"Skipped (\S+) from target list as found unresponsive")
#: The -elog kind nuclei gives the errors it skips a target over.
_PERMANENT_ERROR = "network-permanent-error"
_TEMPLATE_ID_LINE = re.compile(r"^id:[ \t]*['\"]?([A-Za-z0-9_.-]+)", re.MULTILINE)


def _template_tags(path: Path) -> set[str]:
    """The ``info.tags`` of one template, as nuclei matches ``-exclude-tags``.

    Parsed properly, and only for the handful of templates a pinned run asked
    for: tags sit below a free-text description, and nuclei accepts both the
    comma string and a YAML list. An unreadable file has no tags here, which
    the run itself then settles -- nuclei refuses to load it either way.
    """
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, yaml.YAMLError):
        return set()
    info = document.get("info") if isinstance(document, dict) else None
    raw = info.get("tags") if isinstance(info, dict) else None
    if isinstance(raw, str):
        return {tag.strip().lower() for tag in raw.split(",") if tag.strip()}
    if isinstance(raw, list):
        return {str(tag).strip().lower() for tag in raw if str(tag).strip()}
    return set()


def index_template_ids(wanted: Sequence[str], dirs: Sequence[Path]) -> dict[str, list[set[str]]]:
    """``{template id: [tags of each file with that id]}`` for ``wanted`` under ``dirs``.

    A pinned run has to know which of its ids nuclei can load before it runs:
    nuclei filters the templates it loaded by ``-id`` and says nothing about an
    id that filtered nothing in, so a missing template would otherwise vanish
    without a trace and the run would read as having checked it.

    Every file, not the first: the same id in two directories (a custom copy
    beside the baked one) is two templates nuclei loads under one id, and its
    "Templates loaded" count could then hide one that failed to parse behind
    the other (#451 review). One full pass over the heads — 0.19 s over the
    8936 baked templates, measured in the aio image.
    """
    remaining = set(wanted)
    found: dict[str, list[set[str]]] = {}
    for root in dirs:
        if not root.is_dir():
            continue
        for directory, _subdirs, files in os.walk(root):
            for name in files:
                if not name.endswith((".yaml", ".yml")):
                    continue
                path = Path(directory) / name
                try:
                    with path.open("rb") as handle:
                        head = handle.read(_TEMPLATE_HEAD_BYTES).decode("utf-8", errors="replace")
                except OSError:
                    continue
                match = _TEMPLATE_ID_LINE.search(head)
                if match is None or match.group(1) not in remaining:
                    continue
                found.setdefault(match.group(1), []).append(_template_tags(path))
    return found


def _candidate_endpoints(
    open_ports: list[str], http_ports: set[int], https_ports: set[int]
) -> list[tuple[str, int, str]]:
    """(host, port, scheme) tuples for open TCP endpoints on configured web ports.

    A port listed under *both* ``http_ports`` and ``https_ports`` yields a
    candidate for each scheme rather than just one. That is how a custom scan
    port -- one the operator asked for but whose scheme is unknown -- is
    covered: it is added to both sets (see ``extend_web_ports_with_custom``),
    so the endpoint is probed as http *and* https and a wrong scheme guess
    never silently drops it. The default port lists do not overlap, so this is
    a no-op for the built-in 80/443/... classification.
    """
    candidates: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for entry in open_ports:
        parsed = parse_endpoint(entry)
        if parsed is None or parsed.protocol != "tcp":
            continue
        try:
            port = int(parsed.port)
        except ValueError:
            continue
        schemes: list[str] = []
        if port in https_ports:
            schemes.append("https")
        if port in http_ports:
            schemes.append("http")
        for scheme in schemes:
            key = (parsed.host, port, scheme)
            if key in seen:
                continue
            seen.add(key)
            candidates.append((parsed.host, port, scheme))
    candidates.sort()
    return candidates


def _build_url(host: str, port: int, scheme: str) -> str:
    hostpart = f"[{host}]" if is_ipv6(host) else host
    return f"{scheme}://{hostpart}:{port}/"


def _parse_result_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _to_finding(raw: dict[str, Any]) -> dict[str, Any]:
    info = raw.get("info") if isinstance(raw.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    cve_ids = classification.get("cve-id") or []
    if not isinstance(cve_ids, list):
        cve_ids = [cve_ids]
    return {
        "host": str(raw.get("host") or ""),
        "port": str(raw.get("port") or ""),
        "matched_at": str(raw.get("matched-at") or ""),
        "template_id": str(raw.get("template-id") or ""),
        "name": str(info.get("name") or ""),
        "severity": str(info.get("severity") or "unknown").lower(),
        "tags": [str(t) for t in (info.get("tags") or [])],
        "cve": [str(c) for c in cve_ids if c],
        "cvss_score": classification.get("cvss-score"),
        "cwe": classification.get("cwe-id") or [],
    }


def _to_vulnerability_rows(finding: dict[str, Any]) -> list[dict[str, Any]]:
    if not finding["cve"] or not finding["host"]:
        return []
    cvss = finding.get("cvss_score")
    if not isinstance(cvss, (int, float)):
        cvss = _SEVERITY_CVSS_FLOOR.get(finding["severity"])
    return [
        {
            "host": finding["host"],
            "port": finding["port"],
            "cve": str(cve).upper(),
            "cvss": cvss,
            "severity": finding["severity"],
            "script_id": f"nuclei:{finding['template_id']}",
            "source": "nuclei",
            "protocol": "tcp",
            "cwe": finding.get("cwe") or [],
        }
        for cve in finding["cve"]
    ]


#: nuclei_errors.jsonl travels with the run (it is tarred and uploaded), and
#: an unreachable target can fill it with one line per request; read in full
#: for the skipped targets first, then kept to this many bytes.
_ERRORS_LOG_MAX_BYTES = 1024 * 1024


def _cap_errors_log(errors_file: Path) -> bool:
    """Truncate ``errors_file`` to whole lines under the cap; True if it was."""
    try:
        if not errors_file.is_file() or errors_file.stat().st_size <= _ERRORS_LOG_MAX_BYTES:
            return False
        with errors_file.open("rb") as handle:
            head = handle.read(_ERRORS_LOG_MAX_BYTES)
        errors_file.write_bytes(head[: head.rfind(b"\n") + 1])
    except OSError:
        LOG.warning("could not cap %s", errors_file, exc_info=True)
        return False
    return True


def _permanent_error_addresses(errors_file: Path) -> set[str]:
    """``host:port`` of each target nuclei's -elog says it gave up on."""
    out: set[str] = set()
    if not errors_file.is_file():
        return out
    for line in errors_file.read_text(encoding="utf-8", errors="replace").splitlines():
        record = _parse_result_line(line)
        if record and record.get("kind") == _PERMANENT_ERROR and record.get("address"):
            out.add(str(record["address"]))
    return out


def _persist(output_dir: Path, result: dict[str, Any]) -> None:
    save_json(output_dir / "nuclei.json", result)
    lines = [f"{f['host']}:{f['port']}:{f['template_id']}:{f['severity']}" for f in result["findings"]]
    write_lines(output_dir / "nuclei_findings.txt", lines)


def _interactsh_args(server: str) -> tuple[list[str], Path | None]:
    """The OAST flags for nuclei, and a private directory the caller removes.

    No server: ``-no-interactsh``. A server: ``-interactsh-server``, plus
    ``-config`` pointing at a 0600 file holding the token when
    :data:`INTERACTSH_TOKEN_ENV` is set. The file lives in a fresh temp
    directory, never under the run's output directory, which is uploaded.
    If the file cannot be written OAST is turned off for the run rather than
    registering without the token the server expects.
    """
    if not server:
        return ["-no-interactsh"], None
    args = ["-interactsh-server", server]
    token = os.environ.get(INTERACTSH_TOKEN_ENV, "").strip()
    if not token:
        return args, None
    private_dir: Path | None = None
    try:
        private_dir = Path(tempfile.mkdtemp(prefix="shapoclyack-nuclei-"))
        config_file = private_dir / "interactsh.yaml"
        fd = os.open(config_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            # A JSON string is a valid YAML scalar, quoted and escaped.
            handle.write(f"interactsh-token: {json.dumps(token)}\n")
    except OSError as exc:
        LOG.warning("nuclei: cannot write the interactsh token file (%s); OAST is off for this run", exc)
        if private_dir is not None:
            shutil.rmtree(private_dir, ignore_errors=True)
        return ["-no-interactsh"], None
    return [*args, "-config", str(config_file)], private_dir


def run_nuclei_scan(
    open_ports: list[str],
    config: NucleiConfig,
    output_dir: Path,
    resolvers: Sequence[str] = (),
) -> dict[str, Any]:
    """Run nuclei against already-open web ports. Never raises.

    ``resolvers`` is ``dns.resolvers`` from the scanner config. Empty means
    the system's resolvers, never nuclei's built-in public ones (see
    ``dns_resolvers.py``).
    """
    result: dict[str, Any] = {
        "targets_considered": 0,
        "checked_count": 0,
        "findings": [],
        "cve_findings": [],
        "truncated": False,
        "skipped_reason": None,
        # Which interactsh server the OAST templates were given, or "disabled"
        # when they were not run at all, so a report without blind-SSRF/RCE
        # findings says whether those checks happened. With a server,
        # "interactsh_registered" says whether nuclei actually got to use it.
        "interactsh": config.interactsh_server or "disabled",
        "interactsh_registered": None,
        # What this run demonstrably did, for the verification closure (see
        # the module docstring). ``ran`` turns true only once nuclei itself
        # has exited 0; every skip below leaves it false.
        "coverage": {
            "ran": False,
            "returncode": None,
            "targets": [],
            "template_ids_requested": list(config.template_ids),
            "template_ids_missing": [],
            "template_ids_excluded": [],
            "severities": None if config.template_ids else list(config.severities),
            # nuclei's own account of the run: templates it loaded (a pinned
            # run only; -silent hides the line on a sweep) and the targets it
            # dropped as unresponsive. A target it dropped was not checked.
            "templates_loaded": None,
            "templates_expected": None,
            # An id found in more than one file across the template dirs.
            "template_ids_ambiguous": [],
            "skipped_targets": [],
            # As nuclei applies it: it raises a value below -concurrency.
            "max_host_error": max(config.max_host_error, config.concurrency),
            "errors_log_truncated": False,
        },
    }
    coverage = result["coverage"]
    if not config.enabled:
        result["skipped_reason"] = "nuclei.disabled"
        _persist(output_dir, result)
        return result

    if shutil.which("nuclei") is None:
        result["skipped_reason"] = "nuclei_binary_missing"
        _persist(output_dir, result)
        return result

    templates_dir = Path(config.templates_dir)
    if not templates_dir.is_dir():
        result["skipped_reason"] = "templates_dir_missing"
        _persist(output_dir, result)
        return result

    custom_dir = Path(config.custom_templates_dir) if config.custom_templates_dir else None
    pinned: list[str] = []
    if config.template_ids:
        # Resolved before anything is sent: an id that is not on this host,
        # or that the host's own exclusions would filter out, is recorded as
        # such rather than left for nuclei to drop without a word.
        dirs = [templates_dir, *([custom_dir] if custom_dir and custom_dir.exists() else [])]
        index = index_template_ids(config.template_ids, dirs)
        excluded_tags = {tag.lower() for tag in config.exclude_tags}
        expected = 0
        for template_id in config.template_ids:
            files = index.get(template_id, [])
            loadable = [tags for tags in files if not tags & excluded_tags]
            if not files:
                coverage["template_ids_missing"].append(template_id)
            elif not loadable:
                coverage["template_ids_excluded"].append(template_id)
            else:
                pinned.append(template_id)
                expected += len(loadable)
            if len(files) > 1:
                coverage["template_ids_ambiguous"].append(template_id)
        # What nuclei has to report loading, exactly: one per loadable file
        # of each pinned id.
        coverage["templates_expected"] = expected
        if coverage["template_ids_missing"] or coverage["template_ids_excluded"]:
            LOG.warning(
                "nuclei: of the %d pinned template(s), not on this host: %s; excluded by "
                "nuclei.exclude_tags: %s",
                len(config.template_ids),
                ", ".join(coverage["template_ids_missing"]) or "none",
                ", ".join(coverage["template_ids_excluded"]) or "none",
            )
        if not pinned:
            # Not run at all: nuclei given only ids it cannot load exits 1
            # with "no templates provided for scan" (v3.11.1, checked live).
            result["skipped_reason"] = (
                "template_ids_missing" if coverage["template_ids_missing"] else "template_ids_excluded"
            )
            _persist(output_dir, result)
            return result

    candidates = _candidate_endpoints(open_ports, set(config.http_ports), set(config.https_ports))
    result["targets_considered"] = len(candidates)
    if not candidates:
        result["skipped_reason"] = "no_web_ports"
        _persist(output_dir, result)
        return result

    truncated = len(candidates) > config.max_targets
    candidates = candidates[: config.max_targets]
    result["truncated"] = truncated

    targets_file = output_dir / "nuclei_targets.txt"
    jsonl_file = output_dir / "nuclei_raw.jsonl"
    urls = [_build_url(host, port, scheme) for host, port, scheme in candidates]
    write_lines(targets_file, urls)
    coverage["targets"] = sorted(urls)
    jsonl_file.unlink(missing_ok=True)
    # Written directly, not through write_lines: that sorts, and the order
    # here is the operator's.
    resolvers_file = output_dir / "nuclei_resolvers.txt"
    resolver_lines = [host_port(resolver) for resolver in scan_resolvers(resolvers)]
    resolvers_file.write_text("\n".join(resolver_lines) + "\n", encoding="utf-8")

    command = [
        "nuclei",
        # First, and in the literal itself, so no branch below can build a
        # command without it: unasked, nuclei checks for a newer release and
        # installs templates it cannot find, which on an air-gapped network is
        # a DNS timeout per run and anywhere else a beacon (#339).
        "-disable-update-check",
        "-list", str(targets_file),
        "-templates", str(templates_dir),
        # Without this, nuclei's fastdialer rotates 1.1.1.1/8.8.8.8/... in
        # with the system resolver, and its DNS client asks only those.
        "-resolvers", str(resolvers_file),
    ]
    if custom_dir is not None and custom_dir.exists():
        command.extend(["-templates", str(custom_dir)])
    if pinned:
        # Exactly these templates, whatever their severity or tags: the run is
        # re-checking what they found, and a severity floor that skips a
        # medium template would make "not observed" mean "not looked for".
        command.extend(["-id", ",".join(pinned)])
    else:
        if config.severities:
            command.extend(["-severity", ",".join(config.severities)])
        if config.tags:
            command.extend(["-tags", ",".join(config.tags)])
    if config.exclude_tags:
        command.extend(["-exclude-tags", ",".join(config.exclude_tags)])
    errors_file = output_dir / "nuclei_errors.jsonl"
    errors_file.unlink(missing_ok=True)
    command.extend([
        "-jsonl-export", str(jsonl_file),
        "-rate-limit", str(config.rate_limit),
        "-concurrency", str(config.concurrency),
        "-timeout", str(config.timeout_seconds),
        "-retries", str(config.retries),
        "-max-host-error", str(config.max_host_error),
        "-elog", str(errors_file),
        "-silent",
        "-no-color",
    ])  # fmt: skip
    if pinned:
        # A verification needs nuclei's "Templates loaded for current scan"
        # line, which -silent hides; the run is a handful of requests, so the
        # rest of the INFO output costs nothing.
        command.remove("-silent")
    # interactsh ignores -resolvers above: its client resolves the server name
    # through nuclei's built-in public resolvers as well (dns_resolvers.py).
    interactsh_args, private_dir = _interactsh_args(config.interactsh_server)
    command.extend(interactsh_args)
    oast = "-no-interactsh" not in interactsh_args
    if oast:
        # A registration that fails prints nothing under -silent, or at any
        # level short of -v, which logs every request. The only signal is the
        # INFO line on success, and -silent hides that too.
        if "-silent" in command:
            command.remove("-silent")
    else:
        result["interactsh"] = "disabled"

    try:
        completed = run_command(command, timeout=config.overall_timeout_seconds, retries=0, check=False)
    except Exception as exc:  # noqa: BLE001
        LOG.warning("nuclei scan failed for %d endpoint(s): %s", len(candidates), exc)
        result["skipped_reason"] = "nuclei_run_failed"
        _persist(output_dir, result)
        return result
    finally:
        if private_dir is not None:
            shutil.rmtree(private_dir, ignore_errors=True)

    # Not ``check=True`` above, and still not a skip: nuclei's findings from a
    # run that then exited non-zero are kept as before. But such a run did not
    # demonstrably complete, so it does not count as having looked.
    returncode = getattr(completed, "returncode", None)
    coverage["returncode"] = returncode if isinstance(returncode, int) else None
    coverage["ran"] = coverage["returncode"] == 0
    if coverage["returncode"] not in (0, None):
        LOG.warning("nuclei exited %s; its run is not counted as coverage", returncode)
    stderr_text = getattr(completed, "stderr", None)
    stderr_text = stderr_text if isinstance(stderr_text, str) else ""
    loaded = _TEMPLATES_LOADED.findall(stderr_text)
    coverage["templates_loaded"] = int(loaded[-1]) if loaded else None
    coverage["skipped_targets"] = sorted(
        set(_TARGET_SKIPPED.findall(stderr_text)) | _permanent_error_addresses(errors_file)
    )
    coverage["errors_log_truncated"] = _cap_errors_log(errors_file)
    if coverage["skipped_targets"]:
        LOG.warning(
            "nuclei dropped %d target(s) as unresponsive: %s",
            len(coverage["skipped_targets"]),
            ", ".join(coverage["skipped_targets"][:8]),
        )

    if oast:
        stderr = getattr(completed, "stderr", None)
        registered = isinstance(stderr, str) and _INTERACTSH_REGISTERED in stderr
        result["interactsh_registered"] = registered
        if not registered:
            LOG.warning(
                "nuclei never registered with interactsh server %s, so no OAST template ran: "
                "either none reached a live target, or the server could not be resolved or "
                "reached (see docs/network-requirements.md)",
                config.interactsh_server,
            )

    findings: list[dict[str, Any]] = []
    cve_findings: list[dict[str, Any]] = []
    if jsonl_file.is_file():
        for line in jsonl_file.read_text(encoding="utf-8", errors="replace").splitlines():
            raw = _parse_result_line(line)
            if raw is None:
                continue
            finding = _to_finding(raw)
            findings.append(finding)
            cve_findings.extend(_to_vulnerability_rows(finding))

    result["checked_count"] = len(candidates)
    result["findings"] = findings
    result["cve_findings"] = cve_findings
    _persist(output_dir, result)
    LOG.info(
        "nuclei: %d endpoint(s) scanned -> %d finding(s) (%d with CVE)%s",
        len(candidates),
        len(findings),
        len(cve_findings),
        " [truncated]" if truncated else "",
    )
    return result
