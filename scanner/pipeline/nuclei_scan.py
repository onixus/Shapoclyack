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
panels, misconfig, tech detection) remain in ``nuclei.json``; operator-reviewed
``non_cve_rules`` with actionable severity also enter the common remediation tracker.

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

NETWORK PASS (#547): the sweep above only ever sees ``http(s)://`` URLs, so a
``javascript:``/``tcp:`` template could never run. ``nuclei_network.NETWORK_RULES``
names, per service, the few such templates that answer an Nmap ``vuln``/``safe``
script; :func:`_run_network_pass` runs each rule's ids, pinned with ``-id``,
against ``host:port`` of the endpoints Pulse named as that service, one nuclei
process per rule so an id never meets an endpoint of another service. It
obeys the sweep's two safety dials -- ``severities`` and ``exclude_tags`` --
checked here against the template files rather than handed to nuclei, because
``-id`` plus ``-severity`` drops an id without a word. It is skipped in a
pinned (``template_ids``) run, never uses OAST, and is off with
``nuclei.network_templates: false``. Its evidence is ``coverage["network"]``.

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
import hashlib
import shutil
import tempfile
import time
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import yaml

from .config_schema import NucleiConfig
from .dns_resolvers import host_port, scan_resolvers
from .nuclei_plan import (
    build_plan,
    catalog,
    forward_names,
    read_services,
    snapshot_catalog,
)
from .nuclei_network import (
    NETWORK_RULES,
    NetworkRule,
    load_service_names,
    plan_network_targets,
    target_string,
)
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


def _template_facts(path: Path) -> tuple[set[str], str]:
    """``(info.tags, info.severity)`` of one template, as nuclei reads them.

    Parsed properly, and only for the handful of templates a pinned run asked
    for: tags sit below a free-text description, and nuclei accepts both the
    comma string and a YAML list. An unreadable file has no tags and no
    severity here, which the run itself then settles -- nuclei refuses to load
    it either way.
    """
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, yaml.YAMLError):
        return set(), ""
    info = document.get("info") if isinstance(document, dict) else None
    if not isinstance(info, dict):
        return set(), ""
    raw = info.get("tags")
    tags: set[str] = set()
    if isinstance(raw, str):
        tags = {tag.strip().lower() for tag in raw.split(",") if tag.strip()}
    elif isinstance(raw, list):
        tags = {str(tag).strip().lower() for tag in raw if str(tag).strip()}
    return tags, str(info.get("severity") or "").strip().lower()


def _template_tags(path: Path) -> set[str]:
    """The ``info.tags`` of one template, as nuclei matches ``-exclude-tags``."""
    return _template_facts(path)[0]


def _index_templates(
    wanted: Sequence[str], dirs: Sequence[Path], read: Any
) -> dict[str, list[Any]]:
    """``{template id: [read(path) of each file with that id]}`` for ``wanted`` under ``dirs``.

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
    found: dict[str, list[Any]] = {}
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
                        head = handle.read(_TEMPLATE_HEAD_BYTES).decode(
                            "utf-8", errors="replace"
                        )
                except OSError:
                    continue
                match = _TEMPLATE_ID_LINE.search(head)
                if match is None or match.group(1) not in remaining:
                    continue
                found.setdefault(match.group(1), []).append(read(path))
    return found


def index_template_ids(
    wanted: Sequence[str], dirs: Sequence[Path]
) -> dict[str, list[set[str]]]:
    """``{template id: [tags of each file with that id]}`` for ``wanted`` under ``dirs``."""
    return _index_templates(wanted, dirs, _template_tags)


def _template_facts_sha(path: Path) -> tuple[set[str], str, str]:
    """``(tags, severity, sha256 of the file)``: the facts the network pass records."""
    tags, severity = _template_facts(path)
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        digest = ""
    return tags, severity, digest


def index_template_facts(
    wanted: Sequence[str], dirs: Sequence[Path]
) -> dict[str, list[tuple[set[str], str, str]]]:
    """``{template id: [(tags, severity, sha256) of each file with that id]}`` for ``wanted`` under ``dirs``."""
    return _index_templates(wanted, dirs, _template_facts_sha)


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
    classification = (
        info.get("classification")
        if isinstance(info.get("classification"), dict)
        else {}
    )
    cve_ids = classification.get("cve-id") or []
    if not isinstance(cve_ids, list):
        cve_ids = [cve_ids]
    result = {
        "host": str(raw.get("host") or ""),
        "port": str(raw.get("port") or ""),
        "matched_at": str(raw.get("matched-at") or ""),
        "template_id": str(raw.get("template-id") or ""),
        "name": str(info.get("name") or ""),
        "severity": str(info.get("severity") or "unknown").lower(),
        "tags": ([t.strip() for t in info["tags"].split(",")]
                 if isinstance(info.get("tags"), str) else [str(t) for t in (info.get("tags") or [])]),
        "observed_at": raw.get("timestamp"),
        "matcher": str(raw.get("matcher-name") or ""),
        "protocol": "udp" if raw.get("type") == "udp" else "tcp",
        "cve": [str(c) for c in cve_ids if c],
        "cvss_score": classification.get("cvss-score"),
        "cwe": classification.get("cwe-id") or [],
    }
    binding = raw.get("shapoclyack_input")
    if binding is not None:
        from .finding_evidence import subject, http_authority
        try:
            if (not isinstance(binding, dict)
                    or set(binding) != {"schema", "ip", "port", "authority", "sni"}
                    or binding.get("schema") != "octo.nuclei_input.v1"):
                raise ValueError("invalid invocation binding")
            actual = subject(result)
            declared = subject({"host": binding["ip"], "port": binding["port"],
                                "protocol": "tcp", "sni": binding["sni"]})
            if any(actual[k] != declared[k] for k in ("host", "port", "protocol")) or actual["scheme"] is None:
                raise ValueError("conflicting invocation binding")
            result["http_authority"] = http_authority(binding["authority"], declared["port"])
            result["sni"] = declared["sni"]
        except (ValueError, TypeError, KeyError):
            result["subject_invalid"] = True
    return result


def _non_cve_row(finding: dict[str, Any], config: NucleiConfig) -> dict[str, Any] | None:
    """Only reviewed rules with actionable severities create remediation work.

    A panel/technology match or arbitrary tags never establish a vulnerability.
    Raw output remains inventory; unknown non-informational matches are hypotheses.
    """
    from .finding_evidence import safe_text, subject
    if finding.get("cve"):
        finding["classification"] = "cve"
        return None
    severity = finding.get("severity")
    finding["classification"] = "inventory" if severity in {"info", "unknown"} else "hypothesis"
    rule = config.non_cve_rules.get(str(finding.get("template_id") or ""))
    if rule is None or severity not in _SEVERITY_CVSS_FLOOR or finding.get("subject_invalid"):
        return None
    row = {"host": finding.get("host"), "port": finding.get("port"), "cve": None,
           "cvss": None, "severity": severity, "source": "nuclei",
           "script_id": "nuclei:" + finding["template_id"], "template_id": finding["template_id"],
           "rule_id": rule.rule_id, "finding_type": rule.issue_type,
           "non_cve_policy": "nuclei-actionable-v1",
           "remediation": safe_text(rule.remediation, 4000), "protocol": finding.get("protocol", "tcp"),
           "matched_at": finding.get("matched_at"), "http_authority": finding.get("http_authority"),
           "sni": finding.get("sni"), "title": safe_text(finding.get("name"), 256),
           "evidence_kind": "template_match", "requires_confirmation": False,
           "matcher": finding.get("matcher"), "observed_at": finding.get("observed_at"),
           "cwe": finding.get("cwe") or []}
    try:
        target = subject(row)
    except (ValueError, TypeError):
        return None
    if not target["host"] or target["port"] is None:
        return None
    row["host"], row["port"] = target["host"], str(target["port"])
    finding["classification"] = "actionable"
    return row


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
    """Truncate ``errors_file`` to whole lines under the cap; True if it was.

    A first line longer than the cap is kept cut, not dropped: whole lines
    alone would leave an empty file, and an operator reading it would see
    no error where nuclei wrote one.
    """
    try:
        if (
            not errors_file.is_file()
            or errors_file.stat().st_size <= _ERRORS_LOG_MAX_BYTES
        ):
            return False
        with errors_file.open("rb") as handle:
            head = handle.read(_ERRORS_LOG_MAX_BYTES)
        whole = head[: head.rfind(b"\n") + 1]
        errors_file.write_bytes(whole or head[: _ERRORS_LOG_MAX_BYTES - 1] + b"\n")
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
    lines = [
        f"{f['host']}:{f['port']}:{f['template_id']}:{f['severity']}"
        for f in result["findings"]
    ]
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
        LOG.warning(
            "nuclei: cannot write the interactsh token file (%s); OAST is off for this run",
            exc,
        )
        if private_dir is not None:
            shutil.rmtree(private_dir, ignore_errors=True)
        return ["-no-interactsh"], None
    return [*args, "-config", str(config_file)], private_dir


def _sweep_authorities(candidates, names):
    """Bind input-forward DNS authority to a discovered IP; never dial the name."""
    targets = []
    for ip, port, scheme in candidates:
        valid = sorted({name.lower().rstrip('.') for name in names.get(ip, [])
                        if isinstance(name, str) and len(name) <= 253
                        and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                                for label in name.rstrip('.').split('.'))
                        and '.' in name.rstrip('.')})
        for name in valid or [None]:
            authority = (name or (f"[{ip}]" if ':' in ip else ip)) + f":{port}"
            targets.append(dict(ip=ip, port=port, url=_build_url(ip, port, scheme),
                                authority=authority, sni=name if scheme == 'https' else None,
                                host_header=authority if name else None))
    return targets


def _run_authority_sweep(command, targets, output_dir, timeout):
    """Isolate each authority's Host/SNI and preserve per-invocation raw evidence."""
    deadline = time.monotonic() + timeout
    codes, stderr, matches, errors = [], [], [], []
    bytes_left = 16 * 1024 * 1024
    for index, target in enumerate(targets):
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            codes.append(1)
            break
        cmd = list(command)
        inputs = output_dir / f"nuclei_authority_{index:04d}_targets.txt"
        raw = output_dir / f"nuclei_authority_{index:04d}_raw.jsonl"
        elog = output_dir / f"nuclei_authority_{index:04d}_errors.jsonl"
        write_lines(inputs, [target['url']])
        raw.unlink(missing_ok=True)
        elog.unlink(missing_ok=True)
        cmd[cmd.index('-list') + 1] = str(inputs)
        cmd[cmd.index('-jsonl-export') + 1] = str(raw)
        cmd[cmd.index('-elog') + 1] = str(elog)
        if target['host_header']:
            cmd.extend(['-H', 'Host: ' + target['host_header']])
        if target['sni']:
            cmd.extend(['-sni', target['sni']])
        try:
            result = run_command(cmd, timeout=remaining, retries=0, check=False)
            codes.append(result.returncode)
            stderr.append(result.stderr or '')
        except Exception as exc:  # preserve partial evidence and fail coverage
            codes.append(1)
            stderr.append(str(exc))
        for path, sink in [(raw, matches), (elog, errors)]:
            if path.exists():
                with path.open('rb') as handle:
                    content = handle.read(min(bytes_left, 8 * 1024 * 1024) + 1)
                if len(content) > min(bytes_left, 8 * 1024 * 1024):
                    codes.append(1)
                    content = content[:min(bytes_left, 8 * 1024 * 1024)].rsplit(b'\n', 1)[0]
                bytes_left -= len(content)
                if path == raw:
                    for line in content.decode(errors='replace').splitlines():
                        record = _parse_result_line(line)
                        if record is None:
                            codes.append(1)
                            continue
                        if record is not None:
                            record['shapoclyack_input'] = dict(schema='octo.nuclei_input.v1',
                                **{k: target[k] for k in ['ip', 'port', 'authority', 'sni']})
                            sink.append(json.dumps(record))
                else:
                    sink.append(content.decode(errors='replace'))
    Path(command[command.index('-jsonl-export') + 1]).write_text('\n'.join(matches))
    Path(command[command.index('-elog') + 1]).write_text('\n'.join(errors))
    return subprocess.CompletedProcess(command, 0 if len(codes) == len(targets) and all(c == 0 for c in codes) else 1,
                                       '', '\n'.join(stderr))


def _run_web_sweep(
    open_ports: list[str],
    config: NucleiConfig,
    output_dir: Path,
    resolvers: Sequence[str] = (),
) -> dict[str, Any]:
    """The web sweep (or, with ``template_ids``, the pinned re-check). Never raises."""
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

    custom_dir = (
        Path(config.custom_templates_dir) if config.custom_templates_dir else None
    )
    pinned: list[str] = []
    if config.template_ids:
        # Resolved before anything is sent: an id that is not on this host,
        # or that the host's own exclusions would filter out, is recorded as
        # such rather than left for nuclei to drop without a word.
        dirs = [
            templates_dir,
            *([custom_dir] if custom_dir and custom_dir.exists() else []),
        ]
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
                "template_ids_missing"
                if coverage["template_ids_missing"]
                else "template_ids_excluded"
            )
            _persist(output_dir, result)
            return result

    plan = None
    # Resume must not project previous directed raw matches as this run.
    for stale in output_dir.glob("nuclei_plan_*"):
        if stale.is_file():
            stale.unlink(missing_ok=True)
    (output_dir / "nuclei_plan.json").unlink(missing_ok=True)
    if config.planner_mode == "directed" and not config.template_ids:
        try:
            digest, templates, error = catalog(
                [
                    templates_dir,
                    *([custom_dir] if custom_dir and custom_dir.is_dir() else []),
                ],
                config.planner_max_templates,
            )
            if error:
                result["skipped_reason"] = error
                coverage["plan"] = {
                    "mode": "directed",
                    "complete": False,
                    "skipped_reason": error,
                }
                save_json(output_dir / "nuclei_plan.json", coverage["plan"])
                _persist(output_dir, result)
                return result
            plan = build_plan(
                open_ports,
                read_services(output_dir),
                config,
                digest,
                templates,
                forward_names(output_dir),
            )
            coverage["plan"] = plan
            save_json(output_dir / "nuclei_plan.json", plan)
            pinned = plan["template_sets"]["safe_http_fallback"]
            coverage["template_ids_requested"] = pinned
            coverage["templates_expected"] = len(pinned) * len(plan["targets"])
            if not pinned:
                result["skipped_reason"] = "planner_no_eligible_templates"
                _persist(output_dir, result)
                return result
            candidates = [
                (t["ip"], t["port"], t["url"].split(":", 1)[0]) for t in plan["targets"]
            ]
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            LOG.warning("nuclei planner failed: %s", exc)
            result["skipped_reason"] = "planner_failed"
            _persist(output_dir, result)
            return result
    else:
        candidates = _candidate_endpoints(
            open_ports, set(config.http_ports), set(config.https_ports)
        )
    exact_targets = list(config.verification_targets)
    if exact_targets:
        # Only a platform-pinned verification may provide an exact HTTP input.
        # Names must be either an open endpoint or an input-forward DNS name
        # of one. A certificate/banner hostname is never scan authorization.
        from .non_cve_verification import validate_target
        names = forward_names(output_dir)
        endpoints = {(host.lower(), port) for host, port, _ in candidates}
        endpoints |= {(name.lower(), port) for host, port, _ in candidates
                      for name in names.get(host, [])}
        try:
            for target in exact_targets:
                validate_target(target)
                st = target['subject']
                if (not config.template_ids or target['template_id'] not in pinned
                        or (st['host'], st['port']) not in endpoints):
                    raise ValueError('exact target is outside the discovered approved endpoint set')
            candidates = [(t['subject']['host'], t['subject']['port'], t['subject']['scheme'])
                          for t in exact_targets]
        except (ValueError, TypeError, KeyError):
            result['skipped_reason'] = 'verification_target_not_covered'
            _persist(output_dir, result)
            return result
    result["targets_considered"] = (
        plan["targets_considered"] if plan else len(candidates)
    )
    if not candidates:
        result["skipped_reason"] = "no_web_ports"
        _persist(output_dir, result)
        return result

    truncated = (
        plan["targets_considered"] if plan else len(candidates)
    ) > config.max_targets
    candidates = candidates[: config.max_targets]
    result["truncated"] = truncated

    targets_file = output_dir / "nuclei_targets.txt"
    jsonl_file = output_dir / "nuclei_raw.jsonl"
    urls = [_build_url(host, port, scheme) for host, port, scheme in candidates]
    if exact_targets:
        urls = [target['url'] for target in exact_targets]
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
        "-list",
        str(targets_file),
        "-templates",
        str(templates_dir),
        # Without this, nuclei's fastdialer rotates 1.1.1.1/8.8.8.8/... in
        # with the system resolver, and its DNS client asks only those.
        "-resolvers",
        str(resolvers_file),
    ]
    snapshot_dir = None
    if exact_targets:
        # Pin validated bytes as well as the id. Passing a matched URL to a
        # template which appends a path can check an entirely different object.
        from .non_cve_verification import exact_template
        directories = [templates_dir, *([custom_dir] if custom_dir else [])]
        try:
            _, inventory, catalog_error = catalog(directories, config.planner_max_templates)
            selected = [row for row in inventory if row['id'] in pinned]
            if catalog_error or len(selected) != len(pinned):
                raise ValueError('verification_template_inventory_incomplete')
            for row in selected:
                root = directories[1 if row['origin'] == 'custom' else 0]
                content = (root / row['path']).read_bytes()
                if hashlib.sha256(content).hexdigest() != row['sha256'] or not exact_template(content):
                    raise ValueError('verification_template_exact_input_unproven')
            snapshot_dir = Path(tempfile.mkdtemp(prefix='shapoclyack-exact-verification-'))
            snapshot_catalog(directories, selected, snapshot_dir)
            command[command.index('-templates') + 1] = str(snapshot_dir)
        except (OSError, ValueError, TypeError, KeyError):
            if snapshot_dir is not None:
                shutil.rmtree(snapshot_dir, ignore_errors=True)
            result['skipped_reason'] = 'verification_template_exact_input_unproven'
            _persist(output_dir, result)
            return result
        command.extend(['-disable-redirects'])
    if plan is not None:
        try:
            snapshot_dir = Path(tempfile.mkdtemp(prefix="shapoclyack-nuclei-catalog-"))
            snapshot_catalog(
                [templates_dir, *([custom_dir] if custom_dir else [])],
                plan["catalog"],
                snapshot_dir,
            )
            command[command.index("-templates") + 1] = str(snapshot_dir)
        except (OSError, ValueError):
            if snapshot_dir:
                shutil.rmtree(snapshot_dir, ignore_errors=True)
            result["skipped_reason"] = "catalog_snapshot_failed"
            plan["execution_status"] = "catalog_snapshot_failed"
            save_json(output_dir / "nuclei_plan.json", plan)
            _persist(output_dir, result)
            return result
        # Never follow redirects beyond the authorized input endpoint.
        command.extend(["-disable-redirects"])
    if plan is None and not exact_targets and custom_dir is not None and custom_dir.exists():
        command.extend(["-templates", str(custom_dir)])
    if pinned and plan is None:
        # Exactly these templates, whatever their severity or tags: the run is
        # re-checking what they found, and a severity floor that skips a
        # medium template would make "not observed" mean "not looked for".
        command.extend(["-id", ",".join(pinned)])
    elif plan is None:
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
        authorities = _sweep_authorities(candidates, forward_names(output_dir)) if plan is None and not exact_targets else []
        if authorities and any(t['host_header'] for t in authorities):
            if len(authorities) > config.max_targets:
                result['truncated'] = True
            authorities = authorities[:config.max_targets]
            coverage['authorities'] = authorities
            completed = _run_authority_sweep(command, authorities, output_dir, config.overall_timeout_seconds)
        elif plan is None:
            completed = run_command(
                command, timeout=config.overall_timeout_seconds, retries=0, check=False
            )
        else:
            # One authority/SNI per process: a global Host header must never
            # leak another virtual host's authority to unrelated endpoints.
            deadline = time.monotonic() + config.overall_timeout_seconds
            stderr_parts = []
            raw_parts = []
            error_parts = []
            codes = []
            plan["process_results"] = []
            attempted = 0
            host_seconds = {}
            host_processes = {}
            raw_bytes_left = 8 * 1024 * 1024
            error_bytes_left = 8 * 1024 * 1024
            for index, target in enumerate(plan["targets"]):
                if attempted >= config.planner_max_processes:
                    result["skipped_reason"] = "planner_process_limit"
                    plan["skipped"].append({"target_index": index, "reason": "planner_process_limit", "count": len(plan["targets"]) - index})
                    break
                host = target["ip"]
                if host_processes.get(host, 0) >= config.planner_per_host_max_processes:
                    plan["skipped"].append({"target_index": index, "reason": "per_host_process_limit"})
                    continue
                host_remaining = config.planner_per_host_timeout_seconds - host_seconds.get(host, 0)
                stage_remaining = deadline - time.monotonic()
                host_limited = host_remaining < stage_remaining
                remaining = int(min(stage_remaining, host_remaining))
                if remaining < _MIN_PROCESS_SECONDS:
                    if host_remaining < _MIN_PROCESS_SECONDS:
                        plan["skipped"].append({"target_index": index, "reason": "per_host_budget_exhausted"})
                        continue
                    result["skipped_reason"] = "planner_budget_exhausted"
                    break
                write_lines(targets_file, [target["url"]])
                target_command = list(command)
                if target["host_header"]:
                    target_command.extend(["-H", "Host: " + target["host_header"]])
                if target["sni"]:
                    target_command.extend(["-sni", target["sni"]])
                part = output_dir / f"nuclei_plan_{index:04d}_raw.jsonl"
                target_command[target_command.index("-jsonl-export") + 1] = str(part)
                part.unlink(missing_ok=True)
                part_errors = output_dir / f"nuclei_plan_{index:04d}_errors.jsonl"
                part_errors.unlink(missing_ok=True)
                target_command[target_command.index("-elog") + 1] = str(part_errors)
                invocation_started = time.monotonic()
                host_timeout = False
                try:
                    item = run_command(
                        target_command, timeout=remaining, retries=0, check=False
                    )
                    codes.append(item.returncode)
                    stderr_parts.append(item.stderr or "")
                except Exception as exc:  # noqa: BLE001
                    host_timeout = host_limited and isinstance(exc, subprocess.TimeoutExpired)
                    codes.append(None)
                    stderr = getattr(exc, "stderr", "") or ""
                    stderr_parts.append(
                        stderr.decode(errors="replace")
                        if isinstance(stderr, bytes)
                        else stderr
                    )
                    result["skipped_reason"] = "nuclei_run_failed"
                elapsed = time.monotonic() - invocation_started
                host_seconds[host] = host_seconds.get(host, 0) + elapsed
                host_processes[host] = host_processes.get(host, 0) + 1
                attempted += 1
                invocation_loaded = _TEMPLATES_LOADED.findall(stderr_parts[-1])
                loaded_count = int(invocation_loaded[-1]) if invocation_loaded else None
                dropped = sorted(set(_TARGET_SKIPPED.findall(stderr_parts[-1])))
                if part_errors.is_file():
                    # A capped error part invalidates aggregate completion.
                    if _cap_errors_log(part_errors):
                        plan["artifact_truncated"] = True
                    dropped = sorted(
                        set(dropped) | _permanent_error_addresses(part_errors)
                    )
                plan["process_results"].append(
                    {
                        "target_index": index,
                        "duration_seconds": elapsed,
                        "timeout_seconds": remaining,
                        "host_budget_seconds_remaining": max(0, config.planner_per_host_timeout_seconds - host_seconds[host]),
                        "returncode": codes[-1],
                        "templates_expected": len(pinned),
                        "templates_loaded": loaded_count,
                        "skipped_targets": dropped,
                        "complete": codes[-1] == 0
                        and loaded_count == len(pinned)
                        and not dropped,
                    }
                )
                if part_errors.is_file():
                    if _cap_errors_log(part_errors):
                        plan["artifact_truncated"] = True
                    with part_errors.open("rb") as handle:
                        error_head = handle.read(error_bytes_left + 1)
                    if len(error_head) > error_bytes_left:
                        plan["artifact_truncated"] = True
                    error_head = error_head[:error_bytes_left]
                    error_bytes_left -= len(error_head)
                    error_parts.append(error_head.decode("utf-8", errors="replace"))
                if part.is_file():
                    with part.open("rb") as handle:
                        raw = handle.read(min(1024 * 1024, raw_bytes_left) + 1)
                    if len(raw) > min(1024 * 1024, raw_bytes_left):
                        plan["artifact_truncated"] = True
                        raw = raw[: min(1024 * 1024, raw_bytes_left)]
                        raw = raw[: raw.rfind(b"\n") + 1]
                        part.write_bytes(raw)
                    # Per-process originals remain byte-exact engine artifacts.
                    # The combined adapter projection binds actual Host/SNI
                    # invocation context which nuclei omits from IP URL output.
                    projected = []
                    for line in raw.decode("utf-8", errors="replace").split("\n"):
                        if not line.strip():
                            continue
                        record = _parse_result_line(line)
                        if record is None:
                            plan["malformed_result"] = True
                            projected.append(line)
                            continue
                        record["shapoclyack_input"] = {
                            "schema": "octo.nuclei_input.v1",
                            "ip": target["ip"],
                            "port": target["port"],
                            "authority": target["authority"],
                            "sni": target["sni"],
                        }
                        encoded = json.dumps(record, separators=(",", ":")).encode(
                            "utf-8"
                        )
                        if len(encoded) + 1 > raw_bytes_left:
                            plan["artifact_truncated"] = True
                            break
                        raw_bytes_left -= len(encoded) + 1
                        projected.append(encoded.decode("utf-8"))
                    raw_parts.append("\n".join(projected))
                # A host deadline must not consume another host's budget.
                # Preserve the failed receipt and partial matches without retrying;
                # global expiry and other execution failures still stop the sweep.
                if codes[-1] is None and not (
                    host_timeout and deadline - time.monotonic() >= _MIN_PROCESS_SECONDS
                ):
                    break
            jsonl_file.write_text("\n".join(raw_parts), encoding="utf-8")
            errors_file.write_text("\n".join(error_parts), encoding="utf-8")
            write_lines(targets_file, urls)
            plan["processes_attempted"] = attempted
            code = (
                0
                if len(codes) == len(plan["targets"]) and all(c == 0 for c in codes)
                else 1
            )
            completed = subprocess.CompletedProcess(
                command, code, "", "\n".join(stderr_parts)
            )
    except Exception as exc:  # noqa: BLE001
        LOG.warning("nuclei scan failed for %d endpoint(s): %s", len(candidates), exc)
        result["skipped_reason"] = "nuclei_run_failed"
        # Keep partial matches emitted before a deadline, never claim ran.
        stderr = getattr(exc, "stderr", "") or ""
        stderr = (
            stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr
        )
        completed = subprocess.CompletedProcess(command, None, "", stderr)
    finally:
        if snapshot_dir is not None:
            shutil.rmtree(snapshot_dir, ignore_errors=True)
        if private_dir is not None:
            shutil.rmtree(private_dir, ignore_errors=True)

    # Not ``check=True`` above, and still not a skip: nuclei's findings from a
    # run that then exited non-zero are kept as before. But such a run did not
    # demonstrably complete, so it does not count as having looked.
    returncode = getattr(completed, "returncode", None)
    coverage["returncode"] = returncode if isinstance(returncode, int) else None
    coverage["ran"] = coverage["returncode"] == 0
    if plan is not None:
        receipts = plan.get("process_results", [])
        coverage["ran"] = (
            coverage["ran"]
            and len(receipts) == len(plan["targets"])
            and all(r["complete"] for r in receipts)
        )
    if coverage["returncode"] not in (0, None):
        LOG.warning("nuclei exited %s; its run is not counted as coverage", returncode)
    stderr_text = getattr(completed, "stderr", None)
    stderr_text = stderr_text if isinstance(stderr_text, str) else ""
    loaded = _TEMPLATES_LOADED.findall(stderr_text)
    coverage["templates_loaded"] = (
        (sum(map(int, loaded)) if plan else int(loaded[-1])) if loaded else None
    )
    coverage["skipped_targets"] = sorted(
        set(_TARGET_SKIPPED.findall(stderr_text))
        | _permanent_error_addresses(errors_file)
    )
    coverage["errors_log_truncated"] = _cap_errors_log(errors_file) or bool(
        plan and plan.get("artifact_truncated")
    )
    if coverage["errors_log_truncated"]:
        coverage["ran"] = False
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
    actionable: list[dict[str, Any]] = []
    if jsonl_file.is_file():
        for line in jsonl_file.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            raw = _parse_result_line(line)
            if raw is None:
                if line.strip():
                    coverage["ran"] = False
                    if plan is not None:
                        plan["malformed_result"] = True
                continue
            finding = _to_finding(raw)
            row = _non_cve_row(finding, config)
            if row is not None:
                actionable.append(row)
            findings.append(finding)
            cve_findings.extend(_to_vulnerability_rows(finding))

    # A submitted target is not evidence of a completed target. Only a
    # successful run with its pinned catalog loaded can contribute here.
    complete = (
        coverage["ran"]
        and not coverage["skipped_targets"]
        and coverage["templates_expected"] is not None
        and coverage["templates_loaded"] == coverage["templates_expected"]
        and not coverage["template_ids_missing"]
        and not coverage["template_ids_excluded"]
        and not coverage["template_ids_ambiguous"]
        and not (plan and plan.get("artifact_truncated"))
    )
    if exact_targets:
        # The receipt is earned by successful execution, never configuration.
        # It carries only digests/canonical subjects, not raw paths or queries.
        coverage['verification_targets'] = [
            {'subject': target['subject'], 'template_id': target['template_id'],
             'input_contract': 'exact-baseurl-v1',
             'template_sha256': next(row['sha256'] for row in selected if row['id'] == target['template_id']),
             'complete': bool(complete and not truncated
                              and not (errors_file.is_file() and errors_file.stat().st_size))}
            for target in exact_targets
        ]
    result["checked_count"] = len(candidates) if complete else 0
    if plan is not None:
        plan["process_returncode"] = coverage["returncode"]
        plan["templates_loaded"] = coverage["templates_loaded"]
        plan["completed_targets"] = len(candidates) if complete else None
        # Nuclei reports template loading, not per-request execution counts.
        plan["complete"] = (
            complete and not truncated and not plan.get("artifact_truncated", False)
        )
        plan["execution_status"] = "completed" if complete else "incomplete"
        save_json(output_dir / "nuclei_plan.json", plan)
    result["findings"] = findings
    result["cve_findings"] = cve_findings
    result["actionable_findings"] = actionable
    _persist(output_dir, result)
    LOG.info(
        "nuclei: %d endpoint(s) scanned -> %d finding(s) (%d with CVE)%s",
        len(candidates),
        len(findings),
        len(cve_findings),
        " [truncated]" if truncated else "",
    )
    return result


# ---------------------------------------------------------------------------
# The network pass (#547)
# ---------------------------------------------------------------------------


def _finding_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    """``(template id, host, port)`` as one identity, whichever way nuclei wrote the host.

    nuclei v3.11.1 writes ``host`` and ``port`` as separate fields for a URL
    input and for a ``host:port`` input alike (checked live); the normalising is
    for a bracketed IPv6 host or a ``host:port`` that ever lands in ``host``.
    """
    host = str(finding.get("host") or "").strip().lower()
    port = str(finding.get("port") or "").strip()
    if host.startswith("["):
        host, _, rest = host[1:].partition("]")
        port = port or rest.lstrip(":")
    elif host.count(":") == 1:
        host, _, tail = host.partition(":")
        port = port or tail
    return str(finding.get("template_id") or ""), host, port


def _network_row(finding: dict[str, Any]) -> dict[str, Any]:
    """The ``vulnerabilities.json`` row of a network-pass finding that names no CVE."""
    return {
        "host": finding["host"],
        "port": finding["port"],
        "script_id": f"nuclei:{finding['template_id']}",
        "source": "nuclei",
        "protocol": "tcp",
        "cve": "",
        "cvss": None,
        "severity": finding["severity"],
        "title": finding["name"] or finding["template_id"],
        "detail": finding["matched_at"],
        "cwe": finding.get("cwe") or [],
        "epss": None,
        "in_kev": False,
    }


#: The network pass may run this long past the sweep's own ``overall_timeout_seconds``
#: (the stage deadline is that plus this), so a sweep that used its whole budget
#: does not starve it, and the stage as a whole stays bounded.
NETWORK_GRACE_SECONDS = 120

#: A process started with less than this left would be killed before it loaded templates.
_MIN_PROCESS_SECONDS = 10

#: Why the pass is not even attempted, when the sweep's own preconditions fail.
_UNAVAILABLE = ("nuclei.disabled", "nuclei_binary_missing", "templates_dir_missing")


def _network_pass_block(config: NucleiConfig) -> dict[str, Any]:
    """The evidence record of the pass, empty: what was configured, nothing run."""
    return {
        "enabled": config.network_templates,
        "ran": False,
        "skipped_reason": None,
        "targets_considered": 0,
        "truncated": False,
        "severities": list(config.severities),
        "duplicates_of_sweep": 0,
        "passes": [],
    }


def _resolve_network_templates(
    rule: NetworkRule, config: NucleiConfig, dirs: Sequence[Path]
) -> tuple[list[str], int, dict[str, list[str]], dict[str, str]]:
    """``(ids to run, templates nuclei must load, {why not: ids}, {id: sha256})`` for one rule.

    Four reasons an id of the table is not run, each recorded by name so the
    absence of a finding is not read as a look: not on this host (``missing``),
    every file of it carries a tag the host excludes (``excluded``), every
    file is below the configured severity floor (``below_floor``), or the id
    names more than one file (``ambiguous``: a copy in ``custom_templates_dir``
    shadowing the baked one). The table's choice of an id is a judgement about
    one reviewed file; a second file under the same id is a template nobody
    reviewed, and it would run against every SMB host. An empty ``severities``
    list is no floor, as in the sweep.

    The sha256 of the file that will run is recorded, not enforced: pinning it
    would silently switch the pass off with every nuclei-templates bump.
    """
    index = index_template_facts(rule.template_ids, dirs)
    excluded_tags = {tag.lower() for tag in config.exclude_tags}
    floor = {severity.lower() for severity in config.severities}
    run: list[str] = []
    expected = 0
    skipped: dict[str, list[str]] = {
        "missing": [],
        "excluded": [],
        "below_floor": [],
        "ambiguous": [],
    }
    digests: dict[str, str] = {}
    for template_id in rule.template_ids:
        files = index.get(template_id, [])
        loadable = [facts for facts in files if not facts[0] & excluded_tags]
        if not files:
            skipped["missing"].append(template_id)
        elif len(files) > 1:
            skipped["ambiguous"].append(template_id)
        elif not loadable:
            skipped["excluded"].append(template_id)
        elif floor and not any(severity in floor for _tags, severity, _sha in loadable):
            skipped["below_floor"].append(template_id)
        else:
            run.append(template_id)
            expected += len(loadable)
            digests[template_id] = loadable[0][2]
    return run, expected, skipped, digests


def _run_network_pass(
    open_ports: list[str],
    config: NucleiConfig,
    output_dir: Path,
    resolvers: Sequence[str],
    unavailable: str | None,
    deadline: float,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """``(coverage["network"], findings)``. Never raises.

    One nuclei process per rule that has targets: its ids against its
    endpoints only. ``unavailable`` is the sweep's own reason for not having
    a usable nuclei (disabled, binary or templates missing), passed on as the
    pass's reason so the two blocks agree. ``deadline`` is a ``time.monotonic()``
    instant: each process gets at most what is left of it, and a rule reached
    after it is recorded as ``stage_deadline_exhausted``, not run.
    """
    block = _network_pass_block(config)
    findings: list[dict[str, Any]] = []
    if not config.network_templates:
        block["skipped_reason"] = "network_templates_disabled"
        return block, findings
    if unavailable in _UNAVAILABLE:
        block["skipped_reason"] = unavailable
        return block, findings

    plan = plan_network_targets(
        open_ports, load_service_names(output_dir), NETWORK_RULES
    )
    block["targets_considered"] = sum(len(endpoints) for endpoints in plan.values())
    if not plan:
        block["skipped_reason"] = "no_network_targets"
        return block, findings

    templates_dir = Path(config.templates_dir)
    custom_dir = (
        Path(config.custom_templates_dir) if config.custom_templates_dir else None
    )
    dirs = [
        templates_dir,
        *([custom_dir] if custom_dir and custom_dir.exists() else []),
    ]
    resolvers_file = output_dir / "nuclei_resolvers.txt"
    resolver_lines = [host_port(resolver) for resolver in scan_resolvers(resolvers)]
    resolvers_file.write_text("\n".join(resolver_lines) + "\n", encoding="utf-8")

    for rule_name, endpoints in plan.items():
        rule = next(
            candidate for candidate in NETWORK_RULES if candidate.name == rule_name
        )
        truncated = len(endpoints) > config.max_targets
        endpoints = endpoints[: config.max_targets]
        block["truncated"] = block["truncated"] or truncated
        targets = [target_string(host, port) for host, port in endpoints]
        run, expected, skipped, digests = _resolve_network_templates(rule, config, dirs)
        entry: dict[str, Any] = {
            "rule": rule.name,
            "nse": list(rule.nse),
            "ran": False,
            "returncode": None,
            "skipped_reason": None,
            "targets": sorted(targets),
            "truncated": truncated,
            "template_ids_requested": list(rule.template_ids),
            "template_ids_missing": skipped["missing"],
            "template_ids_excluded": skipped["excluded"],
            "template_ids_below_floor": skipped["below_floor"],
            "template_ids_ambiguous": skipped["ambiguous"],
            "template_sha256": digests,
            "templates_loaded": None,
            "templates_expected": expected,
            "skipped_targets": [],
            "errors_log_truncated": False,
        }
        block["passes"].append(entry)
        if any(skipped.values()):
            LOG.warning(
                "nuclei network pass %s: not run -- missing: %s; excluded by nuclei.exclude_tags: %s; "
                "below nuclei.severities: %s; more than one file under the id: %s",
                rule.name,
                ", ".join(skipped["missing"]) or "none",
                ", ".join(skipped["excluded"]) or "none",
                ", ".join(skipped["below_floor"]) or "none",
                ", ".join(skipped["ambiguous"]) or "none",
            )
        if not run:
            entry["skipped_reason"] = "no_template_available"
            continue

        targets_file = output_dir / f"nuclei_network_{rule.name}_targets.txt"
        jsonl_file = output_dir / f"nuclei_network_{rule.name}_raw.jsonl"
        errors_file = output_dir / f"nuclei_network_{rule.name}_errors.jsonl"
        write_lines(targets_file, targets)
        jsonl_file.unlink(missing_ok=True)
        errors_file.unlink(missing_ok=True)
        command = [
            "nuclei",
            "-disable-update-check",
            "-list", str(targets_file),
            "-templates", str(templates_dir),
        ]  # fmt: skip
        if custom_dir is not None and custom_dir.exists():
            command.extend(["-templates", str(custom_dir)])
        command.extend(["-resolvers", str(resolvers_file), "-id", ",".join(run)])
        if config.exclude_tags:
            command.extend(["-exclude-tags", ",".join(config.exclude_tags)])
        # No -silent: "Templates loaded for current scan" is INFO and is the
        # only proof the ids were loaded. No OAST: nothing in the table needs it.
        command.extend([
            "-jsonl-export", str(jsonl_file),
            "-rate-limit", str(config.rate_limit),
            "-concurrency", str(config.concurrency),
            "-timeout", str(config.timeout_seconds),
            "-retries", str(config.retries),
            "-max-host-error", str(config.max_host_error),
            "-elog", str(errors_file),
            "-no-color",
            "-no-interactsh",
        ])  # fmt: skip
        remaining = deadline - time.monotonic()
        if remaining < _MIN_PROCESS_SECONDS:
            entry["skipped_reason"] = "stage_deadline_exhausted"
            continue
        completed = None
        try:
            completed = run_command(
                command,
                timeout=min(config.overall_timeout_seconds, int(remaining)),
                retries=0,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            # A timeout or a crash is not a look (``ran`` stays false), but what
            # nuclei had already written to its JSONL is real observation and is
            # kept, as the sweep keeps the findings of a run that exited non-zero.
            LOG.warning(
                "nuclei network pass %s failed for %d endpoint(s): %s",
                rule.name,
                len(targets),
                exc,
            )
            entry["skipped_reason"] = "nuclei_run_failed"

        if completed is not None:
            returncode = getattr(completed, "returncode", None)
            entry["returncode"] = returncode if isinstance(returncode, int) else None
            entry["ran"] = entry["returncode"] == 0
            if entry["returncode"] not in (0, None):
                LOG.warning(
                    "nuclei network pass %s exited %s; not counted as coverage",
                    rule.name,
                    returncode,
                )
            stderr_text = getattr(completed, "stderr", None)
            stderr_text = stderr_text if isinstance(stderr_text, str) else ""
            loaded = _TEMPLATES_LOADED.findall(stderr_text)
            entry["templates_loaded"] = int(loaded[-1]) if loaded else None
            entry["skipped_targets"] = sorted(
                set(_TARGET_SKIPPED.findall(stderr_text))
                | _permanent_error_addresses(errors_file)
            )
            entry["errors_log_truncated"] = _cap_errors_log(errors_file)
        if jsonl_file.is_file():
            for line in jsonl_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                raw = _parse_result_line(line)
                if raw is not None:
                    findings.append(
                        {**_to_finding(raw), "pass": "network", "rule": rule.name}
                    )

    block["ran"] = bool(block["passes"]) and all(
        entry["ran"] for entry in block["passes"]
    )
    if not block["ran"]:
        # Every pass has its own reason; the block says in one word that the
        # network side as a whole did not complete.
        block["skipped_reason"] = "not_all_passes_ran"
    return block, findings


def run_nuclei_scan(
    open_ports: list[str],
    config: NucleiConfig,
    output_dir: Path,
    resolvers: Sequence[str] = (),
) -> dict[str, Any]:
    """Run nuclei against already-open web ports, then the network pass. Never raises.

    ``resolvers`` is ``dns.resolvers`` from the scanner config. Empty means
    the system's resolvers, never nuclei's built-in public ones (see
    ``dns_resolvers.py``).

    The web sweep is what it was; the network pass (module docstring) adds its
    findings to ``findings``/``cve_findings`` marked ``"pass": "network"`` and
    its evidence to ``coverage["network"]``. A pinned run (``template_ids``)
    makes no network pass and its ``coverage`` is exactly what it was before the
    pass existed: a verification loads the ids it was sent and nothing else, and
    the closure rules (``api/services/verification_coverage.py``) read only
    that. So ``network`` is absent there and in a ``nuclei.json`` written
    earlier, and present, with a ``skipped_reason`` when nothing ran, in every
    sweep.
    """
    started = time.monotonic()
    result = _run_web_sweep(open_ports, config, output_dir, resolvers)
    # Files of an earlier attempt in this run directory (a --resume after the
    # pass was switched off, or found nothing to do) must not outlive it: the
    # evidence projection reads every nuclei_network_*_raw.jsonl it finds, and
    # nuclei.json is what says whether the pass ran.
    try:
        for stale in output_dir.glob("nuclei_network_*"):
            stale.unlink(missing_ok=True)
    except OSError:
        # Fail-soft like the rest of the stage: a stale file we cannot remove is
        # logged, and nuclei.json still says whether the pass ran.
        LOG.warning(
            "could not remove stale nuclei_network_* files in %s",
            output_dir,
            exc_info=True,
        )
    if config.template_ids:
        return result
    deadline = started + config.overall_timeout_seconds + NETWORK_GRACE_SECONDS
    try:
        block, network_findings = _run_network_pass(
            open_ports,
            config,
            output_dir,
            resolvers,
            result.get("skipped_reason"),
            deadline,
        )
    except Exception:  # noqa: BLE001
        # Fail-soft like the sweep: a planning bug must not fail the scan, and
        # the block says the pass did not run, which a reader can act on.
        LOG.exception("nuclei network pass failed")
        block, network_findings = _network_pass_block(config), []
        block["skipped_reason"] = "network_pass_error"
    # A host with a web port and SMB gets the SMB template twice: the sweep
    # hands nuclei a URL, and for a javascript template nuclei then uses the
    # template's own port (445), not the URL's (checked live, v3.11.1: host and
    # port fields are the same for both inputs). One finding per
    # (template, host, port), the sweep's first.
    seen = {_finding_key(f) for f in result["findings"]}
    fresh = [f for f in network_findings if _finding_key(f) not in seen]
    block["duplicates_of_sweep"] = len(network_findings) - len(fresh)
    result["coverage"]["network"] = block
    for finding in fresh:
        result["cve_findings"].extend(_to_vulnerability_rows(finding))
    result["findings"].extend(fresh)
    # Rows for vulnerabilities.json. A CVE-tagged finding is a CVE row like any
    # nuclei one. A match of a template of the network table that names no CVE
    # gets a row keyed by ``nuclei:<template id>`` and port, the shape a plugin
    # finding has (``cve: ""``), which the report dedupe and the API tracker
    # (``vulnerabilities._detector_of``) already understand. That holds for a
    # match the web sweep made too -- it reaches the SMB port of any host with a
    # web port -- so the rows come from every finding, deduplicated by the same
    # key, not from the pass alone. The web sweep's other CVE-less matches stay
    # out, as before.
    table_ids = {template for rule in NETWORK_RULES for template in rule.template_ids}
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in result["findings"]:
        if (
            config.network_templates
            and finding["template_id"] in table_ids
            and finding["host"]
            and not _to_vulnerability_rows(finding)
        ):
            rows.setdefault(_finding_key(finding), _network_row(finding))
    result["network_vulnerabilities"] = list(rows.values())
    _persist(output_dir, result)
    if fresh:
        LOG.info("nuclei network pass: %d finding(s)", len(fresh))
    return result


def nuclei_vulnerability_rows(nuclei_result: dict[str, Any]) -> list[dict[str, Any]]:
    """What the report merges from a nuclei result: its CVE rows, then the network pass's CVE-less ones.

    Also the answer for a ``--resume`` that reloads ``nuclei.json`` (a file from
    before the pass has no ``network_vulnerabilities``, and a skipped stage has
    only the fallback ``{"cve_findings": []}``).
    """
    return (list(nuclei_result.get("cve_findings") or [])
            + list(nuclei_result.get("network_vulnerabilities") or [])
            + list(nuclei_result.get("actionable_findings") or []))
