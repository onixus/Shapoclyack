"""What a verification run demonstrably re-checked (#451, #450).

A verification re-scan closes a finding as ``machine_verified`` when its run
does not report it. "Did not report it" is only evidence of a fix if the run
*looked* -- and a run can succeed without looking at all: the nuclei binary or
its templates missing (``nuclei.json`` says ``skipped_reason`` and the run
carries on), a medium nuclei finding re-checked by ``intent=vuln``, which loads
critical and high templates only, an NSE finding re-checked on the Pulse
backend, which runs no NSE, a port that did not answer this time. Each of those
closed a finding as verified-fixed before this module existed.

So the closure asks, per detector the finding has (``vulnerabilities.detectors``),
whether this run's own artifacts show that detector re-checked the finding's
endpoint, and gets back the list of what was *not* covered. Empty means closable.
Anything else is ``verification_inconclusive``: the finding goes back to
``FIXING`` and the list is on the event.

The evidence, per detector:

``nuclei``
    ``nuclei.json`` with no ``skipped_reason`` and a ``coverage`` block (written
    since overlay v2) saying nuclei ran and exited 0, the endpoint among the
    URLs it was given -- the host spelled as the detector saw it, IP for IP and
    name for name, because a template that matched a virtual host proves
    nothing against the bare address -- and the detector's template among the
    ids the run pinned and found. A run that did not pin it is not accepted:
    whether a severity sweep happened to load a given template is not
    something the run records.
``pulse``
    ``pulse/raw.json`` with ``adapter.cve`` true (also since v2: a receipt
    alone proves the port was probed, not that its banner was matched against
    anything) and a success receipt (``completion``) for the host and port.
``nmap-nse``
    An nmap XML that finished with ``exit="success"``, was run with the
    script named in ``--script`` (a category such as ``vuln`` does not count:
    which scripts it expanded to is not in the file), and lists the host with
    the port open. A host-level script finding has no port and needs the host.
no detectors at all (a row from before 0079 that nothing could be derived for)
    The legacy rule, and the weaker one: what ``intent=vuln`` always ran, i.e.
    the ``pulse`` rule on the finding's port, against any address of its asset.

A detector stored without a host (backfilled by 0079) is likewise matched
against any address of the finding's asset. A detector name this module has no
rule for is never covered. Artifacts are read from the run's local working copy
(``runs_service.get_written_run_dir``), the same one the findings are read from,
and read once per run however many findings are waiting on it.
"""

from __future__ import annotations

import ipaddress
import logging
import shlex
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# nmap XML embeds banner and NSE output a scanned host controls; parsed through
# defusedxml for the same reason scanner/pipeline/report.py does.
from defusedxml.ElementTree import fromstring as safe_fromstring

from api.services import runs as runs_service
from scanner.pipeline import pulse_progress

LOG = logging.getLogger("shapoclyack.verification")

PULSE = "pulse"
NUCLEI = "nuclei"
NMAP_NSE = "nmap-nse"
#: The detectors this module can judge. Recorded detectors outside it are kept
#: on the finding for the record and are never counted as covered.
KNOWN_DETECTORS = (PULSE, NUCLEI, NMAP_NSE)


def normalize_host(value: str | None) -> str:
    """One host as both sides compare it: an IP canonicalised, a name lowercased."""
    text = str(value or "").strip().strip("[]").rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _port(value: Any) -> int | None:
    try:
        port = int(str(value).strip().split("/")[0])
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _script_names(args: str) -> set[str]:
    """The scripts named in an nmap command line's ``--script`` arguments."""
    try:
        argv = shlex.split(args)
    except ValueError:
        argv = args.split()
    names: set[str] = set()
    for index, token in enumerate(argv):
        if token == "--script" and index + 1 < len(argv):
            value = argv[index + 1]
        elif token.startswith("--script="):
            value = token.split("=", 1)[1]
        else:
            continue
        for part in value.split(","):
            name = Path(part.strip()).name
            names.add(name[: -len(".nse")] if name.endswith(".nse") else name)
    return {name for name in names if name}


@dataclass
class _NseRun:
    scripts: set[str]
    open_ports: dict[str, set[int]] = field(default_factory=dict)


class RunCoverage:
    """One run's coverage evidence, each artifact read the first time a rule asks."""

    def __init__(self, run_dir: Path | None) -> None:
        self.run_dir = run_dir

    def _json(self, relative: str) -> dict[str, Any] | None:
        if self.run_dir is None:
            return None
        raw = runs_service._load_json(self.run_dir / relative)  # noqa: SLF001
        return raw if isinstance(raw, dict) else None

    @cached_property
    def nuclei(self) -> dict[str, Any] | None:
        return self._json("nuclei.json")

    @cached_property
    def pulse(self) -> dict[str, Any] | None:
        return self._json("pulse/raw.json")

    @cached_property
    def nse(self) -> list[_NseRun]:
        if self.run_dir is None:
            return []
        nmap_dir = self.run_dir / "nmap"
        if not nmap_dir.is_dir():
            return []
        runs: list[_NseRun] = []
        for xml_file in sorted(nmap_dir.rglob("*.xml")):
            try:
                root = safe_fromstring(xml_file.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ET.ParseError):
                continue
            finished = root.find("./runstats/finished")
            if finished is None or finished.attrib.get("exit") != "success":
                continue
            run = _NseRun(scripts=_script_names(root.attrib.get("args", "")))
            for host in root.findall("host"):
                addresses = {
                    normalize_host(address.attrib.get("addr"))
                    for address in host.findall("address")
                    if address.attrib.get("addrtype") in ("ipv4", "ipv6")
                }
                ports = {
                    port
                    for element in host.findall("./ports/port")
                    if (state := element.find("state")) is not None
                    and state.attrib.get("state") == "open"
                    and (port := _port(element.attrib.get("portid"))) is not None
                }
                for address in addresses:
                    run.open_ports.setdefault(address, set()).update(ports)
            runs.append(run)
        return runs

    # ------------------------------------------------------------------
    # The rules
    # ------------------------------------------------------------------

    def _nuclei_gap(self, ref: str, hosts: set[str], port: int | None) -> str | None:
        document = self.nuclei
        if document is None:
            return "nuclei_not_run"
        if document.get("skipped_reason"):
            return f"nuclei_skipped:{document['skipped_reason']}"
        coverage = document.get("coverage")
        if not isinstance(coverage, dict):
            return "nuclei_coverage_not_recorded"
        if coverage.get("ran") is not True:
            return f"nuclei_did_not_complete:{coverage.get('returncode')}"
        missing = set(coverage.get("template_ids_missing") or [])
        excluded = set(coverage.get("template_ids_excluded") or [])
        if ref in missing:
            return "template_missing"
        if ref in excluded:
            return "template_excluded"
        if not ref or ref not in set(coverage.get("template_ids_requested") or []):
            return "template_not_pinned"
        if port is None:
            return "no_port"
        targets = set()
        for url in coverage.get("targets") or []:
            try:
                parts = urlsplit(str(url))
                targets.add((normalize_host(parts.hostname), parts.port))
            except ValueError:
                continue
        if not any((host, port) in targets for host in hosts):
            return "endpoint_not_targeted"
        return None

    def _pulse_gap(self, hosts: set[str], port: int | None) -> str | None:
        document = self.pulse
        if document is None:
            return "pulse_not_run"
        adapter = document.get("adapter") if isinstance(document.get("adapter"), dict) else {}
        if "cve" not in adapter:
            return "pulse_cve_matching_not_recorded"
        if adapter.get("cve") is not True:
            return "pulse_cve_matching_off"
        receipts = {
            normalize_host(host): ports
            for host, ports in pulse_progress._successful_tcp_ports(document).items()  # noqa: SLF001
        }
        for host in hosts:
            probed = receipts.get(host)
            if probed and (port is None or port in probed):
                return None
        return "endpoint_not_probed"

    def _nse_gap(self, ref: str, hosts: set[str], port: int | None) -> str | None:
        runs = self.nse
        if not runs:
            return "nse_not_run"
        with_script = [run for run in runs if ref and ref in run.scripts]
        if not with_script:
            return "script_not_run"
        for run in with_script:
            for host in hosts:
                ports = run.open_ports.get(host)
                if ports is None:
                    continue
                if port is None or port in ports:
                    return None
        return "endpoint_not_scanned"

    def gaps(
        self,
        detectors: list[dict[str, Any]],
        *,
        port: str | None,
        asset_hosts: set[str],
    ) -> list[dict[str, Any]]:
        """What this run did not demonstrably re-check, one row per detector.

        ``port`` is the finding's; ``asset_hosts`` every address its asset has,
        used for a detector that never recorded where it looked.
        """
        fallback_hosts = {normalize_host(host) for host in asset_hosts if host}
        entries = [entry for entry in detectors if isinstance(entry, dict)]
        legacy = not entries
        if legacy:
            entries = [{"detector": PULSE, "ref": None, "host": None, "port": port}]
        out: list[dict[str, Any]] = []
        for entry in entries:
            detector = str(entry.get("detector") or "")
            ref = str(entry.get("ref") or "")
            host = entry.get("host")
            hosts = {normalize_host(host)} if host else fallback_hosts
            endpoint_port = _port(entry.get("port") if entry.get("port") not in (None, "") else port)
            if detector == NUCLEI:
                reason = self._nuclei_gap(ref, hosts, endpoint_port)
            elif detector == PULSE:
                reason = self._pulse_gap(hosts, endpoint_port)
            elif detector == NMAP_NSE:
                reason = self._nse_gap(ref, hosts, endpoint_port)
            else:
                reason = "no_coverage_rule"
            if reason is not None:
                out.append(
                    {
                        "detector": detector or "unknown",
                        "ref": ref or None,
                        "host": host or None,
                        "port": entry.get("port") or port,
                        "reason": reason,
                        **({"legacy_rule": True} if legacy else {}),
                    }
                )
        return out


def describe(gaps: list[dict[str, Any]]) -> str:
    """One line per gap, for the event note an operator reads first."""
    parts = []
    for gap in gaps:
        what = gap["detector"] + (f" {gap['ref']}" if gap.get("ref") else "")
        where = f"{gap.get('host') or 'any address of the asset'}:{gap.get('port') or '-'}"
        parts.append(f"{what} on {where}: {gap['reason']}")
    return "; ".join(parts)
