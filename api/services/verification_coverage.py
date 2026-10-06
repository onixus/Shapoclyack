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
    since overlay v2) saying nuclei ran and exited 0, that nuclei itself
    reported loading at least the pinned templates the sensor had, that it
    did not drop the endpoint as unresponsive, the endpoint among the
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
    A CVE pulse found online (origin ``nvd``) needs ``adapter.cve_online`` as
    well, and a CVE found with offline ruleset R needs the run's
    ``adapter.ruleset`` to be R or newer.
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
from scanner.pipeline.protocol import parse_endpoint
from scanner.pipeline.pulse_probe import parse_ruleset

LOG = logging.getLogger("shapoclyack.verification")

PULSE = "pulse"
NUCLEI = "nuclei"
NMAP_NSE = "nmap-nse"
#: The detectors this module can judge. Recorded detectors outside it are kept
#: on the finding for the record and are never counted as covered.
KNOWN_DETECTORS = (PULSE, NUCLEI, NMAP_NSE)
#: The ``source`` pulse gives a CVE its online NVD lookup found (GenDec
#: ``src/scanner/cve.rs``: ``local`` for its offline rules, ``nvd`` online),
#: and so the ref of such a detector (``script_id`` ``pulse:nvd``).
PULSE_ONLINE_ORIGIN = "nvd"


def normalize_host(value: str | None) -> str:
    """One host as both sides compare it: an IP canonicalised, a name lowercased."""
    text = str(value or "").strip().strip("[]").rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _endpoint(value: Any) -> tuple[str, int | None]:
    """``(host, port)`` from nuclei's ``host:port`` / ``[v6]:port`` spelling."""
    host, _, port = str(value).strip().rpartition(":")
    return normalize_host(host), _port(port)


def port_of(value: Any) -> int | None:
    """A finding's port as the rules compare it, or ``None``."""
    return _port(value) if value not in (None, "") else None


def _explicit_ports(port_args: Any) -> set[int]:
    """The TCP ports a naabu ``-p`` list names; empty for ``-top-ports``."""
    args = [str(arg) for arg in port_args or []]
    if "-p" not in args or args.index("-p") + 1 >= len(args):
        return set()
    out: set[int] = set()
    for part in args[args.index("-p") + 1].split(","):
        part = part.strip()
        if part.startswith("u:"):
            continue
        low, _, high = part.partition("-")
        first, last = _port(low), _port(high) if high else _port(low)
        if first and last and first <= last and last - first <= 65535:
            out.update(range(first, last + 1))
    return out


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
    # host -> {(port, "tcp"|"udp")}
    open_ports: dict[str, set[tuple[int, str]]] = field(default_factory=dict)


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
                    (port, str(element.attrib.get("protocol") or "tcp").lower())
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
    # Reachability: what the port stage and discovery recorded
    # ------------------------------------------------------------------

    @cached_property
    def reachability(self) -> dict[tuple[str, int], dict[str, Any]]:
        """The run's connect-probe results (``reachability.json``) by endpoint."""
        document = self._json("reachability.json") or {}
        out: dict[tuple[str, int], dict[str, Any]] = {}
        for probe in document.get("probes") or []:
            if isinstance(probe, dict) and _port(probe.get("port")):
                out[(normalize_host(probe.get("host")), int(probe["port"]))] = probe
        return out

    @cached_property
    def port_scans(self) -> list[dict[str, Any]]:
        """The port stage's per-batch records (``ports/<tag>.scan.json``, v2)."""
        if self.run_dir is None:
            return []
        ports = self.run_dir / "ports"
        if not ports.is_dir():
            return []
        records = []
        for record_file in sorted(ports.glob("*.scan.json")):
            record = runs_service._load_json(record_file)  # noqa: SLF001
            if isinstance(record, dict) and record.get("protocol") == "tcp":
                records.append(record)
        return records

    @cached_property
    def open_tcp(self) -> set[tuple[str, int]]:
        """Every TCP endpoint anything in this run saw open: naabu, Pulse."""
        out: set[tuple[str, int]] = set()
        if self.run_dir is None:
            return out
        sources = [self.run_dir / "open_ports.txt"]
        ports_dir = self.run_dir / "ports"
        if ports_dir.is_dir():
            sources.extend(sorted(ports_dir.glob("*.open.txt")))
        for source in sources:
            if not source.is_file():
                continue
            for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
                parsed = parse_endpoint(line.strip()) if line.strip() else None
                if parsed is not None and parsed.protocol == "tcp" and _port(parsed.port):
                    out.add((normalize_host(parsed.host), int(parsed.port)))
        for row in (self.pulse or {}).get("open") or []:
            if not isinstance(row, dict):
                continue
            proto = str(row.get("protocol") or "tcp").lower()
            port = _port(row.get("port"))
            if proto in {"tcp", "tcpsyn", "syn"} and port and row.get("open") is not False:
                for key in ("ip", "host"):
                    if row.get(key):
                        out.add((normalize_host(row[key]), port))
        out.update(key for key, probe in self.reachability.items() if probe.get("result") == "open")
        return out

    def endpoint_unreachable(
        self, hosts: set[str], port: int | None, *, protocol: str | None = "tcp"
    ) -> dict[str, Any] | None:
        """Evidence that ``port`` is closed on every one of ``hosts``, or ``None``.

        All of it has to hold, on each host — an IP: a name is resolved by
        the scanner, and which address the port stage saw for it is not
        recorded:

        * the host **refused** the connection: the run's own connect probe
          (``reachability.json``, a verification run's) got ``ECONNREFUSED``
          on every attempt. A refusal is the host's stack answering, so it is
          the proof of life too; a timeout or an unreachable route is what a
          firewall dropping the packets looks like, and proves nothing;
        * the port was in the port stage's explicit list for that host, in a
          batch that finished (a ``-top-ports`` set is not explicit);
        * nothing in the run saw the port open — not naabu, not Pulse, not
          the probe.

        Anything short of that is the firewalled-during-the-window case the
        tracker does not forgive.
        """
        if port is None or not hosts or protocol != "tcp":
            # Every piece of evidence here is TCP; a UDP or protocol-unknown
            # finding is never closed by it.
            return None
        evidence = []
        for host in sorted(hosts):
            if not _is_ip(host):
                return None
            if (host, port) in self.open_tcp:
                return None
            probe = self.reachability.get((host, port))
            if probe is None or probe.get("result") != "refused":
                return None
            batches = [
                record
                for record in self.port_scans
                if host in {normalize_host(h) for h in record.get("hosts") or []}
            ]
            if not batches or not all(record.get("complete") is True for record in batches):
                return None
            if not any(
                port in _explicit_ports(record.get("port_args"))
                and port not in set(record.get("exclude_ports") or [])
                for record in batches
            ):
                return None
            evidence.append(
                {"host": host, "port": port, "probe": list(probe.get("attempts") or [])}
            )
        return {"endpoints": evidence}

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
        requested = set(coverage.get("template_ids_requested") or [])
        if not ref or ref not in requested:
            return "template_not_pinned"
        # nuclei's own count, not the index's: a template the index found but
        # nuclei refused to parse is loaded by nobody.
        loaded = coverage.get("templates_loaded")
        if not isinstance(loaded, int):
            return "nuclei_templates_loaded_not_recorded"
        if loaded < len(requested - missing - excluded):
            return "nuclei_templates_not_loaded"
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
        skipped = {_endpoint(value) for value in coverage.get("skipped_targets") or []}
        if all((host, port) in skipped for host in hosts if (host, port) in targets):
            # Given to nuclei and dropped by it as unresponsive (a refused
            # port, or -max-host-error reached): never checked.
            return "nuclei_target_skipped"
        return None

    def _pulse_gap(
        self, ref: str, ruleset: str | None, hosts: set[str], port: int | None
    ) -> str | None:
        document = self.pulse
        if document is None:
            return "pulse_not_run"
        adapter = document.get("adapter") if isinstance(document.get("adapter"), dict) else {}
        if "cve" not in adapter:
            return "pulse_cve_matching_not_recorded"
        if adapter.get("cve") is not True:
            return "pulse_cve_matching_off"
        if ref == PULSE_ONLINE_ORIGIN and adapter.get("cve_online") is not True:
            # Found by an NVD keyword query, re-checked against the offline
            # rules only: those never contained it, so their silence is no
            # evidence. Online lookups are the sensor host's own setting
            # (NVD key, outbound HTTPS), deliberately not something a job
            # can turn on.
            return "pulse_cve_online_off"
        if ruleset:
            current = adapter.get("ruleset")
            if not current:
                return "pulse_ruleset_not_recorded"
            found_with, run_with = parse_ruleset(ruleset), parse_ruleset(str(current))
            if found_with is None or run_with is None:
                # No "older or newer" about an id either side cannot read.
                return "pulse_ruleset_unparseable"
            if run_with < found_with:
                # A rule added in the newer ruleset is the one that matched.
                return "pulse_ruleset_older"
        receipts = {
            normalize_host(host): ports
            for host, ports in pulse_progress._successful_tcp_ports(document).items()  # noqa: SLF001
        }
        for host in hosts:
            probed = receipts.get(host)
            if probed and (port is None or port in probed):
                return None
        return "endpoint_not_probed"

    def _nse_gap(
        self, ref: str, hosts: set[str], port: int | None, protocol: str | None = None
    ) -> str | None:
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
                if port is None or any(
                    p == port and (protocol is None or proto == protocol) for p, proto in ports
                ):
                    return None
        return "endpoint_not_scanned"

    def _reason(self, entry: dict[str, Any], hosts: set[str], port: int | None) -> str | None:
        detector = str(entry.get("detector") or "")
        ref = str(entry.get("ref") or "")
        if detector == NUCLEI:
            return self._nuclei_gap(ref, hosts, port)
        if detector == PULSE:
            return self._pulse_gap(ref, entry.get("ruleset"), hosts, port)
        if detector == NMAP_NSE:
            return self._nse_gap(ref, hosts, port, detector_protocol(entry))
        return "no_coverage_rule"

    def assess(
        self,
        detectors: list[dict[str, Any]],
        *,
        port: str | None,
        asset_hosts: set[str],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """``(gaps, waived)``: what this run did not demonstrably re-check.

        ``port`` is the finding's; ``asset_hosts`` every address its asset has.

        A detector that never recorded where it looked (migrated by 0079, or
        the legacy rule of a row with none) is held to **every** IP address of
        the asset, one by one: "some address answered" would let a re-scan of
        the address the finding was not on close it. An asset known only by
        name falls back to its names, which no IP-based stage covers.

        ``waived`` are NSE detectors excused by another detector of the same
        finding: an NSE script the safe-mode re-scan cannot be asked to run by
        name (its profile names categories) is covered when Pulse or a nuclei
        template of the same finding re-checked the same address and did not
        see it. An NSE-only finding has nobody to stand in for it.
        """
        known = {normalize_host(host) for host in asset_hosts if host}
        ips = {host for host in known if _is_ip(host)}
        hostless = sorted(ips or known)
        entries = [entry for entry in detectors if isinstance(entry, dict)]
        legacy = not entries
        if legacy:
            entries = [{"detector": PULSE, "ref": None, "host": None, "port": port}]
        results: list[tuple[dict[str, Any], set[str], str | None, str | None]] = []
        for entry in entries:
            endpoint_port = _port(entry.get("port") if entry.get("port") not in (None, "") else port)
            if entry.get("host"):
                hosts = {normalize_host(entry["host"])}
                results.append((entry, hosts, self._reason(entry, hosts, endpoint_port), None))
                continue
            failing: tuple[str | None, str | None] = (None, None)
            if not hostless:
                failing = ("no_address", None)
            for host in hostless:
                reason = self._reason(entry, {host}, endpoint_port)
                if reason is not None:
                    failing = (reason, host)
                    break
            results.append((entry, set(hostless), failing[0], failing[1]))

        covered = [
            (entry, hosts)
            for entry, hosts, reason, _where in results
            if reason is None and entry.get("detector") in (PULSE, NUCLEI)
        ]
        gaps: list[dict[str, Any]] = []
        waived: list[dict[str, Any]] = []
        for entry, hosts, reason, where in results:
            if reason is None:
                continue
            detector = str(entry.get("detector") or "")
            ref = str(entry.get("ref") or "")
            row = {
                "detector": detector or "unknown",
                "ref": ref or None,
                "host": entry.get("host") or where,
                "port": entry.get("port") or port,
                "reason": reason,
                **({"legacy_rule": True} if legacy else {}),
            }
            if detector == NMAP_NSE:
                stand_in = next(
                    (other for other, other_hosts in covered if other_hosts & hosts), None
                )
                if stand_in is not None:
                    waived.append({**row, "covered_by": stand_in.get("detector")})
                    continue
            gaps.append(row)
        return gaps, waived

    def gaps(
        self,
        detectors: list[dict[str, Any]],
        *,
        port: str | None,
        asset_hosts: set[str],
    ) -> list[dict[str, Any]]:
        """The gaps of :meth:`assess`."""
        return self.assess(detectors, port=port, asset_hosts=asset_hosts)[0]


def detector_protocol(entry: dict[str, Any]) -> str | None:
    """``tcp``/``udp`` a detector observed on; pulse and nuclei are TCP-only."""
    recorded = str(entry.get("protocol") or "").lower()
    if recorded in ("tcp", "udp"):
        return recorded
    return "tcp" if entry.get("detector") in (PULSE, NUCLEI) else None


def finding_protocol(detectors: list[dict[str, Any]]) -> str | None:
    """The finding's protocol when every detector agrees on it, else ``None``.

    ``None`` — a legacy row with no detector, an NSE entry from before the
    protocol was recorded, detectors disagreeing — means "unknown", and
    nothing that rests on TCP evidence alone applies.
    """
    seen = {detector_protocol(e) for e in detectors if isinstance(e, dict)}
    return seen.pop() if len(seen) == 1 and None not in seen else None


def describe(gaps: list[dict[str, Any]]) -> str:
    """One line per gap, for the event note an operator reads first."""
    parts = []
    for gap in gaps:
        what = gap["detector"] + (f" {gap['ref']}" if gap.get("ref") else "")
        where = f"{gap.get('host') or 'any address of the asset'}:{gap.get('port') or '-'}"
        parts.append(f"{what} on {where}: {gap['reason']}")
    return "; ".join(parts)
