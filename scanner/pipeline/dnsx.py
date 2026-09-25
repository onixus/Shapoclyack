"""One dnsx JSONL invocation, shared by the org_profile DNS stages (M2, #182).

``dns_hygiene.py`` and ``mail_posture.py`` need seven record types between
them (NS, SOA, CAA, A/AAAA, MX, TXT and the AXFR probe). ``domain_monitor.py``
spells its two out as two near-identical functions, which is the right shape
for two and the wrong shape for seven -- so the batch mechanics live here once
and each stage keeps its own thin, named wrapper on top. Those wrappers are
what the tests monkeypatch, exactly as ``test_domain_monitor.py`` patches
``_run_dnsx_a_aaaa``; nothing in this module resolves anything by itself.

Fail-soft: a missing or broken ``dnsx`` raises :class:`DnsxError` rather than
escaping as a bare tool exception. ``_run_stage`` in ``scanner/main.py`` turns
any exception into ``StageFailureError`` and the run exits with
``STAGE_FAILURE`` -- and the module invariant of #182 is that a control which
could not be evaluated reports ``not_checked``/``error``, it does not take the
scan down with it.

AXFR does **not** go through here on purpose; see ``dns_hygiene._probe_axfr``.

Every other dnsx argv in the scanner -- the batches here and the runs in
``resolve.py``, ``hostnames.py`` and ``domain_monitor.py`` -- is built by
:func:`command`, because dnsx 1.2.3 without ``-r`` does not read
``/etc/resolv.conf``: it asks 1.1.1.1, 8.8.8.8, 9.9.9.9, 208.67.222.222 and
four more public resolvers directly (``dnsx.DefaultResolvers``). The sensor
would then miss split-horizon names, resolve nothing on a network that blocks
outbound UDP 53 -- and dnsx still exits 0 -- and send every target name to
those operators. So a run always gets ``-r``: ``dns.resolvers`` from the
config, else the sensor's own resolvers.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .config_schema import normalize_resolver
from .utils import run_command, write_lines

LOG = logging.getLogger("shapoclyack.dnsx")

#: Where the sensor's own resolvers come from when ``dns.resolvers`` is empty.
RESOLV_CONF = Path("/etc/resolv.conf")
#: What libc asks when resolv.conf names no nameserver (resolv.conf(5)).
LOCAL_RESOLVER = "127.0.0.1:53"
#: glibc and musl read at most this many ``nameserver`` lines (MAXNS).
_MAXNS = 3


class DnsxError(Exception):
    """dnsx could not be run, or failed after its retries."""


#: Messages already logged, so the resolver choice is said once per
#: resolv.conf content rather than on each of a run's dozen dnsx batches.
_LOGGED: set[str] = set()


def _log_once(level: int, message: str, *args: object) -> None:
    key = message % args
    if key in _LOGGED:
        return
    _LOGGED.add(key)
    LOG.log(level, message, *args)


def system_resolvers() -> list[str]:
    """What libc would ask for this sensor, in ``-r`` form.

    Not every ``nameserver`` line. libc asks the first and moves on to the
    next only when it does not answer; dnsx has no such fallback and rotates
    over every ``-r`` entry. Handing it a VPN resolver and the ``8.8.8.8``
    listed as its backup would send half the target names to Google and give
    internal names a public NXDOMAIN. So: the first nameserver, or the first
    three under ``options rotate``, where libc rotates as well. No usable
    nameserver -- or no file -- means the local machine, as it does for libc.

    Read on every call rather than once per run: a VPN or DHCP renewal can
    rewrite the file while a long scan is under way.
    """
    resolv_conf = RESOLV_CONF
    try:
        text = resolv_conf.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _log_once(
            logging.WARNING,
            "dnsx: cannot read %s (%s); asking %s as libc would",
            resolv_conf,
            exc,
            LOCAL_RESOLVER,
        )
        return [LOCAL_RESOLVER]
    listed: list[str] = []
    rotate = False
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "options":
            rotate = rotate or "rotate" in fields[1:]
        if len(fields) < 2 or fields[0] != "nameserver":
            continue
        # A bare address, as libc reads it: "10.0.0.5:5353" is a line glibc
        # skips, so it must not become the resolver here either.
        try:
            address = ipaddress.ip_address(fields[1])
        except ValueError:
            _log_once(
                logging.WARNING,
                "dnsx: ignoring nameserver %r in %s, not an IP address",
                fields[1],
                resolv_conf,
            )
            continue
        listed.append(normalize_resolver(str(address)))
    if not listed:
        return [LOCAL_RESOLVER]
    # libc keeps the first MAXNS lines as they are, repeats included, and only
    # then rotates -- so cap first and deduplicate after, or a fourth line
    # libc never asks could slip in behind a repeat.
    in_use = listed[:_MAXNS] if rotate else listed[:1]
    chosen = list(dict.fromkeys(in_use))
    backups = [value for value in dict.fromkeys(listed) if value not in chosen]
    if backups:
        _log_once(
            logging.INFO,
            "dnsx: asking %s from %s, not the backup nameserver(s) %s: dnsx would "
            "rotate over them rather than fall back; set dns.resolvers to choose",
            ",".join(chosen),
            resolv_conf,
            ",".join(backups),
        )
    return chosen


def resolver_flag(resolvers: Sequence[str]) -> list[str]:
    """``-r`` for one dnsx run: ``resolvers`` if any, else the system's.

    Never empty: leaving ``-r`` off is what sends the names to dnsx's public
    resolvers.
    """
    chosen = [normalize_resolver(value) for value in resolvers] or system_resolvers()
    return ["-r", ",".join(chosen)]


def command(
    targets_file: Path,
    flags: Sequence[str],
    json_out: Path,
    *,
    resolvers: Sequence[str],
) -> list[str]:
    """The argv of one dnsx JSONL batch over ``targets_file``."""
    return [
        "dnsx",
        "-l",
        str(targets_file),
        *resolver_flag(resolvers),
        *flags,
        "-json",
        "-silent",
        "-o",
        str(json_out),
    ]


def query(
    names: list[str],
    output_dir: Path,
    *,
    stage: str,
    kind: str,
    flags: list[str],
    timeout: int,
    retries: int,
    resolvers: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Resolve ``names`` with one dnsx run and return ``host -> parsed record``.

    ``kind`` names the pair of files written under ``output_dir/<stage>/``, so
    two record types of the same stage never share a target list or an output
    file.
    """
    if not names:
        return {}

    batch_dir = output_dir / stage
    batch_dir.mkdir(parents=True, exist_ok=True)
    targets_file = batch_dir / f"{kind}_targets.txt"
    json_out = batch_dir / f"{kind}_records.jsonl"
    write_lines(targets_file, sorted(set(names)))

    argv = command(targets_file, flags, json_out, resolvers=resolvers)
    try:
        run_command(argv, timeout=timeout, retries=retries)
    except Exception as exc:  # noqa: BLE001 - re-raised as the module's own type
        raise DnsxError(f"dnsx {kind} lookup failed: {exc}") from exc

    records: dict[str, dict[str, Any]] = {}
    if not json_out.exists():
        return records
    for line in json_out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            # One unparseable line is a dnsx quirk, not a reason to fail the
            # control for every other domain in the same batch. Logged rather
            # than swallowed so it is visible when it happens.
            LOG.warning("dnsx: skipping unparseable %s record line", kind)
            continue
        if not isinstance(parsed, dict):
            continue
        host = str(parsed.get("host") or "").strip().rstrip(".").lower()
        if not host:
            continue
        records[host] = parsed
    return records
