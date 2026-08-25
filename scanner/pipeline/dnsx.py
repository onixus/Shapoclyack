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
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .utils import run_command, write_lines

LOG = logging.getLogger("shapoclyack.dnsx")


class DnsxError(Exception):
    """dnsx could not be run, or failed after its retries."""


def query(
    names: list[str],
    output_dir: Path,
    *,
    stage: str,
    kind: str,
    flags: list[str],
    timeout: int,
    retries: int,
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

    try:
        run_command(
            [
                "dnsx",
                "-l",
                str(targets_file),
                *flags,
                "-json",
                "-silent",
                "-o",
                str(json_out),
            ],
            timeout=timeout,
            retries=retries,
        )
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
