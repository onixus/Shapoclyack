from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path

from .dnsx import command as dnsx_command
from .utils import run_command, save_json, write_lines


def resolve_fqdns(
    fqdns: list[str],
    output_dir: Path,
    timeout: int,
    retries: int,
    *,
    resolvers: Sequence[str],
) -> list[str]:
    if not fqdns:
        write_lines(output_dir / "resolved_ips.txt", [])
        save_json(output_dir / "dns_resolution.json", {"records": []})
        return []

    input_file = output_dir / "normalized" / "fqdn_targets.txt"
    json_out = output_dir / "dnsx_records.jsonl"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    input_file.write_text("\n".join(fqdns) + "\n", encoding="utf-8")

    run_command(
        dnsx_command(input_file, ["-a", "-aaaa"], json_out, resolvers=resolvers),
        timeout=timeout,
        retries=retries,
    )

    resolved_ips: list[str] = []
    records: list[dict] = []
    for line in json_out.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parsed = json.loads(line)
        records.append(parsed)
        for key in ("a", "aaaa"):
            for ip in parsed.get(key, []) or []:
                resolved_ips.append(ip)

    if not records:
        # dnsx 1.2.3 writes a line even for an NXDOMAIN, and nothing at all --
        # with exit code 0 -- when no resolver answered. This is that case, and
        # the only place it shows before the run ends with "no targets".
        logging.warning(
            "resolve: no resolver answered for any of %d name(s); check that the "
            "sensor reaches the -r resolvers in the dnsx command above on UDP/TCP 53 "
            "(dns.resolvers, or /etc/resolv.conf when that is empty)",
            len(fqdns),
        )
    write_lines(output_dir / "resolved_ips.txt", resolved_ips)
    save_json(output_dir / "dns_resolution.json", {"records": records})
    return sorted(set(resolved_ips))
