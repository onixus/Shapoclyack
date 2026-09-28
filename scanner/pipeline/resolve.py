from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from .dns_resolvers import dnsx_resolver_args
from .utils import run_command, save_json, write_lines


def resolve_fqdns(
    fqdns: list[str],
    output_dir: Path,
    timeout: int,
    retries: int,
    *,
    resolvers: Sequence[str] = (),
) -> list[str]:
    """A/AAAA for ``fqdns`` with dnsx.

    ``resolvers`` is ``dns.resolvers``. Empty means the system's resolvers,
    never dnsx's built-in public ones (see ``dns_resolvers.py``).
    """
    if not fqdns:
        write_lines(output_dir / "resolved_ips.txt", [])
        save_json(output_dir / "dns_resolution.json", {"records": []})
        return []

    input_file = output_dir / "normalized" / "fqdn_targets.txt"
    json_out = output_dir / "dnsx_records.jsonl"
    input_file.parent.mkdir(parents=True, exist_ok=True)
    input_file.write_text("\n".join(fqdns) + "\n", encoding="utf-8")

    run_command(
        [
            "dnsx",
            "-l",
            str(input_file),
            "-a",
            "-aaaa",
            *dnsx_resolver_args(resolvers),
            "-json",
            "-silent",
            "-disable-update-check",  # no phone-home from an air-gapped scan (#339)
            "-o",
            str(json_out),
        ],
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

    write_lines(output_dir / "resolved_ips.txt", resolved_ips)
    save_json(output_dir / "dns_resolution.json", {"records": records})
    return sorted(set(resolved_ips))
