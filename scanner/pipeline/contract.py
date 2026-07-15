from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from .utils import is_fqdn, is_ip_or_cidr, read_lines, save_json, write_lines


@dataclass
class ContractOutput:
    valid_ips_or_cidr: list[str]
    valid_fqdns: list[str]
    rejected: list[str]


def validate_inputs(
    ranges_file: Path,
    domains_file: Path,
    output_dir: Path,
) -> ContractOutput:
    ranges = read_lines(ranges_file)
    domains = read_lines(domains_file)

    valid_ips_or_cidr: list[str] = []
    valid_fqdns: list[str] = []
    rejected: list[str] = []

    for value in ranges:
        if is_ip_or_cidr(value):
            valid_ips_or_cidr.append(value)
        else:
            rejected.append(value)

    for value in domains:
        if is_fqdn(value):
            valid_fqdns.append(value.rstrip("."))
        else:
            rejected.append(value)

    write_lines(output_dir / "normalized" / "ip_targets.txt", valid_ips_or_cidr)
    write_lines(output_dir / "normalized" / "fqdn_targets.txt", valid_fqdns)
    save_json(
        output_dir / "normalized" / "contract_validation.json",
        {
            "valid_ip_or_cidr_count": len(valid_ips_or_cidr),
            "valid_fqdn_count": len(valid_fqdns),
            "rejected_count": len(rejected),
            "rejected": sorted(rejected),
        },
    )
    if rejected:
        logging.warning("Rejected %s invalid targets", len(rejected))

    return ContractOutput(
        valid_ips_or_cidr=sorted(set(valid_ips_or_cidr)),
        valid_fqdns=sorted(set(valid_fqdns)),
        rejected=sorted(set(rejected)),
    )
