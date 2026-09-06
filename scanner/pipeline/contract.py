from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from .scan_scope import normalize_domain
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


def read_promoted_domains(path: Path | None) -> tuple[list[str], list[str]]:
    """``(valid, rejected)`` from the promoted-domains file the API hands a job.

    Related domains an operator promoted (org_profile M4) arrive in their own
    file rather than appended to ``domains.txt``, so they *widen* whatever
    target files the run reads instead of replacing them. Validated with the
    same FQDN rule as the contract: the API stored a single hostname per line,
    but the file crossed a process boundary and is re-read as untrusted input.
    """
    if path is None:
        return [], []
    valid: list[str] = []
    rejected: list[str] = []
    for value in read_lines(path):
        normalized = normalize_domain(value)
        if normalized and is_fqdn(normalized):
            valid.append(normalized)
        else:
            rejected.append(value)
    return valid, rejected
