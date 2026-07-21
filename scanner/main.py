from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from pydantic import ValidationError

from scanner import exit_codes
from scanner.pipeline.batching import expand_batches, single_batch
from scanner.pipeline.batch_runner import run_batches_parallel
from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.config_schema import AppConfig, format_validation_error, load_config
from scanner.pipeline.discovery_profiles import apply_discovery_profile, resolve_discovery_profile_name
from scanner.pipeline.contract import validate_inputs
from scanner.pipeline.discovery_runner import run_discovery_stage, verify_alive_without_ports
from scanner.pipeline.discovery_delta import (
    load_previous_alive,
    load_seed_alive,
    resolve_previous_alive_file,
)
from scanner.pipeline.errors import StageFailureError
from scanner.pipeline.asn_discovery import discover_asn_ranges
from scanner.pipeline.cloud_discovery import discover_cloud_buckets_sync
from scanner.pipeline.discover import import_cloudflare_dns_targets
from scanner.pipeline.hostnames import (
    base_domains_from_fqdns,
    discover_ct_subdomains_sync,
    enrich_discovery_hostnames,
    merge_name_lists,
)
from scanner.pipeline.nse import run_nse
from scanner.pipeline.ports import fast_port_scan
from scanner.pipeline.alerts import send_alerts
from scanner.pipeline.defectdojo import export_to_defectdojo
from scanner.pipeline.pdf_report import write_business_pdf
from scanner.pipeline.report import build_reports
from scanner.pipeline.report_diff import resolve_previous_run_dir, write_report_diff
from scanner.pipeline.resolve import resolve_fqdns
from scanner.pipeline.run_context import resolve_run_paths, write_run_meta
from scanner.pipeline.utils import load_json, load_yaml, read_lines, setup_logging, write_lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Containerized network scan pipeline")
    parser.add_argument("--config", default="scanner/config/default.yaml", help="Path to YAML config")
    parser.add_argument("--ranges", default="scanner/inputs/ranges.txt", help="Path to CIDR/IP inputs")
    parser.add_argument("--domains", default="scanner/inputs/domains.txt", help="Path to FQDN inputs")
    parser.add_argument(
        "--ports-file",
        help="Override ports.custom_ports_file for this run (TCP port list)",
    )
    parser.add_argument(
        "--ports-udp-file",
        help="Override ports.custom_udp_ports_file for this run (UDP port list)",
    )
    parser.add_argument("--mode", choices=["safe", "balanced", "fast"], help="Override speed profile")
    parser.add_argument("--run-id", help="Run identifier for per-run output dirs (required for explicit resume)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument(
        "--skip-nse",
        action="store_true",
        help="Skip NSE stage (discover + ports + reports only); re-run with --resume to enrich",
    )
    parser.add_argument(
        "--delta",
        action="store_true",
        help="Incremental discovery: probe only new scope hosts and refresh a sample of known alive",
    )
    parser.add_argument(
        "--compare-run-id",
        help="Previous run id for report diffs (default: latest_run.json before this run)",
    )
    parser.add_argument(
        "--no-diff",
        action="store_true",
        help="Disable report diffs for this run",
    )
    parser.add_argument(
        "--notify",
        action="store_true",
        help="Send Slack/Telegram/SMTP alerts after reports (requires alerts.* config or env credentials)",
    )
    parser.add_argument(
        "--export-defectdojo",
        action="store_true",
        help="Export vulnerabilities to DefectDojo after reports (requires defectdojo.* or env credentials)",
    )
    return parser.parse_args()


def _run_stage(stage: str, func):  # type: ignore[no-untyped-def]
    try:
        return func()
    except Exception as exc:  # noqa: BLE001
        raise StageFailureError(stage, exc) from exc


def _run_pipeline(args: argparse.Namespace) -> int:
    raw = load_yaml(Path(args.config))
    try:
        config: AppConfig = load_config(raw)
    except ValidationError as exc:
        print(format_validation_error(exc), file=sys.stderr)
        return exit_codes.CONFIG_ERROR

    profile_name = args.mode or config.runtime.mode
    discovery_preset = resolve_discovery_profile_name(config.discovery, profile_name) or "custom"
    config = apply_discovery_profile(config, active_mode=profile_name)
    if args.delta:
        config = config.model_copy(
            update={
                "discovery": config.discovery.model_copy(
                    update={"delta": config.discovery.delta.model_copy(update={"enabled": True})}
                )
            }
        )
    profile = config.profiles[profile_name]

    if args.notify:
        config = config.model_copy(
            update={"alerts": config.alerts.model_copy(update={"enabled": True})}
        )
    if args.export_defectdojo:
        config = config.model_copy(
            update={"defectdojo": config.defectdojo.model_copy(update={"enabled": True})}
        )
    ports_updates: dict[str, str] = {}
    if args.ports_file:
        ports_updates["custom_ports_file"] = str(Path(args.ports_file))
    if args.ports_udp_file:
        ports_updates["custom_udp_ports_file"] = str(Path(args.ports_udp_file))
    if ports_updates:
        config = config.model_copy(
            update={"ports": config.ports.model_copy(update=ports_updates)}
        )

    output_base = Path(config.runtime.output_dir)
    state_base = Path(config.runtime.state_dir)
    previous_alive_file = None
    if config.discovery.delta.enabled:
        previous_alive_file = resolve_previous_alive_file(
            output_base=output_base,
            state_base=state_base,
            previous_run_dir=config.discovery.delta.previous_run_dir,
            per_run_output=config.runtime.per_run_output,
        )

    # Capture previous run *before* resolve_run_paths overwrites latest_run.json.
    diff_enabled = config.reporting.diff.enabled and not args.no_diff and not args.resume
    previous_run_dir = None
    if diff_enabled:
        previous_run_dir = resolve_previous_run_dir(
            output_base=output_base,
            state_base=state_base,
            previous_run_dir=config.reporting.diff.previous_run_dir,
            compare_run_id=args.compare_run_id or "",
            per_run_output=config.runtime.per_run_output,
        )

    try:
        paths = resolve_run_paths(config.runtime, run_id=args.run_id, resume=args.resume)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return exit_codes.CONFIG_ERROR

    # Avoid diffing a run against itself when --run-id reuses the previous id.
    if previous_run_dir is not None and previous_run_dir.resolve() == paths.output_dir.resolve():
        logging.info("Report diff skipped: previous run dir is the current run")
        previous_run_dir = None

    paths.output_dir.mkdir(parents=True, exist_ok=True)
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.logs_dir.mkdir(parents=True, exist_ok=True)

    setup_logging(
        paths.logs_dir / "pipeline.log",
        max_bytes=config.runtime.log_max_bytes,
        backup_count=config.runtime.log_backup_count,
    )
    logging.info(
        "Starting scan pipeline in '%s' mode (discovery preset=%s, setting=%s, run_id=%s, ports=%s)",
        profile_name,
        discovery_preset,
        config.discovery.profile,
        paths.run_id,
        config.ports.protocol,
    )
    if not args.resume:
        write_run_meta(paths, profile_name, args.config)

    runtime = config.runtime
    retries = runtime.retries
    timeout = runtime.timeout_seconds
    checkpoint = CheckpointStore(paths.state_dir / "checkpoint.json")

    if not args.resume:
        checkpoint.clear()

    contract = validate_inputs(Path(args.ranges), Path(args.domains), paths.output_dir)
    checkpoint.mark_done("contract")
    if (
        not contract.valid_ips_or_cidr
        and not contract.valid_fqdns
        and not config.discovery.cloudflare.enabled
        and not config.discovery.ct.enabled
        and not config.discovery.asn.enabled
        and not config.discovery.cloud.enabled
    ):
        logging.error("No valid targets after input validation")
        return exit_codes.INPUT_ERROR

    # Phase 5: expand FQDN/IP scope via Cloudflare zone import + CT subdomains (before resolve).
    scope_fqdns = list(contract.valid_fqdns)
    scope_ips = list(contract.valid_ips_or_cidr)

    if args.resume and checkpoint.is_done("cloudflare"):
        cf_result = load_json(
            paths.output_dir / "cloudflare_dns.json",
            fallback={"fqdns": [], "ips": []},
        )
    else:
        cf_result = _run_stage(
            "cloudflare",
            lambda: import_cloudflare_dns_targets(config.discovery.cloudflare, paths.output_dir),
        )
        checkpoint.mark_done("cloudflare")
    if config.discovery.cloudflare.enabled:
        scope_fqdns = merge_name_lists(scope_fqdns, cf_result.get("fqdns") or [])
        scope_ips = sorted(set(scope_ips + list(cf_result.get("ips") or [])))

    if args.resume and checkpoint.is_done("ct"):
        ct_result = load_json(
            paths.output_dir / "ct_subdomains.json",
            fallback={"subdomains": []},
        )
    else:
        ct_domains = config.discovery.ct.domains or base_domains_from_fqdns(scope_fqdns)
        ct_result = _run_stage(
            "ct",
            lambda: discover_ct_subdomains_sync(
                ct_domains,
                config.discovery.ct,
                paths.output_dir,
            ),
        )
        checkpoint.mark_done("ct")
    if config.discovery.ct.enabled:
        scope_fqdns = merge_name_lists(scope_fqdns, ct_result.get("subdomains") or [])

    # Phase 8.1: ASN/BGP org mapping (after CT so it can also see CT-expanded
    # domains via base_domains_from_fqdns). Adds IP ranges, not FQDNs.
    if args.resume and checkpoint.is_done("asn"):
        asn_result = load_json(
            paths.output_dir / "asn_discovery.json",
            fallback={"ip_ranges": []},
        )
    else:
        asn_domains = config.discovery.asn.domains or base_domains_from_fqdns(scope_fqdns)
        asn_result = _run_stage(
            "asn",
            lambda: discover_asn_ranges(asn_domains, config.discovery.asn, paths.output_dir),
        )
        checkpoint.mark_done("asn")
    if config.discovery.asn.enabled:
        scope_ips = sorted(set(scope_ips + list(asn_result.get("ip_ranges") or [])))

    # Phase 8.3: cloud storage bucket enumeration (asset-inventory finding,
    # not scope-expanding -- see module docstring). Domains only; no merge
    # into scope_ips/scope_fqdns, so --resume just needs to skip re-running.
    if not (args.resume and checkpoint.is_done("cloud")):
        cloud_domains = config.discovery.cloud.domains or base_domains_from_fqdns(scope_fqdns)
        _run_stage(
            "cloud",
            lambda: discover_cloud_buckets_sync(cloud_domains, config.discovery.cloud, paths.output_dir),
        )
        checkpoint.mark_done("cloud")

    if args.resume and checkpoint.is_done("resolve"):
        resolved_ips = read_lines(paths.output_dir / "resolved_ips.txt")
    else:
        resolved_ips = _run_stage(
            "resolve",
            lambda: resolve_fqdns(scope_fqdns, paths.output_dir, timeout=timeout, retries=retries),
        )
        checkpoint.mark_done("resolve")

    all_targets = sorted(set(scope_ips + resolved_ips))
    write_lines(paths.output_dir / "all_targets.txt", all_targets)
    if not all_targets:
        logging.error("No targets after Cloudflare/CT expansion and DNS resolve")
        return exit_codes.INPUT_ERROR

    batching = config.batching

    def make_batches(items: list[str]) -> list[tuple[str, list[str]]]:
        if batching.enabled:
            return expand_batches(
                items,
                ipv4_prefix=batching.ipv4_prefix,
                max_targets_per_batch=batching.max_targets_per_batch,
            )
        return single_batch(items)

    alive_file = paths.output_dir / "alive_ips.txt"
    seed_alive = load_seed_alive(config.discovery.seed_alive_file)
    previous_alive = load_previous_alive(previous_alive_file)
    previous_source = str(previous_alive_file) if previous_alive_file else ""
    if args.resume and checkpoint.is_done("discover"):
        alive_hosts = sorted(set(read_lines(alive_file)))
    else:
        alive_hosts = run_discovery_stage(
            all_targets=all_targets,
            config=config,
            profile=profile,
            output_dir=paths.output_dir,
            alive_file=alive_file,
            timeout=timeout,
            retries=retries,
            checkpoint=checkpoint,
            resume=args.resume,
            make_batches=make_batches,
            seed_alive=seed_alive,
            previous_alive=previous_alive,
            previous_alive_source=previous_source,
        )

    hostnames_file = paths.output_dir / "hostnames.json"
    if args.resume and checkpoint.is_done("discover-hostnames"):
        hostnames_map: dict = load_json(hostnames_file, fallback={})
    else:
        hostnames_map = _run_stage(
            "discover-hostnames",
            lambda: enrich_discovery_hostnames(
                alive_hosts,
                paths.output_dir,
                config.discovery,
                timeout=timeout,
                retries=retries,
            ),
        )
        checkpoint.mark_done("discover-hostnames")

    open_file = paths.output_dir / "open_ports.txt"
    if args.resume and checkpoint.is_done("ports"):
        open_ports = sorted(set(read_lines(open_file)))
    else:
        open_set: set[str] = set(read_lines(open_file)) if args.resume else set()
        custom_ports_file = Path(config.ports.custom_ports_file)
        custom_udp_ports_file = Path(config.ports.custom_udp_ports_file)
        port_cfg = config.ports
        batches = make_batches(alive_hosts)
        run_batches_parallel(
            stage="ports",
            batches=batches,
            done_ids=checkpoint.done_items("ports"),
            concurrency=runtime.ports_concurrency,
            process_batch=lambda bid, members: fast_port_scan(
                members,
                output_dir=paths.output_dir,
                rate=profile.port_rate,
                top_ports=profile.top_ports,
                top_udp_ports=port_cfg.top_udp_ports,
                timeout=timeout,
                retries=retries,
                protocol_mode=port_cfg.protocol,
                custom_ports_file=custom_ports_file,
                custom_udp_ports_file=custom_udp_ports_file,
                udp_probes=port_cfg.udp_probes,
                tag=bid,
            ),
            aggregate=open_set,
            aggregate_file=open_file,
            checkpoint=checkpoint,
            checkpoint_key="ports",
        )
        checkpoint.mark_done("ports")
        open_ports = sorted(open_set)

    alive_hosts = verify_alive_without_ports(
        alive_hosts=alive_hosts,
        open_ports=open_ports,
        config=config,
        profile=profile,
        output_dir=paths.output_dir,
        timeout=timeout,
        retries=retries,
    )
    write_lines(alive_file, alive_hosts)

    skip_nse = args.skip_nse or runtime.skip_nse
    nmap_dir = paths.output_dir / "nmap"
    if skip_nse:
        logging.info("Skipping NSE stage (skip_nse enabled)")
        nmap_dir.mkdir(parents=True, exist_ok=True)
    elif args.resume and checkpoint.is_done("nse"):
        pass
    else:
        nse_profile = config.nse_profiles[profile.nse_profile]
        nse_timeout = runtime.nse_timeout_seconds
        nse_concurrency = profile.nse_concurrency or runtime.nse_concurrency
        nse_max_rate = profile.nse_max_rate if profile.nse_max_rate is not None else runtime.nse_max_rate
        nmap_dir = _run_stage(
            "nse",
            lambda: run_nse(
                open_ports,
                output_dir=paths.output_dir,
                scripts=nse_profile.scripts,
                version_detection=nse_profile.version_detection,
                os_detection=nse_profile.os_detection,
                nmap_timing=profile.nmap_timing,
                timeout=nse_timeout,
                retries=retries,
                concurrency=nse_concurrency,
                max_rate=nse_max_rate,
                hosts_per_scan=runtime.nse_hosts_per_scan,
                done_hosts=checkpoint.done_items("nse") if args.resume else set(),
                on_host_done=lambda host: checkpoint.mark_item_done("nse", host),
            ),
        )
        checkpoint.mark_done("nse")

    reporting = config.reporting
    enrichment = config.enrichment
    build_reports(
        output_dir=paths.output_dir,
        total_targets=len(all_targets),
        alive_hosts=alive_hosts,
        open_ports=open_ports,
        nmap_dir=nmap_dir,
        hostnames_map=hostnames_map,
        markdown_summary=reporting.markdown_summary,
        html_summary=reporting.html_summary,
        csv_export=reporting.csv_export,
        json_export=reporting.json_export,
        cvss4_enabled=enrichment.cvss4.enabled,
        cvss4_database=enrichment.cvss4.database,
        geoip_enabled=enrichment.geoip.enabled,
        geoip_database=enrichment.geoip.database,
    )
    checkpoint.mark_done("report")

    diff_result = None
    if previous_run_dir is not None:
        try:
            diff_result = write_report_diff(
                paths.output_dir,
                previous_run_dir,
                markdown=reporting.diff.markdown,
            )
            checkpoint.mark_done("diff")
        except Exception:  # noqa: BLE001
            logging.exception("Report diff failed; continuing without diff artifacts")

    if reporting.pdf_summary:
        try:
            write_business_pdf(
                paths.output_dir,
                run_id=paths.run_id,
                title=reporting.pdf_title,
                org_name=reporting.pdf_org_name,
                max_vulnerabilities=reporting.pdf_max_vulnerabilities,
            )
            checkpoint.mark_done("pdf")
        except Exception:  # noqa: BLE001
            logging.exception("PDF business report failed; continuing without summary.pdf")

    if config.alerts.enabled:
        summary = load_json(paths.output_dir / "summary.json", fallback={})
        alert_result = send_alerts(
            config.alerts,
            run_id=paths.run_id,
            summary=summary if isinstance(summary, dict) else {},
            diff=diff_result,
        )
        (paths.output_dir / "alerts.json").write_text(
            json.dumps(alert_result, indent=2) + "\n",
            encoding="utf-8",
        )

    if config.defectdojo.enabled:
        dd_result = export_to_defectdojo(
            config.defectdojo,
            run_id=paths.run_id,
            output_dir=paths.output_dir,
        )
        (paths.output_dir / "defectdojo.json").write_text(
            json.dumps(dd_result, indent=2) + "\n",
            encoding="utf-8",
        )

    logging.info("Pipeline finished. Output directory: %s", paths.output_dir)
    return exit_codes.SUCCESS


def main() -> int:
    args = parse_args()
    try:
        return _run_pipeline(args)
    except StageFailureError as exc:
        logging.error("%s", exc)
        return exit_codes.STAGE_FAILURE
    except KeyboardInterrupt:
        logging.warning("Pipeline interrupted")
        return exit_codes.INTERRUPTED
    except Exception:
        logging.exception("Unexpected pipeline failure")
        return exit_codes.GENERAL_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
