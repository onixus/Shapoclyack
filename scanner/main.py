from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar, copy_context
from pathlib import Path

from pydantic import ValidationError

from scanner import exit_codes
from scanner.pipeline.batching import expand_batches, single_batch
from scanner.pipeline.batch_runner import run_batches_parallel
from scanner.pipeline.checkpoint import CheckpointStore
from scanner.pipeline.config_schema import (
    AppConfig,
    format_validation_error,
    load_config,
    merge_nuclei_config,
    merge_pulse_config,
    resolve_service_probe_backend,
)
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
from scanner.pipeline.controls import evaluate_controls
from scanner.pipeline.credential_leaks import check_credential_leaks
from scanner.pipeline.discover import import_cloudflare_dns_targets
from scanner.pipeline.dns_hygiene import check_dns_hygiene
from scanner.pipeline.domain_monitor import monitor_domains
from scanner.pipeline.mail_posture import check_mail_posture
from scanner.pipeline.fingerprint import fingerprint_hosts_sync
from scanner.pipeline.screenshots import capture_screenshots_sync
from scanner.pipeline.nuclei_scan import run_nuclei_scan
from scanner.pipeline.tls_posture import check_tls_posture
from scanner.pipeline.hostnames import (
    base_domains_from_fqdns,
    discover_ct_subdomains_sync,
    enrich_discovery_hostnames,
    merge_name_lists,
)
from scanner.pipeline.nse import run_nse
from scanner.pipeline.ownership import resolve_ownership
from scanner.pipeline.ports import fast_port_scan
from scanner.pipeline.pulse_probe import run_pulse_probe, sync_report_primary_marker
from scanner.pipeline.pulse_shadow import write_pulse_nmap_diff
from scanner.pipeline.alerts import send_alerts
from scanner.pipeline.defectdojo import export_to_defectdojo
from scanner.pipeline.pdf_report import write_business_pdf
from scanner.pipeline.related_domains import discover_related_domains
from scanner.pipeline.report import build_reports
from scanner.pipeline.report_diff import resolve_previous_run_dir, write_report_diff
from scanner.pipeline.resolve import resolve_fqdns
from scanner.pipeline import scan_scope
from scanner.pipeline.run_context import resolve_run_paths, write_run_meta
from scanner.pipeline.stage_timing import StageTimer
from scanner.pipeline.utils import load_json, load_yaml, read_lines, setup_logging, write_lines

# Active run timer (set for the duration of _run_pipeline). ContextVar so the
# pulse+nse ThreadPoolExecutor workers still see the same collector.
_STAGE_TIMER: ContextVar[StageTimer | None] = ContextVar("stage_timer", default=None)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Containerized network scan pipeline")
    parser.add_argument("--config", default="scanner/config/default.yaml", help="Path to YAML config")
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help=(
            "Parse and validate the config file, then exit without starting any "
            "external tool. Exit code 0 when it is valid, 2 when it is not."
        ),
    )
    parser.add_argument("--ranges", default="scanner/inputs/ranges.txt", help="Path to CIDR/IP inputs")
    parser.add_argument("--domains", default="scanner/inputs/domains.txt", help="Path to FQDN inputs")
    parser.add_argument(
        "--scan-scope",
        help=(
            "Path to the tenant's approved scan scope (#244). Set by the API for "
            "every job it starts; targets outside the scope are dropped, and "
            "resolved addresses inside a denied range are dropped after resolve. "
            "Omitted for a standalone run, which is then unfiltered."
        ),
    )
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
        help=(
            "Ports-only L1: skip Pulse and nmap NSE (discover + ports + reports). "
            "Default path already uses Pulse without nmap; use backend nmap|hybrid "
            "for full NSE. Re-run with --resume to enrich after ports-only."
        ),
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


def _run_stage(stage: str, func, timer: StageTimer | None = None):  # type: ignore[no-untyped-def]
    def _call():  # type: ignore[no-untyped-def]
        try:
            return func()
        except Exception as exc:  # noqa: BLE001
            raise StageFailureError(stage, exc) from exc

    active = timer if timer is not None else _STAGE_TIMER.get()
    if active is not None:
        return active.run(stage, _call)
    return _call()


def _keep_in_scope(
    result: scan_scope.FilterResult, *, what: str, refusals: list[str]
) -> list[str]:
    """Log and record what the approved scope refused, and return what it kept.

    Dropping rather than failing is the deliberate choice explained in
    ``scanner/pipeline/scan_scope.py``: this is not the authorization boundary,
    it is the last point at which the real target list is known.
    """
    if result.refused:
        refusals.extend(result.refused)
        logging.warning(
            "Scan scope dropped %d %s outside the tenant's approved scope: %s",
            len(result.refused),
            what,
            ", ".join(sorted(result.refused)[:8]),
        )
    return result.kept


def _run_pipeline(args: argparse.Namespace) -> int:
    timer = StageTimer()
    token = _STAGE_TIMER.set(timer)
    output_dirs: list[Path] = []
    try:
        return _run_pipeline_body(args, timer, output_dirs)
    finally:
        if output_dirs:
            try:
                timer.write(output_dirs[0])
            except Exception:  # noqa: BLE001
                logging.exception("Failed to write stage_timings.json")
        _STAGE_TIMER.reset(token)


def _run_pipeline_body(
    args: argparse.Namespace,
    timer: StageTimer,
    output_dirs: list[Path],
) -> int:
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

    # pulse (--cve-online) and scripts/fetch-cvss4-db.py both read NVD_API_KEY
    # from the environment, and run_command hands the child our own environ, so
    # exporting it here is all the plumbing the config-stored key needs. An
    # operator-set env var wins: a k8s Secret should not lose to stored config.
    if config.enrichment.cvss4.nvd_api_key and not os.environ.get("NVD_API_KEY", "").strip():
        os.environ["NVD_API_KEY"] = config.enrichment.cvss4.nvd_api_key

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
    # So stage_timings.json is written even if a later stage fails.
    output_dirs.append(paths.output_dir)

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

    # The tenant's approved scope, if this run carries one (#244). None means a
    # standalone run with no control plane behind it, which stays unfiltered; an
    # *unapproved* scope is a different thing and stops the run here, before any
    # stage has looked anything up.
    scope = scan_scope.load_scope_file(args.scan_scope)
    scope_refusals: list[str] = []
    if scope is not None and not scope.approved:
        logging.error(
            "Tenant %s has no approved scan scope; refusing to scan anything",
            scope.tenant_id or "(unnamed)",
        )
        scan_scope.write_denials(
            paths.output_dir, scope, ["all targets (tenant has no approved scan scope)"]
        )
        return exit_codes.INPUT_ERROR

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

    # Filtered before the OSINT stages, not only before the scan: a name the
    # tenant is not approved for should not be looked up in CT, RDAP or the
    # cloud-bucket probes either. For a run on the installation's default target
    # files this is the *only* check these targets ever get — the API does not
    # open those files (#244).
    if scope is not None:
        scope_fqdns = _keep_in_scope(
            scan_scope.filter_names(scope, scope_fqdns), what="names", refusals=scope_refusals
        )
        scope_ips = _keep_in_scope(
            scan_scope.filter_ranges(scope, scope_ips), what="ranges", refusals=scope_refusals
        )

    if args.resume and checkpoint.is_done("cloudflare"):
        timer.skip("cloudflare")
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
        timer.skip("ct")
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
        timer.skip("asn")
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

    # EPIC #182 (org_profile M1): domain ownership via RDAP. Sits beside ct/asn
    # and before resolve because the owner identifiers it produces are the seed
    # for the related-domains stage, which may influence scope. Findings-only
    # here: it adds neither FQDNs nor IPs, so --resume just skips it.
    if args.resume and checkpoint.is_done("ownership"):
        timer.skip("ownership")
    else:
        ownership_config = config.org_profile.ownership
        ownership_domains = ownership_config.domains or base_domains_from_fqdns(scope_fqdns)
        _run_stage(
            "ownership",
            lambda: resolve_ownership(
                ownership_domains,
                ownership_config,
                paths.output_dir,
                paths.state_dir,
            ),
        )
        checkpoint.mark_done("ownership")

    # Phase 8.3: cloud storage bucket enumeration (asset-inventory finding,
    # not scope-expanding -- see module docstring). Domains only; no merge
    # into scope_ips/scope_fqdns, so --resume just needs to skip re-running.
    if args.resume and checkpoint.is_done("cloud"):
        timer.skip("cloud")
    else:
        cloud_domains = config.discovery.cloud.domains or base_domains_from_fqdns(scope_fqdns)
        _run_stage(
            "cloud",
            lambda: discover_cloud_buckets_sync(cloud_domains, config.discovery.cloud, paths.output_dir),
        )
        checkpoint.mark_done("cloud")

    # Second pass, over what discovery added since the first one: CT subdomains,
    # Cloudflare zone entries and ASN ranges are targets nobody submitted and no
    # API check has ever seen. Re-filtering the whole list rather than the
    # additions keeps this independent of which stages ran.
    if scope is not None:
        scope_fqdns = _keep_in_scope(
            scan_scope.filter_names(scope, scope_fqdns),
            what="discovered names",
            refusals=scope_refusals,
        )
        scope_ips = _keep_in_scope(
            scan_scope.filter_ranges(scope, scope_ips),
            what="discovered ranges",
            refusals=scope_refusals,
        )

    if args.resume and checkpoint.is_done("resolve"):
        timer.skip("resolve")
        resolved_ips = read_lines(paths.output_dir / "resolved_ips.txt")
    else:
        resolved_ips = _run_stage(
            "resolve",
            lambda: resolve_fqdns(scope_fqdns, paths.output_dir, timeout=timeout, retries=retries),
        )
        checkpoint.mark_done("resolve")

    # The TOCTOU fix itself (#244): the API resolved these names at admission,
    # but the answer that decides what gets scanned is this one, taken minutes
    # or — for a schedule — hours later from a record the scanned party owns.
    # Deny entries only, matching the API's rule: approving a domain says
    # nothing about the addresses behind it, in either direction.
    if scope is not None:
        resolved_ips = _keep_in_scope(
            scan_scope.filter_resolved(scope, resolved_ips),
            what="resolved addresses",
            refusals=scope_refusals,
        )
        # Rewritten, so the stage artifact does not keep listing an address the
        # run refused as if it were a target. The lookup itself is not erased —
        # dns_resolution.json still holds every record dnsx returned.
        write_lines(paths.output_dir / "resolved_ips.txt", resolved_ips)

    # Phase 8.4: typosquat / dangling-CNAME domain monitoring (findings-only,
    # non-escalating -- see domain_monitor.py module docstring). Runs after
    # resolve so the dangling-CNAME check sees the final in-scope FQDN list.
    if args.resume and checkpoint.is_done("domain_monitor"):
        timer.skip("domain_monitor")
    else:
        dm_config = config.discovery.domain_monitor
        dm_domains = dm_config.domains or base_domains_from_fqdns(scope_fqdns)
        _run_stage(
            "domain_monitor",
            lambda: monitor_domains(dm_domains, scope_fqdns, dm_config, paths.output_dir),
        )
        checkpoint.mark_done("domain_monitor")

    # EPIC #182 (org_profile M2): zone hygiene and mail authentication posture.
    # Beside domain_monitor and for the same reason -- after resolve, so both
    # see the final in-scope FQDN list. Findings-only: neither adds FQDNs or
    # IPs, so --resume just skips them.
    if args.resume and checkpoint.is_done("dns_hygiene"):
        timer.skip("dns_hygiene")
    else:
        dns_hygiene_config = config.org_profile.dns_hygiene
        dns_hygiene_domains = dns_hygiene_config.domains or base_domains_from_fqdns(scope_fqdns)
        _run_stage(
            "dns_hygiene",
            lambda: check_dns_hygiene(
                dns_hygiene_domains,
                dns_hygiene_config,
                paths.output_dir,
            ),
        )
        checkpoint.mark_done("dns_hygiene")

    if args.resume and checkpoint.is_done("mail_posture"):
        timer.skip("mail_posture")
    else:
        mail_posture_config = config.org_profile.mail_posture
        mail_posture_domains = mail_posture_config.domains or base_domains_from_fqdns(scope_fqdns)
        _run_stage(
            "mail_posture",
            lambda: check_mail_posture(
                mail_posture_domains,
                mail_posture_config,
                paths.output_dir,
            ),
        )
        checkpoint.mark_done("mail_posture")

    if scope is not None:
        # Written before the emptiness check below, so a run that ends with
        # nothing left says *why* it had nothing left. The artifact rides back
        # in the results archive and the API folds it into auth_events — the
        # access-decision journal the scanner has no path to of its own (#244).
        scan_scope.write_denials(paths.output_dir, scope, scope_refusals)

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
        timer.skip("discover")
        alive_hosts = sorted(set(read_lines(alive_file)))
    else:
        alive_hosts = _run_stage(
            "discover",
            lambda: run_discovery_stage(
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
            ),
        )

    hostnames_file = paths.output_dir / "hostnames.json"
    if args.resume and checkpoint.is_done("discover-hostnames"):
        timer.skip("discover-hostnames")
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
        timer.skip("ports")
        open_ports = sorted(set(read_lines(open_file)))
    else:

        def _ports_stage() -> list[str]:
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
                    scan_type=port_cfg.scan_type,
                ),
                aggregate=open_set,
                aggregate_file=open_file,
                checkpoint=checkpoint,
                checkpoint_key="ports",
            )
            checkpoint.mark_done("ports")
            return sorted(open_set)

        open_ports = _run_stage("ports", _ports_stage)

    def _verify_alive() -> list[str]:
        verified = verify_alive_without_ports(
            alive_hosts=alive_hosts,
            open_ports=open_ports,
            config=config,
            profile=profile,
            output_dir=paths.output_dir,
            timeout=timeout,
            retries=retries,
        )
        write_lines(alive_file, verified)
        return verified

    # Default config enables discovery.verify — can re-probe hosts with no open
    # ports and dominate wall-clock after the ports stage; keep it visible.
    alive_hosts = _run_stage("verify_alive", _verify_alive)

    skip_nse = args.skip_nse or runtime.skip_nse
    nmap_dir = paths.output_dir / "nmap"
    # service_probe.backend: pulse (Phase 4.1 default) | nmap | hybrid.
    # Precedence: OCTO_SERVICE_BACKEND > profiles.<mode>.service_backend > YAML.
    resolution = resolve_service_probe_backend(
        env_backend=os.environ.get("OCTO_SERVICE_BACKEND", ""),
        profile_backend=profile.service_backend,
        yaml_backend=config.service_probe.backend,
        yaml_shadow=config.service_probe.shadow,
        env_shadow=os.environ.get("OCTO_PULSE_SHADOW", ""),
        skip_nse=skip_nse,
        warn=lambda msg: logging.warning(msg),
    )
    service_backend = resolution.backend
    shadow = resolution.shadow
    run_pulse = resolution.run_pulse
    run_nmap_nse = resolution.run_nmap_nse
    report_primary_pulse = resolution.report_primary_pulse

    # Keep pulse/REPORT_PRIMARY in sync with the *resolved* backend on every
    # invocation, not just when the pulse stage itself runs -- otherwise a
    # --resume that switches the backend away from pulse/hybrid leaves a
    # stale marker from an earlier run and report.py silently keeps
    # preferring outdated Pulse data (see build_reports' report_primary arg).
    (paths.output_dir / "pulse").mkdir(parents=True, exist_ok=True)
    sync_report_primary_marker(paths.output_dir / "pulse", report_primary_pulse)

    if shadow and not skip_nse:
        logging.info(
            "service_probe shadow enabled (backend=%s): running pulse + nmap, will write diff",
            service_backend,
        )
    elif not skip_nse:
        logging.info(
            "service_probe backend=%s (pulse=%s nmap_nse=%s)",
            service_backend,
            run_pulse,
            run_nmap_nse,
        )

    if skip_nse:
        logging.info("Skipping service probe / NSE stage (skip_nse: ports-only L1)")
        timer.skip("pulse", "skip_nse")
        timer.skip("nse", "skip_nse")
        nmap_dir.mkdir(parents=True, exist_ok=True)
    else:
        pulse_pending = run_pulse and not (args.resume and checkpoint.is_done("pulse"))
        nse_pending = run_nmap_nse and not (args.resume and checkpoint.is_done("nse"))

        def _do_pulse() -> None:
            pulse_cfg = merge_pulse_config(config.service_probe.pulse, profile.pulse)
            # Chunks that still report every port closed after their retry are
            # contradictions, not results (see pulse_probe). Marking the stage done
            # would let --resume skip it and keep that zero forever, so the flag is
            # withheld until a later run gets an answer for those hosts.
            unresolved: list[str] = []
            _run_stage(
                "pulse",
                lambda: run_pulse_probe(
                    open_ports,
                    output_dir=paths.output_dir,
                    bin_path=pulse_cfg.bin,
                    concurrency=pulse_cfg.concurrency,
                    rate=pulse_cfg.rate,
                    adaptive=pulse_cfg.adaptive,
                    host_parallel=pulse_cfg.host_parallel,
                    timeout_ms=pulse_cfg.timeout_ms,
                    banner=pulse_cfg.banner,
                    os_detect=pulse_cfg.os_detect,
                    os_mode=pulse_cfg.os_mode,
                    cve=pulse_cfg.cve,
                    cve_online=pulse_cfg.cve_online,
                    syn=pulse_cfg.syn,
                    max_hosts=pulse_cfg.max_hosts,
                    timeout_seconds=runtime.nse_timeout_seconds,
                    retries=retries,
                    done_hosts=checkpoint.done_items("pulse") if args.resume else set(),
                    on_host_done=lambda host: checkpoint.mark_item_done("pulse", host),
                    chunk_hosts=pulse_cfg.chunk_hosts,
                    report_primary=report_primary_pulse,
                    retry_settle_seconds=pulse_cfg.retry_settle_seconds,
                    on_unresolved=unresolved.extend,
                ),
            )
            if unresolved:
                logging.warning(
                    "pulse: %s host(s) still reported no services after re-probing; leaving the "
                    "stage open so --resume asks again: %s",
                    len(unresolved),
                    ", ".join(sorted(unresolved)[:10]),
                )
            else:
                checkpoint.mark_done("pulse")

        def _do_nse() -> Path:
            nse_profile = config.nse_profiles[profile.nse_profile]
            nse_timeout = runtime.nse_timeout_seconds
            nse_concurrency = profile.nse_concurrency or runtime.nse_concurrency
            nse_max_rate = (
                profile.nse_max_rate if profile.nse_max_rate is not None else runtime.nse_max_rate
            )
            result_dir = _run_stage(
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
            return result_dir

        if pulse_pending and nse_pending:
            # Pulse and nmap NSE are independent subprocess-based stages over
            # the same open_ports (no data dependency) -- only reachable when
            # both run (shadow/hybrid). Run them concurrently instead of
            # paying the full sum of both wall-clocks; CheckpointStore is
            # thread-safe and the two stages write to disjoint output paths.
            # Note: stages_sum_sec can exceed pipeline_wall_sec when concurrent.
            # copy_context so StageTimer ContextVar is visible in worker threads.
            with ThreadPoolExecutor(max_workers=2) as pool:
                pulse_future = pool.submit(copy_context().run, _do_pulse)
                nse_future = pool.submit(copy_context().run, _do_nse)
                pulse_exc: Exception | None = None
                nse_exc: Exception | None = None
                try:
                    pulse_future.result()
                except Exception as exc:  # noqa: BLE001
                    pulse_exc = exc
                try:
                    nmap_dir = nse_future.result()
                except Exception as exc:  # noqa: BLE001
                    nse_exc = exc
                if pulse_exc is not None:
                    raise pulse_exc
                if nse_exc is not None:
                    raise nse_exc
        else:
            if run_pulse:
                if not pulse_pending:
                    timer.skip("pulse")
                    logging.info("Skipping Pulse probe (checkpoint)")
                else:
                    _do_pulse()
            else:
                timer.skip("pulse", "backend")
            if run_nmap_nse:
                if nse_pending:
                    nmap_dir = _do_nse()
                else:
                    timer.skip("nse")
            else:
                timer.skip("nse", "backend")
                nmap_dir.mkdir(parents=True, exist_ok=True)

        # Shadow / hybrid: compare Pulse vs Nmap coverage when both sides exist.
        if (shadow or service_backend == "hybrid") and not (
            args.resume and checkpoint.is_done("pulse_shadow")
        ):
            if (paths.output_dir / "services.json").exists() or any(nmap_dir.rglob("*.xml")):
                _run_stage(
                    "pulse_shadow",
                    lambda: write_pulse_nmap_diff(
                        paths.output_dir,
                        nmap_dir,
                        extra={
                            "backend": service_backend,
                            "shadow": shadow,
                            "open_ports": len(open_ports),
                        },
                    ),
                )
                checkpoint.mark_done("pulse_shadow")
        elif args.resume and checkpoint.is_done("pulse_shadow"):
            timer.skip("pulse_shadow")

    # Phase 9.2 + Pulse Phase 4: TLS/certificate posture (findings-only,
    # non-escalating -- see tls_posture.py). Prefers nmap ssl-cert/ssl-enum-ciphers;
    # else Pulse pulse/tls.json; else probe_fallback stdlib handshake (tls_probe).
    if args.resume and checkpoint.is_done("tls_posture"):
        timer.skip("tls_posture")
    else:
        _run_stage(
            "tls_posture",
            lambda: check_tls_posture(
                nmap_dir,
                config.tls_posture,
                paths.output_dir,
                open_ports=open_ports,
                hostnames=hostnames_map,
            ),
        )
        checkpoint.mark_done("tls_posture")

    # Phase 9.1: tech stack fingerprinting (asset-inventory finding, not
    # scope-expanding -- see fingerprint.py module docstring). Runs against
    # already-open web ports from the ports stage; --resume just skips
    # re-running.
    if args.resume and checkpoint.is_done("fingerprint"):
        timer.skip("fingerprint")
    else:
        _run_stage(
            "fingerprint",
            lambda: fingerprint_hosts_sync(open_ports, config.fingerprint, paths.output_dir),
        )
        checkpoint.mark_done("fingerprint")

    # P4.4 / Phase 9.3: screenshots of already-open web ports. Opt-in,
    # redacted in-DOM, never a new scan. Playwright missing → skip.
    if args.resume and checkpoint.is_done("screenshots"):
        timer.skip("screenshots")
    else:
        _run_stage(
            "screenshots",
            lambda: capture_screenshots_sync(open_ports, config.screenshots, paths.output_dir),
        )
        checkpoint.mark_done("screenshots")

    # Phase 4.2: Nuclei web CVE/misconfig scan (default on; see nuclei_scan.py).
    # CVE path without nmap-vulners: Pulse --cve + Nuclei + CVSS4 enrichment.
    # CVE-tagged matches feed into build_reports alongside Pulse/NSE vulns.
    # Under --resume, reload prior result from disk (reports still regenerate).
    if args.resume and checkpoint.is_done("nuclei"):
        timer.skip("nuclei")
        nuclei_result = load_json(
            paths.output_dir / "nuclei.json",
            fallback={"cve_findings": []},
        )
    else:
        # Speed profile wins over the global nuclei block, same merge rule as
        # profiles.<mode>.pulse — this is the stage that dominates runtime once
        # ports are actually found, so a profile that cannot reach it is not
        # really a speed profile.
        nuclei_cfg = merge_nuclei_config(config.nuclei, profile.nuclei)
        nuclei_result = _run_stage(
            "nuclei",
            lambda: run_nuclei_scan(open_ports, nuclei_cfg, paths.output_dir),
        )
        checkpoint.mark_done("nuclei")
    nuclei_cve_findings = nuclei_result.get("cve_findings") or []

    reporting = config.reporting
    enrichment = config.enrichment
    # Env overrides let a shared-volume deployment (k8s enrichment overlay) point
    # GeoIP/CVSS4 at a refreshed data path without shipping a separate config,
    # mirroring the env-or-config pattern used for alerts/DefectDojo secrets.
    cvss4_database = os.environ.get("OCTO_CVSS4_DATABASE", "").strip() or enrichment.cvss4.database
    geoip_database = os.environ.get("OCTO_GEOIP_DATABASE", "").strip() or enrichment.geoip.database
    asn_database = os.environ.get("OCTO_ASN_DATABASE", "").strip() or enrichment.asn.database
    _run_stage(
        "report",
        lambda: build_reports(
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
            sarif_export=reporting.sarif_export,
            cvss4_enabled=enrichment.cvss4.enabled,
            cvss4_database=cvss4_database,
            geoip_enabled=enrichment.geoip.enabled,
            geoip_database=geoip_database,
            asn_enabled=enrichment.asn.enabled,
            asn_database=asn_database,
            extra_vulnerabilities=nuclei_cve_findings,
            report_primary=report_primary_pulse,
        ),
    )
    checkpoint.mark_done("report")

    # EPIC #182 (org_profile M4): Related domains passive discovery & correlation.
    if config.org_profile.related_domains.enabled:
        if args.resume and checkpoint.is_done("related_domains"):
            timer.skip("related_domains")
        else:
            rel_domains = config.org_profile.ownership.domains or base_domains_from_fqdns(scope_fqdns)
            _run_stage(
                "related_domains",
                lambda: discover_related_domains(
                    paths.output_dir,
                    config.org_profile.related_domains,
                    seed_domains=rel_domains,
                ),
            )
            checkpoint.mark_done("related_domains")

    # EPIC #182 (org_profile M5): Corporate credential leaks via pluggable provider.
    if config.org_profile.credential_leaks.enabled:
        if args.resume and checkpoint.is_done("credential_leaks"):
            timer.skip("credential_leaks")
        else:
            leak_domains = config.org_profile.credential_leaks.domains or base_domains_from_fqdns(scope_fqdns)
            _run_stage(
                "credential_leaks",
                lambda: check_credential_leaks(
                    leak_domains,
                    config.org_profile.credential_leaks,
                    paths.output_dir,
                ),
            )
            checkpoint.mark_done("credential_leaks")

    # EPIC #182 (org_profile M3): Security controls matrix & NIST risk evaluation.
    # Reads findings and posture from stage artifacts and builds controls.json.
    if config.org_profile.controls.enabled:
        if args.resume and checkpoint.is_done("controls"):
            timer.skip("controls")
        else:
            _run_stage(
                "controls",
                lambda: evaluate_controls(paths.output_dir, config.org_profile.controls),
            )
            checkpoint.mark_done("controls")

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


def _validate_config_only(config_path: Path) -> int:
    """Parse the config file and report the first failure. No stage is started."""
    import yaml

    try:
        raw = load_yaml(config_path)
    except FileNotFoundError:
        print(f"configuration file not found: {config_path}", file=sys.stderr)
        return exit_codes.CONFIG_ERROR
    except yaml.YAMLError as exc:
        print(f"configuration is not valid YAML: {exc}", file=sys.stderr)
        return exit_codes.CONFIG_ERROR
    try:
        load_config(raw)
    except ValidationError as exc:
        print(format_validation_error(exc), file=sys.stderr)
        return exit_codes.CONFIG_ERROR
    print(f"configuration OK: {config_path}")
    return exit_codes.SUCCESS


def main() -> int:
    args = parse_args()
    if args.validate_config:
        return _validate_config_only(Path(args.config))
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
