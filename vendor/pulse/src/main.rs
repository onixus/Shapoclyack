mod cli;
mod scanner;
mod ui;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, DiscoverMethodCli, OsEngine, OutputFormat, ProtocolChoice};
use owo_colors::OwoColorize;
use scanner::{
    analyze_cves, detect_os_batch, discover_hosts, ensure_os_capable, ensure_syn_capable,
    expand_targets_combined_with, parse_ports, remaining_targets, scan_ports_ex, top_ports,
    top_udp_ports, Checkpoint, CheckpointStatus, CveFinding, DiscoverConfig, DiscoverMethod,
    ExpandOptions, JobFingerprint, OsDetectConfig, OsGuess, OsMode, Protocol, RateLimiter,
    ScanConfig, ScanMode, Target,
};
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use ui::{
    print_banner, print_cve_results, print_live_open, print_os_results, print_results, print_summary,
    run_tui_scan, write_html_report, ScanProgress, TuiScanMeta,
};

#[tokio::main]
async fn main() -> Result<()> {
    // When launched from GUI (no TTY), stdout is fully buffered and the macOS
    // app appears "stuck" until process exit. Force line-buffering / unbuffered.
    force_live_output();

    let cli = Cli::parse();

    let protocols = resolve_protocols(&cli);
    let ports = resolve_ports(&cli, &protocols)?;
    let mode = if cli.syn {
        ScanMode::Syn
    } else {
        ScanMode::Connect
    };

    if cli.syn {
        if matches!(cli.protocol, ProtocolChoice::Udp) && !cli.udp {
            anyhow::bail!("--syn is a TCP technique; use --protocol tcp|both (not udp-only)");
        }
        ensure_syn_capable()?;
        if cli.banner && !cli.quiet {
            eprintln!(
                "  {}  --banner ignored in SYN mode (no full handshake)",
                "note".yellow()
            );
        }
    }
    if cli.os {
        ensure_os_capable()?;
    }

    let want_cve = cli.cve || cli.cve_online;
    let grab_banner = (cli.banner || want_cve) && !cli.syn;
    let checkpoint_path = cli.checkpoint.clone().or_else(|| cli.resume.clone());

    let mut resume_open: Vec<scanner::PortResult> = Vec::new();
    let mut resume_probes_done = 0usize;
    let mut resume_closed = 0usize;
    let mut full_host_count = 0usize;
    let mut resuming = false;

    // ── Resume path: restore hosts from checkpoint (skip re-expand / re-discover) ──
    let mut targets: Vec<Target> = if let Some(path) = &checkpoint_path {
        if path.exists() {
            let ck = Checkpoint::load_for_resume(path, &ports, &protocols, mode)?;
            full_host_count = if ck.all_hosts.is_empty() {
                ck.job.host_count
            } else {
                ck.all_hosts.len()
            };

            if ck.status == CheckpointStatus::Done {
                if !cli.quiet {
                    eprintln!(
                        "  {}  already complete ({} open) — {}",
                        "resume".magenta().bold(),
                        ck.open.len().to_string().green(),
                        path.display()
                    );
                }
                let stats = Arc::new(scanner::ScanStats::new(ck.probes_done.max(1)));
                stats
                    .open
                    .store(ck.open_count, std::sync::atomic::Ordering::Relaxed);
                stats
                    .closed
                    .store(ck.closed_count, std::sync::atomic::Ordering::Relaxed);
                stats
                    .done
                    .store(ck.probes_done, std::sync::atomic::Ordering::Relaxed);
                stats.finish();
                print_results(
                    &ck.open,
                    &stats,
                    cli.format,
                    !cli.all,
                    cli.quiet,
                    &[],
                    &[],
                );
                print_summary(full_host_count, ports.len(), &stats, cli.quiet);
                return Ok(());
            }

            let all = if ck.all_hosts.is_empty() {
                // Legacy checkpoint without all_hosts — fall through to expand
                Vec::new()
            } else {
                ck.targets_from_all()
            };

            if !all.is_empty() {
                let completed = ck.completed_set();
                let remaining = remaining_targets(&all, &completed);
                resume_open = ck.open.clone();
                resume_probes_done = ck.probes_done;
                resume_closed = ck.closed_count;
                resuming = true;
                if !cli.quiet {
                    eprintln!(
                        "  {}  {} done · {} left · {} open saved · {}",
                        "resume".magenta().bold(),
                        completed.len().to_string().cyan(),
                        remaining.len().to_string().green(),
                        resume_open.len(),
                        path.display()
                    );
                }
                if remaining.is_empty() {
                    let mut ck = ck;
                    ck.mark_done();
                    ck.save(path)?;
                    let stats = Arc::new(scanner::ScanStats::new(ck.probes_done.max(1)));
                    stats
                        .open
                        .store(ck.open_count, std::sync::atomic::Ordering::Relaxed);
                    stats
                        .closed
                        .store(ck.closed_count, std::sync::atomic::Ordering::Relaxed);
                    stats
                        .done
                        .store(ck.probes_done, std::sync::atomic::Ordering::Relaxed);
                    stats.finish();
                    print_results(
                        &ck.open,
                        &stats,
                        cli.format,
                        !cli.all,
                        cli.quiet,
                        &[],
                        &[],
                    );
                    print_summary(full_host_count, ports.len(), &stats, cli.quiet);
                    return Ok(());
                }
                remaining
            } else {
                Vec::new() // trigger fresh expand below
            }
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    // ── Fresh expand (+ optional discovery) when not resuming ──
    if !resuming {
        if cli.target.is_none() && cli.targets_file.is_none() {
            anyhow::bail!("provide TARGET and/or --targets-file (-T)");
        }

        let expand_opts = ExpandOptions {
            max_hosts: cli.max_hosts,
            exclude_specs: cli.exclude.clone(),
            exclude_file: cli.exclude_file.clone(),
        };

        targets = expand_targets_combined_with(
            cli.target.as_deref(),
            cli.targets_file.as_deref(),
            &expand_opts,
        )
        .with_context(|| {
            format!(
                "invalid target(s) '{}'{}",
                cli.target.as_deref().unwrap_or(""),
                cli.targets_file
                    .as_ref()
                    .map(|p| format!(" + file {}", p.display()))
                    .unwrap_or_default()
            )
        })?;

        let estimate = targets
            .len()
            .saturating_mul(ports.len())
            .saturating_mul(protocols.len().max(1));
        if estimate > 1_000_000 && !cli.quiet {
            eprintln!(
                "  {}  large job ~{} probes ({} hosts × {} ports). \
                 Tip: -D --top 100 --rate 3000 --checkpoint job.ckpt",
                "warn".yellow().bold(),
                estimate,
                targets.len(),
                ports.len()
            );
        }

        if cli.discover {
            let method = match cli.discover_method {
                DiscoverMethodCli::Tcp => DiscoverMethod::Tcp,
                DiscoverMethodCli::Icmp => DiscoverMethod::Icmp,
                DiscoverMethodCli::Arp => DiscoverMethod::Arp,
                DiscoverMethodCli::Both => DiscoverMethod::Both,
                DiscoverMethodCli::Auto => DiscoverMethod::Auto,
            };
            let disc_ports = parse_ports(&cli.discover_ports).unwrap_or_else(|_| {
                vec![80, 443, 22, 445, 3389]
            });
            let rate = Arc::new(match cli.rate {
                Some(pps) if pps > 0 => RateLimiter::per_second(pps),
                _ => RateLimiter::unlimited(),
            });
            let dcfg = DiscoverConfig {
                method,
                ports: disc_ports,
                timeout: Duration::from_millis(cli.discover_timeout),
                concurrency: cli.concurrency,
                rate,
            };
            if !cli.quiet {
                eprintln!(
                    "  {}  discovering live hosts among {} candidates…",
                    "discover".magenta().bold(),
                    targets.len().to_string().cyan()
                );
            }
            let candidates = targets.len();
            let (live, dstats) = discover_hosts(targets, dcfg).await?;
            if !cli.quiet {
                eprintln!(
                    "  {}  {} live / {} candidates  ·  method {}",
                    "discover".magenta().bold(),
                    dstats.live.to_string().green().bold(),
                    candidates,
                    dstats.method_used.bright_black()
                );
            }
            if live.is_empty() {
                if cli.discover_strict {
                    anyhow::bail!(
                        "discovery found 0 live hosts (strict mode). \
                         Try --discover-method tcp --discover-ports 22,80,443 or disable -D"
                    );
                }
                if !cli.quiet {
                    eprintln!(
                        "  {}  no live hosts — aborting port scan",
                        "note".yellow()
                    );
                }
                return Ok(());
            }
            targets = live;
        }

        full_host_count = targets.len();

        // Create fresh checkpoint
        if let Some(path) = &checkpoint_path {
            let label = cli.target.clone().or_else(|| {
                cli.targets_file
                    .as_ref()
                    .map(|p| p.display().to_string())
            });
            let job = JobFingerprint::compute(&targets, &ports, &protocols, mode, label);
            let all_hosts: Vec<String> = targets.iter().map(|t| t.addr.to_string()).collect();
            let ck = Checkpoint::new(job, all_hosts);
            ck.save(path)?;
            if !cli.quiet {
                eprintln!(
                    "  {}  writing progress → {}",
                    "checkpoint".magenta().bold(),
                    path.display()
                );
            }
        }
    }

    // Resume without TARGET is ok; fresh scan needs TARGET
    if targets.is_empty() {
        anyhow::bail!("no hosts to scan");
    }

    let probes_per_host = ports.len().saturating_mul(protocols.len().max(1));
    let full_total_probes = full_host_count.saturating_mul(probes_per_host);

    let config = ScanConfig {
        concurrency: cli.concurrency,
        timeout: Duration::from_millis(cli.timeout),
        grab_banner,
        protocols: protocols.clone(),
        mode,
        rate_pps: cli.rate.filter(|&r| r > 0),
        store_closed: cli.all,
        progress_every: 64,
        host_batch: cli.host_batch.max(1),
        checkpoint_path: checkpoint_path.clone(),
        resume_open: resume_open.clone(),
        resume_probes_done,
        resume_closed,
        resume_total_probes: Some(full_total_probes.max(1)),
        adaptive: cli.adaptive,
        host_first: cli.host_first || cli.host_parallel.is_some(),
        host_parallel: cli.host_parallel.unwrap_or(0),
        syn_retries: cli.syn_retries.min(5),
    };

    let port_label = port_label(&cli, &ports);
    let mut proto_label = protocols
        .iter()
        .map(|p| p.as_str().to_uppercase())
        .collect::<Vec<_>>()
        .join("+");
    if cli.syn {
        proto_label = if proto_label.contains("UDP") {
            "SYN+UDP".into()
        } else {
            "SYN".into()
        };
    }
    let target_label = if targets.len() == 1 {
        targets[0].display.clone()
    } else if resuming {
        format!(
            "{} hosts (resume · {} total)",
            targets.len(),
            full_host_count
        )
    } else {
        let src = match (&cli.target, &cli.targets_file) {
            (Some(t), Some(f)) => format!("{t} + {}", f.display()),
            (Some(t), None) => t.clone(),
            (None, Some(f)) => f.display().to_string(),
            _ => "targets".into(),
        };
        let disc = if cli.discover { " live" } else { "" };
        format!("{}{} hosts from {}", targets.len(), disc, src)
    };

    let (results, stats) = if cli.tui {
        let meta = TuiScanMeta {
            target_label: target_label.clone(),
            port_label: port_label.clone(),
            concurrency: cli.concurrency,
            timeout_ms: cli.timeout,
            protocols: proto_label.clone(),
            banner: cli.banner && !cli.syn,
            syn: cli.syn,
            adaptive: cli.adaptive,
            host_first: cli.host_first || cli.host_parallel.is_some(),
            host_parallel: cli.host_parallel.unwrap_or(0),
            syn_retries: cli.syn_retries.min(5),
        };
        run_tui_scan(targets.clone(), ports.clone(), config, meta).await?
    } else {
        run_cli_scan(
            &cli,
            &targets,
            &ports,
            &config,
            &target_label,
            &port_label,
            &proto_label,
        )
        .await?
    };

    // OS fingerprint only hosts that had open ports (big win on large nets)
    let open_hosts: Vec<Target> = {
        let mut seen = HashSet::new();
        let mut list = Vec::new();
        for r in results.iter().filter(|r| r.open) {
            if seen.insert(r.ip.clone()) {
                if let Ok(ip) = r.ip.parse() {
                    list.push(Target {
                        display: r.host.clone(),
                        addr: ip,
                    });
                }
            }
        }
        list
    };

    let prefer_open: Vec<u16> = results
        .iter()
        .filter(|r| r.open)
        .map(|r| r.port)
        .collect();
    let prefer_closed: Vec<u16> = results
        .iter()
        .filter(|r| !r.open)
        .map(|r| r.port)
        .take(32)
        .collect();

    let os_guesses: Vec<OsGuess> = if cli.os {
        let mode = match cli.os_mode {
            OsEngine::SinFp => OsMode::SinFp,
            OsEngine::Nmap => OsMode::Nmap,
            OsEngine::Auto => OsMode::Auto,
        };
        let os_targets = if open_hosts.is_empty() {
            // fallback: original targets if nothing open (still try)
            targets.clone()
        } else {
            open_hosts
        };
        if !cli.quiet && matches!(cli.format, OutputFormat::Pretty) {
            let engine = match mode {
                OsMode::SinFp => "SinFP (fast, 1 probe)",
                OsMode::Nmap => "nmap-os-db (deep)",
                OsMode::Auto => "auto (SinFP → nmap)",
            };
            println!(
                "  {}  fingerprinting {} host(s) with open ports · {}",
                "os".magenta().bold(),
                os_targets.len().to_string().cyan(),
                engine.yellow()
            );
        }
        let os_cfg = OsDetectConfig {
            timeout: Duration::from_millis(cli.timeout.max(500)),
            os_db: cli.os_db.clone(),
            fetch_db: cli.os_db_fetch,
            limit: cli.os_limit,
            min_accuracy: cli.os_min_accuracy.clamp(0.0, 1.0),
            prefer_open,
            prefer_closed,
            mode,
        };
        detect_os_batch(&os_targets, os_cfg).await?
    } else {
        Vec::new()
    };

    let cves: Vec<CveFinding> = if want_cve {
        if !cli.quiet && matches!(cli.format, OutputFormat::Pretty) {
            println!(
                "  {}  correlating CVE/CVSS{}…",
                "cve".magenta().bold(),
                if cli.cve_online {
                    " (local + NVD online)"
                } else {
                    " (local rules)"
                }
            );
        }
        analyze_cves(&results, cli.cve_online).await
    } else {
        Vec::new()
    };

    // After TUI, still print a compact summary to normal terminal
    if cli.tui {
        print_results(
            &results,
            &stats,
            OutputFormat::Pretty,
            true,
            false,
            &os_guesses,
            &cves,
        );
        if cli.os {
            print_os_results(&os_guesses, false, OutputFormat::Pretty);
        }
        if want_cve {
            print_cve_results(&cves, false, OutputFormat::Pretty);
        }
        print_summary(targets.len(), ports.len(), &stats, false);
    } else {
        let pretty = matches!(cli.format, OutputFormat::Pretty);
        print_results(
            &results,
            &stats,
            cli.format,
            !cli.all,
            cli.quiet,
            &os_guesses,
            &cves,
        );
        if cli.os && !matches!(cli.format, OutputFormat::Json) {
            print_os_results(&os_guesses, cli.quiet, cli.format);
        }
        if want_cve && !matches!(cli.format, OutputFormat::Json) {
            print_cve_results(&cves, cli.quiet, cli.format);
        }
        print_summary(targets.len(), ports.len(), &stats, cli.quiet || !pretty);
    }

    if let Some(path) = &cli.html {
        let report_name = cli
            .target
            .clone()
            .or_else(|| {
                cli.targets_file
                    .as_ref()
                    .map(|p| p.display().to_string())
            })
            .unwrap_or_else(|| format!("{} hosts", full_host_count));
        write_html_report(path, &report_name, &results, &stats, &os_guesses, &cves)
            .with_context(|| format!("failed to write HTML report to {}", path.display()))?;
        if !cli.quiet {
            println!(
                "  {}  {}\n",
                "REPORT".bright_black().bold(),
                path.display().to_string().white().bold()
            );
        }
    }

    // Mark checkpoint complete
    if let Some(path) = &checkpoint_path {
        if let Ok(mut ck) = Checkpoint::load(path) {
            // Ensure all final opens are present
            ck.mark_hosts_done(
                std::iter::empty::<String>(),
                &results.iter().filter(|r| r.open).cloned().collect::<Vec<_>>(),
                0,
                0,
            );
            ck.mark_done();
            if let Err(e) = ck.save(path) {
                eprintln!("  checkpoint finalize warning: {e:#}");
            } else if !cli.quiet {
                eprintln!(
                    "  {}  complete → {}",
                    "checkpoint".magenta().bold(),
                    path.display()
                );
            }
        }
    }

    Ok(())
}

async fn run_cli_scan(
    cli: &Cli,
    targets: &[scanner::Target],
    ports: &[u16],
    config: &ScanConfig,
    target_label: &str,
    port_label: &str,
    proto_label: &str,
) -> Result<(Vec<scanner::PortResult>, Arc<scanner::ScanStats>)> {
    let pretty = matches!(cli.format, OutputFormat::Pretty);
    let quiet = cli.quiet;

    if !quiet && pretty {
        print_banner();
        print_scan_plan(
            cli,
            target_label,
            port_label,
            proto_label,
            config.grab_banner,
            cli.cve || cli.cve_online,
        );
    }

    let total = (targets.len() * ports.len() * config.protocols.len().max(1)) as u64;
    let progress = Arc::new(ScanProgress::new(total, quiet || !pretty));
    let live_lock = Arc::new(Mutex::new(()));

    // Optional NDJSON stream of open ports
    let stream_file: Option<Arc<Mutex<std::fs::File>>> = if let Some(path) = &cli.stream {
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open --stream {}", path.display()))?;
        if !quiet {
            eprintln!(
                "  {}  streaming open events → {}",
                "stream".magenta().bold(),
                path.display()
            );
        }
        Some(Arc::new(Mutex::new(f)))
    } else {
        None
    };

    let progress_cb = {
        let progress = progress.clone();
        move |n: usize| progress.set(n as u64)
    };

    let open_cb = {
        let stream_file = stream_file.clone();
        let live_lock = live_lock.clone();
        move |r: &scanner::PortResult| {
            if pretty && !quiet {
                let _guard = live_lock.lock().unwrap();
                print_live_open(r, false);
            }
            if let Some(sf) = &stream_file {
                if let Ok(mut f) = sf.lock() {
                    let _ = write_stream_open(&mut *f, r);
                }
            }
        }
    };

    let show_host_done = pretty && !quiet && config.host_first;
    let host_done_cb = {
        let live_lock = live_lock.clone();
        move |h: scanner::HostDoneInfo| {
            if show_host_done {
                let _guard = live_lock.lock().unwrap();
                use owo_colors::OwoColorize;
                println!(
                    "  {}  {:<15}  {} open / {} ports",
                    "▸".cyan().bold(),
                    h.ip.bright_black(),
                    h.open.to_string().green().bold(),
                    h.ports.to_string().bright_black()
                );
            }
        }
    };

    let (results, stats) =
        scan_ports_ex(targets, ports, config, progress_cb, open_cb, host_done_cb).await;
    progress.finish();

    if let (Some(path), Some(sf)) = (&cli.stream, &stream_file) {
        if let Ok(mut f) = sf.lock() {
            let _ = write_stream_done(&mut *f, stats.open_count(), stats.elapsed());
        }
        if !quiet {
            eprintln!(
                "  {}  wrote {}",
                "stream".magenta().bold(),
                path.display()
            );
        }
    }

    Ok((results, stats))
}

fn write_stream_open(f: &mut impl Write, r: &scanner::PortResult) -> Result<()> {
    let line = serde_json::json!({
        "event": "open",
        "host": r.host,
        "ip": r.ip,
        "port": r.port,
        "protocol": r.protocol.as_str(),
        "service": r.service,
        "latency_ms": r.latency_ms,
        "banner": r.banner,
    });
    writeln!(f, "{line}")?;
    f.flush()?;
    Ok(())
}

fn write_stream_done(f: &mut impl Write, open: usize, elapsed_ms: u64) -> Result<()> {
    let line = serde_json::json!({
        "event": "done",
        "open": open,
        "elapsed_ms": elapsed_ms,
    });
    writeln!(f, "{line}")?;
    f.flush()?;
    Ok(())
}

fn force_live_output() {
    // GUI launches pulse without a TTY → full block buffering → empty log until exit.
    #[cfg(target_os = "macos")]
    unsafe {
        extern "C" {
            static mut __stdoutp: *mut libc::FILE;
            static mut __stderrp: *mut libc::FILE;
        }
        if !__stdoutp.is_null() {
            libc::setvbuf(__stdoutp, std::ptr::null_mut(), libc::_IONBF, 0);
        }
        if !__stderrp.is_null() {
            libc::setvbuf(__stderrp, std::ptr::null_mut(), libc::_IONBF, 0);
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    unsafe {
        extern "C" {
            static mut stdout: *mut libc::FILE;
            static mut stderr: *mut libc::FILE;
        }
        if !stdout.is_null() {
            libc::setvbuf(stdout, std::ptr::null_mut(), libc::_IONBF, 0);
        }
        if !stderr.is_null() {
            libc::setvbuf(stderr, std::ptr::null_mut(), libc::_IONBF, 0);
        }
    }
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let _ = std::io::Write::flush(&mut std::io::stderr());
}

fn resolve_protocols(cli: &Cli) -> Vec<Protocol> {
    match cli.protocol {
        ProtocolChoice::Tcp if cli.udp => vec![Protocol::Tcp, Protocol::Udp],
        ProtocolChoice::Tcp => vec![Protocol::Tcp],
        ProtocolChoice::Udp => vec![Protocol::Udp],
        ProtocolChoice::Both => vec![Protocol::Tcp, Protocol::Udp],
    }
}

fn resolve_ports(cli: &Cli, protocols: &[Protocol]) -> Result<Vec<u16>> {
    if let Some(n) = cli.top {
        let only_udp = protocols == [Protocol::Udp];
        if only_udp {
            Ok(top_udp_ports(n))
        } else {
            Ok(top_ports(n))
        }
    } else {
        parse_ports(&cli.ports).context("invalid port specification")
    }
}

fn port_label(cli: &Cli, ports: &[u16]) -> String {
    if let Some(n) = cli.top {
        format!("top {n}")
    } else if ports.len() <= 8 {
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        format!(
            "{} ports ({}–{})",
            ports.len(),
            ports.first().unwrap(),
            ports.last().unwrap()
        )
    }
}

fn print_scan_plan(
    cli: &Cli,
    target_label: &str,
    port_label: &str,
    proto_label: &str,
    grab_banner: bool,
    want_cve: bool,
) {
    use ui::theme::{kv, rule, section_title, value_white};

    section_title("mission");
    kv("target", value_white(target_label));
    kv(
        "ports",
        format!(
            "{}  ·  {}",
            port_label.white(),
            proto_label.bright_black()
        ),
    );

    let mut engine = if cli.adaptive {
        format!("≤{}c adaptive  ·  {}ms", cli.concurrency, cli.timeout)
    } else {
        format!("{}c  ·  {}ms", cli.concurrency, cli.timeout)
    };
    if cli.syn {
        engine.push_str("  ·  SYN");
    }
    if cli.discover {
        engine.push_str("  ·  DISCOVER");
    }
    if let Some(rate) = cli.rate.filter(|&r| r > 0) {
        engine.push_str(&format!("  ·  {rate}pps"));
    }
    if cli.checkpoint.is_some() || cli.resume.is_some() {
        engine.push_str("  ·  CHECKPOINT");
    }
    if cli.host_first || cli.host_parallel.is_some() {
        if let Some(n) = cli.host_parallel {
            engine.push_str(&format!("  ·  HOST×{n}"));
        } else {
            engine.push_str("  ·  HOST-FIRST");
        }
    }
    if cli.syn && cli.syn_retries > 0 {
        engine.push_str(&format!("  ·  SYN×{}", cli.syn_retries + 1));
    }
    if cli.os {
        let eng = match cli.os_mode {
            OsEngine::SinFp => "SinFP",
            OsEngine::Nmap => "nmap-OS",
            OsEngine::Auto => "auto-OS",
        };
        engine.push_str("  ·  ");
        engine.push_str(eng);
    }
    if grab_banner {
        engine.push_str("  ·  BANNER");
    }
    if want_cve {
        engine.push_str(if cli.cve_online {
            "  ·  CVE+NVD"
        } else {
            "  ·  CVE"
        });
    }
    if cli.stream.is_some() {
        engine.push_str("  ·  STREAM");
    }
    kv("engine", value_white(engine));
    rule();
    println!(
        "  {}\n",
        "LIVE  open ports stream below".bright_black()
    );
}
