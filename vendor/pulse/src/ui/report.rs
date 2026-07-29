use crate::cli::OutputFormat;
use crate::scanner::{CveFinding, OsGuess, PortResult, ScanStats};
use crate::ui::theme::{
    kv, rule, section_title, td_dim, td_open, td_port, td_svc, td_white, th, value_ok, value_white,
};
use comfy_table::presets::UTF8_HORIZONTAL_ONLY;
use comfy_table::{ContentArrangement, Table};
use owo_colors::OwoColorize;
use std::sync::Arc;

pub fn print_live_open(r: &PortResult, quiet: bool) {
    if quiet {
        return;
    }
    let lat = r
        .latency_ms
        .map(|ms| format!("{ms:>4}ms"))
        .unwrap_or_else(|| "   — ".into());
    let banner = r
        .banner
        .as_ref()
        .map(|b| format!("  {}", b.bright_black()))
        .unwrap_or_default();

    // Mission-control live hit: green mark · proto · host · port · service · latency
    println!(
        "  {}  {:<4}  {:<15}  {:>5}  {:<12}  {}{}",
        "●".green().bold(),
        r.protocol.as_str().to_uppercase().bright_black(),
        r.ip.white(),
        r.port.to_string().white().bold(),
        r.service.bright_black(),
        lat.bright_black(),
        banner
    );
}

pub fn print_results(
    results: &[PortResult],
    stats: &Arc<ScanStats>,
    format: OutputFormat,
    open_only: bool,
    quiet: bool,
    os_guesses: &[OsGuess],
    cves: &[CveFinding],
) {
    let mut open: Vec<&PortResult> = results.iter().filter(|r| r.open).collect();
    open.sort_by(|a, b| {
        a.ip.cmp(&b.ip)
            .then(a.protocol.as_str().cmp(b.protocol.as_str()))
            .then(a.port.cmp(&b.port))
    });

    match format {
        OutputFormat::Json => {
            let stats_json = serde_json::json!({
                "total": stats.total,
                "open": stats.open_count(),
                "closed": stats.closed_count(),
                "elapsed_ms": stats.elapsed(),
                "rate_pps": stats.rate(),
            });
            let payload = if open_only {
                serde_json::json!({
                    "open": open,
                    "os": os_guesses,
                    "cves": cves,
                    "stats": stats_json,
                })
            } else {
                serde_json::json!({
                    "results": results,
                    "os": os_guesses,
                    "cves": cves,
                    "stats": stats_json,
                })
            };
            println!("{}", serde_json::to_string_pretty(&payload).unwrap());
        }
        OutputFormat::Csv => {
            println!("host,ip,port,protocol,open,service,latency_ms,banner");
            let rows: Vec<&PortResult> = if open_only {
                open
            } else {
                results.iter().collect()
            };
            for r in rows {
                println!(
                    "{},{},{},{},{},{},{},{}",
                    csv_escape(&r.host),
                    r.ip,
                    r.port,
                    r.protocol.as_str(),
                    r.open,
                    r.service,
                    r.latency_ms.map(|v| v.to_string()).unwrap_or_default(),
                    r.banner
                        .as_ref()
                        .map(|b| csv_escape(b))
                        .unwrap_or_default()
                );
            }
        }
        OutputFormat::Pretty => {
            if open.is_empty() {
                if !quiet {
                    section_title("open ports");
                    println!("  {}\n", "none".bright_black());
                }
                return;
            }

            if !quiet {
                section_title("open ports");
            }

            // Multi-host: group by IP for readable per-host blocks
            let multi_host = {
                let mut ips = open.iter().map(|r| r.ip.as_str()).collect::<Vec<_>>();
                ips.sort_unstable();
                ips.dedup();
                ips.len() > 1
            };

            if multi_host && !quiet {
                print_open_by_host(&open);
            } else {
                let mut table = Table::new();
                table
                    .load_preset(UTF8_HORIZONTAL_ONLY)
                    .set_content_arrangement(ContentArrangement::Dynamic)
                    .set_header(vec![
                        th("STATUS"),
                        th("PROTO"),
                        th("HOST"),
                        th("PORT"),
                        th("SERVICE"),
                        th("LATENCY"),
                        th("BANNER"),
                    ]);

                for r in &open {
                    let lat = r
                        .latency_ms
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| "—".into());
                    let banner = r.banner.as_deref().unwrap_or("—");

                    table.add_row(vec![
                        td_open(),
                        td_dim(r.protocol.as_str().to_uppercase()),
                        td_white(&r.ip),
                        td_port(r.port.to_string()),
                        td_svc(&r.service),
                        td_dim(lat),
                        td_dim(banner),
                    ]);
                }

                println!("{table}");
            }
        }
    }
}

/// Pretty multi-host report: one block per IP.
fn print_open_by_host(open: &[&PortResult]) {
    use std::collections::BTreeMap;
    let mut by_host: BTreeMap<&str, Vec<&&PortResult>> = BTreeMap::new();
    for r in open {
        by_host.entry(r.ip.as_str()).or_default().push(r);
    }

    for (ip, rows) in by_host {
        let host_label = rows.first().map(|r| r.host.as_str()).unwrap_or(ip);
        println!(
            "  {}  {}  {}  ({} open)",
            "▸".cyan().bold(),
            ip.white().bold(),
            if host_label != ip {
                format!("· {host_label}").bright_black().to_string()
            } else {
                String::new()
            },
            rows.len().to_string().green().bold()
        );

        let mut table = Table::new();
        table
            .load_preset(UTF8_HORIZONTAL_ONLY)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                th("STATUS"),
                th("PROTO"),
                th("PORT"),
                th("SERVICE"),
                th("LATENCY"),
                th("BANNER"),
            ]);

        for r in rows {
            let lat = r
                .latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "—".into());
            let banner = r.banner.as_deref().unwrap_or("—");
            table.add_row(vec![
                td_open(),
                td_dim(r.protocol.as_str().to_uppercase()),
                td_port(r.port.to_string()),
                td_svc(&r.service),
                td_dim(lat),
                td_dim(banner),
            ]);
        }
        println!("{table}");
    }
}

pub fn print_summary(targets: usize, ports: usize, stats: &Arc<ScanStats>, quiet: bool) {
    if quiet {
        return;
    }

    let elapsed_s = stats.elapsed() as f64 / 1000.0;
    let _ = ports;

    section_title("complete");
    kv("hosts", value_white(targets));
    kv("probes", value_white(stats.total));
    kv(
        "open",
        format!(
            "{}  ·  {} closed",
            value_ok(stats.open_count()),
            stats.closed_count().to_string().bright_black()
        ),
    );
    kv(
        "time",
        format!(
            "{}s  ·  {} pps",
            format!("{elapsed_s:.2}").white().bold(),
            format!("{:.0}", stats.rate()).bright_black()
        ),
    );
    println!();
}

pub fn print_os_results(guesses: &[OsGuess], quiet: bool, format: OutputFormat) {
    if guesses.is_empty() {
        return;
    }

    match format {
        OutputFormat::Json => {}
        OutputFormat::Csv => {
            println!(
                "ip,family,detail,confidence,ttl,initial_ttl,window,df,mss,wscale,options,probe_port,source"
            );
            for g in guesses {
                println!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    g.ip,
                    csv_escape(&g.family),
                    csv_escape(&g.detail),
                    g.confidence,
                    g.ttl.map(|v| v.to_string()).unwrap_or_default(),
                    g.initial_ttl.map(|v| v.to_string()).unwrap_or_default(),
                    g.window.map(|v| v.to_string()).unwrap_or_default(),
                    g.df.map(|v| v.to_string()).unwrap_or_default(),
                    g.mss.map(|v| v.to_string()).unwrap_or_default(),
                    g.wscale.map(|v| v.to_string()).unwrap_or_default(),
                    csv_escape(&g.option_layout),
                    g.probe_port.map(|v| v.to_string()).unwrap_or_default(),
                    g.source,
                );
            }
        }
        OutputFormat::Pretty => {
            if quiet {
                for g in guesses {
                    println!(
                        "{}  {}  {}%  {}  [{}]",
                        g.ip, g.family, g.confidence, g.detail, g.source
                    );
                }
                return;
            }

            section_title("os fingerprint");

            let mut table = Table::new();
            table
                .load_preset(UTF8_HORIZONTAL_ONLY)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    th("HOST"),
                    th("OS"),
                    th("CONF"),
                    th("ENGINE"),
                    th("TTL"),
                    th("WIN"),
                    th("MATCH"),
                ]);

            for g in guesses {
                let ttl = match (g.ttl, g.initial_ttl) {
                    (Some(t), Some(i)) => format!("{t}→{i}"),
                    (Some(t), None) => t.to_string(),
                    _ => "—".into(),
                };
                let win = g
                    .window
                    .map(|w| w.to_string())
                    .unwrap_or_else(|| "—".into());
                let conf = format!("{}%", g.confidence);
                let conf_cell = if g.confidence >= 85 {
                    td_white(conf)
                } else if g.confidence >= 50 {
                    td_svc(conf)
                } else {
                    td_dim(conf)
                };

                table.add_row(vec![
                    td_white(&g.ip),
                    td_white(&g.family),
                    conf_cell,
                    td_dim(&g.source),
                    td_dim(ttl),
                    td_dim(win),
                    td_svc(&g.detail),
                ]);
            }

            println!("{table}");

            for g in guesses {
                if !g.matches.is_empty() {
                    println!(
                        "  {}  {}",
                        "RANK".bright_black(),
                        g.ip.white().bold()
                    );
                    for (i, m) in g.matches.iter().enumerate() {
                        println!(
                            "  {:>2}  {}  {}  {}",
                            format!("#{}", i + 1).bright_black(),
                            format!("{:>3}%", m.accuracy_pct).white().bold(),
                            m.name.white(),
                            format!("{} {}", m.vendor, m.family).bright_black()
                        );
                    }
                    rule();
                }
            }
            println!();
        }
    }
}

pub fn print_cve_results(cves: &[CveFinding], quiet: bool, format: OutputFormat) {
    if cves.is_empty() {
        if !quiet && matches!(format, OutputFormat::Pretty) {
            section_title("cve / cvss");
            println!("  {}\n", "none matched".bright_black());
        }
        return;
    }

    match format {
        OutputFormat::Json => {}
        OutputFormat::Csv => {
            println!("cve,cvss,severity,ip,port,service,title,reason,source");
            for c in cves {
                println!(
                    "{},{},{},{},{},{},{},{},{}",
                    c.cve_id,
                    c.cvss.map(|v| format!("{v:.1}")).unwrap_or_default(),
                    c.severity,
                    c.ip,
                    c.port,
                    csv_escape(&c.service),
                    csv_escape(&c.title),
                    csv_escape(&c.match_reason),
                    c.source,
                );
            }
        }
        OutputFormat::Pretty => {
            if quiet {
                for c in cves {
                    println!(
                        "{}  {:>4}  {}  {}:{}  {}",
                        c.cve_id,
                        c.cvss.map(|v| format!("{v:.1}")).unwrap_or_else(|| "—".into()),
                        c.severity,
                        c.ip,
                        c.port,
                        c.title
                    );
                }
                return;
            }

            section_title("cve / cvss");

            let mut table = Table::new();
            table
                .load_preset(UTF8_HORIZONTAL_ONLY)
                .set_content_arrangement(ContentArrangement::Dynamic)
                .set_header(vec![
                    th("CVE"),
                    th("CVSS"),
                    th("SEV"),
                    th("HOST"),
                    th("PORT"),
                    th("SERVICE"),
                    th("TITLE"),
                    th("WHY"),
                ]);

            for c in cves {
                let score = c
                    .cvss
                    .map(|v| format!("{v:.1}"))
                    .unwrap_or_else(|| "—".into());
                let sev_cell = match c.severity.as_str() {
                    "CRITICAL" | "HIGH" => td_white(&c.severity),
                    "MEDIUM" => td_svc(&c.severity),
                    _ => td_dim(&c.severity),
                };
                table.add_row(vec![
                    td_white(&c.cve_id),
                    td_white(score),
                    sev_cell,
                    td_dim(&c.ip),
                    td_port(c.port.to_string()),
                    td_svc(&c.service),
                    td_svc(&c.title),
                    td_dim(&c.match_reason),
                ]);
            }
            println!("{table}");

            // Severity rollup
            let mut crit = 0usize;
            let mut high = 0usize;
            let mut med = 0usize;
            let mut low = 0usize;
            for c in cves {
                match c.severity.as_str() {
                    "CRITICAL" => crit += 1,
                    "HIGH" => high += 1,
                    "MEDIUM" => med += 1,
                    _ => low += 1,
                }
            }
            println!(
                "  {}  {} crit  ·  {} high  ·  {} med  ·  {} low/other\n",
                "ROLLUP".bright_black(),
                crit.to_string().red().bold(),
                high.to_string().yellow().bold(),
                med.to_string().white(),
                low.to_string().bright_black()
            );
        }
    }
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
