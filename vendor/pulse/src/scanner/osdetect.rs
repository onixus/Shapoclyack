//! OS detection: SinFP (fast) / nmap-os-db (deep) / heuristic fallback.
//!
//! Requires root / CAP_NET_RAW for active probes.

use super::nmap_db::{find_os_db, MatchResult, NmapOsDb};
use super::nmap_probes::{build_subject_fingerprint, discover_ports};
use super::sinfp::{detect_sinfp, SinFpMatch};
use super::Target;
use anyhow::{Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{transport_channel, TransportChannelType, TransportProtocol};
use serde::Serialize;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Which OS fingerprint engine to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OsMode {
    /// Single-probe SinFP — fast (default for quick scans)
    #[default]
    SinFp,
    /// Full nmap-os-db probe suite — slower, higher resolution
    Nmap,
    /// SinFP first; if confidence low, escalate to nmap
    Auto,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsDbMatch {
    pub name: String,
    pub vendor: String,
    pub family: String,
    pub generation: String,
    pub device_type: String,
    pub accuracy: f64,
    pub accuracy_pct: u8,
    pub cpe: Vec<String>,
    pub db_line: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OsGuess {
    pub host: String,
    pub ip: String,
    pub family: String,
    pub detail: String,
    pub confidence: u8,
    pub source: String,
    pub ttl: Option<u8>,
    pub initial_ttl: Option<u8>,
    pub window: Option<u16>,
    pub df: Option<bool>,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack_ok: bool,
    pub timestamp: bool,
    pub option_layout: String,
    pub signals: Vec<String>,
    pub probe_port: Option<u16>,
    pub matches: Vec<OsDbMatch>,
    pub open_port: Option<u16>,
    pub closed_port: Option<u16>,
    pub db_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OsDetectConfig {
    pub timeout: Duration,
    pub os_db: Option<PathBuf>,
    pub fetch_db: bool,
    pub limit: usize,
    pub min_accuracy: f64,
    pub prefer_open: Vec<u16>,
    pub prefer_closed: Vec<u16>,
    pub mode: OsMode,
}

impl Default for OsDetectConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(800),
            os_db: None,
            fetch_db: false,
            limit: 3,
            min_accuracy: 0.85,
            prefer_open: Vec::new(),
            prefer_closed: Vec::new(),
            mode: OsMode::SinFp,
        }
    }
}

/// Ensure raw sockets work (root / CAP_NET_RAW).
pub fn ensure_os_capable() -> Result<()> {
    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    transport_channel(64, channel_type)
        .map(|_| ())
        .context(
            "OS detection needs raw sockets (run as root/sudo, or setcap cap_net_raw+ep on Linux)",
        )?;
    Ok(())
}

pub async fn detect_os_batch(
    targets: &[Target],
    config: OsDetectConfig,
) -> Result<Vec<OsGuess>> {
    let targets = targets.to_vec();
    let handle = tokio::task::spawn_blocking(move || detect_os_batch_sync(&targets, config));
    handle.await.context("OS detection task panicked")?
}

fn detect_os_batch_sync(targets: &[Target], config: OsDetectConfig) -> Result<Vec<OsGuess>> {
    // Only load heavy nmap DB when needed
    let need_nmap = matches!(config.mode, OsMode::Nmap | OsMode::Auto) || config.fetch_db;
    let db = if need_nmap {
        load_db(&config)?
    } else {
        None
    };

    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        out.push(detect_one(t, &config, db.as_ref()));
    }
    Ok(out)
}

fn load_db(config: &OsDetectConfig) -> Result<Option<Arc<NmapOsDb>>> {
    if config.fetch_db {
        let dest = config
            .os_db
            .clone()
            .or_else(super::nmap_db::default_fetch_path)
            .context("cannot determine path for nmap-os-db (no HOME)")?;
        eprintln!(
            "  fetching nmap-os-db → {} …",
            dest.display()
        );
        super::nmap_db::fetch_os_db(&dest)?;
        let db = NmapOsDb::load(&dest)?;
        eprintln!(
            "  loaded {} fingerprints from {}",
            db.fingerprints.len(),
            dest.display()
        );
        return Ok(Some(Arc::new(db)));
    }

    if let Some(path) = find_os_db(config.os_db.as_deref()) {
        match NmapOsDb::load(&path) {
            Ok(db) => {
                eprintln!(
                    "  nmap-os-db: {} fingerprints ({})",
                    db.fingerprints.len(),
                    path.display()
                );
                Ok(Some(Arc::new(db)))
            }
            Err(e) => {
                eprintln!("  warning: failed to load {}: {e:#}", path.display());
                Ok(None)
            }
        }
    } else {
        eprintln!(
            "  note: nmap-os-db not found — using heuristic only\n\
             \t fetch with: pulse <target> --os --os-db-fetch\n\
             \t or set --os-db /path/to/nmap-os-db / PULSE_OS_DB"
        );
        Ok(None)
    }
}

fn detect_one(target: &Target, config: &OsDetectConfig, db: Option<&Arc<NmapOsDb>>) -> OsGuess {
    let IpAddr::V4(_) = target.addr else {
        return unknown_guess(
            target,
            "OS detection supports IPv4 only",
            "error",
            db.map(|d| d.path.display().to_string()),
        );
    };

    match config.mode {
        OsMode::SinFp => detect_one_sinfp(target, config),
        OsMode::Nmap => detect_one_nmap(target, config, db),
        OsMode::Auto => {
            let fast = detect_one_sinfp(target, config);
            // Escalate when SinFP is weak
            if fast.confidence >= 60 {
                return fast;
            }
            if db.is_some() || config.fetch_db {
                let deep = detect_one_nmap(target, config, db);
                if deep.confidence > fast.confidence {
                    return deep;
                }
            }
            fast
        }
    }
}

fn detect_one_sinfp(target: &Target, config: &OsDetectConfig) -> OsGuess {
    match detect_sinfp(target, &config.prefer_open, config.timeout) {
        Ok((sample, hits)) => {
            let matches: Vec<OsDbMatch> = hits.iter().map(sinfp_to_db_match).collect();
            let (family, detail, conf, source) = if let Some(best) = hits.first() {
                let good = best.accuracy >= 0.55;
                if good {
                    (
                        best.family.clone(),
                        best.name.clone(),
                        best.accuracy_pct,
                        "sinfp".into(),
                    )
                } else {
                    (
                        best.family.clone(),
                        format!(
                            "SinFP weak: {} ({:.0}%)",
                            best.name,
                            best.accuracy * 100.0
                        ),
                        best.accuracy_pct,
                        "sinfp-low".into(),
                    )
                }
            } else {
                (
                    "Unknown".into(),
                    "SinFP: no signature match".into(),
                    0u8,
                    "sinfp".into(),
                )
            };

            let mut signals = vec![
                format!("ttl={}", sample.ttl),
                format!("ittl={}", sample.initial_ttl),
                format!("df={}", if sample.df { 1 } else { 0 }),
                format!("win={}", sample.window),
                format!("opts={}", sample.options),
                format!("flags={}", sample.flags),
                format!("port={}", sample.port),
            ];
            if sample.sack {
                signals.push("sack".into());
            }
            if sample.timestamp {
                signals.push("ts".into());
            }

            OsGuess {
                host: target.display.clone(),
                ip: target.addr.to_string(),
                family,
                detail,
                confidence: conf,
                source,
                ttl: Some(sample.ttl),
                initial_ttl: Some(sample.initial_ttl),
                window: Some(sample.window),
                df: Some(sample.df),
                mss: sample.mss,
                wscale: sample.wscale,
                sack_ok: sample.sack,
                timestamp: sample.timestamp,
                option_layout: sample.options,
                signals,
                probe_port: Some(sample.port),
                matches,
                open_port: Some(sample.port),
                closed_port: None,
                db_path: None,
            }
        }
        Err(e) => unknown_guess(target, &format!("SinFP failed: {e:#}"), "sinfp-error", None),
    }
}

fn detect_one_nmap(
    target: &Target,
    config: &OsDetectConfig,
    db: Option<&Arc<NmapOsDb>>,
) -> OsGuess {
    let IpAddr::V4(dst) = target.addr else {
        return unknown_guess(target, "IPv4 only", "error", None);
    };

    let (open, closed) = discover_ports(
        dst,
        &config.prefer_open,
        &config.prefer_closed,
        config.timeout,
    );

    let subject = match build_subject_fingerprint(dst, open, closed, config.timeout) {
        Ok(s) => s,
        Err(e) => {
            return unknown_guess(
                target,
                &format!("probe failed: {e:#}"),
                "error",
                db.map(|d| d.path.display().to_string()),
            );
        }
    };

    let (ttl, window, df, opts, signals) = extract_signals(&subject);

    if let Some(db) = db {
        let hits = db.match_subject(&subject, config.limit.max(1));
        if let Some(best) = hits.first() {
            let matches: Vec<OsDbMatch> = hits.iter().map(to_db_match).collect();
            let conf = (best.accuracy * 100.0).round().clamp(0.0, 100.0) as u8;
            let good = best.accuracy >= config.min_accuracy;

            let (family, detail, source) = if good {
                let class = best.classes.first();
                (
                    class
                        .map(|c| {
                            if c.generation.is_empty() {
                                c.family.clone()
                            } else {
                                format!("{} {}", c.family, c.generation)
                            }
                        })
                        .unwrap_or_else(|| best.name.clone()),
                    best.name.clone(),
                    "nmap-os-db".into(),
                )
            } else {
                (
                    best.classes
                        .first()
                        .map(|c| c.family.clone())
                        .unwrap_or_else(|| "Unknown".into()),
                    format!(
                        "best guess: {} ({:.0}%, below {:.0}% threshold)",
                        best.name,
                        best.accuracy * 100.0,
                        config.min_accuracy * 100.0
                    ),
                    "nmap-os-db-low".into(),
                )
            };

            return OsGuess {
                host: target.display.clone(),
                ip: target.addr.to_string(),
                family,
                detail,
                confidence: conf,
                source,
                ttl,
                initial_ttl: ttl.map(guess_initial_ttl),
                window,
                df,
                mss: None,
                wscale: None,
                sack_ok: opts.contains('S'),
                timestamp: opts.contains('T'),
                option_layout: opts,
                signals,
                probe_port: open,
                matches,
                open_port: open,
                closed_port: closed,
                db_path: Some(db.path.display().to_string()),
            };
        }
    }

    heuristic_guess(target, ttl, window, df, opts, signals, open, closed, db)
}

fn sinfp_to_db_match(m: &SinFpMatch) -> OsDbMatch {
    OsDbMatch {
        name: m.name.clone(),
        vendor: String::new(),
        family: m.family.clone(),
        generation: String::new(),
        device_type: String::new(),
        accuracy: m.accuracy,
        accuracy_pct: m.accuracy_pct,
        cpe: vec![],
        db_line: 0,
    }
}

fn to_db_match(m: &MatchResult) -> OsDbMatch {
    let class = m.classes.first();
    OsDbMatch {
        name: m.name.clone(),
        vendor: class.map(|c| c.vendor.clone()).unwrap_or_default(),
        family: class.map(|c| c.family.clone()).unwrap_or_default(),
        generation: class.map(|c| c.generation.clone()).unwrap_or_default(),
        device_type: class.map(|c| c.device_type.clone()).unwrap_or_default(),
        accuracy: m.accuracy,
        accuracy_pct: (m.accuracy * 100.0).round().clamp(0.0, 100.0) as u8,
        cpe: m.cpes.clone(),
        db_line: m.line,
    }
}

fn extract_signals(
    subject: &std::collections::HashMap<String, std::collections::HashMap<String, String>>,
) -> (Option<u8>, Option<u16>, Option<bool>, String, Vec<String>) {
    let mut signals = Vec::new();
    let mut ttl = None;
    let mut window = None;
    let mut df = None;
    let mut opts = String::new();

    for test in ["T1", "ECN", "T3", "T5", "IE"] {
        if let Some(attrs) = subject.get(test) {
            if attrs.get("R").map(|s| s.as_str()) == Some("Y") {
                if let Some(t) = attrs.get("T") {
                    if let Ok(v) = u8::from_str_radix(t, 16) {
                        ttl = Some(v);
                        signals.push(format!("{test}.ttl={v}"));
                    }
                }
                if let Some(w) = attrs.get("W") {
                    if let Ok(v) = u16::from_str_radix(w, 16) {
                        window = Some(v);
                        signals.push(format!("{test}.win={v}"));
                    }
                }
                if let Some(d) = attrs.get("DF") {
                    df = Some(d == "Y");
                    signals.push(format!("{test}.df={d}"));
                }
                if let Some(o) = attrs.get("O") {
                    if !o.is_empty() {
                        opts = o.clone();
                        signals.push(format!("{test}.opts={o}"));
                    }
                }
                if let Some(f) = attrs.get("F") {
                    signals.push(format!("{test}.flags={f}"));
                }
            } else if attrs.get("R").map(|s| s.as_str()) == Some("N") {
                signals.push(format!("{test}=no-reply"));
            }
        }
    }

    if let Some(ops) = subject.get("OPS") {
        for i in 1..=6 {
            if let Some(o) = ops.get(&format!("O{i}")) {
                signals.push(format!("OPS.O{i}={o}"));
                if opts.is_empty() {
                    opts = o.clone();
                }
            }
        }
    }

    (ttl, window, df, opts, signals)
}

fn guess_initial_ttl(observed: u8) -> u8 {
    if observed <= 32 {
        32
    } else if observed <= 64 {
        64
    } else if observed <= 128 {
        128
    } else {
        255
    }
}

fn unknown_guess(target: &Target, detail: &str, source: &str, db_path: Option<String>) -> OsGuess {
    OsGuess {
        host: target.display.clone(),
        ip: target.addr.to_string(),
        family: "Unknown".into(),
        detail: detail.into(),
        confidence: 0,
        source: source.into(),
        ttl: None,
        initial_ttl: None,
        window: None,
        df: None,
        mss: None,
        wscale: None,
        sack_ok: false,
        timestamp: false,
        option_layout: String::new(),
        signals: vec![],
        probe_port: None,
        matches: vec![],
        open_port: None,
        closed_port: None,
        db_path,
    }
}

fn heuristic_guess(
    target: &Target,
    ttl: Option<u8>,
    window: Option<u16>,
    df: Option<bool>,
    opts: String,
    signals: Vec<String>,
    open: Option<u16>,
    closed: Option<u16>,
    db: Option<&Arc<NmapOsDb>>,
) -> OsGuess {
    let initial = ttl.map(guess_initial_ttl);
    let (family, detail, conf) = match (initial, window) {
        (Some(128), _) => ("Windows".into(), "Windows-like (TTL heuristic)".into(), 35),
        (Some(64), Some(w)) if matches!(w, 29200 | 64240 | 65535 | 28960) => {
            ("Linux".into(), "Linux-like (TTL+window heuristic)".into(), 40)
        }
        (Some(64), _) => ("Linux/BSD".into(), "Linux/BSD/macOS-like (TTL heuristic)".into(), 30),
        (Some(255), _) => ("Network".into(), "Network/Unix-like (TTL heuristic)".into(), 30),
        _ => (
            "Unknown".into(),
            "Insufficient fingerprint data (install nmap-os-db for better results)".into(),
            0,
        ),
    };

    OsGuess {
        host: target.display.clone(),
        ip: target.addr.to_string(),
        family,
        detail,
        confidence: conf,
        source: "heuristic".into(),
        ttl,
        initial_ttl: initial,
        window,
        df,
        mss: None,
        wscale: None,
        sack_ok: opts.contains('S'),
        timestamp: opts.contains('T'),
        option_layout: opts,
        signals,
        probe_port: open,
        matches: vec![],
        open_port: open,
        closed_port: closed,
        db_path: db.map(|d| d.path.display().to_string()),
    }
}

