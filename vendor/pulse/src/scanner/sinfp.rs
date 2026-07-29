//! SinFP-style single-probe OS fingerprinting (fast path).
//!
//! Classic SinFP (Patrice Auffret) identifies an OS from **one** carefully
//! crafted SYN → SYN-ACK exchange (TTL, DF, window, TCP options). That is
//! typically 10–50× faster than a full nmap-os-db probe suite.
//!
//! We ship a curated signature set inspired by public SinFP patterns
//! (not the proprietary full SinFP2 commercial DB). Optional extra
//! signatures: `~/.pulse/sinfp-db.json`.

use super::nmap_probes::encode_tcp_options;
use super::Target;
use anyhow::{bail, Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Single SYN-ACK sample (SinFP P1 response).
#[derive(Debug, Clone)]
pub struct SinFpSample {
    pub ttl: u8,
    pub initial_ttl: u8,
    pub df: bool,
    pub window: u16,
    pub flags: String,
    pub options: String,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub sack: bool,
    pub timestamp: bool,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct SinFpMatch {
    pub name: String,
    pub family: String,
    pub score: u32,
    pub max_score: u32,
    pub accuracy: f64,
    pub accuracy_pct: u8,
}

#[derive(Debug, Clone, Deserialize)]
struct Sig {
    /// Human label, e.g. "Linux 3.x|4.x|5.x"
    name: String,
    /// Coarse family for UI grouping
    family: String,
    /// Expected initial TTL (32/64/128/255); None = ignore
    #[serde(default)]
    ittl: Option<u8>,
    /// Don't-fragment expected
    #[serde(default)]
    df: Option<bool>,
    /// Exact window, or list of accepted windows
    #[serde(default)]
    window: Option<u16>,
    #[serde(default)]
    windows: Vec<u16>,
    /// Substring / glob-ish option pattern (`*` = wildcard segment)
    /// e.g. "M*ST11NW*" or exact "M5B4NNT11"
    #[serde(default)]
    options: Option<String>,
    /// Require SACK / timestamp presence
    #[serde(default)]
    sack: Option<bool>,
    #[serde(default)]
    timestamp: Option<bool>,
    /// MSS exact or range via list
    #[serde(default)]
    mss: Option<u16>,
    #[serde(default)]
    wscale: Option<u8>,
    /// Weight multiplier 1–3 (default 1)
    #[serde(default = "default_weight")]
    weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Built-in SinFP-inspired signatures (curated, not full commercial DB).
fn builtin_signatures() -> Vec<Sig> {
    vec![
        // —— Linux ——
        Sig {
            name: "Linux 2.6.x|3.x|4.x|5.x|6.x".into(),
            family: "Linux".into(),
            ittl: Some(64),
            df: Some(true),
            window: None,
            windows: vec![29200, 28960, 26883, 64240, 62727, 42340, 14600, 5840, 5792, 65535],
            options: Some("M*ST*NW*".into()),
            sack: Some(true),
            timestamp: Some(true),
            mss: None,
            wscale: None,
            weight: 2,
        },
        Sig {
            name: "Linux (modern, TS+SACK+WS)".into(),
            family: "Linux".into(),
            ittl: Some(64),
            df: Some(true),
            window: None,
            windows: vec![],
            options: Some("M*S*T*W*".into()),
            sack: Some(true),
            timestamp: Some(true),
            mss: None,
            wscale: None,
            weight: 1,
        },
        // —— Windows ——
        Sig {
            name: "Microsoft Windows 10|11|Server 2016+".into(),
            family: "Windows".into(),
            ittl: Some(128),
            df: Some(true),
            window: None,
            windows: vec![8192, 64240, 65535, 16384, 21072, 8190],
            options: Some("M*NW*NNS".into()),
            sack: Some(true),
            timestamp: None,
            mss: None,
            wscale: None,
            weight: 2,
        },
        Sig {
            name: "Microsoft Windows 7|8|Server 2008R2".into(),
            family: "Windows".into(),
            ittl: Some(128),
            df: Some(true),
            window: None,
            windows: vec![8192, 16384, 65535],
            options: Some("M*NW*".into()),
            sack: Some(true),
            timestamp: None,
            mss: None,
            wscale: None,
            weight: 1,
        },
        Sig {
            name: "Microsoft Windows (generic TTL128)".into(),
            family: "Windows".into(),
            ittl: Some(128),
            df: Some(true),
            window: None,
            windows: vec![],
            options: None,
            sack: None,
            timestamp: None,
            mss: None,
            wscale: None,
            weight: 1,
        },
        // —— macOS / BSD ——
        Sig {
            name: "Apple macOS / Darwin".into(),
            family: "macOS/BSD".into(),
            ittl: Some(64),
            df: Some(true),
            window: None,
            windows: vec![65535, 32768, 16384, 13176],
            options: Some("M*NW*NNT*".into()),
            sack: Some(true),
            timestamp: Some(true),
            mss: None,
            wscale: None,
            weight: 2,
        },
        Sig {
            name: "FreeBSD 10+|OpenBSD|NetBSD".into(),
            family: "macOS/BSD".into(),
            ittl: Some(64),
            df: Some(true),
            window: None,
            windows: vec![65535, 32768],
            options: Some("M*NNT*".into()),
            sack: None,
            timestamp: Some(true),
            mss: None,
            wscale: None,
            weight: 1,
        },
        // —— Network / embedded ——
        Sig {
            name: "Network appliance / router (TTL 255)".into(),
            family: "Network".into(),
            ittl: Some(255),
            df: None,
            window: None,
            windows: vec![4128, 8192, 4096, 16384, 512, 1024],
            options: None,
            sack: None,
            timestamp: None,
            mss: None,
            wscale: None,
            weight: 2,
        },
        Sig {
            name: "Cisco IOS / networking gear".into(),
            family: "Network".into(),
            ittl: Some(255),
            df: Some(true),
            window: None,
            windows: vec![4128, 8192],
            options: Some("M*".into()),
            sack: None,
            timestamp: None,
            mss: None,
            wscale: None,
            weight: 1,
        },
        // —— Older / niche ——
        Sig {
            name: "Solaris / older Unix (TTL 255)".into(),
            family: "Unix".into(),
            ittl: Some(255),
            df: Some(true),
            window: None,
            windows: vec![49640, 32850, 8760],
            options: None,
            sack: None,
            timestamp: None,
            mss: None,
            wscale: None,
            weight: 1,
        },
        Sig {
            name: "Embedded / IoT (TTL 64, small window)".into(),
            family: "Embedded".into(),
            ittl: Some(64),
            df: None,
            window: None,
            windows: vec![1024, 2048, 4096, 512, 256],
            options: None,
            sack: Some(false),
            timestamp: Some(false),
            mss: None,
            wscale: None,
            weight: 1,
        },
    ]
}

fn load_extra_signatures() -> Vec<Sig> {
    let path = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(|h| PathBuf::from(h).join(".pulse").join("sinfp-db.json"));
    let Some(path) = path else {
        return Vec::new();
    };
    if !path.is_file() {
        return Vec::new();
    }
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str::<Vec<Sig>>(&text).unwrap_or_else(|e| {
            eprintln!("  warning: bad sinfp-db.json: {e}");
            Vec::new()
        }),
        Err(_) => Vec::new(),
    }
}

/// Run SinFP single-probe detect against one IPv4 host.
pub fn detect_sinfp(
    target: &Target,
    prefer_open: &[u16],
    timeout: Duration,
) -> Result<(SinFpSample, Vec<SinFpMatch>)> {
    let IpAddr::V4(dst) = target.addr else {
        bail!("SinFP supports IPv4 only");
    };

    let port = find_open_port(dst, prefer_open, timeout)
        .context("SinFP needs at least one open TCP port (SYN-ACK)")?;

    let sample = probe_p1(dst, port, timeout)
        .with_context(|| format!("no SYN-ACK from {dst}:{port}"))?;

    let mut sigs = builtin_signatures();
    sigs.extend(load_extra_signatures());

    let mut matches = score_sample(&sample, &sigs);
    matches.sort_by(|a, b| {
        b.accuracy
            .partial_cmp(&a.accuracy)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.score.cmp(&a.score))
    });
    matches.truncate(5);

    Ok((sample, matches))
}

fn score_sample(sample: &SinFpSample, sigs: &[Sig]) -> Vec<SinFpMatch> {
    sigs.iter()
        .filter_map(|sig| {
            let (score, max) = score_one(sample, sig);
            if max == 0 || score == 0 {
                return None;
            }
            let accuracy = score as f64 / max as f64;
            Some(SinFpMatch {
                name: sig.name.clone(),
                family: sig.family.clone(),
                score,
                max_score: max,
                accuracy,
                accuracy_pct: (accuracy * 100.0).round().clamp(0.0, 100.0) as u8,
            })
        })
        .collect()
}

fn score_one(s: &SinFpSample, sig: &Sig) -> (u32, u32) {
    let w = sig.weight.max(1);
    let mut score = 0u32;
    let mut max = 0u32;

    // initial TTL is a hard filter when present — wrong family otherwise
    if let Some(ittl) = sig.ittl {
        if s.initial_ttl != ittl {
            return (0, 1);
        }
        max += 40 * w;
        score += 40 * w;
    }

    // DF
    if let Some(df) = sig.df {
        max += 15 * w;
        if s.df == df {
            score += 15 * w;
        }
    }

    // Window
    let wins: Vec<u16> = if let Some(w0) = sig.window {
        let mut v = sig.windows.clone();
        v.push(w0);
        v
    } else {
        sig.windows.clone()
    };
    if !wins.is_empty() {
        max += 25 * w;
        if wins.contains(&s.window) {
            score += 25 * w;
        }
    }

    // Options pattern
    if let Some(ref pat) = sig.options {
        max += 30 * w;
        if option_pattern_match(pat, &s.options) {
            score += 30 * w;
        }
    }

    // SACK / TS
    if let Some(sack) = sig.sack {
        max += 10 * w;
        if s.sack == sack {
            score += 10 * w;
        }
    }
    if let Some(ts) = sig.timestamp {
        max += 10 * w;
        if s.timestamp == ts {
            score += 10 * w;
        }
    }

    // MSS / WScale
    if let Some(mss) = sig.mss {
        max += 10 * w;
        if s.mss == Some(mss) {
            score += 10 * w;
        }
    }
    if let Some(ws) = sig.wscale {
        max += 10 * w;
        if s.wscale == Some(ws) {
            score += 10 * w;
        }
    }

    (score, max)
}

/// Simple glob: `*` matches any run of non-empty chars (including empty).
fn option_pattern_match(pattern: &str, value: &str) -> bool {
    if pattern == value {
        return true;
    }
    // Convert * glob to regex-ish recursive match
    fn rec(p: &[u8], v: &[u8]) -> bool {
        match (p.first(), v.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                // * matches zero or more
                if rec(&p[1..], v) {
                    return true;
                }
                if !v.is_empty() && rec(p, &v[1..]) {
                    return true;
                }
                false
            }
            (Some(a), Some(b)) if a == b => rec(&p[1..], &v[1..]),
            _ => false,
        }
    }
    rec(pattern.as_bytes(), value.as_bytes())
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

fn parse_opts_details(options: &str) -> (Option<u16>, Option<u8>, bool, bool) {
    let mut mss = None;
    let mut wscale = None;
    let sack = options.contains('S');
    let timestamp = options.contains('T');

    let bytes = options.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'M' => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                if i > start {
                    if let Ok(v) = u16::from_str_radix(&options[start..i], 16) {
                        mss = Some(v);
                    }
                }
            }
            b'W' => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
                    i += 1;
                }
                if i > start {
                    if let Ok(v) = u8::from_str_radix(&options[start..i], 16) {
                        wscale = Some(v);
                    }
                }
            }
            b'T' => {
                // T11 / T10 / T01 / T00
                i += 1;
                if i + 1 < bytes.len() {
                    i += 2;
                }
            }
            _ => i += 1,
        }
    }
    (mss, wscale, sack, timestamp)
}

/// SinFP P1: SYN with rich options (MSS, SACK, TS, WS) — one packet.
fn probe_p1(dst: Ipv4Addr, dport: u16, timeout: Duration) -> Option<SinFpSample> {
    let src = local_ipv4_for(dst).ok()?;
    let sport: u16 = rand::rng().random_range(40000..60000);
    let seq: u32 = rand::rng().random();

    // Classic SinFP-ish option set: MSS 1460, SACK, TS, NOP, WS 7
    // (bytes similar to common active fingerprint probes)
    let options: &[u8] =
        b"\x02\x04\x05\xb4\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x01\x03\x03\x07";

    let recv_type = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (_, mut rrx) = transport_channel(65535, recv_type).ok()?;

    let done = Arc::new(AtomicBool::new(false));
    let result: Arc<Mutex<Option<SinFpSample>>> = Arc::new(Mutex::new(None));
    let done_c = done.clone();
    let result_c = result.clone();

    let handle = thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut rrx);
        while !done_c.load(Ordering::Relaxed) {
            let Ok((ip_pkt, _)) = iter.next() else {
                continue;
            };
            if ip_pkt.get_source() != dst {
                continue;
            }
            if ip_pkt.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                continue;
            }
            let Some(tcp) = TcpPacket::new(ip_pkt.payload()) else {
                continue;
            };
            if tcp.get_destination() != sport || tcp.get_source() != dport {
                continue;
            }
            let flags = tcp.get_flags();
            if flags & TcpFlags::SYN == 0 || flags & TcpFlags::ACK == 0 {
                if flags & TcpFlags::RST != 0 {
                    break; // closed
                }
                continue;
            }

            let df = ip_pkt.get_flags() & Ipv4Flags::DontFragment != 0;
            let ttl = ip_pkt.get_ttl();
            let options = encode_tcp_options(&tcp);
            let (mss, wscale, sack, timestamp) = parse_opts_details(&options);
            let flags_s = {
                let mut s = String::new();
                if flags & TcpFlags::ACK != 0 {
                    s.push('A');
                }
                if flags & TcpFlags::SYN != 0 {
                    s.push('S');
                }
                s
            };

            // polite RST
            let _ = send_rst(src, dst, sport, dport, tcp.get_acknowledgement());

            *result_c.lock().unwrap() = Some(SinFpSample {
                ttl,
                initial_ttl: guess_initial_ttl(ttl),
                df,
                window: tcp.get_window(),
                flags: flags_s,
                options,
                mss,
                wscale,
                sack,
                timestamp,
                port: dport,
            });
            break;
        }
    });

    let send_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    if let Ok((mut stx, _)) = transport_channel(512, send_type) {
        let _ = send_syn(
            &mut stx, src, dst, sport, dport, seq, 64240, options,
        );
    }

    let start = Instant::now();
    while start.elapsed() < timeout {
        if result.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(3));
    }
    done.store(true, Ordering::Relaxed);
    // NEVER join: pnet recv blocks forever if no packet arrives.
    // Detach so timeouts always return.
    drop(handle);
    let value = result.lock().unwrap().take();
    value
}

fn find_open_port(dst: Ipv4Addr, prefer: &[u16], timeout: Duration) -> Option<u16> {
    let mut ports: Vec<u16> = prefer.to_vec();
    ports.extend([80, 443, 22, 445, 3389, 8080, 21, 25, 135, 139, 3306, 5900, 8443]);
    ports.sort_unstable();
    ports.dedup();

    for &p in &ports {
        if probe_p1(dst, p, timeout.min(Duration::from_millis(400))).is_some() {
            return Some(p);
        }
    }
    None
}

fn send_syn(
    sender: &mut TransportSender,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    window: u16,
    options: &[u8],
) -> Result<()> {
    let pad = (4 - (options.len() % 4)) % 4;
    let tcp_len = 20 + options.len() + pad;
    let mut buf = vec![0u8; tcp_len];
    {
        let mut pkt = MutableTcpPacket::new(&mut buf).context("tcp buf")?;
        pkt.set_source(sport);
        pkt.set_destination(dport);
        pkt.set_sequence(seq);
        pkt.set_acknowledgement(0);
        pkt.set_data_offset(((20 + options.len() + pad) / 4) as u8);
        pkt.set_flags(TcpFlags::SYN);
        pkt.set_window(window);
        pkt.set_urgent_ptr(0);
        let hdr = pkt.packet_mut();
        if !options.is_empty() && hdr.len() >= 20 + options.len() {
            hdr[20..20 + options.len()].copy_from_slice(options);
        }
        let csum = ipv4_checksum(&pkt.to_immutable(), &src, &dst);
        pkt.set_checksum(csum);
    }
    let pkt = TcpPacket::new(&buf).context("tcp")?;
    sender
        .send_to(pkt, IpAddr::V4(dst))
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("send: {e}"))
}

fn send_rst(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) -> Result<()> {
    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut sender, _) = transport_channel(128, channel_type)?;
    let mut buf = [0u8; 20];
    {
        let mut pkt = MutableTcpPacket::new(&mut buf).context("rst")?;
        pkt.set_source(sport);
        pkt.set_destination(dport);
        pkt.set_sequence(seq);
        pkt.set_acknowledgement(0);
        pkt.set_data_offset(5);
        pkt.set_flags(TcpFlags::RST | TcpFlags::ACK);
        pkt.set_window(0);
        pkt.set_urgent_ptr(0);
        let csum = ipv4_checksum(&pkt.to_immutable(), &src, &dst);
        pkt.set_checksum(csum);
    }
    let pkt = TcpPacket::new(&buf).context("rst")?;
    let _ = sender.send_to(pkt, IpAddr::V4(dst));
    Ok(())
}

fn local_ipv4_for(dst: Ipv4Addr) -> Result<Ipv4Addr> {
    let sock = StdUdpSocket::bind("0.0.0.0:0").context("bind")?;
    sock.connect(SocketAddrV4::new(dst, 9)).context("connect")?;
    match sock.local_addr()? {
        std::net::SocketAddr::V4(a) => Ok(*a.ip()),
        _ => bail!("need ipv4"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_options() {
        assert!(option_pattern_match("M*ST*NW*", "M5B4ST11NW7"));
        assert!(option_pattern_match("M*NW*NNS", "M4ECNW8NNS"));
        assert!(!option_pattern_match("M*ST*", "M5B4NW8"));
    }

    #[test]
    fn scores_linux_like() {
        let sample = SinFpSample {
            ttl: 54,
            initial_ttl: 64,
            df: true,
            window: 29200,
            flags: "AS".into(),
            options: "M5B4ST11NW7".into(),
            mss: Some(1460),
            wscale: Some(7),
            sack: true,
            timestamp: true,
            port: 80,
        };
        let matches = score_sample(&sample, &builtin_signatures());
        assert!(!matches.is_empty());
        assert_eq!(matches[0].family, "Linux");
        assert!(matches[0].accuracy > 0.5);
    }

    #[test]
    fn scores_windows_like() {
        let sample = SinFpSample {
            ttl: 120,
            initial_ttl: 128,
            df: true,
            window: 8192,
            flags: "AS".into(),
            options: "M5B4NW8NNS".into(),
            mss: Some(1460),
            wscale: Some(8),
            sack: true,
            timestamp: false,
            port: 445,
        };
        let matches = score_sample(&sample, &builtin_signatures());
        assert!(!matches.is_empty());
        assert_eq!(matches[0].family, "Windows");
    }
}
