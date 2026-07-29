//! Nmap-compatible IPv4 OS detection probes (2nd generation).
//!
//! Probe templates, option encoding, and subject fingerprint construction
//! follow nmap's `osscan2.cc` / fingerprint format docs.
//! Requires raw sockets (root / CAP_NET_RAW).

use anyhow::{bail, Context, Result};
use pnet::packet::icmp::{echo_request, IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Flags;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType, TransportProtocol, TransportSender,
};
use rand::RngExt;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Nmap prbOpts[0..13] — exact option byte templates from osscan2.cc
const PRB_OPTS: &[&[u8]] = &[
    // 0: WScale(10), Nop, MSS(1460), Timestamp, SackP
    b"\x03\x03\x0A\x01\x02\x04\x05\xb4\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    // 1: MSS(1400), WScale(0), SackP, T, EOL
    b"\x02\x04\x05\x78\x03\x03\x00\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x00",
    // 2: T, Nop, Nop, WScale(5), Nop, MSS(640)
    b"\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x01\x01\x03\x03\x05\x01\x02\x04\x02\x80",
    // 3: SackP, T, WScale(10), EOL
    b"\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00",
    // 4: MSS(536), SackP, T, WScale(10), EOL
    b"\x02\x04\x02\x18\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x03\x03\x0A\x00",
    // 5: MSS(265), SackP, T
    b"\x02\x04\x01\x09\x04\x02\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00",
    // 6: ECN — WScale(10), Nop, MSS(1460), SackP, Nop, Nop
    b"\x03\x03\x0A\x01\x02\x04\x05\xb4\x04\x02\x01\x01",
    // 7-11: T2-T6 opts
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    b"\x03\x03\x0A\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
    // 12: T7 — WScale(15), ...
    b"\x03\x03\x0f\x01\x02\x04\x01\x09\x08\x0A\xff\xff\xff\xff\x00\x00\x00\x00\x04\x02",
];

const PRB_WINDOW: [u16; 13] = [
    1, 63, 4, 4, 16, 512, 3, 128, 256, 1024, 31337, 32768, 65535,
];

#[derive(Clone, Debug)]
struct TcpReply {
    ttl: u8,
    df: bool,
    window: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    options: String,
    ip_id: u16,
}

/// Build a nmap-format subject fingerprint for `dst`.
pub fn build_subject_fingerprint(
    dst: Ipv4Addr,
    open_port: Option<u16>,
    closed_port: Option<u16>,
    timeout: Duration,
) -> Result<HashMap<String, HashMap<String, String>>> {
    let src = local_ipv4_for(dst)?;
    let mut subject: HashMap<String, HashMap<String, String>> = HashMap::new();

    let seq_base: u32 = rand::rng().random();
    let ack_base: u32 = rand::rng().random();
    let mut sport_base: u16 = rand::rng().random_range(40000..50000);

    // --- S1..S6 (SEQ / OPS / WIN / T1) ---
    let mut ops = HashMap::new();
    let mut win = HashMap::new();
    let mut seq_replies: Vec<Option<TcpReply>> = Vec::new();
    let mut t1: Option<TcpReply> = None;

    if let Some(open) = open_port {
        for i in 0..6 {
            let sport = sport_base.wrapping_add(i as u16);
            let seq = seq_base.wrapping_add(i as u32);
            let reply = send_tcp_and_wait(
                src,
                dst,
                sport,
                open,
                seq,
                ack_base,
                TcpFlags::SYN,
                PRB_WINDOW[i],
                PRB_OPTS[i],
                false, // DF
                timeout,
            );
            if let Some(ref r) = reply {
                ops.insert(format!("O{}", i + 1), r.options.clone());
                win.insert(format!("W{}", i + 1), format!("{:X}", r.window));
                if i == 0 {
                    t1 = Some(r.clone());
                }
            }
            seq_replies.push(reply);
            thread::sleep(Duration::from_millis(100));
        }

        if !ops.is_empty() {
            subject.insert("OPS".into(), ops);
        }
        if !win.is_empty() {
            subject.insert("WIN".into(), win);
        }

        if let Some(r) = t1 {
            subject.insert(
                "T1".into(),
                tcp_test_attrs(&r, seq_base, ack_base, true),
            );
        } else {
            subject.insert("T1".into(), no_response());
        }

        // SEQ simplified
        if let Some(seq_map) = build_seq_test(&seq_replies) {
            subject.insert("SEQ".into(), seq_map);
        }

        // ECN: SYN|ECE|CWR
        sport_base = sport_base.wrapping_add(20);
        let reply = send_tcp_raw_flags(
            src,
            dst,
            sport_base,
            open,
            seq_base,
            0,
            0xC2, // SYN|ECE|CWR
            PRB_WINDOW[6],
            PRB_OPTS[6],
            false,
            timeout,
        );

        subject.insert(
            "ECN".into(),
            match reply {
                Some(r) => {
                    let mut m = tcp_test_attrs(&r, seq_base, 0, false);
                    // CC: ECE without CWR = Y; both = S; none = N
                    let ece = r.flags & 0x40 != 0;
                    let cwr = r.flags & 0x80 != 0;
                    let cc = if ece && !cwr {
                        "Y"
                    } else if ece && cwr {
                        "S"
                    } else {
                        "N"
                    };
                    m.insert("CC".into(), cc.into());
                    m.insert("R".into(), "Y".into());
                    m
                }
                None => {
                    let mut m = no_response();
                    m.insert("CC".into(), "N".into());
                    m
                }
            },
        );

        // T2: NULL + DF to open
        sport_base = sport_base.wrapping_add(10);
        let r = send_tcp_raw_flags(
            src,
            dst,
            sport_base,
            open,
            seq_base,
            ack_base,
            0, // no flags
            PRB_WINDOW[7],
            PRB_OPTS[7],
            true,
            timeout,
        );
        subject.insert(
            "T2".into(),
            r.map(|r| tcp_test_attrs(&r, seq_base, ack_base, true))
                .unwrap_or_else(no_response),
        );

        // T3: SYN|FIN|URG|PSH
        let r = send_tcp_raw_flags(
            src,
            dst,
            sport_base.wrapping_add(1),
            open,
            seq_base,
            ack_base,
            TcpFlags::SYN | TcpFlags::FIN | TcpFlags::URG | TcpFlags::PSH,
            PRB_WINDOW[8],
            PRB_OPTS[8],
            false,
            timeout,
        );
        subject.insert(
            "T3".into(),
            r.map(|r| tcp_test_attrs(&r, seq_base, ack_base, true))
                .unwrap_or_else(no_response),
        );

        // T4: ACK + DF
        let r = send_tcp_raw_flags(
            src,
            dst,
            sport_base.wrapping_add(2),
            open,
            seq_base,
            ack_base,
            TcpFlags::ACK,
            PRB_WINDOW[9],
            PRB_OPTS[9],
            true,
            timeout,
        );
        subject.insert(
            "T4".into(),
            r.map(|r| tcp_test_attrs(&r, seq_base, ack_base, true))
                .unwrap_or_else(no_response),
        );
    } else {
        subject.insert("T1".into(), no_response());
        subject.insert("T2".into(), no_response());
        subject.insert("T3".into(), no_response());
        subject.insert("T4".into(), no_response());
        subject.insert("ECN".into(), no_response());
    }

    // Closed-port probes T5-T7
    if let Some(closed) = closed_port {
        sport_base = sport_base.wrapping_add(30);
        let r = send_tcp_raw_flags(
            src,
            dst,
            sport_base,
            closed,
            seq_base,
            ack_base,
            TcpFlags::SYN,
            PRB_WINDOW[10],
            PRB_OPTS[10],
            false,
            timeout,
        );
        subject.insert(
            "T5".into(),
            r.map(|r| tcp_test_attrs(&r, seq_base, ack_base, true))
                .unwrap_or_else(no_response),
        );

        let r = send_tcp_raw_flags(
            src,
            dst,
            sport_base.wrapping_add(1),
            closed,
            seq_base,
            ack_base,
            TcpFlags::ACK,
            PRB_WINDOW[11],
            PRB_OPTS[11],
            true,
            timeout,
        );
        subject.insert(
            "T6".into(),
            r.map(|r| tcp_test_attrs(&r, seq_base, ack_base, true))
                .unwrap_or_else(no_response),
        );

        let r = send_tcp_raw_flags(
            src,
            dst,
            sport_base.wrapping_add(2),
            closed,
            seq_base,
            ack_base,
            TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            PRB_WINDOW[12],
            PRB_OPTS[12],
            false,
            timeout,
        );
        subject.insert(
            "T7".into(),
            r.map(|r| tcp_test_attrs(&r, seq_base, ack_base, true))
                .unwrap_or_else(no_response),
        );
    } else {
        subject.insert("T5".into(), no_response());
        subject.insert("T6".into(), no_response());
        subject.insert("T7".into(), no_response());
    }

    // IE — ICMP echo (best-effort TTL)
    if let Some(ttl) = icmp_echo_ttl(dst, timeout) {
        let tg = guess_initial_ttl(ttl);
        let mut ie = HashMap::new();
        ie.insert("R".into(), "Y".into());
        ie.insert("T".into(), format!("{ttl:X}"));
        ie.insert("TG".into(), format!("{tg:X}"));
        ie.insert("DFI".into(), "N".into()); // simplified
        ie.insert("CD".into(), "Z".into());
        subject.insert("IE".into(), ie);
    }

    Ok(subject)
}

fn no_response() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("R".into(), "N".into());
    m
}

fn tcp_test_attrs(
    r: &TcpReply,
    our_seq: u32,
    our_ack: u32,
    include_sa: bool,
) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert("R".into(), "Y".into());
    m.insert("DF".into(), if r.df { "Y" } else { "N" }.into());
    let tg = guess_initial_ttl(r.ttl);
    m.insert("T".into(), format!("{:X}", r.ttl));
    m.insert("TG".into(), format!("{tg:X}"));
    m.insert("W".into(), format!("{:X}", r.window));
    m.insert("F".into(), flags_string(r.flags));
    m.insert("O".into(), r.options.clone());
    m.insert("RD".into(), "0".into());
    m.insert("Q".into(), String::new());
    if include_sa {
        m.insert("S".into(), seq_relation(r.seq, our_seq, our_ack));
        m.insert("A".into(), ack_relation(r.ack, our_seq, our_ack));
    }
    m
}

fn flags_string(flags: u8) -> String {
    // nmap order roughly: ECN bits then standard
    let mut s = String::new();
    if flags & 0x80 != 0 {
        s.push('C'); // CWR
    }
    if flags & 0x40 != 0 {
        s.push('E'); // ECE
    }
    if flags & TcpFlags::URG != 0 {
        s.push('U');
    }
    if flags & TcpFlags::ACK != 0 {
        s.push('A');
    }
    if flags & TcpFlags::PSH != 0 {
        s.push('P');
    }
    if flags & TcpFlags::RST != 0 {
        s.push('R');
    }
    if flags & TcpFlags::SYN != 0 {
        s.push('S');
    }
    if flags & TcpFlags::FIN != 0 {
        s.push('F');
    }
    s
}

fn seq_relation(their_seq: u32, our_seq: u32, our_ack: u32) -> String {
    if their_seq == 0 {
        "Z".into()
    } else if their_seq == our_ack {
        "A".into()
    } else if their_seq == our_ack.wrapping_add(1) {
        "A+".into()
    } else if their_seq == our_seq {
        "O".into()
    } else if their_seq == our_seq.wrapping_add(1) {
        "O+".into()
    } else {
        "O".into() // common for SYN-ACK (ISN unrelated) — nmap uses O for other
    }
}

fn ack_relation(their_ack: u32, our_seq: u32, our_ack: u32) -> String {
    if their_ack == 0 {
        "Z".into()
    } else if their_ack == our_seq {
        "S".into()
    } else if their_ack == our_seq.wrapping_add(1) {
        "S+".into()
    } else if their_ack == our_ack {
        "O".into()
    } else {
        "O".into()
    }
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

fn build_seq_test(replies: &[Option<TcpReply>]) -> Option<HashMap<String, String>> {
    let got: Vec<&TcpReply> = replies.iter().filter_map(|r| r.as_ref()).collect();
    if got.len() < 2 {
        return None;
    }
    let mut m = HashMap::new();

    // IP ID class (simplified)
    let ids: Vec<u16> = got.iter().map(|r| r.ip_id).collect();
    let ti = classify_ipid(&ids);
    m.insert("TI".into(), ti);

    // TS class from options
    let ts = if got.iter().any(|r| r.options.contains('T')) {
        "A" // timestamps present — rough
    } else {
        "U" // unsupported
    };
    m.insert("TS".into(), ts.into());

    // GCD of seq deltas (very rough)
    let seqs: Vec<u32> = got.iter().map(|r| r.seq).collect();
    if seqs.len() >= 2 {
        let diffs: Vec<u64> = seqs
            .windows(2)
            .map(|w| w[1].wrapping_sub(w[0]) as u64)
            .filter(|&d| d > 0)
            .collect();
        if !diffs.is_empty() {
            let g = diffs.iter().copied().reduce(gcd).unwrap_or(1);
            m.insert("GCD".into(), format!("{g:X}"));
        }
    }

    Some(m)
}

fn classify_ipid(ids: &[u16]) -> String {
    if ids.iter().all(|&id| id == 0) {
        return "Z".into();
    }
    // Incremental?
    let mut inc = true;
    for w in ids.windows(2) {
        let d = w[1].wrapping_sub(w[0]);
        if d == 0 || d > 1000 {
            inc = false;
            break;
        }
    }
    if inc {
        "I".into()
    } else {
        "RD".into() // random-ish
    }
}

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Nmap-style TCP option string encoding.
pub fn encode_tcp_options(tcp: &TcpPacket) -> String {
    let data_offset = tcp.get_data_offset() as usize * 4;
    if data_offset <= 20 {
        return String::new();
    }
    let hdr = tcp.packet();
    if hdr.len() < data_offset {
        return String::new();
    }
    let mut opts = &hdr[20..data_offset];
    let mut out = String::new();

    while !opts.is_empty() {
        match opts[0] {
            0 => {
                out.push('L');
                break;
            }
            1 => {
                out.push('N');
                opts = &opts[1..];
            }
            2 => {
                if opts.len() < 4 || opts[1] != 4 {
                    break;
                }
                let mss = u16::from_be_bytes([opts[2], opts[3]]);
                out.push('M');
                out.push_str(&format!("{mss:X}"));
                opts = &opts[4..];
            }
            3 => {
                if opts.len() < 3 || opts[1] != 3 {
                    break;
                }
                out.push('W');
                out.push_str(&format!("{:X}", opts[2]));
                opts = &opts[3..];
            }
            4 => {
                if opts.len() < 2 || opts[1] != 2 {
                    break;
                }
                out.push('S');
                opts = &opts[2..];
            }
            8 => {
                if opts.len() < 10 || opts[1] != 10 {
                    break;
                }
                out.push('T');
                let tsval_nz = opts[2..6].iter().any(|&b| b != 0);
                let tsecr_nz = opts[6..10].iter().any(|&b| b != 0);
                out.push(if tsval_nz { '1' } else { '0' });
                out.push(if tsecr_nz { '1' } else { '0' });
                opts = &opts[10..];
            }
            _ => {
                if opts.len() < 2 {
                    break;
                }
                let len = opts[1] as usize;
                if len < 2 || opts.len() < len {
                    break;
                }
                opts = &opts[len..];
            }
        }
    }
    out
}

fn send_tcp_and_wait(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    df: bool,
    timeout: Duration,
) -> Option<TcpReply> {
    send_tcp_raw_flags(src, dst, sport, dport, seq, ack, flags, window, options, df, timeout)
}

fn send_tcp_raw_flags(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: &[u8],
    _df: bool, // Layer4 path can't set DF easily; ignored on L4 send
    timeout: Duration,
) -> Option<TcpReply> {
    // Capture L3 for TTL/DF
    let recv_type = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (_, mut rrx) = transport_channel(65535, recv_type).ok()?;

    let done = Arc::new(AtomicBool::new(false));
    let result: Arc<Mutex<Option<TcpReply>>> = Arc::new(Mutex::new(None));
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
            let df = ip_pkt.get_flags() & Ipv4Flags::DontFragment != 0;
            let reply = TcpReply {
                ttl: ip_pkt.get_ttl(),
                df,
                window: tcp.get_window(),
                flags: tcp.get_flags(),
                seq: tcp.get_sequence(),
                ack: tcp.get_acknowledgement(),
                options: encode_tcp_options(&tcp),
                ip_id: ip_pkt.get_identification(),
            };
            // polite RST on SYN-ACK
            if reply.flags & TcpFlags::SYN != 0 && reply.flags & TcpFlags::ACK != 0 {
                let _ = send_rst(src, dst, sport, dport, reply.ack);
            }
            *result_c.lock().unwrap() = Some(reply);
            break;
        }
    });

    // Send via L4 TCP
    let send_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    if let Ok((mut stx, _)) = transport_channel(1024, send_type) {
        let _ = send_tcp_packet(
            &mut stx, src, dst, sport, dport, seq, ack, flags, window, options,
        );
    }

    let start = Instant::now();
    while start.elapsed() < timeout {
        if result.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    done.store(true, Ordering::Relaxed);
    // Detach — joining a blocked pnet recv hangs the whole process (macOS GUI freeze).
    drop(handle);
    let value = result.lock().unwrap().take();
    value
}

fn send_tcp_packet(
    sender: &mut TransportSender,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
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
        pkt.set_acknowledgement(ack);
        pkt.set_data_offset(((20 + options.len() + pad) / 4) as u8);
        pkt.set_flags(flags);
        pkt.set_window(window);
        pkt.set_urgent_ptr(0);
        // copy options into header
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
        .map_err(|e| anyhow::anyhow!("send tcp: {e}"))
}

fn send_rst(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32) -> Result<()> {
    let channel_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
    let (mut sender, _) = transport_channel(128, channel_type)?;
    send_tcp_packet(
        &mut sender,
        src,
        dst,
        sport,
        dport,
        seq,
        0,
        TcpFlags::RST | TcpFlags::ACK,
        0,
        &[],
    )
}

fn icmp_echo_ttl(dst: Ipv4Addr, timeout: Duration) -> Option<u8> {
    let recv_type = TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);
    let (_, mut rrx) = transport_channel(65535, recv_type).ok()?;

    let done = Arc::new(AtomicBool::new(false));
    let result: Arc<Mutex<Option<u8>>> = Arc::new(Mutex::new(None));
    let done_c = done.clone();
    let result_c = result.clone();

    let handle = thread::spawn(move || {
        let mut iter = ipv4_packet_iter(&mut rrx);
        while !done_c.load(Ordering::Relaxed) {
            if let Ok((ip_pkt, _)) = iter.next() {
                if ip_pkt.get_source() != dst {
                    continue;
                }
                if let Some(icmp) = IcmpPacket::new(ip_pkt.payload()) {
                    if icmp.get_icmp_type() == IcmpTypes::EchoReply {
                        *result_c.lock().unwrap() = Some(ip_pkt.get_ttl());
                        break;
                    }
                }
            }
        }
    });

    let send_type =
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp));
    if let Ok((mut stx, _)) = transport_channel(512, send_type) {
        let mut buf = [0u8; 64];
        if let Some(mut icmp) = MutableIcmpPacket::new(&mut buf) {
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_icmp_code(echo_request::IcmpCodes::NoCode);
            let csum = pnet::packet::icmp::checksum(&icmp.to_immutable());
            icmp.set_checksum(csum);
            if let Some(pkt) = IcmpPacket::new(&buf) {
                let _ = stx.send_to(pkt, IpAddr::V4(dst));
            }
        }
    }

    let start = Instant::now();
    while start.elapsed() < timeout {
        if result.lock().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    done.store(true, Ordering::Relaxed);
    drop(handle); // do not join blocked recv
    let value = result.lock().unwrap().take();
    value
}

fn local_ipv4_for(dst: Ipv4Addr) -> Result<Ipv4Addr> {
    let sock = StdUdpSocket::bind("0.0.0.0:0").context("bind route")?;
    sock.connect(SocketAddrV4::new(dst, 9))
        .context("connect route")?;
    match sock.local_addr()? {
        std::net::SocketAddr::V4(a) => Ok(*a.ip()),
        _ => bail!("need ipv4"),
    }
}

/// Try common ports to find one open and one closed for fingerprinting.
pub fn discover_ports(
    dst: Ipv4Addr,
    prefer_open: &[u16],
    prefer_closed: &[u16],
    timeout: Duration,
) -> (Option<u16>, Option<u16>) {
    let src = match local_ipv4_for(dst) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };

    let mut open = None;
    let mut closed = None;

    let mut candidates: Vec<u16> = prefer_open.to_vec();
    candidates.extend_from_slice(&[80, 443, 22, 445, 3389, 8080, 21, 25, 135, 139, 3306]);
    candidates.sort_unstable();
    candidates.dedup();

    for &p in &candidates {
        if open.is_some() {
            break;
        }
        let sport: u16 = rand::rng().random_range(40000..60000);
        let seq: u32 = rand::rng().random();
        if let Some(r) = send_tcp_raw_flags(
            src,
            dst,
            sport,
            p,
            seq,
            0,
            TcpFlags::SYN,
            1024,
            PRB_OPTS[0],
            false,
            timeout,
        ) {
            if r.flags & TcpFlags::SYN != 0 && r.flags & TcpFlags::ACK != 0 {
                open = Some(p);
            } else if r.flags & TcpFlags::RST != 0 {
                closed = Some(p);
            }
        }
    }

    // Find closed if still missing
    let mut closed_cands: Vec<u16> = prefer_closed.to_vec();
    closed_cands.extend([1, 9, 13, 17, 19, 42, 81, 1234, 4444, 31337, 65000]);
    for &p in &closed_cands {
        if closed.is_some() {
            break;
        }
        if Some(p) == open {
            continue;
        }
        let sport: u16 = rand::rng().random_range(40000..60000);
        let seq: u32 = rand::rng().random();
        match send_tcp_raw_flags(
            src,
            dst,
            sport,
            p,
            seq,
            0,
            TcpFlags::SYN,
            1024,
            PRB_OPTS[0],
            false,
            timeout.min(Duration::from_millis(400)),
        ) {
            Some(r) if r.flags & TcpFlags::RST != 0 => closed = Some(p),
            Some(r) if r.flags & TcpFlags::SYN != 0 && r.flags & TcpFlags::ACK != 0 => {
                if open.is_none() {
                    open = Some(p);
                }
            }
            None => {
                // timeout — might be filtered; still usable as "closed-ish" for T5 if desperate
            }
            _ => {}
        }
    }

    (open, closed)
}
