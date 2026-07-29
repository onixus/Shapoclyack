use anyhow::{bail, Context, Result};
use ipnet::{IpNet, Ipv4Net};
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

/// Soft default; override via `--max-hosts`.
pub const DEFAULT_MAX_HOSTS: usize = 4096;

#[derive(Debug, Clone)]
pub struct Target {
    pub display: String,
    pub addr: IpAddr,
}

/// Options for expanding target specs into concrete hosts.
#[derive(Debug, Clone, Default)]
pub struct ExpandOptions {
    pub max_hosts: usize,
    /// Hosts matching any of these specs are dropped after resolve.
    pub exclude_specs: Vec<String>,
    pub exclude_file: Option<std::path::PathBuf>,
}

impl ExpandOptions {
    pub fn new(max_hosts: usize) -> Self {
        Self {
            max_hosts,
            exclude_specs: Vec::new(),
            exclude_file: None,
        }
    }
}

/// Expand one or many target specs into concrete IP addresses.
#[allow(dead_code)] // used by tests + public API
///
/// Accepts (combined with `,` / whitespace / newlines):
/// - single IP: `192.168.1.1`
/// - hostname / domain: `example.com`
/// - CIDR: `10.0.0.0/24`, `2001:db8::/64`
/// - netmask: `10.0.0.0/255.255.255.0` or `10.0.0.0 255.255.255.0`
/// - IPv4 range: `10.0.0.1-10.0.0.50` or `10.0.0.1-50`
///
/// File path can be loaded via [`expand_targets_file`].
pub fn expand_targets(input: &str) -> Result<Vec<Target>> {
    expand_targets_limited(input, DEFAULT_MAX_HOSTS)
}

#[allow(dead_code)]
pub fn expand_targets_limited(input: &str, max_hosts: usize) -> Result<Vec<Target>> {
    expand_targets_with(input, &ExpandOptions::new(max_hosts))
}

/// Expand with exclude support.
pub fn expand_targets_with(input: &str, opts: &ExpandOptions) -> Result<Vec<Target>> {
    let specs = split_target_specs(input);
    if specs.is_empty() {
        bail!("no targets specified");
    }

    let exclude = build_exclude_set(opts)?;
    let max_hosts = opts.max_hosts.max(1);

    let mut out = Vec::new();
    let mut seen = HashSet::new();

    for spec in specs {
        let batch = expand_one_spec(&spec)?;
        for t in batch {
            if exclude.contains(&t.addr) {
                continue;
            }
            if seen.insert(t.addr) {
                out.push(t);
            }
        }
        if out.len() > max_hosts {
            bail!(
                "target list expands to more than {} hosts (got ≥{}). \
                 Raise --max-hosts, use --discover on smaller batches, or narrow the scope.",
                max_hosts,
                out.len()
            );
        }
    }

    if out.is_empty() {
        bail!("no addresses resolved from targets (after excludes)");
    }
    Ok(out)
}

/// Load targets from a file (one host/domain/CIDR/mask per line).
/// Lines starting with `#` and empty lines are ignored.
#[allow(dead_code)]
pub fn expand_targets_file(path: &Path, max_hosts: usize) -> Result<Vec<Target>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read targets file '{}'", path.display()))?;
    expand_targets_limited(&text, max_hosts)
}

/// Merge CLI positional target + optional file into one list.
#[allow(dead_code)]
pub fn expand_targets_combined(
    positional: Option<&str>,
    file: Option<&Path>,
    max_hosts: usize,
) -> Result<Vec<Target>> {
    expand_targets_combined_with(positional, file, &ExpandOptions::new(max_hosts))
}

/// Merge targets with exclude options.
pub fn expand_targets_combined_with(
    positional: Option<&str>,
    file: Option<&Path>,
    opts: &ExpandOptions,
) -> Result<Vec<Target>> {
    let mut chunks = Vec::new();
    if let Some(p) = positional {
        let p = p.trim();
        if !p.is_empty() {
            chunks.push(p.to_string());
        }
    }
    if let Some(path) = file {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read targets file '{}'", path.display()))?;
        chunks.push(text);
    }
    if chunks.is_empty() {
        bail!("provide TARGET and/or --targets-file");
    }
    expand_targets_with(&chunks.join("\n"), opts)
}

/// Build a set of excluded IP addresses from specs + optional file.
fn build_exclude_set(opts: &ExpandOptions) -> Result<HashSet<IpAddr>> {
    let mut set = HashSet::new();
    let mut chunks = opts.exclude_specs.clone();
    if let Some(path) = &opts.exclude_file {
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read exclude file '{}'", path.display()))?;
        chunks.push(text);
    }
    if chunks.is_empty() {
        return Ok(set);
    }
    // Expand excludes without max-hosts (but cap insane ranges)
    let blob = chunks.join("\n");
    let specs = split_target_specs(&blob);
    for spec in specs {
        // Allow large exclude ranges up to 1M
        match expand_one_spec_capped(&spec, 1_000_000) {
            Ok(batch) => {
                for t in batch {
                    set.insert(t.addr);
                }
            }
            Err(e) => {
                bail!("invalid --exclude '{spec}': {e}");
            }
        }
    }
    Ok(set)
}

fn expand_one_spec_capped(spec: &str, max: usize) -> Result<Vec<Target>> {
    let batch = expand_one_spec(spec)?;
    if batch.len() > max {
        bail!(
            "exclude spec expands to {} hosts (cap {max})",
            batch.len()
        );
    }
    Ok(batch)
}

/// Split a blob into individual target tokens.
/// Supports commas, whitespace, and newlines. Does **not** split inside
/// `a.b.c.d-e.f.g.h` ranges (hyphen kept) or `ip mask` pairs (rejoined).
fn split_target_specs(input: &str) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // strip inline comments
        let line = line.split('#').next().unwrap_or(line).trim();
        if line.is_empty() {
            continue;
        }
        for part in line.split(&[',', ';'][..]) {
            let part = part.trim();
            if !part.is_empty() {
                raw.push(part.to_string());
            }
        }
    }

    // Re-join patterns like "10.0.0.0 255.255.255.0" that were split only by newline
    // (they stay as one line above). Also handle space-separated list of domains.
    let mut specs = Vec::new();
    let mut i = 0;
    let tokens: Vec<String> = raw
        .into_iter()
        .flat_map(|s| {
            // If the string looks like "ip mask", keep together; else split spaces
            if looks_like_ip_and_mask(&s) {
                vec![s]
            } else if s.contains(' ') && !s.contains('/') && !is_range_spec(&s) {
                s.split_whitespace()
                    .filter(|t| !t.is_empty())
                    .map(|t| t.to_string())
                    .collect()
            } else {
                vec![s]
            }
        })
        .collect();

    while i < tokens.len() {
        let t = &tokens[i];
        // "10.0.0.0" + "255.255.255.0" across tokens
        if i + 1 < tokens.len()
            && IpAddr::from_str(t).is_ok()
            && is_netmask_token(&tokens[i + 1])
        {
            specs.push(format!("{} {}", t, tokens[i + 1]));
            i += 2;
            continue;
        }
        specs.push(t.clone());
        i += 1;
    }
    specs
}

fn looks_like_ip_and_mask(s: &str) -> bool {
    let parts: Vec<&str> = s.split_whitespace().collect();
    parts.len() == 2 && IpAddr::from_str(parts[0]).is_ok() && is_netmask_token(parts[1])
}

fn is_netmask_token(s: &str) -> bool {
    match IpAddr::from_str(s) {
        Ok(IpAddr::V4(m)) => is_valid_v4_netmask(m),
        Ok(IpAddr::V6(_)) => false, // require CIDR for v6
        Err(_) => false,
    }
}

fn is_range_spec(s: &str) -> bool {
    s.contains('-') && !s.contains("://")
}

fn expand_one_spec(spec: &str) -> Result<Vec<Target>> {
    let spec = spec.trim();
    if spec.is_empty() {
        bail!("empty target spec");
    }

    // 1) ip + dotted netmask: "10.0.0.0 255.255.255.0" or "10.0.0.0/255.255.255.0"
    if let Some(net) = parse_ip_with_netmask(spec)? {
        return expand_ipnet(net);
    }

    // 2) Standard CIDR
    if let Ok(net) = IpNet::from_str(spec) {
        return expand_ipnet(net);
    }

    // 3) IPv4 range
    if let Some(list) = parse_ipv4_range(spec)? {
        return Ok(list);
    }

    // 4) Single IP
    if let Ok(ip) = IpAddr::from_str(spec) {
        return Ok(vec![Target {
            display: ip.to_string(),
            addr: ip,
        }]);
    }

    // 5) Hostname / domain
    resolve_hostname(spec)
}

fn parse_ip_with_netmask(spec: &str) -> Result<Option<IpNet>> {
    // Form A: 10.0.0.0/255.255.255.0
    if let Some((left, right)) = spec.split_once('/') {
        let left = left.trim();
        let right = right.trim();
        if let (Ok(IpAddr::V4(ip)), Ok(IpAddr::V4(mask))) =
            (IpAddr::from_str(left), IpAddr::from_str(right))
        {
            if is_valid_v4_netmask(mask) {
                let net = Ipv4Net::with_netmask(ip, mask)
                    .map_err(|e| anyhow::anyhow!("invalid network {spec}: {e}"))?;
                return Ok(Some(IpNet::V4(net.trunc())));
            }
        }
        // not a mask form — let CIDR parser handle "10.0.0.0/24"
        return Ok(None);
    }

    // Form B: 10.0.0.0 255.255.255.0
    let parts: Vec<&str> = spec.split_whitespace().collect();
    if parts.len() == 2 {
        if let (Ok(IpAddr::V4(ip)), Ok(IpAddr::V4(mask))) =
            (IpAddr::from_str(parts[0]), IpAddr::from_str(parts[1]))
        {
            if is_valid_v4_netmask(mask) {
                let net = Ipv4Net::with_netmask(ip, mask)
                    .map_err(|e| anyhow::anyhow!("invalid network {spec}: {e}"))?;
                return Ok(Some(IpNet::V4(net.trunc())));
            }
        }
    }
    Ok(None)
}

fn is_valid_v4_netmask(mask: Ipv4Addr) -> bool {
    let n = u32::from(mask);
    if n == 0 {
        return false;
    }
    // contiguous ones then zeros: e.g. 1111…0000
    let inv = !n;
    inv & inv.wrapping_add(1) == 0
}

fn expand_ipnet(net: IpNet) -> Result<Vec<Target>> {
    let hosts: Vec<Target> = match net {
        IpNet::V4(n) => n
            .hosts()
            .map(|ip| Target {
                display: ip.to_string(),
                addr: IpAddr::V4(ip),
            })
            .collect(),
        IpNet::V6(n) => {
            // hosts() on large v6 is dangerous; limit by prefix
            if n.prefix_len() < 112 {
                bail!(
                    "IPv6 prefix /{} is too wide (min /112 for enumeration, or use single addr)",
                    n.prefix_len()
                );
            }
            n.hosts()
                .map(|ip| Target {
                    display: ip.to_string(),
                    addr: IpAddr::V6(ip),
                })
                .collect()
        }
    };

    if hosts.is_empty() {
        return Ok(vec![Target {
            display: net.addr().to_string(),
            addr: net.addr(),
        }]);
    }
    Ok(hosts)
}

/// Parse `10.0.0.1-10.0.0.50` or short `10.0.0.1-50`.
fn parse_ipv4_range(spec: &str) -> Result<Option<Vec<Target>>> {
    let Some((a, b)) = spec.split_once('-') else {
        return Ok(None);
    };
    let a = a.trim();
    let b = b.trim();
    if a.is_empty() || b.is_empty() {
        return Ok(None);
    }

    let start = match Ipv4Addr::from_str(a) {
        Ok(ip) => ip,
        Err(_) => return Ok(None), // not an IP range (maybe hostname with hyphen)
    };

    let end = if let Ok(ip) = Ipv4Addr::from_str(b) {
        ip
    } else if b.chars().all(|c| c.is_ascii_digit()) {
        // short form: 192.168.1.10-50
        let octets = start.octets();
        let last: u8 = b
            .parse()
            .with_context(|| format!("invalid range end '{b}'"))?;
        Ipv4Addr::new(octets[0], octets[1], octets[2], last)
    } else {
        return Ok(None);
    };

    let s = u32::from(start);
    let e = u32::from(end);
    if e < s {
        bail!("invalid range {spec}: end < start");
    }
    let count = (e - s) as usize + 1;
    if count > DEFAULT_MAX_HOSTS * 4 {
        // hard safety even before max_hosts merge
        bail!("IPv4 range {spec} is too large ({count} addresses)");
    }

    let mut out = Vec::with_capacity(count);
    for n in s..=e {
        let ip = Ipv4Addr::from(n);
        out.push(Target {
            display: ip.to_string(),
            addr: IpAddr::V4(ip),
        });
    }
    Ok(Some(out))
}

fn resolve_hostname(input: &str) -> Result<Vec<Target>> {
    let addrs: Vec<SocketAddr> = format!("{input}:0")
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve hostname '{input}'"))?
        .collect();

    if addrs.is_empty() {
        bail!("no addresses resolved for '{input}'");
    }

    let mut seen = HashSet::new();
    let mut targets = Vec::new();
    for sa in addrs {
        let ip = sa.ip();
        if seen.insert(ip) {
            targets.push(Target {
                display: format!("{input} ({ip})"),
                addr: ip,
            });
        }
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ip() {
        let t = expand_targets("127.0.0.1").unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].addr, IpAddr::from_str("127.0.0.1").unwrap());
    }

    #[test]
    fn parses_cidr() {
        let t = expand_targets("10.0.0.0/30").unwrap();
        assert_eq!(t.len(), 2); // .1 and .2
    }

    #[test]
    fn parses_dotted_netmask_slash() {
        let t = expand_targets("10.0.0.0/255.255.255.252").unwrap();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn parses_dotted_netmask_space() {
        let t = expand_targets("10.0.0.0 255.255.255.252").unwrap();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn parses_ipv4_range_full() {
        let t = expand_targets("10.0.0.1-10.0.0.3").unwrap();
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn parses_ipv4_range_short() {
        let t = expand_targets("10.0.0.1-3").unwrap();
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn parses_list_mixed() {
        let t = expand_targets("127.0.0.1, 10.0.0.0/30").unwrap();
        // 127.0.0.1 + .1 + .2
        assert_eq!(t.len(), 3);
    }

    #[test]
    fn parses_multiline_domains_style() {
        let input = "\
        # comment
        127.0.0.1
        10.0.0.5
        ";
        let t = expand_targets(input).unwrap();
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn dedupes() {
        let t = expand_targets("127.0.0.1,127.0.0.1").unwrap();
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn excludes_cidr_from_range() {
        let opts = ExpandOptions {
            max_hosts: 100,
            exclude_specs: vec!["10.0.0.2".into()],
            exclude_file: None,
        };
        let t = expand_targets_with("10.0.0.1-10.0.0.4", &opts).unwrap();
        assert_eq!(t.len(), 3);
        assert!(!t.iter().any(|x| x.addr.to_string() == "10.0.0.2"));
    }

    #[test]
    fn excludes_subnet() {
        let opts = ExpandOptions {
            max_hosts: 100,
            exclude_specs: vec!["10.0.0.0/30".into()],
            exclude_file: None,
        };
        // /30 hosts are .1 and .2; exclude them from /29-ish list
        let t = expand_targets_with("10.0.0.1-10.0.0.4", &opts).unwrap();
        assert!(!t.iter().any(|x| x.addr.to_string() == "10.0.0.1"));
        assert!(!t.iter().any(|x| x.addr.to_string() == "10.0.0.2"));
        assert!(t.iter().any(|x| x.addr.to_string() == "10.0.0.3"));
    }

    #[test]
    fn rejects_non_contiguous_mask() {
        assert!(parse_ip_with_netmask("10.0.0.0/255.0.255.0")
            .unwrap()
            .is_none());
    }

    #[test]
    fn file_and_list() {
        let dir = std::env::temp_dir();
        let path = dir.join("pulse-targets-test.txt");
        std::fs::write(&path, "127.0.0.1\n# cmt\n10.0.0.1-10.0.0.2\n").unwrap();
        let t = expand_targets_file(&path, 100).unwrap();
        assert_eq!(t.len(), 3);
        let _ = std::fs::remove_file(&path);
    }
}
