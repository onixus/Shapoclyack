//! CVE / CVSS correlation for open ports & banners.
//!
//! Offline-first: curated high-signal rules (port / service / version).
//! Optional online enrichment via NVD 2.0 when `PULSE_CVE_ONLINE=1` or `--cve-online`.

use super::PortResult;
use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct CveFinding {
    pub cve_id: String,
    pub cvss: Option<f32>,
    pub severity: String,
    pub title: String,
    pub summary: String,
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub match_reason: String,
    pub source: String,
    pub refs: Vec<String>,
}

#[derive(Clone)]
struct Rule {
    /// Optional TCP port filter
    port: Option<u16>,
    /// Service name contains (lowercase)
    service_sub: Option<&'static str>,
    /// Banner regex (case-insensitive)
    banner_re: Option<&'static str>,
    cve_id: &'static str,
    cvss: f32,
    title: &'static str,
    summary: &'static str,
}

fn severity_from_cvss(score: f32) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        "NONE"
    }
}

fn nvd_url(cve: &str) -> String {
    format!("https://nvd.nist.gov/vuln/detail/{cve}")
}

/// Curated high-signal rules (not a full NVD mirror — fast offline triage).
fn rules() -> &'static [Rule] {
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    RULES.get_or_init(|| {
        vec![
            // —— SMB / Windows ——
            Rule {
                port: Some(445),
                service_sub: Some("smb"),
                banner_re: None,
                cve_id: "CVE-2017-0144",
                cvss: 8.1,
                title: "EternalBlue (SMBv1 RCE)",
                summary: "SMBv1 remote code execution (WannaCry/NotPetya class). Patch or disable SMBv1.",
            },
            Rule {
                port: Some(139),
                service_sub: Some("netbios"),
                banner_re: None,
                cve_id: "CVE-2017-0144",
                cvss: 8.1,
                title: "EternalBlue-related NetBIOS/SMB exposure",
                summary: "Legacy NetBIOS/SMB often co-exposed with vulnerable SMBv1 stacks.",
            },
            Rule {
                port: Some(3389),
                service_sub: Some("rdp"),
                banner_re: None,
                cve_id: "CVE-2019-0708",
                cvss: 9.8,
                title: "BlueKeep (RDP RCE)",
                summary: "Unauthenticated RCE in Remote Desktop Services on unpatched Windows.",
            },
            Rule {
                port: Some(3389),
                service_sub: None,
                banner_re: None,
                cve_id: "CVE-2019-1181",
                cvss: 9.8,
                title: "DejaBlue-class RDP issues (family)",
                summary: "Post-BlueKeep RDP RCE family; ensure RDP fully patched / NLA enforced.",
            },
            // —— SSH ——
            Rule {
                port: Some(22),
                service_sub: Some("ssh"),
                banner_re: Some(r"OpenSSH[_ ]([1-6]\.|7\.[0-3])"),
                cve_id: "CVE-2016-0777",
                cvss: 5.8,
                title: "OpenSSH client roaming info leak (old)",
                summary: "Very old OpenSSH; upgrade — also many other CVEs apply to EOL builds.",
            },
            Rule {
                port: Some(22),
                service_sub: Some("ssh"),
                banner_re: Some(r"OpenSSH[_ ](8\.[0-7]|7\.)"),
                cve_id: "CVE-2023-38408",
                cvss: 9.8,
                title: "OpenSSH ssh-agent PKCS11 remote code execution",
                summary: "Affects OpenSSH before 9.3p2 under specific agent/PKCS11 conditions.",
            },
            Rule {
                port: Some(22),
                service_sub: Some("ssh"),
                banner_re: Some(r"OpenSSH[_ ](8\.|9\.[0-5])"),
                cve_id: "CVE-2024-6387",
                cvss: 8.1,
                title: "regreSSHion (OpenSSH signal handler race)",
                summary: "glibc-based OpenSSH server race → potential RCE; upgrade to fixed releases.",
            },
            // —— FTP ——
            Rule {
                port: Some(21),
                service_sub: Some("ftp"),
                banner_re: Some(r"vsftpd\s*2\.3\.4"),
                cve_id: "CVE-2011-2523",
                cvss: 9.8,
                title: "vsftpd 2.3.4 backdoor",
                summary: "Infamous smiley-face backdoor bind shell on port 6200.",
            },
            Rule {
                port: Some(21),
                service_sub: Some("ftp"),
                banner_re: Some(r"ProFTPD\s*1\.3\.[0-3]"),
                cve_id: "CVE-2015-3306",
                cvss: 10.0,
                title: "ProFTPD mod_copy RCE",
                summary: "Unauthenticated file copy leading to RCE on vulnerable ProFTPD.",
            },
            // —— HTTP stacks ——
            Rule {
                port: Some(80),
                service_sub: Some("http"),
                banner_re: Some(r"Apache/2\.4\.(4[0-9]|5[0-2])"),
                cve_id: "CVE-2021-41773",
                cvss: 7.5,
                title: "Apache path traversal / RCE (2.4.49-2.4.50)",
                summary: "Path traversal and possible RCE on misconfigured Apache 2.4.49/2.4.50.",
            },
            Rule {
                port: Some(443),
                service_sub: Some("http"),
                banner_re: Some(r"Apache/2\.4\.(4[0-9]|5[0-2])"),
                cve_id: "CVE-2021-41773",
                cvss: 7.5,
                title: "Apache path traversal / RCE (2.4.49-2.4.50)",
                summary: "Path traversal and possible RCE on misconfigured Apache 2.4.49/2.4.50.",
            },
            Rule {
                port: None,
                service_sub: Some("http"),
                banner_re: Some(r"Apache/2\.2\."),
                cve_id: "CVE-2017-3169",
                cvss: 9.8,
                title: "Apache 2.2 EOL — multiple critical issues",
                summary: "Apache 2.2 is end-of-life; plan migration to supported 2.4.x.",
            },
            Rule {
                port: None,
                service_sub: Some("http"),
                banner_re: Some(r"nginx/1\.(1[0-5]|[0-9])\."),
                cve_id: "CVE-2019-20372",
                cvss: 5.3,
                title: "Old nginx — review CVEs",
                summary: "EOL/old nginx often missing fixes for request smuggling / error page issues.",
            },
            Rule {
                port: None,
                service_sub: Some("http"),
                banner_re: Some(r"(IIS/6\.0|IIS/7\.0|IIS/7\.5)"),
                cve_id: "CVE-2017-7269",
                cvss: 9.8,
                title: "IIS 6.0 WebDAV RCE / legacy IIS",
                summary: "Legacy IIS frequently targeted; upgrade off IIS 6/7.x.",
            },
            // —— Databases ——
            Rule {
                port: Some(3306),
                service_sub: Some("mysql"),
                banner_re: None,
                cve_id: "CVE-2012-2122",
                cvss: 7.5,
                title: "MySQL auth bypass family (historical + exposure)",
                summary: "Exposed MySQL is high risk; ensure auth, TLS, no public bind, current version.",
            },
            Rule {
                port: Some(5432),
                service_sub: Some("postgres"),
                banner_re: None,
                cve_id: "CVE-2019-9193",
                cvss: 7.2,
                title: "PostgreSQL COPY PROGRAM (misconfig RCE)",
                summary: "Superuser + COPY PROGRAM can lead to RCE; don't expose PG publicly.",
            },
            Rule {
                port: Some(27017),
                service_sub: Some("mongo"),
                banner_re: None,
                cve_id: "CVE-2019-2391",
                cvss: 7.5,
                title: "MongoDB exposure / auth bypass class",
                summary: "Unauthenticated or internet-exposed MongoDB is routinely mass-scanned.",
            },
            Rule {
                port: Some(6379),
                service_sub: Some("redis"),
                banner_re: None,
                cve_id: "CVE-2022-0543",
                cvss: 10.0,
                title: "Redis Lua sandbox escape (Debian/Ubuntu packaging)",
                summary: "Critical RCE via Lua; also generic risk if Redis has no AUTH on WAN.",
            },
            Rule {
                port: Some(9200),
                service_sub: Some("elastic"),
                banner_re: None,
                cve_id: "CVE-2015-1427",
                cvss: 9.8,
                title: "Elasticsearch groovy RCE class / exposure",
                summary: "Internet-facing Elasticsearch without auth is critical risk.",
            },
            // —— Java / app servers ——
            Rule {
                port: Some(8080),
                service_sub: Some("http"),
                banner_re: Some(r"(Tomcat|Coyote)"),
                cve_id: "CVE-2020-1938",
                cvss: 9.8,
                title: "Ghostcat (Tomcat AJP)",
                summary: "AJP file read/inclusion; ensure AJP not exposed and Tomcat patched.",
            },
            Rule {
                port: Some(1099),
                service_sub: None,
                banner_re: None,
                cve_id: "CVE-2017-3241",
                cvss: 9.8,
                title: "Java RMI exposure",
                summary: "RMI registries on the internet are frequently abused for deserialization RCE.",
            },
            // —— VPN / edge ——
            Rule {
                port: Some(1194),
                service_sub: Some("openvpn"),
                banner_re: None,
                cve_id: "CVE-2024-5594",
                cvss: 7.5,
                title: "OpenVPN server issues (keep updated)",
                summary: "Edge VPN services must stay current; review latest OpenVPN advisories.",
            },
            Rule {
                port: Some(443),
                service_sub: Some("http"),
                banner_re: Some(r"(Forti|Pulse Secure|Ivanti|Citrix)"),
                cve_id: "CVE-2021-22893",
                cvss: 10.0,
                title: "VPN appliance auth bypass class",
                summary: "Edge VPN appliances (Pulse/Ivanti/etc.) have had wormable auth bypasses — patch ASAP.",
            },
            // —— Mail ——
            Rule {
                port: Some(25),
                service_sub: Some("smtp"),
                banner_re: Some(r"Exim 4\.(9[0-4]|8)"),
                cve_id: "CVE-2019-15846",
                cvss: 9.8,
                title: "Exim RCE (old 4.9x)",
                summary: "Multiple critical RCEs hit older Exim; upgrade immediately.",
            },
            // —— Generic dangerous services ——
            Rule {
                port: Some(23),
                service_sub: Some("telnet"),
                banner_re: None,
                cve_id: "CVE-1999-0619",
                cvss: 7.5,
                title: "Telnet cleartext protocol",
                summary: "Credentials and sessions in cleartext; replace with SSH.",
            },
            Rule {
                port: Some(512),
                service_sub: None,
                banner_re: None,
                cve_id: "CVE-1999-0170",
                cvss: 7.5,
                title: "rexec/rlogin legacy exposure",
                summary: "r-services are obsolete and dangerous on modern networks.",
            },
            Rule {
                port: Some(111),
                service_sub: Some("rpc"),
                banner_re: None,
                cve_id: "CVE-2017-8779",
                cvss: 7.5,
                title: "rpcbind / RPC exposure",
                summary: "RPC portmapper often enables further NFS/mountd attacks.",
            },
            Rule {
                port: Some(2049),
                service_sub: Some("nfs"),
                banner_re: None,
                cve_id: "CVE-1999-0170",
                cvss: 7.5,
                title: "NFS export exposure",
                summary: "Public NFS can leak or allow write to critical shares.",
            },
            Rule {
                port: Some(5900),
                service_sub: Some("vnc"),
                banner_re: None,
                cve_id: "CVE-2019-8262",
                cvss: 7.5,
                title: "VNC exposure",
                summary: "Internet VNC is routinely brute-forced; tunnel or firewall.",
            },
            Rule {
                port: Some(11211),
                service_sub: Some("memcache"),
                banner_re: None,
                cve_id: "CVE-2018-1000115",
                cvss: 7.5,
                title: "Memcached amplification / exposure",
                summary: "Open memcached used in DDoS and data theft.",
            },
            Rule {
                port: Some(2375),
                service_sub: Some("docker"),
                banner_re: None,
                cve_id: "CVE-2019-5736",
                cvss: 8.6,
                title: "Docker API unauthenticated exposure",
                summary: "Open Docker API ≈ root on host. Never expose 2375 publicly.",
            },
            Rule {
                port: Some(6443),
                service_sub: Some("k8s"),
                banner_re: None,
                cve_id: "CVE-2018-1002105",
                cvss: 9.8,
                title: "Kubernetes API exposure",
                summary: "Exposed k8s API must use strong auth/RBAC; historical privilege escalations exist.",
            },
            Rule {
                port: Some(1025),
                service_sub: None,
                banner_re: Some(r"Microsoft"),
                cve_id: "CVE-2020-0796",
                cvss: 10.0,
                title: "SMBGhost-adjacent Microsoft stack (check build)",
                summary: "If SMBv3 compression stack is unpatched, critical RCE risk (CVE-2020-0796).",
            },
            Rule {
                port: Some(445),
                service_sub: None,
                banner_re: None,
                cve_id: "CVE-2020-0796",
                cvss: 10.0,
                title: "SMBGhost (SMBv3 compression RCE)",
                summary: "Windows SMBv3 compression RCE; verify patches on modern Windows hosts.",
            },
            // HTTP management UIs
            Rule {
                port: Some(8080),
                service_sub: Some("http"),
                banner_re: Some(r"(Jenkins|X-Jenkins)"),
                cve_id: "CVE-2019-1003000",
                cvss: 9.0,
                title: "Jenkins script security / RCE class",
                summary: "Exposed Jenkins without auth is critical; keep plugins patched.",
            },
            Rule {
                port: Some(9000),
                service_sub: None,
                banner_re: Some(r"Sonar"),
                cve_id: "CVE-2020-27986",
                cvss: 7.5,
                title: "SonarQube exposure",
                summary: "Misconfigured SonarQube can leak source / allow takeover.",
            },
        ]
    })
}

fn compile_re(pat: &str) -> Option<Regex> {
    Regex::new(&format!("(?i){pat}")).ok()
}

/// Match open ports against local CVE rules.
pub fn correlate_local(open: &[&PortResult]) -> Vec<CveFinding> {
    let mut out = Vec::new();
    for r in open {
        if !r.open {
            continue;
        }
        let svc = r.service.to_lowercase();
        let banner = r.banner.clone().unwrap_or_default();
        for rule in rules() {
            if let Some(p) = rule.port {
                if r.port != p {
                    continue;
                }
            }
            if let Some(sub) = rule.service_sub {
                if !svc.contains(sub) && !banner.to_lowercase().contains(sub) {
                    // also allow port-only rules with service_sub matching known map
                    if rule.banner_re.is_some() {
                        // need banner or service
                        if !svc.contains(sub) {
                            continue;
                        }
                    } else if rule.port.is_some() {
                        // port-only with service hint: soft match — allow if service unknown or matches
                        if svc != "unknown" && !svc.contains(sub) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            }
            if let Some(pat) = rule.banner_re {
                let Some(re) = compile_re(pat) else { continue };
                if !re.is_match(&banner) {
                    // if no banner at all and rule requires banner pattern, skip
                    if banner.is_empty() {
                        continue;
                    }
                    continue;
                }
            }

            let reason = match (rule.port, rule.banner_re, &banner) {
                (Some(p), Some(_), b) if !b.is_empty() => {
                    format!("port {p} + banner match")
                }
                (Some(p), _, _) => format!("port {p} / service {}", r.service),
                (_, Some(_), b) if !b.is_empty() => "banner version match".into(),
                _ => format!("service {}", r.service),
            };

            out.push(CveFinding {
                cve_id: rule.cve_id.into(),
                cvss: Some(rule.cvss),
                severity: severity_from_cvss(rule.cvss).into(),
                title: rule.title.into(),
                summary: rule.summary.into(),
                ip: r.ip.clone(),
                port: r.port,
                service: r.service.clone(),
                match_reason: reason,
                source: "local".into(),
                refs: vec![nvd_url(rule.cve_id)],
            });
        }
    }

    // de-dupe by (ip, port, cve)
    out.sort_by(|a, b| {
        b.cvss
            .partial_cmp(&a.cvss)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cve_id.cmp(&b.cve_id))
            .then(a.port.cmp(&b.port))
    });
    out.dedup_by(|a, b| a.ip == b.ip && a.port == b.port && a.cve_id == b.cve_id);
    out
}
// Note: Ordering::Equal works via PartialOrd for Option; keep sort stable.

/// Optional NVD enrichment for a product keyword (banner-derived).
pub async fn enrich_online(open: &[&PortResult], max_per_service: usize) -> Result<Vec<CveFinding>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(12))
        .user_agent("pulse-scanner/0.1 (security research; local admin use)")
        .build()
        .context("http client")?;

    let mut findings = Vec::new();
    let mut seen_queries = std::collections::HashSet::new();

    for r in open.iter().filter(|r| r.open).take(12) {
        let q = keyword_from_result(r);
        if q.len() < 3 || !seen_queries.insert(q.clone()) {
            continue;
        }

        // NVD 2.0 keyword search
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage={}",
            urlencoding_minimal(&q),
            max_per_service.max(1).min(5)
        );

        let mut req = client.get(&url);
        if let Some(key) = nvd_api_key() {
            req = req.header("apiKey", key);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  cve-online: request failed for '{q}': {e}");
                continue;
            }
        };
        if !resp.status().is_success() {
            eprintln!(
                "  cve-online: HTTP {} for '{q}'{}",
                resp.status(),
                if nvd_api_key().is_none() {
                    " (set NVD_API_KEY or ~/.pulse/nvd_api_key)"
                } else {
                    ""
                }
            );
            continue;
        }

        let body: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        let vulns = body
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for v in vulns.iter().take(max_per_service) {
            let cve = v.get("cve").unwrap_or(v);
            let id = cve
                .get("id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }

            let (cvss, sev) = extract_cvss(cve);
            let summary = cve
                .get("descriptions")
                .and_then(|d| d.as_array())
                .and_then(|arr| {
                    arr.iter()
                        .find(|x| x.get("lang").and_then(|l| l.as_str()) == Some("en"))
                        .or_else(|| arr.first())
                })
                .and_then(|x| x.get("value"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .chars()
                .take(220)
                .collect::<String>();

            findings.push(CveFinding {
                cve_id: id.clone(),
                cvss,
                severity: sev,
                title: id.clone(),
                summary,
                ip: r.ip.clone(),
                port: r.port,
                service: r.service.clone(),
                match_reason: format!("NVD keyword: {q}"),
                source: "nvd".into(),
                refs: vec![nvd_url(&id)],
            });
        }

        // With API key NVD allows higher rate; without, stay gentle.
        let pause = if nvd_api_key().is_some() { 200 } else { 700 };
        tokio::time::sleep(std::time::Duration::from_millis(pause)).await;
    }

    Ok(findings)
}

/// Resolve NVD API key without hardcoding secrets in the binary/repo.
///
/// Priority:
/// 1. `NVD_API_KEY` env
/// 2. `PULSE_NVD_API_KEY` env
/// 3. `~/.pulse/nvd_api_key` (single line, mode 0600 recommended)
/// 4. `~/.pulse/config` line `nvd_api_key=...` or `NVD_API_KEY=...`
pub fn nvd_api_key() -> Option<String> {
    for var in ["NVD_API_KEY", "PULSE_NVD_API_KEY"] {
        if let Ok(k) = std::env::var(var) {
            let k = k.trim().to_string();
            if !k.is_empty() {
                return Some(k);
            }
        }
    }

    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))?;
    let pulse_dir = std::path::PathBuf::from(home).join(".pulse");

    // Dedicated key file
    let key_file = pulse_dir.join("nvd_api_key");
    if let Ok(text) = std::fs::read_to_string(&key_file) {
        if let Some(line) = text.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#'))
        {
            return Some(line.to_string());
        }
    }

    // Simple key=value config
    let cfg = pulse_dir.join("config");
    if let Ok(text) = std::fs::read_to_string(&cfg) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"').trim_matches('\'');
                if matches!(k, "nvd_api_key" | "NVD_API_KEY" | "PULSE_NVD_API_KEY") && !v.is_empty()
                {
                    return Some(v.to_string());
                }
            }
        }
    }

    None
}

/// Whether a key is available (for status messages; does not print the key).
pub fn nvd_api_key_configured() -> bool {
    nvd_api_key().is_some()
}

fn extract_cvss(cve: &serde_json::Value) -> (Option<f32>, String) {
    let metrics = cve.get("metrics");
    let score = metrics
        .and_then(|m| m.get("cvssMetricV31"))
        .and_then(|a| a.as_array())
        .and_then(|a| a.first())
        .and_then(|x| x.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(|s| s.as_f64())
        .or_else(|| {
            metrics
                .and_then(|m| m.get("cvssMetricV30"))
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.get("cvssData"))
                .and_then(|d| d.get("baseScore"))
                .and_then(|s| s.as_f64())
        })
        .or_else(|| {
            metrics
                .and_then(|m| m.get("cvssMetricV2"))
                .and_then(|a| a.as_array())
                .and_then(|a| a.first())
                .and_then(|x| x.get("cvssData"))
                .and_then(|d| d.get("baseScore"))
                .and_then(|s| s.as_f64())
        })
        .map(|f| f as f32);

    let sev = score
        .map(severity_from_cvss)
        .unwrap_or("UNKNOWN")
        .to_string();
    (score, sev)
}

fn keyword_from_result(r: &PortResult) -> String {
    if let Some(b) = &r.banner {
        // strip non-alnum noise, take first product-ish tokens
        let cleaned: String = b
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == ' ' || c == '_' || c == '/' {
                c
            } else {
                ' '
            })
            .collect();
        let parts: Vec<&str> = cleaned.split_whitespace().take(4).collect();
        if !parts.is_empty() {
            return parts.join(" ");
        }
    }
    if r.service != "unknown" {
        return r.service.clone();
    }
    format!("port {}", r.port)
}

fn urlencoding_minimal(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            b' ' => "%20".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// Run full CVE correlation for scan results.
pub async fn analyze_cves(results: &[PortResult], online: bool) -> Vec<CveFinding> {
    let open: Vec<&PortResult> = results.iter().filter(|r| r.open).collect();
    let mut findings = correlate_local(&open);

    if online {
        if nvd_api_key_configured() {
            eprintln!("  cve-online: NVD API key loaded (env or ~/.pulse/)");
        } else {
            eprintln!(
                "  cve-online: no API key — using public rate limits. \
                 Put key in ~/.pulse/nvd_api_key (chmod 600) or export NVD_API_KEY"
            );
        }
        match enrich_online(&open, 3).await {
            Ok(mut extra) => {
                findings.append(&mut extra);
            }
            Err(e) => eprintln!("  cve-online: {e:#}"),
        }
    }

    findings.sort_by(|a, b| {
        b.cvss
            .partial_cmp(&a.cvss)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.cve_id.cmp(&b.cve_id))
    });
    findings.dedup_by(|a, b| a.ip == b.ip && a.port == b.port && a.cve_id == b.cve_id);
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Protocol;

    fn open(port: u16, service: &str, banner: Option<&str>) -> PortResult {
        PortResult {
            host: "t".into(),
            ip: "1.2.3.4".into(),
            port,
            protocol: Protocol::Tcp,
            open: true,
            service: service.into(),
            latency_ms: Some(1),
            banner: banner.map(|s| s.into()),
        }
    }

    #[test]
    fn detects_smb_eternalblue() {
        let r = open(445, "smb", None);
        let f = correlate_local(&[&r]);
        assert!(f.iter().any(|x| x.cve_id == "CVE-2017-0144"));
        assert!(f[0].cvss.unwrap() >= 8.0);
    }

    #[test]
    fn detects_vsftpd_backdoor() {
        let r = open(21, "ftp", Some("220 (vsFTPd 2.3.4)"));
        let f = correlate_local(&[&r]);
        assert!(f.iter().any(|x| x.cve_id == "CVE-2011-2523"));
    }

    #[test]
    fn severity_buckets() {
        assert_eq!(severity_from_cvss(9.8), "CRITICAL");
        assert_eq!(severity_from_cvss(7.5), "HIGH");
        assert_eq!(severity_from_cvss(5.0), "MEDIUM");
    }
}
