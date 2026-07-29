use crate::scanner::{CveFinding, OsGuess, PortResult, ScanStats};
use anyhow::Result;
use chrono::Local;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Glass neon cyberpunk HTML report — pink glow on void.
/// Multi-host scans get per-host panels + jump TOC + live filter.
pub fn write_html_report(
    path: &Path,
    target: &str,
    results: &[PortResult],
    stats: &Arc<ScanStats>,
    os_guesses: &[OsGuess],
    cves: &[CveFinding],
) -> Result<()> {
    let mut open: Vec<&PortResult> = results.iter().filter(|r| r.open).collect();
    open.sort_by(|a, b| {
        a.ip.cmp(&b.ip)
            .then(a.protocol.as_str().cmp(b.protocol.as_str()))
            .then(a.port.cmp(&b.port))
    });

    // Group by IP
    let mut by_host: BTreeMap<&str, Vec<&PortResult>> = BTreeMap::new();
    for r in &open {
        by_host.entry(r.ip.as_str()).or_default().push(*r);
    }
    let host_count = by_host.len();
    let multi = host_count > 1;

    // Host TOC chips
    let toc = if multi {
        let chips: String = by_host
            .iter()
            .map(|(ip, rows)| {
                let href = format!("#host-{}", anchor_id(ip));
                format!(
                    r#"<a class="chip" href="{href}" data-host="{ip}">{ip} <span class="n">{n}</span></a>"#,
                    href = escape_attr(&href),
                    ip = escape_html(ip),
                    n = rows.len(),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let summary_rows: String = by_host
            .iter()
            .map(|(ip, rows)| {
                let href = format!("#host-{}", anchor_id(ip));
                let ports = rows
                    .iter()
                    .map(|r| r.port.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    r#"<tr class="sum-row" data-search="{search}">
  <td><a href="{href}">{ip}</a></td>
  <td class="port">{n}</td>
  <td class="dim">{ports}</td>
</tr>"#,
                    href = escape_attr(&href),
                    ip = escape_html(ip),
                    n = rows.len(),
                    ports = escape_html(&ports),
                    search = escape_attr(&format!("{} {}", ip, ports)),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            r#"
    <section class="panel glass toc sticky">
      <h2>Hosts  ·  {host_count} with open ports</h2>
      <div class="toolbar">
        <input id="filter" type="search" placeholder="Filter host / port / service / banner…" autocomplete="off"/>
        <span class="hint" id="filter-hint"></span>
      </div>
      <div class="chips">{chips}</div>
      <table class="summary-table">
        <thead><tr><th>Host</th><th>Open</th><th>Ports</th></tr></thead>
        <tbody>{summary_rows}</tbody>
      </table>
    </section>"#
        )
    } else {
        format!(
            r#"
    <section class="panel glass toc sticky">
      <div class="toolbar">
        <input id="filter" type="search" placeholder="Filter port / service / banner…" autocomplete="off"/>
        <span class="hint" id="filter-hint"></span>
      </div>
    </section>"#
        )
    };

    // Per-host panels (or single flat table for one host)
    let hosts_html: String = if open.is_empty() {
        r#"
    <section class="panel glass">
      <h2>Open Ports</h2>
      <div class="empty">NO OPEN PORTS</div>
    </section>"#
            .into()
    } else if multi {
        by_host
            .iter()
            .map(|(ip, rows)| {
                let label = rows
                    .first()
                    .map(|r| r.host.as_str())
                    .unwrap_or(ip);
                let label_extra = if label != *ip {
                    format!(
                        r#" <span class="host-alias">· {}</span>"#,
                        escape_html(label)
                    )
                } else {
                    String::new()
                };
                let rows_html = port_rows(rows);
                // OS / CVE snippets for this host
                let os_snip = os_guesses
                    .iter()
                    .filter(|g| g.ip == *ip)
                    .map(|g| {
                        format!(
                            r#"<span class="tag os">{conf}% {detail}</span>"#,
                            conf = g.confidence,
                            detail = escape_html(&g.detail),
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let cve_n = cves.iter().filter(|c| c.ip == *ip).count();
                let cve_snip = if cve_n > 0 {
                    format!(r#"<span class="tag cve">{cve_n} CVE</span>"#)
                } else {
                    String::new()
                };

                let section_id = format!("host-{}", anchor_id(ip));
                format!(
                    r#"
    <section class="panel glass host-panel" id="{section_id}" data-search="{search}">
      <h2>
        <span class="host-ip">{ip}</span>{label_extra}
        <span class="host-meta">{n} open {os_snip}{cve_snip}</span>
      </h2>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Proto</th>
            <th>Port</th>
            <th>Service</th>
            <th>Latency</th>
            <th>Banner</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </section>"#,
                    section_id = escape_attr(&section_id),
                    ip = escape_html(ip),
                    label_extra = label_extra,
                    n = rows.len(),
                    os_snip = os_snip,
                    cve_snip = cve_snip,
                    rows_html = rows_html,
                    search = escape_attr(&host_search_blob(ip, label, rows)),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        // Single host: classic one table
        let rows_html = port_rows_with_host(&open);
        format!(
            r#"
    <section class="panel glass host-panel" data-search="{search}">
      <h2>Open Ports  ·  {n}</h2>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Proto</th>
            <th>Host</th>
            <th>Port</th>
            <th>Service</th>
            <th>Latency</th>
            <th>Banner</th>
          </tr>
        </thead>
        <tbody>
          {rows_html}
        </tbody>
      </table>
    </section>"#,
            n = open.len(),
            rows_html = rows_html,
            search = escape_attr(
                &open
                    .iter()
                    .map(|r| format!(
                        "{} {} {} {} {}",
                        r.ip,
                        r.port,
                        r.service,
                        r.protocol.as_str(),
                        r.banner.as_deref().unwrap_or("")
                    ))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        )
    };

    let os_section = build_os_section(os_guesses);
    let cve_section = build_cve_section(cves);

    let now = Local::now().format("%Y-%m-%d %H:%M:%S");
    let elapsed_s = stats.elapsed() as f64 / 1000.0;
    let elapsed_label = format!("{elapsed_s:.2}");
    let rate_label = format!("{:.0}", stats.rate());
    let target_esc = escape_html(target);

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>PULSE · {target_esc}</title>
<style>
  :root {{
    --void: #05010a;
    --glass: rgba(20, 8, 28, 0.55);
    --line: rgba(255, 46, 158, 0.22);
    --text: #ffe6f5;
    --muted: #9a6b88;
    --dim: #c49bb4;
    --pink: #ff2e9e;
    --hot: #ff1493;
    --cyan: #33f0ff;
    --ok: #39ff88;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    min-height: 100vh;
    color: var(--text);
    font-family: "SF Mono", "JetBrains Mono", ui-monospace, Menlo, monospace;
    font-size: 13px;
    line-height: 1.55;
    padding: 3rem 1.5rem 5rem;
    background:
      radial-gradient(900px 500px at 10% -10%, rgba(255, 20, 147, 0.35), transparent 55%),
      radial-gradient(700px 420px at 100% 20%, rgba(180, 0, 255, 0.22), transparent 50%),
      radial-gradient(600px 400px at 50% 100%, rgba(51, 240, 255, 0.08), transparent 45%),
      var(--void);
  }}
  .wrap {{ max-width: 1080px; margin: 0 auto; position: relative; }}
  .wrap::before {{
    content: "";
    pointer-events: none;
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(255,46,158,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,46,158,0.04) 1px, transparent 1px);
    background-size: 32px 32px;
    z-index: 0;
  }}
  .wrap > * {{ position: relative; z-index: 1; }}
  header.glass {{
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    background: var(--glass);
    border: 1px solid var(--line);
    border-radius: 18px;
    padding: 1.75rem 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 0 40px rgba(255, 46, 158, 0.15), inset 0 1px 0 rgba(255,255,255,0.08);
  }}
  .brand {{
    font-size: 0.7rem;
    letter-spacing: 0.35em;
    color: var(--pink);
    text-transform: uppercase;
    text-shadow: 0 0 12px rgba(255, 46, 158, 0.8);
    margin-bottom: 0.5rem;
  }}
  h1 {{
    font-size: 2.1rem;
    font-weight: 800;
    letter-spacing: 0.32em;
    color: #fff;
    text-shadow: 0 0 20px rgba(255, 46, 158, 0.9), 0 0 40px rgba(255, 20, 147, 0.5);
  }}
  .sub {{ margin-top: 0.55rem; color: var(--muted); font-size: 0.8rem; letter-spacing: 0.06em; }}
  .sub strong {{ color: var(--cyan); text-shadow: 0 0 8px rgba(51,240,255,0.5); }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }}
  .card {{
    backdrop-filter: blur(14px);
    background: var(--glass);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 1rem 1.1rem;
    box-shadow: 0 0 20px rgba(255, 46, 158, 0.08);
  }}
  .card .k {{
    font-size: 0.65rem;
    letter-spacing: 0.18em;
    color: var(--pink);
    text-transform: uppercase;
    text-shadow: 0 0 8px rgba(255,46,158,0.5);
  }}
  .card .v {{
    font-size: 1.35rem;
    font-weight: 700;
    margin-top: 0.35rem;
    color: #fff;
  }}
  .card .v.ok {{ color: var(--ok); text-shadow: 0 0 10px rgba(57,255,136,0.5); }}
  .sev-crit {{ color: #ff2d55; font-weight: 800; text-shadow: 0 0 10px rgba(255,45,85,0.55); }}
  .sev-high {{ color: #ff9f0a; font-weight: 700; }}
  .sev-med {{ color: #ffd60a; }}
  a {{ color: var(--pink); text-decoration: none; }}
  a:hover {{ text-shadow: 0 0 12px rgba(255,46,158,0.85); }}
  .panel.glass {{
    backdrop-filter: blur(16px);
    background: var(--glass);
    border: 1px solid var(--line);
    border-radius: 16px;
    overflow: hidden;
    margin-bottom: 1.25rem;
    box-shadow: 0 0 30px rgba(255, 46, 158, 0.1);
  }}
  .panel h2 {{
    font-size: 0.7rem;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--pink);
    text-shadow: 0 0 10px rgba(255,46,158,0.7);
    padding: 0.95rem 1.15rem;
    border-bottom: 1px solid var(--line);
    background: rgba(255, 46, 158, 0.06);
    display: flex;
    flex-wrap: wrap;
    align-items: baseline;
    gap: 0.5rem 1rem;
  }}
  .host-ip {{ color: #fff; font-size: 0.85rem; letter-spacing: 0.08em; }}
  .host-alias {{ color: var(--muted); font-weight: 400; text-transform: none; letter-spacing: 0; }}
  .host-meta {{ margin-left: auto; color: var(--cyan); font-weight: 600; letter-spacing: 0.08em; }}
  .tag {{
    display: inline-block;
    margin-left: 0.4rem;
    padding: 0.1rem 0.45rem;
    border-radius: 999px;
    font-size: 0.6rem;
    letter-spacing: 0.06em;
    border: 1px solid var(--line);
    color: var(--dim);
    text-transform: none;
  }}
  .tag.os {{ border-color: rgba(51,240,255,0.35); color: var(--cyan); }}
  .tag.cve {{ border-color: rgba(255,45,85,0.45); color: #ff6b8a; }}
  .toolbar {{
    padding: 0.85rem 1.15rem;
    display: flex;
    gap: 0.75rem;
    align-items: center;
    flex-wrap: wrap;
  }}
  #filter {{
    flex: 1;
    min-width: 200px;
    background: rgba(0,0,0,0.35);
    border: 1px solid var(--line);
    border-radius: 10px;
    color: var(--text);
    font: inherit;
    padding: 0.55rem 0.85rem;
    outline: none;
  }}
  #filter:focus {{
    border-color: var(--pink);
    box-shadow: 0 0 16px rgba(255,46,158,0.25);
  }}
  #filter::placeholder {{ color: var(--muted); }}
  .hint {{ color: var(--muted); font-size: 0.7rem; letter-spacing: 0.08em; }}
  .chips {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.45rem;
    padding: 0 1.15rem 1rem;
  }}
  .chip {{
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
    padding: 0.35rem 0.65rem;
    border-radius: 999px;
    border: 1px solid rgba(51,240,255,0.35);
    color: var(--cyan);
    font-size: 0.72rem;
    letter-spacing: 0.04em;
    background: rgba(51,240,255,0.06);
    transition: background 0.15s, box-shadow 0.15s;
  }}
  .chip:hover {{
    background: rgba(51,240,255,0.14);
    box-shadow: 0 0 14px rgba(51,240,255,0.25);
  }}
  .chip .n {{
    color: var(--ok);
    font-weight: 800;
  }}
  .chip.hidden, .host-panel.hidden, tr.port-row.hidden {{ display: none !important; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    text-align: left;
    padding: 0.65rem 1rem;
    font-size: 0.65rem;
    letter-spacing: 0.14em;
    color: var(--muted);
    border-bottom: 1px solid var(--line);
    font-weight: 600;
  }}
  td {{
    padding: 0.7rem 1rem;
    border-bottom: 1px solid rgba(255,46,158,0.1);
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255, 46, 158, 0.07); }}
  .badge {{
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 800;
    letter-spacing: 0.12em;
    color: var(--ok);
    border: 1px solid rgba(57,255,136,.45);
    padding: 0.12rem 0.45rem;
    border-radius: 999px;
    box-shadow: 0 0 10px rgba(57,255,136,0.25);
  }}
  .port {{ color: var(--pink); font-weight: 800; text-shadow: 0 0 10px rgba(255,46,158,0.55); }}
  .strong {{ color: #fff; font-weight: 600; }}
  .dim {{ color: var(--dim); }}
  .banner {{ max-width: 280px; word-break: break-all; }}
  .empty {{ text-align: center; color: var(--muted); padding: 2.5rem !important; letter-spacing: 0.2em; }}
  .hit {{ margin: 0.15rem 0; color: var(--dim); }}
  .pct {{ display: inline-block; min-width: 2.6rem; color: var(--cyan); font-weight: 700; text-shadow: 0 0 8px rgba(51,240,255,0.4); }}
  footer {{
    margin-top: 2rem;
    color: var(--muted);
    font-size: 0.7rem;
    letter-spacing: 0.14em;
    text-align: center;
    text-transform: uppercase;
  }}
  .toc.sticky {{
    position: sticky;
    top: 0.5rem;
    z-index: 20;
    box-shadow: 0 8px 32px rgba(0,0,0,0.45);
  }}
  .summary-table td:first-child {{ color: var(--cyan); font-weight: 700; }}
  details.host-panel > summary {{
    list-style: none;
    cursor: pointer;
  }}
  details.host-panel > summary::-webkit-details-marker {{ display: none; }}
  @media (max-width: 640px) {{
    body {{ padding: 1.25rem 0.75rem 3rem; }}
    h1 {{ font-size: 1.5rem; letter-spacing: 0.2em; }}
    .banner {{ max-width: 140px; }}
  }}
  @media print {{
    body {{
      background: #fff !important;
      color: #111 !important;
      padding: 0.5rem;
      font-size: 11px;
    }}
    .wrap::before, .toolbar, .chips, #filter, .hint {{ display: none !important; }}
    .panel.glass, header.glass, .card {{
      backdrop-filter: none !important;
      background: #fff !important;
      border: 1px solid #ccc !important;
      box-shadow: none !important;
      break-inside: avoid;
    }}
    h1, .brand, .panel h2, .card .k, .port, .host-ip {{ color: #111 !important; text-shadow: none !important; }}
    .dim, .sub, .muted, footer {{ color: #444 !important; }}
    .badge {{ color: #060; border-color: #060; box-shadow: none; }}
    a {{ color: #06c !important; }}
  }}
</style>
</head>
<body>
  <div class="wrap">
    <header class="glass">
      <div class="brand">Pulse · Cyber Glass · v0.2</div>
      <h1>PULSE</h1>
      <div class="sub">TARGET <strong>{target_esc}</strong>  ·  {now}</div>
    </header>

    <div class="stats">
      <div class="card"><div class="k">Probes</div><div class="v">{total}</div></div>
      <div class="card"><div class="k">Open</div><div class="v ok">{open_n}</div></div>
      <div class="card"><div class="k">Hosts</div><div class="v">{hosts}</div></div>
      <div class="card"><div class="k">Closed</div><div class="v">{closed}</div></div>
      <div class="card"><div class="k">Duration</div><div class="v">{elapsed_label}s</div></div>
      <div class="card"><div class="k">Rate</div><div class="v">{rate_label} pps</div></div>
    </div>

    {toc}
    {hosts_html}
    {os_section}
    {cve_section}

    <footer>Pulse v0.2 · Neon glass · Only scan what you own · Print-friendly</footer>
  </div>
<script>
(function () {{
  var input = document.getElementById('filter');
  var hint = document.getElementById('filter-hint');
  if (!input) return;
  function apply() {{
    var q = (input.value || '').trim().toLowerCase();
    var panels = document.querySelectorAll('.host-panel');
    var chips = document.querySelectorAll('.chip');
    var sums = document.querySelectorAll('.sum-row');
    var shown = 0;
    panels.forEach(function (p) {{
      var blob = (p.getAttribute('data-search') || p.innerText || '').toLowerCase();
      var ok = !q || blob.indexOf(q) !== -1;
      p.classList.toggle('hidden', !ok);
      if (ok) shown++;
      p.querySelectorAll('tr.port-row').forEach(function (tr) {{
        var rb = (tr.getAttribute('data-search') || tr.innerText || '').toLowerCase();
        tr.classList.toggle('hidden', !!(q && rb.indexOf(q) === -1));
      }});
    }});
    chips.forEach(function (c) {{
      var h = (c.getAttribute('data-host') || c.innerText || '').toLowerCase();
      c.classList.toggle('hidden', !!(q && h.indexOf(q) === -1));
    }});
    sums.forEach(function (tr) {{
      var rb = (tr.getAttribute('data-search') || tr.innerText || '').toLowerCase();
      tr.classList.toggle('hidden', !!(q && rb.indexOf(q) === -1));
    }});
    if (hint) {{
      hint.textContent = q ? (shown + ' host block(s)') : '';
    }}
  }}
  input.addEventListener('input', apply);
  document.querySelectorAll('a.chip').forEach(function (a) {{
    a.addEventListener('click', function (e) {{
      var href = a.getAttribute('href') || '';
      if (href.charAt(0) !== String.fromCharCode(35)) return;
      var id = href.slice(1);
      var el = document.getElementById(id);
      if (el) {{ e.preventDefault(); el.scrollIntoView({{ behavior: 'smooth', block: 'start' }}); }}
    }});
  }});
}})();
</script>
</body>
</html>"#,
        target_esc = target_esc,
        now = now,
        total = stats.total,
        open_n = stats.open_count().max(open.len()),
        hosts = host_count.max(if open.is_empty() { 0 } else { 1 }),
        closed = stats.closed_count(),
        elapsed_label = elapsed_label,
        rate_label = rate_label,
        toc = toc,
        hosts_html = hosts_html,
        os_section = os_section,
        cve_section = cve_section,
    );

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, html)?;
    Ok(())
}

fn port_rows(rows: &[&PortResult]) -> String {
    rows.iter()
        .map(|r| {
            let lat = r
                .latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "—".into());
            let banner = r
                .banner
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "—".into());
            let search = escape_attr(&format!(
                "{} {} {} {}",
                r.port,
                r.service,
                r.protocol.as_str(),
                r.banner.as_deref().unwrap_or("")
            ));
            format!(
                r#"<tr class="port-row" data-search="{search}">
  <td><span class="badge">OPEN</span></td>
  <td class="dim">{proto}</td>
  <td class="port">{port}</td>
  <td class="dim">{svc}</td>
  <td class="dim">{lat}</td>
  <td class="dim banner">{banner}</td>
</tr>"#,
                search = search,
                proto = r.protocol.as_str().to_uppercase(),
                port = r.port,
                svc = escape_html(&r.service),
                lat = lat,
                banner = banner,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn port_rows_with_host(rows: &[&PortResult]) -> String {
    rows.iter()
        .map(|r| {
            let lat = r
                .latency_ms
                .map(|ms| format!("{ms} ms"))
                .unwrap_or_else(|| "—".into());
            let banner = r
                .banner
                .as_deref()
                .map(escape_html)
                .unwrap_or_else(|| "—".into());
            let search = escape_attr(&format!(
                "{} {} {} {} {}",
                r.ip,
                r.port,
                r.service,
                r.protocol.as_str(),
                r.banner.as_deref().unwrap_or("")
            ));
            format!(
                r#"<tr class="port-row" data-search="{search}">
  <td><span class="badge">OPEN</span></td>
  <td class="dim">{proto}</td>
  <td>{ip}</td>
  <td class="port">{port}</td>
  <td class="dim">{svc}</td>
  <td class="dim">{lat}</td>
  <td class="dim banner">{banner}</td>
</tr>"#,
                search = search,
                proto = r.protocol.as_str().to_uppercase(),
                ip = escape_html(&r.ip),
                port = r.port,
                svc = escape_html(&r.service),
                lat = lat,
                banner = banner,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn host_search_blob(ip: &str, label: &str, rows: &[&PortResult]) -> String {
    let mut s = format!("{ip} {label} ");
    for r in rows {
        s.push_str(&format!(
            "{} {} {} {} ",
            r.port,
            r.service,
            r.protocol.as_str(),
            r.banner.as_deref().unwrap_or("")
        ));
    }
    s
}

fn build_os_section(os_guesses: &[OsGuess]) -> String {
    if os_guesses.is_empty() {
        return String::new();
    }
    let os_rows: String = os_guesses
        .iter()
        .map(|g| {
            let ttl = match (g.ttl, g.initial_ttl) {
                (Some(t), Some(i)) => format!("{t}→{i}"),
                (Some(t), None) => t.to_string(),
                _ => "—".into(),
            };
            let win = g
                .window
                .map(|w| w.to_string())
                .unwrap_or_else(|| "—".into());
            let matches = if g.matches.is_empty() {
                "—".into()
            } else {
                g.matches
                    .iter()
                    .map(|m| {
                        format!(
                            "<div class=\"hit\"><span class=\"pct\">{:.0}%</span> {}</div>",
                            m.accuracy * 100.0,
                            escape_html(&m.name)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("")
            };
            let href = format!("#host-{}", anchor_id(&g.ip));
            format!(
                r#"<tr>
  <td><a href="{href}">{ip}</a></td>
  <td class="strong">{detail}</td>
  <td class="port">{conf}%</td>
  <td class="dim">{src}</td>
  <td class="dim">{ttl}</td>
  <td class="dim">{win}</td>
  <td>{matches}</td>
</tr>"#,
                href = escape_attr(&href),
                ip = escape_html(&g.ip),
                detail = escape_html(&g.detail),
                conf = g.confidence,
                src = escape_html(&g.source),
                ttl = ttl,
                win = win,
                matches = matches,
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"
    <section class="panel glass">
      <h2>OS Fingerprint</h2>
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Match</th>
            <th>Conf</th>
            <th>Engine</th>
            <th>TTL</th>
            <th>Win</th>
            <th>Ranked</th>
          </tr>
        </thead>
        <tbody>
          {os_rows}
        </tbody>
      </table>
    </section>"#
    )
}

fn build_cve_section(cves: &[CveFinding]) -> String {
    if cves.is_empty() {
        return String::new();
    }
    let crit = cves.iter().filter(|c| c.severity == "CRITICAL").count();
    let high = cves.iter().filter(|c| c.severity == "HIGH").count();
    let cve_rows: String = cves
        .iter()
        .map(|c| {
            let score = c
                .cvss
                .map(|v| format!("{v:.1}"))
                .unwrap_or_else(|| "—".into());
            let sev_class = match c.severity.as_str() {
                "CRITICAL" => "sev-crit",
                "HIGH" => "sev-high",
                "MEDIUM" => "sev-med",
                _ => "dim",
            };
            let host_href = format!("#host-{}", anchor_id(&c.ip));
            format!(
                r#"<tr>
  <td class="port"><a href="{href}" target="_blank" rel="noopener">{cve}</a></td>
  <td class="port">{score}</td>
  <td class="{sev_class}">{sev}</td>
  <td><a href="{host_href}">{ip}</a>:{port}</td>
  <td class="dim">{svc}</td>
  <td class="strong">{title}</td>
  <td class="dim">{reason}</td>
</tr>"#,
                href = c.refs.first().map(|s| s.as_str()).unwrap_or("#"),
                cve = escape_html(&c.cve_id),
                score = score,
                sev_class = sev_class,
                sev = escape_html(&c.severity),
                host_href = escape_attr(&host_href),
                ip = escape_html(&c.ip),
                port = c.port,
                svc = escape_html(&c.service),
                title = escape_html(&c.title),
                reason = escape_html(&c.match_reason),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"
    <section class="panel glass">
      <h2>CVE / CVSS  ·  {crit} critical · {high} high · {total} total</h2>
      <table>
        <thead>
          <tr>
            <th>CVE</th>
            <th>CVSS</th>
            <th>Sev</th>
            <th>Host:Port</th>
            <th>Service</th>
            <th>Title</th>
            <th>Match</th>
          </tr>
        </thead>
        <tbody>
          {cve_rows}
        </tbody>
      </table>
    </section>"#,
        crit = crit,
        high = high,
        total = cves.len(),
        cve_rows = cve_rows,
    )
}

fn anchor_id(ip: &str) -> String {
    ip.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn escape_html(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '&' => "&amp;".into(),
            '<' => "&lt;".into(),
            '>' => "&gt;".into(),
            '"' => "&quot;".into(),
            '\'' => "&#39;".into(),
            c => c.to_string(),
        })
        .collect()
}

fn escape_attr(s: &str) -> String {
    escape_html(s).replace('\n', " ").replace('\r', " ")
}
