import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  fetchHosts,
  fetchPorts,
  fetchRun,
  fetchVulns,
  type AliveHost,
  type PortAggregate,
  type RunDetail,
  type Vulnerability,
} from "../api";
import { useAuth } from "../auth";

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
type Severity = (typeof SEVERITIES)[number];
type FocusPanel = "none" | "hosts" | "ports";

function normalizeSeverity(value: string | null | undefined): Severity {
  const key = (value || "unknown").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(key) ? (key as Severity) : "unknown";
}

function formatLocation(item: { city?: string | null; country?: string | null; country_iso?: string | null }): string {
  const bits = [item.city, item.country].filter(Boolean);
  if (bits.length === 0 && item.country_iso) {
    return item.country_iso;
  }
  return bits.join(", ");
}

function scoreLabel(item: Vulnerability, severity: Severity): string {
  if (item.cvss4 != null) {
    return `CVSS4 ${item.cvss4}`;
  }
  if (item.cvss != null) {
    return `CVSS ${item.cvss}`;
  }
  return severity.toUpperCase();
}

function countBySeverity(
  vulns: Vulnerability[],
  summarySev: Record<string, number>,
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  for (const key of SEVERITIES) {
    const fromSummary = summarySev[key];
    if (typeof fromSummary === "number") {
      counts[key] = fromSummary;
    }
  }
  if (vulns.length > 0) {
    const live: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const item of vulns) {
      live[normalizeSeverity(item.severity)] += 1;
    }
    return live;
  }
  return counts;
}

export default function RunDetailPage() {
  const { runId = "" } = useParams();
  const { token } = useAuth();
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [hosts, setHosts] = useState<AliveHost[]>([]);
  const [ports, setPorts] = useState<PortAggregate[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [activeSeverity, setActiveSeverity] = useState<Severity | "all">("all");
  const [activeHost, setActiveHost] = useState<string | null>(null);
  const [activePort, setActivePort] = useState<string | null>(null);
  const [focusPanel, setFocusPanel] = useState<FocusPanel>("none");
  const [openGroups, setOpenGroups] = useState<Record<Severity, boolean>>({
    critical: true,
    high: true,
    medium: true,
    low: false,
    unknown: false,
  });

  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!token || !runId) return;
      try {
        const [run, findings, hostRows, portRows] = await Promise.all([
          fetchRun(token, runId),
          fetchVulns(token, runId, 5000),
          fetchHosts(token, runId),
          fetchPorts(token, runId),
        ]);
        if (!cancelled) {
          setDetail(run);
          setVulns(findings);
          setHosts(hostRows);
          setPorts(portRows);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load run");
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [token, runId]);

  const summary = detail?.summary || {};
  const summarySev = (summary.vulnerabilities_by_severity || {}) as Record<string, number>;
  const severityCounts = useMemo(
    () => countBySeverity(vulns, summarySev),
    [vulns, summarySev],
  );
  const totalVulns =
    Number(summary.potential_vulnerabilities ?? 0) ||
    SEVERITIES.reduce((sum, key) => sum + severityCounts[key], 0);

  const geoByHost = useMemo(() => {
    const map = new Map<string, AliveHost>();
    for (const host of hosts) {
      map.set(host.host, host);
    }
    return map;
  }, [hosts]);

  const filteredVulns = useMemo(() => {
    return vulns.filter((item) => {
      if (activeHost && item.host !== activeHost) return false;
      if (activePort && item.port !== activePort) return false;
      return true;
    });
  }, [vulns, activeHost, activePort]);

  const enrichedVulns = useMemo(() => {
    return filteredVulns.map((item) => {
      if (item.country || item.city || item.country_iso || !item.host) return item;
      const geo = geoByHost.get(item.host);
      if (!geo) return item;
      return {
        ...item,
        country: geo.country,
        city: geo.city,
        country_iso: geo.country_iso,
      };
    });
  }, [filteredVulns, geoByHost]);

  const grouped = useMemo(() => {
    const groups: Record<Severity, Vulnerability[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      unknown: [],
    };
    for (const item of enrichedVulns) {
      groups[normalizeSeverity(item.severity)].push(item);
    }
    return groups;
  }, [enrichedVulns]);

  const filteredSeverityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const item of enrichedVulns) {
      counts[normalizeSeverity(item.severity)] += 1;
    }
    return counts;
  }, [enrichedVulns]);

  const filtersActive = Boolean(activeHost || activePort);
  const displayTotal = filtersActive ? enrichedVulns.length : totalVulns;
  const displaySeverityCounts = filtersActive ? filteredSeverityCounts : severityCounts;
  const displayMaxSeverity = Math.max(1, ...SEVERITIES.map((key) => displaySeverityCounts[key]));

  const visibleSeverities = SEVERITIES.filter((key) =>
    activeSeverity === "all"
      ? displaySeverityCounts[key] > 0 || grouped[key].length > 0
      : key === activeSeverity,
  );

  const hostsWithGeo = hosts.filter((h) => h.country || h.city || h.country_iso).length;

  function toggleGroup(key: Severity) {
    setOpenGroups((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  function toggleHostsPanel() {
    setFocusPanel((prev) => (prev === "hosts" ? "none" : "hosts"));
  }

  function togglePortsPanel() {
    setFocusPanel((prev) => (prev === "ports" ? "none" : "ports"));
  }

  function selectHost(host: string) {
    setActiveHost((prev) => (prev === host ? null : host));
    setActivePort(null);
    setFocusPanel("hosts");
  }

  function selectPort(port: string) {
    setActivePort((prev) => (prev === port ? null : port));
    setActiveHost(null);
    setFocusPanel("ports");
  }

  function clearFilters() {
    setActiveHost(null);
    setActivePort(null);
  }

  if (error) {
    return (
      <section className="stack">
        <Link to="/" className="back-link">
          ← Runs
        </Link>
        <p className="form-error">{error}</p>
      </section>
    );
  }

  if (!detail) {
    return <p className="muted">Loading run…</p>;
  }

  const counts = (detail.diff?.counts || null) as Record<string, number> | null;

  return (
    <section className="stack run-detail">
      <Link to="/" className="back-link">
        ← Runs
      </Link>
      <header className="section-head">
        <h1>{detail.run_id}</h1>
        <p>Click Alive hosts or Open ports to explore targets, GeoIP, and port aggregation.</p>
      </header>

      <div className="metric-strip">
        <button
          type="button"
          className={`metric-btn ${focusPanel === "hosts" ? "active" : ""}`}
          onClick={toggleHostsPanel}
          aria-pressed={focusPanel === "hosts"}
        >
          <strong>{String(summary.alive_hosts ?? hosts.length ?? "—")}</strong>
          <span>Alive hosts</span>
          <span className="metric-hint">
            {hostsWithGeo > 0 ? `${hostsWithGeo} with GeoIP` : "show targets"}
          </span>
        </button>
        <button
          type="button"
          className={`metric-btn ${focusPanel === "ports" ? "active" : ""}`}
          onClick={togglePortsPanel}
          aria-pressed={focusPanel === "ports"}
        >
          <strong>
            {String(
              summary.open_host_port_pairs ??
                (ports.reduce((n, p) => n + p.host_count, 0) || "—"),
            )}
          </strong>
          <span>Open ports</span>
          <span className="metric-hint">{ports.length} distinct ports</span>
        </button>
        <div>
          <strong>{String(totalVulns || "—")}</strong>
          <span>Vulnerabilities</span>
        </div>
        <div>
          <strong>{String(summary.os_detected_hosts ?? "—")}</strong>
          <span>OS detected</span>
        </div>
      </div>

      {focusPanel === "hosts" ? (
        <div className="panel explore-panel">
          <div className="vulns-panel-head">
            <h2>Alive hosts</h2>
            <p className="muted">
              {hosts.length} targets · click a host to filter findings
              {activeHost ? ` · selected ${activeHost}` : ""}
            </p>
          </div>
          {hosts.length === 0 ? (
            <p className="muted">No alive hosts recorded for this run.</p>
          ) : (
            <div className="explore-scroll">
              <ul className="explore-list">
                {hosts.map((host) => {
                  const location = formatLocation(host);
                  return (
                    <li key={host.host}>
                      <button
                        type="button"
                        className={`explore-row ${activeHost === host.host ? "active" : ""}`}
                        onClick={() => selectHost(host.host)}
                      >
                        <span className="explore-main">
                          <strong>{host.host}</strong>
                          <span className="muted">
                            {host.hostname || (host.names[0] ?? "no hostname")}
                            {host.vulnerability_count
                              ? ` · ${host.vulnerability_count} vulns`
                              : " · no vulns"}
                          </span>
                        </span>
                        <span className={`vuln-geo ${location ? "" : "missing"}`}>
                          {location || "No GeoIP"}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}
        </div>
      ) : null}

      {focusPanel === "ports" ? (
        <div className="panel explore-panel">
          <div className="vulns-panel-head">
            <h2>Open ports (aggregated)</h2>
            <p className="muted">
              {ports.length} ports · click a port to filter findings
              {activePort ? ` · selected :${activePort}` : ""}
            </p>
          </div>
          {ports.length === 0 ? (
            <p className="muted">No open ports recorded for this run.</p>
          ) : (
            <div className="explore-scroll">
              <ul className="explore-list">
                {ports.map((row) => (
                  <li key={`${row.port}/${row.protocol || "tcp"}`}>
                    <button
                      type="button"
                      className={`explore-row ${activePort === row.port ? "active" : ""}`}
                      onClick={() => selectPort(row.port)}
                    >
                      <span className="explore-main">
                        <strong>
                          :{row.port}
                          {row.protocol ? `/${row.protocol}` : ""}
                        </strong>
                        <span className="muted">
                          {row.host_count} hosts
                          {row.vulnerability_count ? ` · ${row.vulnerability_count} vulns` : ""}
                        </span>
                      </span>
                      <span className="metric-tag">{row.host_count}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : null}

      <div className="panel severity-dashboard">
        <div className="severity-dashboard-head">
          <h2>Severity dashboard</h2>
          <p className="muted">
            {displayTotal} findings · click a row to filter severity
            {activeHost ? ` · host ${activeHost}` : ""}
            {activePort ? ` · port ${activePort}` : ""}
          </p>
        </div>
        <div className="severity-scale">
          <button
            type="button"
            className={`severity-scale-row ${activeSeverity === "all" ? "active" : ""}`}
            onClick={() => setActiveSeverity("all")}
          >
            <span className="severity-scale-label">All</span>
            <span className="severity-scale-track">
              <span className="severity-scale-fill sev-fill-all" style={{ width: "100%" }} />
            </span>
            <span className="severity-scale-count">{displayTotal}</span>
          </button>
          {SEVERITIES.map((key) => {
            const count = displaySeverityCounts[key];
            const pct = Math.max(count > 0 ? 4 : 0, (count / displayMaxSeverity) * 100);
            return (
              <button
                key={key}
                type="button"
                className={`severity-scale-row ${activeSeverity === key ? "active" : ""}`}
                onClick={() => setActiveSeverity((prev) => (prev === key ? "all" : key))}
              >
                <span className={`severity-scale-label sev sev-${key}`}>{key}</span>
                <span className="severity-scale-track" aria-hidden>
                  <span
                    className={`severity-scale-fill sev-fill-${key}`}
                    style={{ width: `${pct}%` }}
                  />
                </span>
                <span className="severity-scale-count">{count}</span>
              </button>
            );
          })}
        </div>
      </div>

      {counts ? (
        <div className="panel">
          <h2>Diff vs previous</h2>
          <p className="muted">
            hosts +{counts.hosts_added ?? 0}/-{counts.hosts_removed ?? 0} · ports +
            {counts.ports_added ?? 0}/-{counts.ports_removed ?? 0} · vulns +
            {counts.vulns_added ?? 0}/-{counts.vulns_removed ?? 0}
          </p>
        </div>
      ) : null}

      <div className="panel vulns-panel">
        <div className="vulns-panel-head">
          <h2>Vulnerabilities by severity</h2>
          <p className="muted">
            GeoIP shown per finding
            {filtersActive ? " · filtered view" : ""}.
          </p>
        </div>

        {filtersActive ? (
          <div className="active-filters">
            {activeHost ? <span className="pill">host {activeHost}</span> : null}
            {activePort ? <span className="pill">port {activePort}</span> : null}
            <button type="button" className="ghost-btn" onClick={clearFilters}>
              Clear filters
            </button>
          </div>
        ) : null}

        {enrichedVulns.length === 0 ? <p className="muted">No vulnerability findings.</p> : null}

        <div className="vuln-groups">
          {visibleSeverities.map((key) => {
            const items = grouped[key];
            const open = openGroups[key];
            return (
              <section key={key} className={`vuln-group vuln-group-${key}`}>
                <button
                  type="button"
                  className="vuln-group-toggle"
                  aria-expanded={open}
                  onClick={() => toggleGroup(key)}
                >
                  <span className={`sev sev-${key}`}>{key}</span>
                  <strong>{items.length}</strong>
                  <span className="muted">{open ? "Hide" : "Show"}</span>
                </button>
                {open ? (
                  <div className="vuln-scroll">
                    <ul className="vuln-list">
                      {items.map((item, idx) => {
                        const location = formatLocation(item);
                        return (
                          <li key={`${key}-${item.host}-${item.port}-${item.cve}-${idx}`}>
                            <span className={`sev sev-${key}`}>{scoreLabel(item, key)}</span>
                            <span className="vuln-main">
                              <strong>{item.cve || item.script_id || "finding"}</strong>
                              <span className="muted">
                                {item.host}
                                {item.port ? `:${item.port}` : ""}
                                {item.script_id && item.cve ? ` · ${item.script_id}` : ""}
                              </span>
                              <span className={`vuln-geo ${location ? "" : "missing"}`}>
                                {location || "No GeoIP"}
                              </span>
                            </span>
                          </li>
                        );
                      })}
                      {items.length === 0 ? (
                        <li className="muted">No findings in this severity.</li>
                      ) : null}
                    </ul>
                  </div>
                ) : null}
              </section>
            );
          })}
        </div>
      </div>
    </section>
  );
}
