import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchRun, fetchVulns, type RunDetail, type Vulnerability } from "../api";
import { useAuth } from "../auth";

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
type Severity = (typeof SEVERITIES)[number];

function normalizeSeverity(value: string | null | undefined): Severity {
  const key = (value || "unknown").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(key) ? (key as Severity) : "unknown";
}

function formatLocation(item: Vulnerability): string {
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
  // Prefer live list counts when they are available (and may exceed summary).
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
  const [error, setError] = useState<string | null>(null);
  const [activeSeverity, setActiveSeverity] = useState<Severity | "all">("all");
  const [activeTarget, setActiveTarget] = useState<string>("all");
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
        const [run, findings] = await Promise.all([
          fetchRun(token, runId),
          fetchVulns(token, runId, 5000),
        ]);
        if (!cancelled) {
          setDetail(run);
          setVulns(findings);
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

  const targetOptions = useMemo(() => {
    const hosts = new Set<string>();
    for (const item of vulns) {
      if (item.host) hosts.add(item.host);
    }
    return Array.from(hosts).sort((a, b) => a.localeCompare(b));
  }, [vulns]);

  const filteredVulns = useMemo(() => {
    if (activeTarget === "all") return vulns;
    return vulns.filter((item) => item.host === activeTarget);
  }, [vulns, activeTarget]);

  const grouped = useMemo(() => {
    const groups: Record<Severity, Vulnerability[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      unknown: [],
    };
    for (const item of filteredVulns) {
      groups[normalizeSeverity(item.severity)].push(item);
    }
    return groups;
  }, [filteredVulns]);

  const filteredSeverityCounts = useMemo(() => {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    for (const item of filteredVulns) {
      counts[normalizeSeverity(item.severity)] += 1;
    }
    return counts;
  }, [filteredVulns]);

  const visibleSeverities = SEVERITIES.filter((key) =>
    activeSeverity === "all"
      ? filteredSeverityCounts[key] > 0 || grouped[key].length > 0
      : key === activeSeverity,
  );

  function toggleGroup(key: Severity) {
    setOpenGroups((prev) => ({ ...prev, [key]: !prev[key] }));
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
  const displayTotal = activeTarget === "all" ? totalVulns : filteredVulns.length;
  const displaySeverityCounts = activeTarget === "all" ? severityCounts : filteredSeverityCounts;
  const displayMaxSeverity = Math.max(1, ...SEVERITIES.map((key) => displaySeverityCounts[key]));

  return (
    <section className="stack run-detail">
      <Link to="/" className="back-link">
        ← Runs
      </Link>
      <header className="section-head">
        <h1>{detail.run_id}</h1>
        <p>Pipeline artifacts and vulnerability findings for this run.</p>
      </header>

      <div className="metric-strip">
        <div>
          <strong>{String(summary.alive_hosts ?? "—")}</strong>
          <span>Alive hosts</span>
        </div>
        <div>
          <strong>{String(summary.open_host_port_pairs ?? "—")}</strong>
          <span>Open ports</span>
        </div>
        <div>
          <strong>{String(totalVulns || "—")}</strong>
          <span>Vulnerabilities</span>
        </div>
        <div>
          <strong>{String(summary.os_detected_hosts ?? "—")}</strong>
          <span>OS detected</span>
        </div>
      </div>

      <div className="panel severity-dashboard">
        <div className="severity-dashboard-head">
          <h2>Severity dashboard</h2>
          <p className="muted">
            {displayTotal} findings · click a row to filter · {filteredVulns.length} shown
            {activeTarget !== "all" ? ` for ${activeTarget}` : ""}
            {totalVulns > vulns.length ? ` of ${totalVulns}` : ""}
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
          <p className="muted">Grouped findings with GeoIP location and target filter.</p>
        </div>

        <div className="vuln-filters">
          <label className="vuln-filter">
            <span>Target</span>
            <select
              value={activeTarget}
              onChange={(event) => setActiveTarget(event.target.value)}
              aria-label="Filter vulnerabilities by target"
            >
              <option value="all">All targets ({targetOptions.length})</option>
              {targetOptions.map((host) => (
                <option key={host} value={host}>
                  {host}
                </option>
              ))}
            </select>
          </label>
          {activeTarget !== "all" ? (
            <button type="button" className="ghost-btn" onClick={() => setActiveTarget("all")}>
              Clear target filter
            </button>
          ) : null}
        </div>

        {filteredVulns.length === 0 ? <p className="muted">No vulnerability findings.</p> : null}

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
                              {location ? (
                                <span className="vuln-geo" title={item.country_iso || undefined}>
                                  {location}
                                </span>
                              ) : null}
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
