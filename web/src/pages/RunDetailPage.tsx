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
  const maxSeverityCount = Math.max(1, ...SEVERITIES.map((key) => severityCounts[key]));

  const grouped = useMemo(() => {
    const groups: Record<Severity, Vulnerability[]> = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      unknown: [],
    };
    for (const item of vulns) {
      groups[normalizeSeverity(item.severity)].push(item);
    }
    return groups;
  }, [vulns]);

  const visibleSeverities = SEVERITIES.filter((key) =>
    activeSeverity === "all" ? severityCounts[key] > 0 || grouped[key].length > 0 : key === activeSeverity,
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
            {totalVulns} findings · click a row to filter · {vulns.length} loaded
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
            <span className="severity-scale-count">{totalVulns}</span>
          </button>
          {SEVERITIES.map((key) => {
            const count = severityCounts[key];
            const pct = Math.max(count > 0 ? 4 : 0, (count / maxSeverityCount) * 100);
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
          <p className="muted">Grouped findings with scrollable lists.</p>
        </div>

        {vulns.length === 0 ? <p className="muted">No vulnerability findings.</p> : null}

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
                      {items.map((item, idx) => (
                        <li key={`${key}-${item.host}-${item.port}-${item.cve}-${idx}`}>
                          <span className={`sev sev-${key}`}>
                            {item.cvss != null ? `CVSS ${item.cvss}` : key.toUpperCase()}
                          </span>
                          <span className="vuln-main">
                            <strong>
                              {item.cve || item.script_id || "finding"}
                            </strong>
                            <span className="muted">
                              {item.host}
                              {item.port ? `:${item.port}` : ""}
                              {item.script_id && item.cve ? ` · ${item.script_id}` : ""}
                            </span>
                          </span>
                        </li>
                      ))}
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
