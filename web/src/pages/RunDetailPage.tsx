import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchRun, fetchVulns, type RunDetail, type Vulnerability } from "../api";
import { useAuth } from "../auth";

export default function RunDetailPage() {
  const { runId = "" } = useParams();
  const { token } = useAuth();
  const [detail, setDetail] = useState<RunDetail | null>(null);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!token || !runId) return;
      try {
        const [run, findings] = await Promise.all([
          fetchRun(token, runId),
          fetchVulns(token, runId),
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

  const summary = detail.summary || {};
  const sev = (summary.vulnerabilities_by_severity || {}) as Record<string, number>;
  const counts = (detail.diff?.counts || null) as Record<string, number> | null;

  return (
    <section className="stack">
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
          <strong>{String(summary.potential_vulnerabilities ?? "—")}</strong>
          <span>Vulnerabilities</span>
        </div>
        <div>
          <strong>{String(summary.os_detected_hosts ?? "—")}</strong>
          <span>OS detected</span>
        </div>
      </div>

      <div className="sev-row">
        {(["critical", "high", "medium", "low", "unknown"] as const).map((key) => (
          <span key={key} className={`sev sev-${key}`}>
            {key} {sev[key] ?? 0}
          </span>
        ))}
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

      <div className="panel">
        <h2>Top vulnerabilities</h2>
        {vulns.length === 0 ? <p className="muted">No vulnerability findings.</p> : null}
        <ul className="vuln-list">
          {vulns.slice(0, 40).map((item, idx) => (
            <li key={`${item.host}-${item.port}-${item.cve}-${idx}`}>
              <span className={`sev sev-${item.severity || "unknown"}`}>
                {(item.severity || "unknown").toUpperCase()}
              </span>
              <span>
                {item.host}
                {item.port ? `:${item.port}` : ""} {item.cve || item.script_id || "finding"}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
