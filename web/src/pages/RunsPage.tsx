import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchRuns, type RunSummary } from "../api";
import { useAuth } from "../auth";

export default function RunsPage() {
  const { token } = useAuth();
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!token) return;
      setLoading(true);
      try {
        const data = await fetchRuns(token);
        if (!cancelled) setRuns(data);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load runs");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, [token]);

  return (
    <section className="stack">
      <header className="section-head">
        <h1>Scan runs</h1>
        <p>Recent pipeline outputs from `scanner/output/runs`.</p>
      </header>
      {loading ? <p className="muted">Loading runs…</p> : null}
      {error ? <p className="form-error">{error}</p> : null}
      {!loading && !error && runs.length === 0 ? (
        <p className="muted">No runs found yet. Start a scan from Jobs (operator+) or the CLI.</p>
      ) : null}
      <div className="run-list">
        {runs.map((run) => (
          <Link key={run.run_id} to={`/runs/${encodeURIComponent(run.run_id)}`} className="run-row">
            <div>
              <strong>{run.run_id}</strong>
              <span className="muted">
                {run.profile || "unknown profile"}
                {run.started_at ? ` · ${new Date(run.started_at).toLocaleString()}` : ""}
              </span>
            </div>
            <div className="run-metrics">
              <span>{run.alive_hosts ?? "—"} hosts</span>
              <span>{run.open_host_port_pairs ?? "—"} ports</span>
              <span>{run.potential_vulnerabilities ?? "—"} vulns</span>
              {run.has_diff ? <span className="pill">diff</span> : null}
            </div>
          </Link>
        ))}
      </div>
    </section>
  );
}
