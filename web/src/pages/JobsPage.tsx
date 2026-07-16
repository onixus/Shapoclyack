import { useEffect, useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { fetchJobs, startScan, type JobInfo } from "../api";
import { useAuth } from "../auth";

export default function JobsPage() {
  const { token, canOperate } = useAuth();
  const [jobs, setJobs] = useState<JobInfo[]>([]);
  const [mode, setMode] = useState("balanced");
  const [delta, setDelta] = useState(false);
  const [skipNse, setSkipNse] = useState(false);
  const [notify, setNotify] = useState(false);
  const [exportDefectdojo, setExportDefectdojo] = useState(false);
  const [ranges, setRanges] = useState("");
  const [domains, setDomains] = useState("");
  const [ports, setPorts] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function refresh() {
    if (!token) return;
    const data = await fetchJobs(token);
    setJobs(data);
  }

  useEffect(() => {
    if (!token || !canOperate) return;
    let cancelled = false;
    async function load() {
      try {
        const data = await fetchJobs(token!);
        if (!cancelled) setJobs(data);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load jobs");
      }
    }
    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 4000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [token, canOperate]);

  if (!canOperate) return <Navigate to="/" replace />;

  async function onStart(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await startScan(token, {
        mode,
        delta,
        skip_nse: skipNse,
        notify,
        export_defectdojo: exportDefectdojo,
        ranges: ranges.trim() ? ranges : undefined,
        domains: domains.trim() ? domains : undefined,
        ports: ports.trim() ? ports : undefined,
      });
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="stack">
      <header className="section-head">
        <h1>Scan jobs</h1>
        <p>Set targets and launch pipeline runs through the API.</p>
      </header>

      <form className="panel job-form" onSubmit={onStart}>
        <label>
          Mode
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="safe">safe</option>
            <option value="balanced">balanced</option>
            <option value="fast">fast</option>
          </select>
        </label>

        <fieldset className="target-fields">
          <legend>Scan targets</legend>
          <p className="muted target-hint">
            Leave fields empty to use server default input files. If you fill ranges or domains,
            both host inputs are overridden for this job (empty side stays empty).
          </p>
          <label>
            Ranges (IP / CIDR)
            <textarea
              value={ranges}
              onChange={(e) => setRanges(e.target.value)}
              rows={4}
              placeholder={"10.0.0.0/24\n192.168.1.10"}
              spellCheck={false}
            />
          </label>
          <label>
            Domains (FQDN)
            <textarea
              value={domains}
              onChange={(e) => setDomains(e.target.value)}
              rows={3}
              placeholder={"scanme.nmap.org\nexample.com"}
              spellCheck={false}
            />
          </label>
          <label>
            Ports (optional TCP list)
            <textarea
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              rows={2}
              placeholder={"22,80,443\n8000-8010"}
              spellCheck={false}
            />
          </label>
        </fieldset>

        <label className="check">
          <input type="checkbox" checked={delta} onChange={(e) => setDelta(e.target.checked)} />
          Delta discovery
        </label>
        <label className="check">
          <input type="checkbox" checked={skipNse} onChange={(e) => setSkipNse(e.target.checked)} />
          Skip NSE
        </label>
        <label className="check">
          <input type="checkbox" checked={notify} onChange={(e) => setNotify(e.target.checked)} />
          Notify
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={exportDefectdojo}
            onChange={(e) => setExportDefectdojo(e.target.checked)}
          />
          Export to DefectDojo
        </label>
        <button type="submit" className="primary-btn" disabled={busy}>
          {busy ? "Starting…" : "Start scan"}
        </button>
      </form>

      {error ? <p className="form-error">{error}</p> : null}

      <div className="run-list">
        {jobs.map((job) => (
          <div key={job.job_id} className="run-row static">
            <div>
              <strong>{job.job_id}</strong>
              <span className="muted">
                {job.mode} · {job.status}
                {job.run_id ? ` · run ${job.run_id}` : ""}
                {job.target_counts
                  ? ` · targets r${job.target_counts.ranges ?? 0}/d${job.target_counts.domains ?? 0}` +
                    (job.target_counts.ports != null ? `/p${job.target_counts.ports}` : "")
                  : ""}
              </span>
            </div>
            <div className="run-metrics">
              <span>by {job.requested_by}</span>
              <span>{job.exit_code === null ? "—" : `exit ${job.exit_code}`}</span>
            </div>
            {job.error ? <p className="form-error">{job.error}</p> : null}
          </div>
        ))}
      </div>
    </section>
  );
}
