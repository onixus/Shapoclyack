import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { fetchAgents, type AgentInfo } from "../api";
import { useAuth } from "../auth";

export default function AgentsPage() {
  const { token, canOperate } = useAuth();
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token || !canOperate) return;
    let cancelled = false;
    async function load() {
      try {
        const data = await fetchAgents(token!);
        if (!cancelled) {
          setAgents(data);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load agents");
      }
    }
    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 5000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [token, canOperate]);

  if (!canOperate) return <Navigate to="/" replace />;

  return (
    <section className="stack">
      <header className="section-head">
        <h1>Remote agents</h1>
        <p>Workers that claim queued scan jobs when the API runs in agent execution mode.</p>
      </header>

      {error ? <p className="form-error">{error}</p> : null}

      {agents.length === 0 ? (
        <p className="muted">No agents registered yet. Start one with <code>python -m agent</code>.</p>
      ) : (
        <div className="run-list runs-grid">
          {agents.map((agent) => (
            <div key={agent.agent_id} className="run-row static">
              <div>
                <strong>{agent.hostname || agent.agent_id}</strong>
                <span className="muted">
                  {" "}
                  · {agent.online ? "online" : "offline"} · {agent.status}
                  {agent.version ? ` · v${agent.version}` : ""}
                  {agent.current_job_id ? ` · job ${agent.current_job_id}` : ""}
                </span>
              </div>
              <div className="run-metrics">
                <span>{agent.agent_id.slice(0, 12)}</span>
                <span>{agent.last_seen_at ? `seen ${agent.last_seen_at}` : "never seen"}</span>
              </div>
              {agent.detail ? <p className="muted">{agent.detail}</p> : null}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
