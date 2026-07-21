import type { PortAggregate, RunSummary, Vulnerability } from "@/lib/api";

/** Static-export friendly run detail URL (no dynamic [runId] segment). */
export function runDetailHref(runId: string): string {
  return `/runs/view?runId=${encodeURIComponent(runId)}`;
}

export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function normalizeSeverity(value: string | null | undefined): Severity {
  const key = (value || "unknown").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(key) ? (key as Severity) : "unknown";
}

/** Prefer a completed summary run; otherwise newest by started_at. */
export function pickLatestRun(runs: RunSummary[]): RunSummary | null {
  if (!runs.length) return null;
  const withSummary = runs.filter((run) => run.has_summary);
  const pool = withSummary.length ? withSummary : runs;
  return [...pool].sort((a, b) => {
    const aTs = a.started_at ? Date.parse(a.started_at) : 0;
    const bTs = b.started_at ? Date.parse(b.started_at) : 0;
    return bTs - aTs;
  })[0];
}

export function countSeverities(vulns: Vulnerability[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };
  for (const item of vulns) {
    counts[normalizeSeverity(item.severity)] += 1;
  }
  return counts;
}

export function recentRunTrend(runs: RunSummary[], limit = 15) {
  return [...runs]
    .filter((run) => run.started_at)
    .sort((a, b) => Date.parse(a.started_at!) - Date.parse(b.started_at!))
    .slice(-limit)
    .map((run) => ({
      date: run.started_at
        ? new Date(run.started_at).toLocaleDateString(undefined, {
            month: "short",
            day: "numeric",
          })
        : run.run_id.slice(0, 8),
      Hosts: run.alive_hosts ?? 0,
      Vulns: run.potential_vulnerabilities ?? 0,
      run_id: run.run_id,
    }));
}

export function topVulnerablePorts(ports: PortAggregate[], limit = 5) {
  return [...ports]
    .map((port) => ({
      name: port.protocol ? `${port.port}/${port.protocol}` : port.port,
      value: port.vulnerability_count || port.host_count || 0,
      vulnerability_count: port.vulnerability_count,
      host_count: port.host_count,
    }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
}

