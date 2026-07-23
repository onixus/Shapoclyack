import type { PortAggregate, RunSummary, Vulnerability } from "@/lib/api";

/** Static-export friendly run detail URL (no dynamic [runId] segment). */
export function runDetailHref(runId: string): string {
  return `/runs/view?runId=${encodeURIComponent(runId)}`;
}

/** "City, Country" when available, falling back to the ISO code. */
export function formatLocation(item: {
  city?: string | null;
  country?: string | null;
  country_iso?: string | null;
}): string {
  const bits = [item.city, item.country].filter(Boolean);
  if (bits.length === 0 && item.country_iso) return item.country_iso;
  return bits.join(", ");
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

/** Highest-scoring critical/high findings for the exec dashboard "top risks"
 * table — sorted by CVSS v4 (falling back to v3), most severe first. */
export function topCriticalFindings(vulns: Vulnerability[], limit = 10) {
  return vulns
    .map((v) => ({
      host: v.host,
      port: v.port,
      cve: v.cve,
      script_id: v.script_id,
      score: v.cvss4 ?? v.cvss ?? 0,
      severity: normalizeSeverity(v.severity),
    }))
    .filter((v) => v.severity === "critical" || v.severity === "high")
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
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
