import type {
  AliveHost,
  PortAggregate,
  RunSummary,
  Vulnerability,
} from "@/lib/api";

export const SEVERITIES = ["critical", "high", "medium", "low", "unknown"] as const;
export type Severity = (typeof SEVERITIES)[number];

export type AssetCriticality = "critical" | "high" | "medium" | "low" | "info";

export type AssetRow = {
  id: string;
  host: string;
  hostname: string | null;
  tenant: string;
  openPorts: number;
  criticality: AssetCriticality;
  lastScanned: string;
  vulnerabilityCount: number;
  diff?: { kind: "port" | "cve"; label: string };
};

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

export function normalizeSeverity(value: string | null | undefined): Severity {
  const key = (value || "unknown").toLowerCase();
  return (SEVERITIES as readonly string[]).includes(key) ? (key as Severity) : "unknown";
}

export function severityToCriticality(sev: Severity): AssetCriticality {
  return sev === "unknown" ? "info" : sev;
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

function maxHostSeverity(vulns: Vulnerability[]): Map<string, Severity> {
  const map = new Map<string, Severity>();
  for (const item of vulns) {
    if (!item.host) continue;
    const sev = normalizeSeverity(item.severity);
    const prev = map.get(item.host);
    if (!prev || SEVERITY_RANK[sev] < SEVERITY_RANK[prev]) {
      map.set(item.host, sev);
    }
  }
  return map;
}

function openPortCounts(ports: PortAggregate[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const port of ports) {
    for (const host of port.hosts || []) {
      map.set(host, (map.get(host) || 0) + 1);
    }
  }
  return map;
}

function hostDiffBadges(diff: Record<string, unknown> | null | undefined) {
  const badges = new Map<string, { kind: "port" | "cve"; label: string }>();
  if (!diff || typeof diff !== "object") return badges;

  const ports = (diff.ports as { added?: unknown } | undefined)?.added;
  if (Array.isArray(ports)) {
    for (const entry of ports) {
      if (typeof entry !== "string") continue;
      const host = entry.split(":")[0];
      if (!host || badges.has(host)) continue;
      badges.set(host, { kind: "port", label: "+1 new port" });
    }
  }

  const vulns = (diff.vulnerabilities as { added?: unknown } | undefined)?.added;
  if (Array.isArray(vulns)) {
    for (const entry of vulns) {
      const host =
        entry && typeof entry === "object" && "host" in entry
          ? String((entry as { host?: unknown }).host || "")
          : "";
      if (!host) continue;
      badges.set(host, { kind: "cve", label: "CVE detected" });
    }
  }

  return badges;
}

export function buildAssetRows(opts: {
  hosts: AliveHost[];
  ports: PortAggregate[];
  vulns: Vulnerability[];
  lastScanned: string | null;
  diff?: Record<string, unknown> | null;
  tenant?: string;
}): AssetRow[] {
  const openPorts = openPortCounts(opts.ports);
  const severities = maxHostSeverity(opts.vulns);
  const diffs = hostDiffBadges(opts.diff);
  const scanned = opts.lastScanned || new Date().toISOString();
  const tenant = opts.tenant || "—";

  return opts.hosts.map((host) => {
    const sev = severities.get(host.host) || "unknown";
    return {
      id: host.host,
      host: host.host,
      hostname: host.hostname,
      tenant,
      openPorts: openPorts.get(host.host) || 0,
      criticality: severityToCriticality(sev),
      lastScanned: scanned,
      vulnerabilityCount: host.vulnerability_count,
      diff: diffs.get(host.host),
    };
  });
}
