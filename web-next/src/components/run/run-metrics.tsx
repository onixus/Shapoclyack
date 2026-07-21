import { KpiCard } from "@/components/kpi-card";
import type { AliveHost, PortAggregate } from "@/lib/api";

export function RunMetrics({
  summary,
  hosts,
  ports,
  vulnCount,
}: {
  summary: Record<string, unknown>;
  hosts: AliveHost[];
  ports: PortAggregate[];
  vulnCount: number;
}) {
  const aliveHosts = summary.alive_hosts as number | undefined;
  const openPairs = summary.open_host_port_pairs as number | undefined;
  const totalVulns = summary.potential_vulnerabilities as number | undefined;
  const osDetected = summary.os_detected_hosts as number | undefined;

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <KpiCard
        label="Alive hosts"
        value={aliveHosts ?? hosts.length}
        hint={hosts.some((h) => h.country || h.city) ? "GeoIP available" : undefined}
      />
      <KpiCard
        label="Open ports"
        value={openPairs ?? ports.reduce((n, p) => n + p.host_count, 0)}
        hint={`${ports.length} distinct`}
      />
      <KpiCard label="Vulnerabilities" value={totalVulns ?? vulnCount} />
      <KpiCard label="OS detected" value={osDetected ?? "—"} />
    </div>
  );
}
