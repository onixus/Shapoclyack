import { KpiCard } from "@/components/kpi-card";
import { useT } from "@/lib/i18n";
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
  const t = useT();
  const aliveHosts = summary.alive_hosts as number | undefined;
  const openPairs = summary.open_host_port_pairs as number | undefined;
  const totalVulns = summary.potential_vulnerabilities as number | undefined;
  const unconfirmed = summary.unconfirmed_findings as number | undefined;
  const osDetected = summary.os_detected_hosts as number | undefined;

  // The headline count includes findings the scanner flagged as unconfirmed
  // (reachable-service exposures, unverified keyword CVE hits). Without this
  // hint a run whose findings are all keyword guesses is indistinguishable
  // from one with the same number of confirmed CVEs — the per-finding
  // "unconfirmed" badge only shows once the list is open.
  const vulnHint =
    typeof unconfirmed === "number" && unconfirmed > 0
      ? `${unconfirmed.toLocaleString()} unconfirmed`
      : undefined;

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <KpiCard
        label={t("kpi.aliveHosts")}
        value={aliveHosts ?? hosts.length}
        hint={hosts.some((h) => h.country || h.city) ? "GeoIP available" : undefined}
      />
      <KpiCard
        label={t("kpi.openPorts")}
        value={openPairs ?? ports.reduce((n, p) => n + p.host_count, 0)}
        hint={t("hint.distinct", { count: ports.length })}
      />
      <KpiCard label={t("kpi.vulnerabilities")} value={totalVulns ?? vulnCount} hint={vulnHint} />
      <KpiCard label={t("kpi.osDetected")} value={osDetected ?? "—"} />
    </div>
  );
}
