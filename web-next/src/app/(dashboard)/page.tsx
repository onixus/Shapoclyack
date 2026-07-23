"use client";

import Link from "next/link";
import { useMemo } from "react";
import { AreaChart, BarChart, Card, DonutChart, Title } from "@tremor/react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
import { useAssets } from "@/hooks/use-assets";
import { useRunPorts, useRuns, useRunVulns } from "@/hooks/use-runs";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { ASSET_CRITICALITY, ASSET_STATUS, SEVERITY_STATUS } from "@/lib/config/statuses";
import {
  countSeverities,
  pickLatestRun,
  recentRunTrend,
  runDetailHref,
  SEVERITIES,
  topCriticalFindings,
  topVulnerablePorts,
} from "@/lib/run-data";

const SEVERITY_DONUT_COLORS = ["rose", "orange", "amber", "sky", "slate"];

export default function DashboardPage() {
  const runsQuery = useRuns(POLL_INTERVALS.dashboard);
  const assetsQuery = useAssets({ status: "" });

  const latest = useMemo(() => pickLatestRun(runsQuery.data || []), [runsQuery.data]);
  const runId = latest?.run_id ?? "";

  const vulnsQuery = useRunVulns(runId);
  const portsQuery = useRunPorts(runId);

  const vulns = useMemo(() => vulnsQuery.data || [], [vulnsQuery.data]);
  const severityCounts = useMemo(() => countSeverities(vulns), [vulns]);
  const trend = useMemo(() => recentRunTrend(runsQuery.data || [], 15), [runsQuery.data]);
  const topPorts = useMemo(() => topVulnerablePorts(portsQuery.data || [], 5), [portsQuery.data]);
  const topRisks = useMemo(() => topCriticalFindings(vulns, 10), [vulns]);

  const severityData = useMemo(
    () => SEVERITIES.map((sev) => ({ name: sev, value: severityCounts[sev] })),
    [severityCounts],
  );

  const assets = useMemo(() => assetsQuery.data || [], [assetsQuery.data]);
  const criticalityData = useMemo(() => {
    const buckets = new Map<string, number>();
    for (const asset of assets) {
      const key =
        asset.asset_criticality == null
          ? "unset"
          : `${asset.asset_criticality} · ${ASSET_CRITICALITY[asset.asset_criticality]?.label ?? ""}`.trim();
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
    }
    return Array.from(buckets.entries()).map(([name, Assets]) => ({ name, Assets }));
  }, [assets]);
  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = { active: 0, stale: 0, decommissioned: 0 };
    for (const asset of assets) counts[asset.status] = (counts[asset.status] ?? 0) + 1;
    return counts;
  }, [assets]);

  const isLoading =
    runsQuery.isLoading || (Boolean(runId) && (vulnsQuery.isLoading || portsQuery.isLoading));
  const error =
    runsQuery.error || vulnsQuery.error || portsQuery.error
      ? ((runsQuery.error || vulnsQuery.error || portsQuery.error) as Error)
      : null;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Dashboard</h1>
          <p className="text-sm text-muted-foreground">
            Fleet exposure from the latest scan run
            {latest ? (
              <>
                {" "}
                (
                <Link
                  href={runDetailHref(latest.run_id)}
                  className="text-sky-700 underline-offset-2 hover:underline"
                >
                  <code className="text-xs">{latest.run_id}</code>
                </Link>
                )
              </>
            ) : null}
            .
          </p>
        </div>
        {runsQuery.isFetching ? <p className="text-xs text-muted-foreground">Refreshing…</p> : null}
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      ) : null}

      {!isLoading && !latest ? (
        <p className="rounded-md border bg-white px-3 py-6 text-center text-sm text-muted-foreground">
          No scan runs yet. Start a job from Jobs, then return here for KPIs.
        </p>
      ) : null}

      <div className="grid gap-4 md:grid-cols-4">
        <KpiCard
          label="Alive hosts (latest)"
          value={isLoading ? "…" : (latest?.alive_hosts ?? 0)}
          decorationColor="blue"
        />
        <KpiCard
          label="Vulnerable hosts"
          value={isLoading ? "…" : (latest?.vulnerable_hosts ?? 0)}
          decorationColor="amber"
        />
        <KpiCard
          label="Critical findings"
          value={isLoading ? "…" : severityCounts.critical}
          decorationColor={SEVERITY_STATUS.critical.tremorColor}
        />
        <KpiCard
          label="High findings"
          value={isLoading ? "…" : severityCounts.high}
          decorationColor={SEVERITY_STATUS.high.tremorColor}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <Title>Exposure trend (recent runs)</Title>
          {trend.length === 0 ? (
            <p className="mt-6 text-sm text-muted-foreground">No run history to chart.</p>
          ) : (
            <AreaChart
              className="mt-4 h-72"
              data={trend}
              index="date"
              categories={["Hosts", "Vulns"]}
              colors={["blue", "rose"]}
              showLegend
              showAnimation={false}
            />
          )}
        </Card>
        <Card className="xl:col-span-2">
          <Title>Findings by severity (latest)</Title>
          {vulns.length === 0 ? (
            <p className="mt-6 text-sm text-muted-foreground">No findings in the latest run.</p>
          ) : (
            <>
              <DonutChart
                className="mt-6 h-52"
                data={severityData}
                category="value"
                index="name"
                colors={SEVERITY_DONUT_COLORS}
                showAnimation={false}
              />
              <ul className="mt-4 space-y-1 text-sm text-slate-600">
                {severityData.map((row) => (
                  <li
                    key={row.name}
                    className="flex items-center justify-between border-b border-slate-100 py-1"
                  >
                    <StatusBadge value={row.name} map={SEVERITY_STATUS} />
                    <span className="font-medium tabular-nums">{row.value.toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <Title>Top critical &amp; high findings (latest)</Title>
          {topRisks.length === 0 ? (
            <p className="mt-6 text-sm text-muted-foreground">
              No critical or high findings in the latest run.
            </p>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="py-2 text-left">CVE / Script</th>
                    <th className="py-2 text-left">Host</th>
                    <th className="py-2 text-left">Port</th>
                    <th className="py-2 text-left">CVSS</th>
                    <th className="py-2 text-left">Severity</th>
                  </tr>
                </thead>
                <tbody>
                  {topRisks.map((risk, idx) => (
                    <tr
                      key={`${risk.cve || risk.script_id}-${risk.host}-${risk.port}-${idx}`}
                      className="border-t border-slate-100"
                    >
                      <td className="py-2 font-mono text-xs">{risk.cve || risk.script_id || "—"}</td>
                      <td className="py-2 font-mono text-xs">{risk.host || "—"}</td>
                      <td className="py-2 tabular-nums">{risk.port || "—"}</td>
                      <td className="py-2 tabular-nums">{risk.score || "—"}</td>
                      <td className="py-2">
                        <StatusBadge value={risk.severity} map={SEVERITY_STATUS} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
        <Card className="xl:col-span-2">
          <Title>Asset posture</Title>
          {assets.length === 0 ? (
            <p className="mt-6 text-sm text-muted-foreground">
              No assets tracked yet{assetsQuery.isFetching ? " …" : ""}.
            </p>
          ) : (
            <>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
                <span className="text-muted-foreground">{assets.length} assets ·</span>
                {(["active", "stale", "decommissioned"] as const).map((s) =>
                  statusCounts[s] ? (
                    <span key={s} className="flex items-center gap-1">
                      <StatusBadge value={s} map={ASSET_STATUS} />
                      <span className="tabular-nums">{statusCounts[s]}</span>
                    </span>
                  ) : null,
                )}
              </div>
              <BarChart
                className="mt-4 h-56"
                data={criticalityData}
                index="name"
                categories={["Assets"]}
                colors={["indigo"]}
                showLegend={false}
                showAnimation={false}
                yAxisWidth={40}
              />
              <p className="mt-2 text-xs text-muted-foreground">Assets by business criticality.</p>
            </>
          )}
        </Card>
      </div>

      <Card>
        <Title>Top vulnerable ports (latest)</Title>
        {topPorts.length === 0 ? (
          <p className="mt-6 text-sm text-muted-foreground">No open ports in the latest run.</p>
        ) : (
          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <DonutChart
              className="h-52"
              data={topPorts}
              category="value"
              index="name"
              colors={["blue", "cyan", "indigo", "violet", "slate"]}
              showAnimation={false}
            />
            <ul className="space-y-2 text-sm text-slate-600">
              {topPorts.map((port) => (
                <li key={port.name} className="flex justify-between border-b border-slate-100 py-1">
                  <span>{port.name}</span>
                  <span className="font-medium tabular-nums">{port.value.toLocaleString()}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
    </div>
  );
}
