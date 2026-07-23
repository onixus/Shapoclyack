"use client";

import Link from "next/link";
import { useMemo } from "react";
import { AreaChart, BarChart, Card, DonutChart, Title } from "@tremor/react";
import { ShieldAlert, Play, RefreshCw, Layers, ArrowUpRight } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
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
          : `L${asset.asset_criticality} · ${ASSET_CRITICALITY[asset.asset_criticality]?.label ?? ""}`.trim();
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
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Security Exposure Dashboard</h1>
            <span className="rounded-full bg-sky-500/10 px-2.5 py-0.5 text-xs font-semibold text-sky-400 border border-sky-500/20">
              SOC Command
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Fleet risk posture from active scan run:{" "}
            {latest ? (
              <Link
                href={runDetailHref(latest.run_id)}
                className="inline-flex items-center gap-1 font-mono font-semibold text-sky-400 hover:text-sky-300 underline underline-offset-2"
              >
                <span>{latest.run_id}</span>
                <ArrowUpRight className="h-3 w-3" />
              </Link>
            ) : (
              <span className="text-slate-500">No active runs</span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={() => runsQuery.refetch()}
            className="gap-2 border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${runsQuery.isFetching ? "animate-spin text-sky-400" : ""}`} />
            Refresh Data
          </Button>
          <Link href="/jobs">
            <Button size="sm" className="gap-2 bg-sky-600 text-white hover:bg-sky-500 shadow-lg shadow-sky-950">
              <Play className="h-3.5 w-3.5 fill-current" />
              Launch Scan
            </Button>
          </Link>
        </div>
      </div>

      {error ? (
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      ) : null}

      {!isLoading && !latest ? (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-8 text-center backdrop-blur">
          <ShieldAlert className="mx-auto h-10 w-10 text-slate-500" />
          <h3 className="mt-3 text-sm font-semibold text-slate-200">No scan runs recorded yet</h3>
          <p className="mt-1 text-xs text-slate-400">Launch a new discovery or vulnerability scan from the Jobs section to populate telemetry.</p>
          <Link href="/jobs" className="mt-4 inline-block">
            <Button size="sm" className="bg-sky-600 hover:bg-sky-500">Start First Scan Job</Button>
          </Link>
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Alive Hosts (Latest)"
          value={isLoading ? "…" : (latest?.alive_hosts ?? 0)}
          decorationColor="sky"
        />
        <KpiCard
          label="Vulnerable Hosts"
          value={isLoading ? "…" : (latest?.vulnerable_hosts ?? 0)}
          decorationColor="amber"
        />
        <KpiCard
          label="Critical Vulnerabilities"
          value={isLoading ? "…" : severityCounts.critical}
          decorationColor="rose"
        />
        <KpiCard
          label="High Vulnerabilities"
          value={isLoading ? "…" : severityCounts.high}
          decorationColor="orange"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
          <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">Exposure Trend (Historical Runs)</Title>
          {trend.length === 0 ? (
            <p className="mt-6 text-xs text-slate-400">No run history telemetry to render graph.</p>
          ) : (
            <AreaChart
              className="mt-4 h-72"
              data={trend}
              index="date"
              categories={["Hosts", "Vulns"]}
              colors={["cyan", "rose"]}
              showLegend
              showAnimation={false}
            />
          )}
        </Card>

        <Card className="xl:col-span-2 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
          <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">Findings by Severity</Title>
          {vulns.length === 0 ? (
            <p className="mt-6 text-xs text-slate-400">No findings detected in the latest run.</p>
          ) : (
            <>
              <DonutChart
                className="mt-4 h-52"
                data={severityData}
                category="value"
                index="name"
                colors={SEVERITY_DONUT_COLORS}
                showAnimation={false}
              />
              <ul className="mt-4 space-y-1.5 text-xs text-slate-300">
                {severityData.map((row) => (
                  <li
                    key={row.name}
                    className="flex items-center justify-between border-b border-slate-800/60 py-1.5"
                  >
                    <StatusBadge value={row.name} map={SEVERITY_STATUS} />
                    <span className="font-semibold tabular-nums text-slate-100">{row.value.toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between">
            <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">Top Critical & High Findings</Title>
            <span className="text-xs text-slate-400">Sorted by CVSS Score</span>
          </div>
          {topRisks.length === 0 ? (
            <p className="mt-6 text-xs text-slate-400">No critical or high severity vulnerabilities found in latest run.</p>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-bold uppercase tracking-wider">
                  <tr>
                    <th className="py-2.5 px-2">CVE / Script</th>
                    <th className="py-2.5 px-2">Host</th>
                    <th className="py-2.5 px-2">Port</th>
                    <th className="py-2.5 px-2">CVSS</th>
                    <th className="py-2.5 px-2">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {topRisks.map((risk, idx) => (
                    <tr
                      key={`${risk.cve || risk.script_id}-${risk.host}-${risk.port}-${idx}`}
                      className="hover:bg-slate-800/40 transition-colors"
                    >
                      <td className="py-2.5 px-2 font-mono font-semibold text-sky-400">{risk.cve || risk.script_id || "—"}</td>
                      <td className="py-2.5 px-2 font-mono text-slate-200">{risk.host || "—"}</td>
                      <td className="py-2.5 px-2 tabular-nums text-slate-300">{risk.port || "—"}</td>
                      <td className="py-2.5 px-2">
                        <span className="rounded bg-rose-500/20 px-1.5 py-0.5 font-bold tabular-nums text-rose-300 border border-rose-500/30">
                          {risk.score ?? "—"}
                        </span>
                      </td>
                      <td className="py-2.5 px-2">
                        <StatusBadge value={risk.severity} map={SEVERITY_STATUS} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card className="xl:col-span-2 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
          <div className="flex items-center justify-between">
            <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">Asset Criticality Posture</Title>
            <Link href="/assets" className="text-xs text-sky-400 hover:underline">View All Assets</Link>
          </div>
          {assets.length === 0 ? (
            <p className="mt-6 text-xs text-slate-400">No assets registered in global inventory.</p>
          ) : (
            <>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                <span className="font-semibold text-slate-300">{assets.length} assets total</span>
                <span className="text-slate-600">·</span>
                {(["active", "stale", "decommissioned"] as const).map((s) =>
                  statusCounts[s] ? (
                    <span key={s} className="flex items-center gap-1">
                      <StatusBadge value={s} map={ASSET_STATUS} />
                      <span className="tabular-nums font-semibold text-slate-200">{statusCounts[s]}</span>
                    </span>
                  ) : null,
                )}
              </div>
              <BarChart
                className="mt-4 h-56"
                data={criticalityData}
                index="name"
                categories={["Assets"]}
                colors={["cyan"]}
                showLegend={false}
                showAnimation={false}
                yAxisWidth={40}
              />
            </>
          )}
        </Card>
      </div>

      <Card className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
        <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">Top Vulnerable Service Ports</Title>
        {topPorts.length === 0 ? (
          <p className="mt-6 text-xs text-slate-400">No open ports detected in the latest run.</p>
        ) : (
          <div className="mt-4 grid gap-6 md:grid-cols-2 items-center">
            <DonutChart
              className="h-52"
              data={topPorts}
              category="value"
              index="name"
              colors={["cyan", "sky", "indigo", "violet", "slate"]}
              showAnimation={false}
            />
            <ul className="space-y-2 text-xs text-slate-300">
              {topPorts.map((port) => (
                <li key={port.name} className="flex justify-between border-b border-slate-800/60 py-2">
                  <span className="font-mono text-sky-400 font-semibold">{port.name}</span>
                  <span className="font-bold tabular-nums text-slate-100">{port.value.toLocaleString()} hosts</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
    </div>
  );
}

