"use client";

import Link from "next/link";
import { useMemo } from "react";
import { AreaChart, BarChart, Card, DonutChart, Title } from "@tremor/react";
import { ArrowUpRight, Play, RefreshCw, ShieldAlert } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { useAssetSummary } from "@/hooks/use-assets";
import { useRuns } from "@/hooks/use-runs";
import { useTrackedVulnerabilities, useVulnerabilitySummary } from "@/hooks/use-vulnerabilities";
import { POLL_INTERVALS } from "@/lib/config/constants";
import {
  ASSET_CRITICALITY,
  ASSET_STATUS,
  RISK_LEVEL_STATUS,
  SEVERITY_STATUS,
} from "@/lib/config/statuses";
import { pickLatestRun, recentRunTrend, runDetailHref, SEVERITIES } from "@/lib/run-data";
import { estateRiskColor, estateRiskLabel } from "@/lib/risk-overview";
import {
  assetDetailHref,
  findingLabel,
  NIST_RISK_LEVELS,
  vulnDetailHref,
  vulnListHref,
} from "@/lib/vuln-lifecycle";

const RISK_DONUT_COLORS = ["slate", "sky", "amber", "orange", "rose"];
const SEVERITY_DONUT_COLORS = ["rose", "orange", "amber", "sky", "slate"];

export default function DashboardPage() {
  const summaryQuery = useVulnerabilitySummary();
  const assetsQuery = useAssetSummary();
  const topRisksQuery = useTrackedVulnerabilities(
    { open_only: true },
    { limit: 10, sort: "contextual_score", order: "desc" },
  );
  const runsQuery = useRuns(POLL_INTERVALS.dashboard, { limit: 50 });

  const summary = summaryQuery.data;
  const assets = assetsQuery.data;
  const topRisks = topRisksQuery.data?.items ?? [];
  const runs = useMemo(() => runsQuery.data?.items ?? [], [runsQuery.data]);
  const latest = useMemo(() => pickLatestRun(runs), [runs]);
  const trend = useMemo(() => recentRunTrend(runs, 15), [runs]);

  const riskData = useMemo(
    () =>
      NIST_RISK_LEVELS.map((level) => ({
        name: RISK_LEVEL_STATUS[level].label,
        value: summary?.by_risk_level_open[level] ?? 0,
        level,
      })),
    [summary],
  );
  const severityData = useMemo(
    () =>
      SEVERITIES.map((sev) => ({
        name: sev,
        value: summary?.by_severity_open[sev] ?? 0,
      })),
    [summary],
  );
  const criticalityData = useMemo(() => {
    if (!assets) return [];
    const order = ["4", "3", "2", "1", "0", "unset"];
    return order
      .filter((key) => (assets.by_criticality[key] ?? 0) > 0)
      .map((key) => ({
        name:
          key === "unset"
            ? "unset"
            : `L${key} · ${ASSET_CRITICALITY[Number(key)]?.label ?? key}`,
        Assets: assets.by_criticality[key] ?? 0,
      }));
  }, [assets]);

  const isLoading = summaryQuery.isLoading || assetsQuery.isLoading;
  const error =
    summaryQuery.error || assetsQuery.error || topRisksQuery.error
      ? ((summaryQuery.error || assetsQuery.error || topRisksQuery.error) as Error)
      : null;

  const criticalOpen = (summary?.by_severity_open.critical ?? 0) + (summary?.by_severity_open.high ?? 0);
  const estateLabel = isLoading ? "…" : estateRiskLabel(summary);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Risk Overview</h1>
            <span className="rounded-full bg-sky-500/10 px-2.5 py-0.5 text-xs font-semibold text-sky-400 border border-sky-500/20">
              Estate
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Current cyber risk from tracked findings — not the last scan&apos;s raw list.{" "}
            <Link href="/vulnerabilities" className="text-sky-400 hover:underline">
              Vulnerability Center
            </Link>
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void summaryQuery.refetch();
              void assetsQuery.refetch();
              void topRisksQuery.refetch();
              void runsQuery.refetch();
            }}
            className="gap-2 border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white"
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${summaryQuery.isFetching || assetsQuery.isFetching ? "animate-spin text-sky-400" : ""}`}
            />
            Refresh
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

      {!isLoading && (summary?.total ?? 0) === 0 ? (
        <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-8 text-center backdrop-blur">
          <ShieldAlert className="mx-auto h-10 w-10 text-slate-500" />
          <h3 className="mt-3 text-sm font-semibold text-slate-200">No tracked findings yet</h3>
          <p className="mt-1 text-xs text-slate-400">
            Findings become tracked work after a scan observes them against an asset. Launch a
            scan to populate the estate view.
          </p>
          <Link href="/jobs" className="mt-4 inline-block">
            <Button size="sm" className="bg-sky-600 hover:bg-sky-500">
              Start First Scan Job
            </Button>
          </Link>
        </div>
      ) : null}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <KpiCard
          label="Estate risk"
          value={estateLabel}
          hint="worst open NIST verdict"
          href={vulnListHref()}
          decorationColor={estateRiskColor(summary?.estate_risk)}
        />
        <KpiCard
          label="Critical / high (open)"
          value={isLoading ? "…" : criticalOpen}
          hint={`${summary?.by_severity_open.critical ?? 0} critical · ${summary?.by_severity_open.high ?? 0} high`}
          href={vulnListHref({ severity: "critical" })}
          decorationColor="rose"
        />
        <KpiCard
          label="SLA breached"
          value={isLoading ? "…" : (summary?.breached ?? 0)}
          hint={
            summary?.worst_breached_severity
              ? `worst open: ${summary.worst_breached_severity}`
              : "no open breaches"
          }
          href={vulnListHref({ sla: "breached" })}
          decorationColor="rose"
        />
        <KpiCard
          label="Unassigned findings"
          value={isLoading ? "…" : (summary?.unassigned ?? 0)}
          hint={`${summary?.untriaged ?? 0} still untriaged`}
          href={vulnListHref({ unassigned: true })}
          decorationColor="amber"
        />
        <KpiCard
          label="Assets without owner"
          value={isLoading ? "…" : (assets?.unowned ?? 0)}
          hint={`${assets?.total ?? 0} assets in inventory`}
          href="/assets?unowned=1"
          decorationColor="amber"
        />
      </div>

      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
        <Link href={vulnListHref()} className="text-sky-400 hover:underline">
          All open findings
        </Link>
        <Link href={vulnListHref({ sla: "breached" })} className="text-sky-400 hover:underline">
          SLA breaches
        </Link>
        <Link href={vulnListHref({ unassigned: true })} className="text-sky-400 hover:underline">
          Unassigned
        </Link>
        <Link href="/assets?unowned=1" className="text-sky-400 hover:underline">
          Unowned assets
        </Link>
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
          <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            Open findings by NIST risk
          </Title>
          {riskData.every((row) => row.value === 0) ? (
            <p className="mt-6 text-xs text-slate-400">No open tracked findings with a risk level.</p>
          ) : (
            <>
              <DonutChart
                className="mt-4 h-52"
                data={riskData}
                category="value"
                index="name"
                colors={RISK_DONUT_COLORS}
                showAnimation={false}
              />
              <ul className="mt-4 space-y-1.5 text-xs text-slate-300">
                {[...riskData].reverse().map((row) => (
                  <li
                    key={row.level}
                    className="flex items-center justify-between border-b border-slate-800/60 py-1.5"
                  >
                    <StatusBadge value={row.level} map={RISK_LEVEL_STATUS} />
                    <span className="font-semibold tabular-nums text-slate-100">
                      {row.value.toLocaleString()}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>

        <Card className="xl:col-span-2 rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
          <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            Open by severity
          </Title>
          {severityData.every((row) => row.value === 0) ? (
            <p className="mt-6 text-xs text-slate-400">No open findings.</p>
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
                    <span className="font-semibold tabular-nums text-slate-100">
                      {row.value.toLocaleString()}
                    </span>
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
            <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">
              Top business risks
            </Title>
            <span className="text-xs text-slate-400">Open, worst NIST score first</span>
          </div>
          {topRisksQuery.isLoading ? (
            <p className="mt-6 text-xs text-slate-400">Loading tracked findings…</p>
          ) : topRisks.length === 0 ? (
            <p className="mt-6 text-xs text-slate-400">No open tracked findings.</p>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-bold uppercase tracking-wider">
                  <tr>
                    <th className="py-2.5 px-2">Finding</th>
                    <th className="py-2.5 px-2">Asset</th>
                    <th className="py-2.5 px-2">Risk</th>
                    <th className="py-2.5 px-2">SLA</th>
                    <th className="py-2.5 px-2">Owner</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {topRisks.map((row) => (
                    <tr key={row.vuln_id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-2.5 px-2">
                        <Link
                          href={vulnDetailHref(row.vuln_id, row.tenant_id)}
                          className="inline-flex items-center gap-1 font-mono font-semibold text-sky-400 hover:underline"
                        >
                          {findingLabel(row)}
                          <ArrowUpRight className="h-3 w-3" />
                        </Link>
                      </td>
                      <td className="py-2.5 px-2">
                        <Link
                          href={assetDetailHref(row.asset_id, row.tenant_id)}
                          className="font-mono text-slate-300 hover:text-sky-300 hover:underline"
                        >
                          {row.asset_id}
                        </Link>
                      </td>
                      <td className="py-2.5 px-2">
                        {row.risk_level ? (
                          <StatusBadge value={row.risk_level} map={RISK_LEVEL_STATUS} />
                        ) : (
                          <StatusBadge
                            value={row.severity}
                            map={SEVERITY_STATUS}
                          />
                        )}
                      </td>
                      <td className="py-2.5 px-2">
                        <SlaIndicator slaState={row.sla_state} dueAt={row.due_at} showDue={false} />
                      </td>
                      <td className="py-2.5 px-2 text-slate-300">
                        {row.assignee || <span className="text-slate-500">Unassigned</span>}
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
            <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">
              Asset posture
            </Title>
            <Link href="/assets" className="text-xs text-sky-400 hover:underline">
              View assets
            </Link>
          </div>
          {!assets || assets.total === 0 ? (
            <p className="mt-6 text-xs text-slate-400">No assets registered in the inventory.</p>
          ) : (
            <>
              <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
                <span className="font-semibold text-slate-300">
                  {assets.total.toLocaleString()} assets
                </span>
                {(["active", "stale", "decommissioned"] as const).map((s) =>
                  assets.by_status[s] ? (
                    <span key={s} className="flex items-center gap-1">
                      <StatusBadge value={s} map={ASSET_STATUS} />
                      <span className="tabular-nums font-semibold text-slate-200">
                        {assets.by_status[s]}
                      </span>
                    </span>
                  ) : null,
                )}
              </div>
              <p className="mt-3 text-xs text-slate-400">
                Internet-facing exposure is not counted yet — that input is{" "}
                <span className="text-slate-300">#171 / #146</span>, not a zero.
              </p>
              {criticalityData.length > 0 ? (
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
              ) : null}
            </>
          )}
        </Card>
      </div>

      <Card className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <Title className="text-sm font-bold text-slate-200 uppercase tracking-wider">
            Scan activity
          </Title>
          {latest ? (
            <Link
              href={runDetailHref(latest.run_id)}
              className="inline-flex items-center gap-1 font-mono text-xs text-sky-400 hover:underline"
            >
              latest {latest.run_id}
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          ) : null}
        </div>
        <p className="mt-1 text-xs text-slate-500">
          Hosts and raw findings per recent run — scan volume, not estate risk over time.
          Historical risk snapshots are not stored yet.
        </p>
        {trend.length === 0 ? (
          <p className="mt-6 text-xs text-slate-400">No run history to chart.</p>
        ) : (
          <AreaChart
            className="mt-4 h-64"
            data={trend}
            index="date"
            categories={["Hosts", "Vulns"]}
            colors={["cyan", "rose"]}
            showLegend
            showAnimation={false}
          />
        )}
      </Card>
    </div>
  );
}
