"use client";

import Link from "next/link";
import { useMemo } from "react";
import { AreaChart, Card, DonutChart, Title } from "@tremor/react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { KpiCard } from "@/components/kpi-card";
import { useRunPorts, useRuns, useRunVulns } from "@/hooks/use-runs";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { SEVERITY_STATUS } from "@/lib/config/statuses";
import {
  countSeverities,
  pickLatestRun,
  recentRunTrend,
  runDetailHref,
  topVulnerablePorts,
} from "@/lib/run-data";

export default function DashboardPage() {
  const runsQuery = useRuns(POLL_INTERVALS.dashboard);

  const latest = useMemo(() => pickLatestRun(runsQuery.data || []), [runsQuery.data]);
  const runId = latest?.run_id ?? "";

  const vulnsQuery = useRunVulns(runId);
  const portsQuery = useRunPorts(runId);

  const severityCounts = useMemo(() => countSeverities(vulnsQuery.data || []), [vulnsQuery.data]);
  const trend = useMemo(() => recentRunTrend(runsQuery.data || [], 15), [runsQuery.data]);
  const topPorts = useMemo(() => topVulnerablePorts(portsQuery.data || [], 5), [portsQuery.data]);

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
            Fleet posture from the latest scan run
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

      <div className="grid gap-4 md:grid-cols-3">
        <KpiCard
          label="Alive hosts (latest)"
          value={isLoading ? "…" : (latest?.alive_hosts ?? 0)}
          decorationColor="blue"
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
          <Title>Hosts &amp; vulnerabilities (recent runs)</Title>
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
          <Title>Top vulnerable ports</Title>
          {topPorts.length === 0 ? (
            <p className="mt-6 text-sm text-muted-foreground">No open ports in the latest run.</p>
          ) : (
            <>
              <DonutChart
                className="mt-6 h-60"
                data={topPorts}
                category="value"
                index="name"
                colors={["blue", "cyan", "indigo", "violet", "slate"]}
                showAnimation={false}
              />
              <ul className="mt-4 space-y-2 text-sm text-slate-600">
                {topPorts.map((port) => (
                  <li
                    key={port.name}
                    className="flex justify-between border-b border-slate-100 py-1"
                  >
                    <span>{port.name}</span>
                    <span className="font-medium tabular-nums">{port.value.toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
