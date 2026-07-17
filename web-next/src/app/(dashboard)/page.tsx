"use client";

import Link from "next/link";
import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { AreaChart, Card, DonutChart, Metric, Text, Title } from "@tremor/react";
import {
  fetchPorts,
  fetchRuns,
  fetchVulns,
} from "@/lib/api";
import {
  countSeverities,
  pickLatestRun,
  recentRunTrend,
  runDetailHref,
  topVulnerablePorts,
} from "@/lib/run-data";

export default function DashboardPage() {
  const runsQuery = useQuery({
    queryKey: ["runs"],
    queryFn: fetchRuns,
    refetchInterval: 15_000,
  });

  const latest = useMemo(
    () => pickLatestRun(runsQuery.data || []),
    [runsQuery.data],
  );
  const runId = latest?.run_id;

  const vulnsQuery = useQuery({
    queryKey: ["run", runId, "vulns", "dashboard"],
    queryFn: () => fetchVulns(runId!, 5000),
    enabled: Boolean(runId),
  });

  const portsQuery = useQuery({
    queryKey: ["run", runId, "ports", "dashboard"],
    queryFn: () => fetchPorts(runId!),
    enabled: Boolean(runId),
  });

  const severityCounts = useMemo(
    () => countSeverities(vulnsQuery.data || []),
    [vulnsQuery.data],
  );
  const trend = useMemo(
    () => recentRunTrend(runsQuery.data || [], 15),
    [runsQuery.data],
  );
  const topPorts = useMemo(
    () => topVulnerablePorts(portsQuery.data || [], 5),
    [portsQuery.data],
  );

  const isLoading = runsQuery.isLoading || (Boolean(runId) && (vulnsQuery.isLoading || portsQuery.isLoading));
  const error =
    runsQuery.error || vulnsQuery.error || portsQuery.error
      ? (runsQuery.error || vulnsQuery.error || portsQuery.error) as Error
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
        {runsQuery.isFetching ? (
          <p className="text-xs text-muted-foreground">Refreshing…</p>
        ) : null}
      </div>

      {error ? (
        <p className="rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800">
          {error.message}
        </p>
      ) : null}

      {!isLoading && !latest ? (
        <p className="rounded-md border bg-white px-3 py-6 text-center text-sm text-muted-foreground">
          No scan runs yet. Start a job from Jobs, then return here for KPIs.
        </p>
      ) : null}

      <div className="grid gap-4 md:grid-cols-3">
        <Card decoration="top" decorationColor="blue">
          <Text>Alive hosts (latest)</Text>
          <Metric>
            {isLoading ? "…" : (latest?.alive_hosts ?? 0).toLocaleString()}
          </Metric>
        </Card>
        <Card decoration="top" decorationColor="rose">
          <Text>Critical findings</Text>
          <Metric>
            {isLoading ? "…" : severityCounts.critical.toLocaleString()}
          </Metric>
        </Card>
        <Card decoration="top" decorationColor="amber">
          <Text>High findings</Text>
          <Metric>
            {isLoading ? "…" : severityCounts.high.toLocaleString()}
          </Metric>
        </Card>
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
                  <li key={port.name} className="flex justify-between border-b border-slate-100 py-1">
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
