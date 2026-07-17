"use client";

import { AreaChart, Card, DonutChart, Metric, Text, Title } from "@tremor/react";
import { TOP_PORTS, TOTAL_ASSETS_SCANNED, VULN_TREND } from "@/lib/mock-data";

export default function DashboardPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          Fleet-wide vulnerability posture across tenants (mock data for Web UI v2).
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card decoration="top" decorationColor="blue">
          <Text>Total Assets Scanned</Text>
          <Metric>{TOTAL_ASSETS_SCANNED.toLocaleString()}</Metric>
        </Card>
        <Card decoration="top" decorationColor="rose">
          <Text>Critical findings (30d)</Text>
          <Metric>{VULN_TREND.at(-1)?.Critical ?? 0}</Metric>
        </Card>
        <Card decoration="top" decorationColor="amber">
          <Text>High findings (30d)</Text>
          <Metric>{VULN_TREND.at(-1)?.High ?? 0}</Metric>
        </Card>
      </div>

      <div className="grid gap-4 xl:grid-cols-5">
        <Card className="xl:col-span-3">
          <Title>High / Critical vulnerabilities (last 30 days)</Title>
          <AreaChart
            className="mt-4 h-72"
            data={VULN_TREND}
            index="date"
            categories={["Critical", "High"]}
            colors={["rose", "amber"]}
            showLegend
            showAnimation
          />
        </Card>
        <Card className="xl:col-span-2">
          <Title>Top vulnerable ports</Title>
          <DonutChart
            className="mt-6 h-60"
            data={TOP_PORTS}
            category="value"
            index="name"
            colors={["blue", "cyan", "indigo", "violet", "slate"]}
            showAnimation
          />
          <ul className="mt-4 space-y-2 text-sm text-slate-600">
            {TOP_PORTS.map((port) => (
              <li key={port.name} className="flex justify-between border-b border-slate-100 py-1">
                <span>{port.name}</span>
                <span className="font-medium tabular-nums">{port.value.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </div>
  );
}
