"use client";

import Link from "next/link";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ArtifactsPanel } from "@/components/run/artifacts-panel";
import { EntityList } from "@/components/run/entity-list";
import { FindingsList } from "@/components/run/findings-list";
import { RunDiffPanel } from "@/components/run/run-diff-panel";
import { RunMetrics } from "@/components/run/run-metrics";
import { SeverityFilter } from "@/components/run/severity-filter";
import { useRunReport } from "@/hooks/use-run-report";
import { formatLocation } from "@/lib/run-data";

export default function RunDetailPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center py-16 text-slate-400 gap-2">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
        <span className="text-sm">Loading run telemetry…</span>
      </div>
    }>
      <RunDetailInner />
    </Suspense>
  );
}

function BackToRuns() {
  return (
    <Button asChild variant="ghost" size="sm" className="gap-2 px-0 text-slate-400 hover:text-slate-100 hover:bg-transparent">
      <Link href="/runs">
        <ArrowLeft className="h-4 w-4" />
        Back to Runs Catalog
      </Link>
    </Button>
  );
}

function RunDetailInner() {
  const searchParams = useSearchParams();
  const runId = (searchParams.get("runId") || "").trim();
  const initialTab = searchParams.get("tab") || "vulns";
  const report = useRunReport(runId);
  const { filters } = report;

  if (!runId) {
    return (
      <div className="space-y-4">
        <BackToRuns />
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>Missing runId query parameter.</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (report.error) {
    return (
      <div className="space-y-4">
        <BackToRuns />
        <Alert variant="destructive" className="border-rose-500/40 bg-rose-950/40 text-rose-200">
          <AlertDescription>
            {report.error instanceof Error ? report.error.message : "Failed to load run"}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (report.isLoading || !report.detail) {
    return (
      <div className="flex items-center justify-center py-16 text-slate-400 gap-2">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
        <span className="text-sm">Retrieving run telemetry artifacts…</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2 border-b border-slate-800/80 pb-4">
        <BackToRuns />
        <h1 className="text-2xl font-extrabold tracking-tight text-slate-100 font-mono">
          Run <span className="text-sky-400">{report.detail.run_id}</span>
        </h1>
        <p className="text-xs text-slate-400">
          Explored hosts, open ports, and security findings for this execution.
          {(filters.host || filters.port) && (
            <>
              {" "}
              Active Filters
              {filters.host ? ` · host ${filters.host}` : ""}
              {filters.port ? ` · port ${filters.port}` : ""}
              {report.isFilterFetching ? " · updating…" : ""}.{" "}
              <button type="button" className="text-sky-400 hover:text-sky-300 font-semibold underline" onClick={report.clearFilters}>
                Clear Filter
              </button>
            </>
          )}
        </p>
      </div>

      <RunMetrics
        summary={report.summary}
        hosts={report.hosts}
        ports={report.ports}
        vulnCount={report.vulns.length}
      />

      {report.diffCounts ? <RunDiffPanel counts={report.diffCounts} /> : null}

      <SeverityFilter
        counts={report.severityCounts}
        active={filters.severity}
        total={report.vulns.length}
        onChange={report.setSeverity}
      />

      <Tabs defaultValue={initialTab} className="space-y-4">
        <TabsList className="bg-slate-900 border border-slate-800 p-1">
          <TabsTrigger value="vulns" className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-300">Findings ({report.vulns.length})</TabsTrigger>
          <TabsTrigger value="hosts" className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-300">Hosts ({report.hosts.length})</TabsTrigger>
          <TabsTrigger value="ports" className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-300">Ports ({report.ports.length})</TabsTrigger>
          <TabsTrigger value="reports" className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-300">Artifacts ({report.detail.artifacts.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="vulns" className="space-y-4">
          <FindingsList grouped={report.grouped} truncation={report.truncation} />
        </TabsContent>

        <TabsContent value="hosts" className="space-y-2">
          <EntityList
            items={report.hosts.map((host) => ({
              key: host.host,
              title: host.host,
              subtitle: `${host.hostname || host.names[0] || "no hostname"}${
                host.vulnerability_count ? ` · ${host.vulnerability_count} vulns` : " · no vulns"
              }${host.os_name ? ` · ${host.os_name}${host.os_accuracy ? ` (${host.os_accuracy}%)` : ""}` : ""}`,
              meta: formatLocation(host) || "No GeoIP",
            }))}
            activeKey={filters.host}
            onSelect={report.toggleHost}
            emptyMessage="No alive hosts recorded for this run."
          />
          {report.hosts.some((h) => h.country || h.city) ? (
            <p className="text-xs text-slate-500">
              <a
                href="https://db-ip.com"
                target="_blank"
                rel="noreferrer"
                className="underline-offset-2 hover:underline hover:text-slate-400"
              >
                IP Geolocation by DB-IP
              </a>
            </p>
          ) : null}
        </TabsContent>

        <TabsContent value="ports">
          <EntityList
            items={report.ports.map((row) => ({
              key: `${row.port}/${row.protocol || "tcp"}`,
              value: row.port,
              title: `:${row.port}${row.protocol ? `/${row.protocol}` : ""}`,
              subtitle: `${row.host_count} hosts${
                row.vulnerability_count ? ` · ${row.vulnerability_count} vulns` : ""
              }`,
              meta: <span className="font-mono font-bold text-slate-200">{row.host_count}</span>,
            }))}
            activeKey={filters.port}
            onSelect={report.togglePort}
            emptyMessage="No open ports recorded for this run."
          />
        </TabsContent>

        <TabsContent value="reports">
          <ArtifactsPanel runId={report.detail.run_id} artifacts={report.detail.artifacts} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

