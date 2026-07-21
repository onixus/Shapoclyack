"use client";

import Link from "next/link";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { EntityList } from "@/components/run/entity-list";
import { FindingsList } from "@/components/run/findings-list";
import { RunDiffPanel } from "@/components/run/run-diff-panel";
import { RunMetrics } from "@/components/run/run-metrics";
import { SeverityFilter } from "@/components/run/severity-filter";
import { useRunReport } from "@/hooks/use-run-report";
import { formatLocation } from "@/lib/run-data";

export default function RunDetailPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">Loading run…</p>}>
      <RunDetailInner />
    </Suspense>
  );
}

function BackToRuns() {
  return (
    <Button asChild variant="ghost" size="sm" className="gap-2 px-0">
      <Link href="/runs">
        <ArrowLeft className="h-4 w-4" />
        Runs
      </Link>
    </Button>
  );
}

function RunDetailInner() {
  const searchParams = useSearchParams();
  const runId = (searchParams.get("runId") || "").trim();
  const report = useRunReport(runId);
  const { filters } = report;

  if (!runId) {
    return (
      <div className="space-y-4">
        <BackToRuns />
        <Alert variant="destructive">
          <AlertDescription>Missing runId query parameter.</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (report.error) {
    return (
      <div className="space-y-4">
        <BackToRuns />
        <Alert variant="destructive">
          <AlertDescription>
            {report.error instanceof Error ? report.error.message : "Failed to load run"}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (report.isLoading || !report.detail) {
    return <p className="text-sm text-muted-foreground">Loading run…</p>;
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <BackToRuns />
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
          <code className="text-xl">{report.detail.run_id}</code>
        </h1>
        <p className="text-sm text-muted-foreground">
          Explore hosts, open ports, and severity-grouped findings for this run.
          {(filters.host || filters.port) && (
            <>
              {" "}
              Filter active
              {filters.host ? ` · host ${filters.host}` : ""}
              {filters.port ? ` · port ${filters.port}` : ""}
              {report.isFilterFetching ? " · updating…" : ""}.{" "}
              <button type="button" className="underline" onClick={report.clearFilters}>
                Clear
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

      <Tabs defaultValue="vulns">
        <TabsList>
          <TabsTrigger value="vulns">Findings</TabsTrigger>
          <TabsTrigger value="hosts">Hosts ({report.hosts.length})</TabsTrigger>
          <TabsTrigger value="ports">Ports ({report.ports.length})</TabsTrigger>
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
              }`,
              meta: formatLocation(host) || "No GeoIP",
            }))}
            activeKey={filters.host}
            onSelect={report.toggleHost}
            emptyMessage="No alive hosts recorded for this run."
          />
          {report.hosts.some((h) => h.country || h.city) ? (
            <p className="text-xs text-muted-foreground">
              <a
                href="https://db-ip.com"
                target="_blank"
                rel="noreferrer"
                className="underline-offset-2 hover:underline"
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
              meta: <span className="tabular-nums">{row.host_count}</span>,
            }))}
            activeKey={filters.port}
            onSelect={report.togglePort}
            emptyMessage="No open ports recorded for this run."
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
