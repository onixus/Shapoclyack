"use client";
import { runText } from "@/lib/run-presentation";

import Link from "next/link";
import { useT } from "@/lib/i18n";
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
import { ControlsMatrix } from "@/components/run/controls-matrix";
import { RelatedDomainsPanel } from "@/components/run/related-domains";
import { SeverityFilter } from "@/components/run/severity-filter";
import { useRunReport } from "@/hooks/use-run-report";
import { scanModeLabel } from "@/lib/scan-labels";
import { ScanTechnicalDetails } from "@/components/scans/scan-technical-details";
import { formatLocation } from "@/lib/run-data";

export default function RunDetailPage() {
  const t = useT();
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
          <span className="text-sm">{runText(t.locale, "Loading run telemetry\u2026")}</span>
        </div>
      }
    >
      <RunDetailInner />
    </Suspense>
  );
}

function BackToRuns() {
  const t = useT();
  return (
    <Button
      asChild
      variant="ghost"
      size="sm"
      className="gap-2 px-0 text-muted-foreground hover:text-foreground hover:bg-transparent"
    >
      <Link href="/runs">
        <ArrowLeft className="h-4 w-4" />
        {t("prose.backToRunsCatalog")}
      </Link>
    </Button>
  );
}

function RunDetailInner() {
  const t = useT();
  const searchParams = useSearchParams();
  const runId = (searchParams.get("runId") || "").trim();
  const requestedTab = searchParams.get("tab") || "vulns";
  const initialTab = ["vulns", "hosts", "ports", "controls", "org-profile", "reports"].includes(
    requestedTab,
  )
    ? requestedTab
    : "vulns";
  const report = useRunReport(runId);
  const { filters } = report;
  const profile =
    report.detail?.meta?.profile ?? report.detail?.meta?.mode ?? report.summary?.profile;

  if (!runId) {
    return (
      <div className="space-y-4">
        <BackToRuns />
        <Alert
          variant="destructive"
          className="border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200"
        >
          <AlertDescription>{t("ui.missingRunidQueryParameter")}</AlertDescription>
        </Alert>
      </div>
    );
  }

  if (report.error) {
    return (
      <div className="space-y-4">
        <BackToRuns />
        <Alert
          variant="destructive"
          className="border-rose-500/40 bg-rose-50 dark:bg-rose-950/40 text-rose-800 dark:text-rose-200"
        >
          <AlertDescription>
            {report.error instanceof Error
              ? report.error.message
              : runText(t.locale, "Failed to load run")}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (report.isLoading || !report.detail) {
    return (
      <div className="flex items-center justify-center py-16 text-muted-foreground gap-2">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
        <span className="text-sm">
          {runText(t.locale, "Retrieving run telemetry artifacts\u2026")}
        </span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2 border-b border-border pb-4">
        <BackToRuns />
        <h1 className="text-2xl font-extrabold tracking-tight text-foreground font-mono">
          {runText(t.locale, "Run")}{" "}
          <span className="text-sky-600 dark:text-sky-400">{report.detail.run_id}</span>
        </h1>
        <p className="text-xs text-muted-foreground">
          {runText(
            t.locale,
            "Explored hosts, open ports, and security findings for this execution.",
          )}
          {(filters.host || filters.port) && (
            <>
              {" "}
              {runText(t.locale, "Active Filters")}
              {filters.host ? ` · ${runText(t.locale, "host {host}", { host: filters.host })}` : ""}
              {filters.port ? ` · ${runText(t.locale, "port {port}", { port: filters.port })}` : ""}
              {report.isFilterFetching ? runText(t.locale, " · updating…") : ""}.{" "}
              <button
                type="button"
                className="text-sky-600 dark:text-sky-400 hover:text-sky-600 dark:text-sky-300 font-semibold underline"
                onClick={report.clearFilters}
              >
                {runText(t.locale, "Clear Filter")}
              </button>
            </>
          )}
        </p>
      </div>

      {typeof profile === "string" ? (
        <div className="text-sm text-foreground">
          {t("col.profileMode")}: {scanModeLabel(t.locale, profile)}
          <ScanTechnicalDetails mode={profile} />
        </div>
      ) : null}
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
        <TabsList className="bg-card border border-border p-1 h-auto flex-wrap justify-start">
          <TabsTrigger
            value="vulns"
            className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-600 dark:text-sky-300"
          >
            {runText(t.locale, "Findings")} ({report.vulns.length})
          </TabsTrigger>
          <TabsTrigger
            value="hosts"
            className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-600 dark:text-sky-300"
          >
            {runText(t.locale, "Hosts")} ({report.hosts.length})
          </TabsTrigger>
          <TabsTrigger
            value="ports"
            className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-600 dark:text-sky-300"
          >
            {runText(t.locale, "Ports")} ({report.ports.length})
          </TabsTrigger>
          <TabsTrigger
            value="controls"
            className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-600 dark:text-sky-300"
          >
            {t("ui.controls")}
          </TabsTrigger>
          <TabsTrigger
            value="org-profile"
            className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-600 dark:text-sky-300"
          >
            {t("ui.orgProfile")}
          </TabsTrigger>
          <TabsTrigger
            value="reports"
            className="text-xs font-semibold data-[state=active]:bg-sky-500/20 data-[state=active]:text-sky-600 dark:text-sky-300"
          >
            {runText(t.locale, "Artifacts")} ({report.detail.artifacts.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="vulns" className="space-y-4">
          <FindingsList grouped={report.grouped} truncation={report.truncation} />
        </TabsContent>

        <TabsContent value="controls" className="space-y-4">
          <ControlsMatrix runId={report.detail.run_id} />
        </TabsContent>

        <TabsContent value="org-profile" className="space-y-4">
          <RelatedDomainsPanel runId={report.detail.run_id} />
        </TabsContent>

        <TabsContent value="hosts" className="space-y-2">
          <EntityList
            items={report.hosts.map((host) => ({
              key: host.host,
              title: host.host,
              subtitle: `${host.hostname || host.names[0] || runText(t.locale, "no hostname")}${
                host.vulnerability_count
                  ? ` · ${runText(t.locale, "{count} vulns", { count: host.vulnerability_count })}`
                  : ` · ${runText(t.locale, "no vulns")}`
              }${host.os_name ? ` · ${host.os_name}${host.os_accuracy ? ` (${host.os_accuracy}%)` : ""}` : ""}`,
              meta: formatLocation(host) || runText(t.locale, "No GeoIP"),
            }))}
            activeKey={filters.host}
            onSelect={report.toggleHost}
            emptyMessage={t("empty.aliveHosts")}
          />
          {report.hosts.some((h) => h.country || h.city) ? (
            <p className="text-xs text-muted-foreground">
              <a
                href="https://db-ip.com"
                target="_blank"
                rel="noreferrer"
                className="underline-offset-2 hover:underline hover:text-muted-foreground"
              >
                {runText(t.locale, "IP Geolocation by DB-IP")}
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
              subtitle: `${runText(t.locale, "{count} hosts", { count: row.host_count })}${
                row.vulnerability_count
                  ? ` · ${runText(t.locale, "{count} vulns", { count: row.vulnerability_count })}`
                  : ""
              }`,
              meta: <span className="font-mono font-bold text-foreground">{row.host_count}</span>,
            }))}
            activeKey={filters.port}
            onSelect={report.togglePort}
            emptyMessage={t("empty.openPorts")}
          />
        </TabsContent>

        <TabsContent value="reports">
          <ArtifactsPanel runId={report.detail.run_id} artifacts={report.detail.artifacts} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
