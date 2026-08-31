"use client";

import Link from "next/link";
import { useCallback, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Download, FileText } from "lucide-react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/data-table";
import { usePagination } from "@/hooks/use-pagination";
import { useRuns } from "@/hooks/use-runs";
import { downloadArtifact, type RunSummary } from "@/lib/api";
import { runDetailHref } from "@/lib/run-data";
import { useT } from "@/lib/i18n";
import { ReportFactoryPanel } from "@/components/reports/report-factory-panel";

export default function ReportsPage() {
  const t = useT();
  // Same server-paged run list as /runs (P3.3); ordering is by run_id.
  const pagination = usePagination({ sort: "run_id", order: "desc" });
  const { data, isLoading, error, isFetching } = useRuns(undefined, pagination.params);
  const runs = data?.items ?? [];
  const [busyRun, setBusyRun] = useState<string | null>(null);

  const downloadPdf = useCallback(async (runId: string) => {
    setBusyRun(runId);
    try {
      await downloadArtifact(runId, "summary.pdf");
    } catch {
      toast.error(t("page.reports.noPdf"));
    } finally {
      setBusyRun(null);
    }
  }, [t]);

  const downloadSarif = useCallback(async (runId: string) => {
    setBusyRun(`sarif-${runId}`);
    try {
      await downloadArtifact(runId, "sarif.json");
    } catch {
      toast.error("SARIF report not available for this run");
    } finally {
      setBusyRun(null);
    }
  }, []);

  const columns = useMemo<ColumnDef<RunSummary>[]>(
    () => [
      {
        accessorKey: "run_id",
        header: t("col.runId"),
        cell: ({ row }) => (
          <Link
            href={`${runDetailHref(row.original.run_id)}&tab=reports`}
            className="font-mono text-xs text-sky-400 hover:text-sky-300 underline-offset-2 hover:underline"
          >
            {row.original.run_id}
          </Link>
        ),
      },
      {
        accessorKey: "profile",
        header: t("col.profile"),
        cell: ({ getValue }) => <Badge variant="secondary" className="bg-slate-800 text-sky-300 font-mono text-[11px]">{String(getValue() || "—")}</Badge>,
      },
      {
        accessorKey: "started_at",
        header: t("col.executionDate"),
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at ? (
            <span className="font-mono text-xs text-slate-300">
              {format(new Date(row.original.started_at), "yyyy-MM-dd HH:mm")}
            </span>
          ) : (
            "—"
          ),
      },
      {
        accessorKey: "potential_vulnerabilities",
        header: t("col.vulnerabilities"),
        cell: ({ getValue, row }) => {
          const val = Number(getValue() ?? 0);
          // Same reasoning as the Runs catalog: the total includes findings the
          // scanner could not confirm, so name that share here.
          const unconfirmed = row.original.unconfirmed_findings ?? 0;
          return (
            <span className="flex items-baseline gap-1.5">
              <span className={`font-mono text-xs font-bold ${val > 0 ? "text-rose-400" : "text-slate-400"}`}>
                {val.toLocaleString()}
              </span>
              {unconfirmed > 0 ? (
                <span className="font-mono text-[10px] text-amber-300/80" title="Unconfirmed — reachable-service exposures and unverified keyword CVE hits, included in the total">
                  {unconfirmed.toLocaleString()} unconf.
                </span>
              ) : null}
            </span>
          );
        },
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex justify-end gap-2">
            {row.original.has_summary ? (
              <Button
                variant="outline"
                size="sm"
                className="gap-1.5 border-sky-500/30 bg-sky-500/10 text-sky-300 hover:bg-sky-500/20 text-xs font-semibold"
                onClick={() => downloadPdf(row.original.run_id)}
                disabled={busyRun === row.original.run_id}
              >
                <Download className="h-3.5 w-3.5" />
                {busyRun === row.original.run_id ? t("common.downloading") : t("common.downloadPdf")}
              </Button>
            ) : (
              <Badge variant="outline" className="border-slate-800 text-slate-500 font-normal">{t("common.noSummary")}</Badge>
            )}
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 border-indigo-500/30 bg-indigo-500/10 text-indigo-300 hover:bg-indigo-500/20 text-xs font-semibold"
              onClick={() => downloadSarif(row.original.run_id)}
              disabled={busyRun === `sarif-${row.original.run_id}`}
            >
              <Download className="h-3.5 w-3.5" />
              {busyRun === `sarif-${row.original.run_id}` ? "Downloading…" : "SARIF"}
            </Button>
            <Button asChild variant="ghost" size="sm" className="text-slate-400 hover:text-slate-100 hover:bg-slate-800 text-xs">
              <Link href={`${runDetailHref(row.original.run_id)}&tab=reports`}>{t("common.artifacts")}</Link>
            </Button>
          </div>
        ),
      },
    ],
    [busyRun, downloadPdf, downloadSarif, t],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <FileText className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">{t("page.reports.title")}</h1>
            <p className="text-xs text-slate-400">
              {t("page.reports.subtitle")}
              {isFetching ? t("common.refreshing") : ""}
            </p>
          </div>
        </div>
      </div>

      {/* The report factory (Sprint 4) sits above the per-run artifacts: a
          customer-facing report is the deliverable, and the run list below is
          the raw material it is built from. */}
      <ReportFactoryPanel />

      <h2 className="border-b border-slate-800/80 pb-2 text-sm font-bold text-slate-200">
        {t("page.reports.runArtifacts")}
      </h2>

      <DataTable
        columns={columns}
        data={runs}
        isLoading={isLoading}
        error={error}
        searchPlaceholder={t("search.reports")}
        loadingMessage={t("loading.reports")}
        emptyMessage={t("empty.reports")}
        meta={`${data?.total ?? 0} runs`}
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: data?.total ?? 0,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["run_id"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />
    </div>
  );
}

