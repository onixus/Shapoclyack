"use client";

import Link from "next/link";
import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Play } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/data-table";
import { usePagination } from "@/hooks/use-pagination";
import { useRuns } from "@/hooks/use-runs";
import { type RunSummary } from "@/lib/api";
import { runDetailHref } from "@/lib/run-data";
import { useT } from "@/lib/i18n";

export default function RunsPage() {
  const t = useT();
  // Server-side paging/search (ROADMAP P3.3). Runs are ordered by run_id —
  // the API cannot sort on summary columns without opening every run's JSON —
  // so only that column is server-sortable here.
  const pagination = usePagination({ sort: "run_id", order: "desc" });
  const { data, isLoading, error, isFetching } = useRuns(undefined, pagination.params);
  const runs = data?.items ?? [];

  const columns = useMemo<ColumnDef<RunSummary>[]>(
    () => [
      {
        accessorKey: "run_id",
        header: t("col.runId"),
        cell: ({ row }) => (
          <Link
            href={runDetailHref(row.original.run_id)}
            className="font-mono text-xs text-sky-400 hover:text-sky-300 underline-offset-2 hover:underline font-semibold"
          >
            {row.original.run_id}
          </Link>
        ),
      },
      {
        accessorKey: "profile",
        header: t("col.profileMode"),
        cell: ({ getValue }) => <Badge variant="secondary" className="bg-slate-800 text-sky-300 font-mono text-[11px]">{String(getValue() || "—")}</Badge>,
      },
      {
        accessorKey: "started_at",
        header: t("col.started"),
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
        accessorKey: "alive_hosts",
        header: t("col.aliveHosts"),
        cell: ({ getValue }) => (
          <span className="font-mono text-xs font-semibold text-slate-200">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
      },
      {
        accessorKey: "open_host_port_pairs",
        header: t("col.openPorts"),
        cell: ({ getValue }) => (
          <span className="font-mono text-xs font-semibold text-slate-200">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
      },
      {
        accessorKey: "potential_vulnerabilities",
        header: t("col.vulns"),
        cell: ({ getValue, row }) => {
          const val = Number(getValue() ?? 0);
          // The total counts unconfirmed findings too, so show how many of it
          // they are rather than letting keyword guesses read as CVEs.
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
        id: "flags",
        accessorFn: (row) => `${row.has_diff ? 1 : 0}${row.has_summary ? 1 : 0}`,
        header: t("col.artifacts"),
        cell: ({ row }) => (
          <div className="flex gap-1.5">
            {row.original.has_diff ? <Badge variant="secondary" className="bg-indigo-500/20 text-indigo-300 border-indigo-500/30 text-[10px]">diff</Badge> : null}
            {row.original.has_summary ? <Badge variant="outline" className="border-emerald-500/30 text-emerald-300 bg-emerald-500/10 text-[10px]">pdf</Badge> : null}
          </div>
        ),
      },
    ],
    [t],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <Play className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">{t("page.runs.title")}</h1>
            <p className="text-xs text-slate-400">
              {t("page.runs.subtitle")}
              {isFetching ? t("common.refreshing") : ""}
            </p>
          </div>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={runs}
        isLoading={isLoading}
        error={error}
        searchPlaceholder={t("search.runs")}
        loadingMessage={t("loading.runs")}
        emptyMessage={t("empty.runs")}
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

