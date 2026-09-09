"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { FileText } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/data-table";
import { PageHeader } from "@/components/page-header";
import { SurfaceBadge } from "@/components/scans/surface-badge";
import { usePagination } from "@/hooks/use-pagination";
import { useRuns } from "@/hooks/use-runs";
import { type RunSummary, type ScanListFilters } from "@/lib/api";
import { runDetailHref } from "@/lib/run-data";
import { runSurface } from "@/lib/scan-surface";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

const SURFACE_FILTERS: Array<ScanListFilters["surface"] | undefined> = [
  undefined,
  "external",
  "internal",
  "mixed",
  "unknown",
];

function parseSurface(value: string | null): ScanListFilters["surface"] | undefined {
  return value === "external" || value === "internal" || value === "mixed" || value === "unknown"
    ? value
    : undefined;
}

export default function RunsPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">…</p>}>
      <RunsInner />
    </Suspense>
  );
}

function RunsInner() {
  const t = useT();
  const searchParams = useSearchParams();
  const surface = parseSurface(searchParams.get("surface"));
  // Server-side paging/search (ROADMAP P3.3). Runs are ordered by run_id —
  // the API cannot sort on summary columns without opening every run's JSON —
  // so only that column is server-sortable here.
  const pagination = usePagination({ sort: "run_id", order: "desc" });
  const { data, isLoading, error, isFetching } = useRuns(
    undefined,
    pagination.params,
    surface ? { surface } : undefined,
  );
  const runs = data?.items ?? [];

  const columns = useMemo<ColumnDef<RunSummary>[]>(
    () => [
      {
        accessorKey: "run_id",
        header: t("col.runId"),
        cell: ({ row }) => (
          <Link
            href={runDetailHref(row.original.run_id)}
            className="font-mono text-xs font-semibold text-primary underline-offset-2 hover:underline"
          >
            {row.original.run_id}
          </Link>
        ),
      },
      {
        id: "surface",
        header: t("col.surface"),
        enableSorting: false,
        cell: ({ row }) => <SurfaceBadge surface={runSurface(row.original)} link />,
      },
      {
        accessorKey: "profile",
        header: t("col.profileMode"),
        cell: ({ getValue }) => (
          <Badge variant="secondary" className="font-mono text-[11px]">
            {String(getValue() || "—")}
          </Badge>
        ),
      },
      {
        accessorKey: "started_at",
        header: t("col.started"),
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at ? (
            <span className="font-mono text-xs text-foreground">
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
          <span className="font-mono text-xs font-semibold text-foreground">
            {Number(getValue() ?? 0).toLocaleString()}
          </span>
        ),
      },
      {
        accessorKey: "open_host_port_pairs",
        header: t("col.openPorts"),
        cell: ({ getValue }) => (
          <span className="font-mono text-xs font-semibold text-foreground">
            {Number(getValue() ?? 0).toLocaleString()}
          </span>
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
              <span
                className={cn(
                  "font-mono text-xs font-bold",
                  val > 0 ? "text-rose-600 dark:text-rose-400" : "text-muted-foreground",
                )}
              >
                {val.toLocaleString()}
              </span>
              {unconfirmed > 0 ? (
                <span
                  className="font-mono text-[10px] text-amber-600 dark:text-amber-300/80"
                  title="Unconfirmed — reachable-service exposures and unverified keyword CVE hits, included in the total"
                >
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
            {row.original.has_diff ? (
              <Badge
                variant="secondary"
                className="border-indigo-500/30 bg-indigo-500/20 text-[10px] text-indigo-700 dark:text-indigo-300"
              >
                diff
              </Badge>
            ) : null}
            {row.original.has_summary ? (
              <Badge
                variant="outline"
                className="border-emerald-500/30 bg-emerald-500/10 text-[10px] text-emerald-700 dark:text-emerald-300"
              >
                pdf
              </Badge>
            ) : null}
          </div>
        ),
      },
    ],
    [t],
  );

  const subtitle =
    surface === "external"
      ? t("runs.subtitle.external")
      : surface === "internal"
        ? t("runs.subtitle.internal")
        : t("page.runs.subtitle");

  return (
    <div className="space-y-6">
      <PageHeader
        icon={FileText}
        tone={surface === "external" ? "sky" : surface === "internal" ? "violet" : "slate"}
        title={t("page.runs.title")}
        subtitle={
          <>
            {subtitle}
            {isFetching ? t("common.refreshing") : ""}
          </>
        }
      >
        <nav
          aria-label={t("runs.surfaceFilter")}
          className="inline-flex flex-wrap rounded-lg border border-border bg-muted/50 p-1"
        >
          {SURFACE_FILTERS.map((value) => {
            const active = value === surface;
            const key = value ?? "all";
            return (
              <Link
                key={key}
                href={value ? `/runs?surface=${value}` : "/runs"}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "rounded-md px-3 py-1.5 text-xs font-semibold transition-colors",
                  active
                    ? "bg-card text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {value ? t(`surface.${value}`) : t("surface.all")}
              </Link>
            );
          })}
        </nav>
      </PageHeader>

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
