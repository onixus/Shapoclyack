"use client";

import Link from "next/link";
import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Play } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { DataTable } from "@/components/data-table";
import { useRuns } from "@/hooks/use-runs";
import { type RunSummary } from "@/lib/api";
import { runDetailHref } from "@/lib/run-data";

export default function RunsPage() {
  const { data = [], isLoading, error, isFetching } = useRuns();

  const columns = useMemo<ColumnDef<RunSummary>[]>(
    () => [
      {
        accessorKey: "run_id",
        header: "Run ID",
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
        header: "Profile Mode",
        cell: ({ getValue }) => <Badge variant="secondary" className="bg-slate-800 text-sky-300 font-mono text-[11px]">{String(getValue() || "—")}</Badge>,
      },
      {
        accessorKey: "started_at",
        header: "Started At",
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
        header: "Alive Hosts",
        cell: ({ getValue }) => (
          <span className="font-mono text-xs font-semibold text-slate-200">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
      },
      {
        accessorKey: "open_host_port_pairs",
        header: "Open Ports",
        cell: ({ getValue }) => (
          <span className="font-mono text-xs font-semibold text-slate-200">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
      },
      {
        accessorKey: "potential_vulnerabilities",
        header: "Vulns",
        cell: ({ getValue }) => {
          const val = Number(getValue() ?? 0);
          return (
            <span className={`font-mono text-xs font-bold ${val > 0 ? "text-rose-400" : "text-slate-400"}`}>
              {val.toLocaleString()}
            </span>
          );
        },
      },
      {
        id: "flags",
        accessorFn: (row) => `${row.has_diff ? 1 : 0}${row.has_summary ? 1 : 0}`,
        header: "Artifact Flags",
        cell: ({ row }) => (
          <div className="flex gap-1.5">
            {row.original.has_diff ? <Badge variant="secondary" className="bg-indigo-500/20 text-indigo-300 border-indigo-500/30 text-[10px]">diff</Badge> : null}
            {row.original.has_summary ? <Badge variant="outline" className="border-emerald-500/30 text-emerald-300 bg-emerald-500/10 text-[10px]">pdf</Badge> : null}
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <Play className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Pipeline Execution Runs</h1>
            <p className="text-xs text-slate-400">
              Live scan runs catalog and historical telemetry artifacts.
              {isFetching ? " · Refreshing run history…" : ""}
            </p>
          </div>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder="Search run IDs or profiles…"
        loadingMessage="Retrieving scan run history…"
        emptyMessage="No scan execution runs recorded yet."
      />
    </div>
  );
}

