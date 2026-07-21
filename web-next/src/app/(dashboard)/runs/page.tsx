"use client";

import Link from "next/link";
import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
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
            className="font-medium text-sky-700 underline-offset-2 hover:underline"
          >
            <code className="text-xs">{row.original.run_id}</code>
          </Link>
        ),
      },
      {
        accessorKey: "profile",
        header: "Profile",
        cell: ({ getValue }) => String(getValue() || "—"),
      },
      {
        accessorKey: "started_at",
        header: "Started",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.started_at
            ? format(new Date(row.original.started_at), "dd-MM-yyyy HH:mm")
            : "—",
      },
      {
        accessorKey: "alive_hosts",
        header: "Hosts",
        cell: ({ getValue }) => (
          <span className="tabular-nums">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
      },
      {
        accessorKey: "open_host_port_pairs",
        header: "Ports",
        cell: ({ getValue }) => (
          <span className="tabular-nums">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
      },
      {
        accessorKey: "potential_vulnerabilities",
        header: "Vulns",
        cell: ({ getValue }) => (
          <span className="tabular-nums">{Number(getValue() ?? 0).toLocaleString()}</span>
        ),
      },
      {
        id: "flags",
        accessorFn: (row) => `${row.has_diff ? 1 : 0}${row.has_summary ? 1 : 0}`,
        header: "Flags",
        cell: ({ row }) => (
          <div className="flex gap-1">
            {row.original.has_diff ? <Badge variant="secondary">diff</Badge> : null}
            {row.original.has_summary ? <Badge variant="outline">summary</Badge> : null}
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Runs</h1>
        <p className="text-sm text-muted-foreground">
          Live pipeline run catalog from <code className="text-xs">GET /api/runs</code>
          {isFetching ? " · refreshing…" : ""}
        </p>
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder="Filter runs…"
        loadingMessage="Loading runs…"
        emptyMessage="No runs yet."
      />
    </div>
  );
}
