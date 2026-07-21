"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { format } from "date-fns";
import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchRuns, type RunSummary } from "@/lib/api";
import { runDetailHref } from "@/lib/run-data";

function SortIcon({ sorted }: { sorted: false | "asc" | "desc" }) {
  if (sorted === "asc") return <ArrowUp className="h-3.5 w-3.5" aria-hidden />;
  if (sorted === "desc") return <ArrowDown className="h-3.5 w-3.5" aria-hidden />;
  return <ArrowUpDown className="h-3.5 w-3.5 opacity-40" aria-hidden />;
}

export default function RunsPage() {
  const [sorting, setSorting] = useState<SortingState>([{ id: "started_at", desc: true }]);

  const {
    data = [],
    isLoading,
    error,
    isFetching,
  } = useQuery({
    queryKey: ["runs"],
    queryFn: fetchRuns,
    refetchInterval: 10_000,
  });

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

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Runs</h1>
        <p className="text-sm text-muted-foreground">
          Live pipeline run catalog from <code className="text-xs">GET /api/runs</code>
          {isFetching ? " · refreshing…" : ""}
        </p>
      </div>

      {error ? (
        <p className="text-sm text-rose-600">
          {error instanceof Error ? error.message : "Failed to load runs"}
        </p>
      ) : null}

      <div className="rounded-lg border bg-white">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder ? null : header.column.getCanSort() ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="-ml-3 h-8 gap-1 px-2 font-medium"
                        onClick={header.column.getToggleSortingHandler()}
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        <SortIcon sorted={header.column.getIsSorted()} />
                      </Button>
                    ) : (
                      flexRender(header.column.columnDef.header, header.getContext())
                    )}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-muted-foreground">
                  Loading runs…
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-muted-foreground">
                  No runs yet.
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id} className="hover:bg-slate-50">
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
