"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { DiffBadge } from "@/components/diff-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchHosts, fetchPorts, fetchRun, fetchRuns, fetchVulns } from "@/lib/api";
import { buildAssetRows, pickLatestRun, type AssetCriticality, type AssetRow } from "@/lib/run-data";

function criticalityBadge(level: AssetCriticality) {
  const map: Record<AssetCriticality, string> = {
    critical: "bg-red-600 hover:bg-red-600",
    high: "bg-orange-500 hover:bg-orange-500",
    medium: "bg-amber-500 hover:bg-amber-500 text-slate-900",
    low: "bg-slate-500 hover:bg-slate-500",
    info: "bg-slate-300 hover:bg-slate-300 text-slate-800",
  };
  return <Badge className={map[level]}>{level}</Badge>;
}

export default function AssetsPage() {
  const [query, setQuery] = useState("");

  const runsQuery = useQuery({
    queryKey: ["runs"],
    queryFn: fetchRuns,
    refetchInterval: 15_000,
  });

  const latest = useMemo(
    () => pickLatestRun(runsQuery.data || []),
    [runsQuery.data],
  );
  const runId = latest?.run_id;

  const detailQuery = useQuery({
    queryKey: ["run", runId],
    queryFn: () => fetchRun(runId!),
    enabled: Boolean(runId),
  });
  const hostsQuery = useQuery({
    queryKey: ["run", runId, "hosts"],
    queryFn: () => fetchHosts(runId!),
    enabled: Boolean(runId),
  });
  const portsQuery = useQuery({
    queryKey: ["run", runId, "ports"],
    queryFn: () => fetchPorts(runId!),
    enabled: Boolean(runId),
  });
  const vulnsQuery = useQuery({
    queryKey: ["run", runId, "vulns"],
    queryFn: () => fetchVulns(runId!, 5000),
    enabled: Boolean(runId),
  });

  const data = useMemo(
    () =>
      buildAssetRows({
        hosts: hostsQuery.data || [],
        ports: portsQuery.data || [],
        vulns: vulnsQuery.data || [],
        lastScanned: latest?.started_at || null,
        diff: detailQuery.data?.diff || null,
      }),
    [hostsQuery.data, portsQuery.data, vulnsQuery.data, latest?.started_at, detailQuery.data?.diff],
  );

  const columns = useMemo<ColumnDef<AssetRow>[]>(
    () => [
      {
        accessorKey: "host",
        header: "IP / Domain",
        cell: ({ row }) => (
          <div className="space-y-1">
            <p className="font-medium text-slate-900">{row.original.host}</p>
            {row.original.hostname ? (
              <p className="text-xs text-muted-foreground">{row.original.hostname}</p>
            ) : null}
            {row.original.diff ? (
              <DiffBadge kind={row.original.diff.kind} label={row.original.diff.label} />
            ) : null}
          </div>
        ),
      },
      {
        accessorKey: "tenant",
        header: "Tenant",
      },
      {
        accessorKey: "openPorts",
        header: "Open Ports",
        cell: ({ getValue }) => <span className="tabular-nums">{String(getValue())}</span>,
      },
      {
        accessorKey: "vulnerabilityCount",
        header: "Vulns",
        cell: ({ getValue }) => <span className="tabular-nums">{String(getValue())}</span>,
      },
      {
        accessorKey: "criticality",
        header: "Criticality",
        cell: ({ row }) => criticalityBadge(row.original.criticality),
      },
      {
        accessorKey: "lastScanned",
        header: "Last Scanned",
        cell: ({ getValue }) => (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
    ],
    [],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return data;
    return data.filter(
      (row) =>
        row.host.toLowerCase().includes(q) ||
        (row.hostname || "").toLowerCase().includes(q) ||
        row.tenant.toLowerCase().includes(q) ||
        row.criticality.includes(q),
    );
  }, [data, query]);

  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: { pageSize: 15 },
    },
  });

  const isLoading =
    runsQuery.isLoading ||
    (Boolean(runId) &&
      (hostsQuery.isLoading || portsQuery.isLoading || vulnsQuery.isLoading || detailQuery.isLoading));
  const error =
    runsQuery.error || hostsQuery.error || portsQuery.error || vulnsQuery.error || detailQuery.error
      ? (runsQuery.error ||
          hostsQuery.error ||
          portsQuery.error ||
          vulnsQuery.error ||
          detailQuery.error) as Error
      : null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Assets Inventory</h1>
        <p className="text-sm text-muted-foreground">
          Alive hosts from the latest run
          {latest ? (
            <>
              {" "}
              (
              <Link
                href={`/runs/${encodeURIComponent(latest.run_id)}`}
                className="text-sky-700 underline-offset-2 hover:underline"
              >
                <code className="text-xs">{latest.run_id}</code>
              </Link>
              ; {data.length.toLocaleString()} hosts)
            </>
          ) : (
            " (no runs yet)"
          )}
          .
        </p>
      </div>

      {error ? (
        <p className="rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800">
          {error.message}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="max-w-md"
          placeholder="Filter by host, tenant, criticality…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          {isLoading
            ? "Loading…"
            : `${filtered.length.toLocaleString()} matching · page ${
                table.getState().pagination.pageIndex + 1
              } / ${Math.max(table.getPageCount(), 1)}`}
        </p>
      </div>

      <div className="rounded-lg border bg-white">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {!isLoading && table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="py-8 text-center text-sm text-muted-foreground">
                  {latest ? "No hosts in this run." : "No scan runs yet."}
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
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

      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => table.previousPage()}
          disabled={!table.getCanPreviousPage()}
        >
          Previous
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => table.nextPage()}
          disabled={!table.getCanNextPage()}
        >
          Next
        </Button>
      </div>
    </div>
  );
}
