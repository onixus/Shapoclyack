"use client";

import { useMemo, useState } from "react";
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
import { MOCK_ASSETS, TOTAL_ASSETS_SCANNED, type AssetRow } from "@/lib/mock-data";

function criticalityBadge(level: AssetRow["criticality"]) {
  const map: Record<AssetRow["criticality"], string> = {
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
  const [data] = useState(MOCK_ASSETS);

  const columns = useMemo<ColumnDef<AssetRow>[]>(
    () => [
      {
        accessorKey: "host",
        header: "IP / Domain",
        cell: ({ row }) => (
          <div className="space-y-1">
            <p className="font-medium text-slate-900">{row.original.host}</p>
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Assets Inventory</h1>
        <p className="text-sm text-muted-foreground">
          Mock view sized for 50k+ scale ({TOTAL_ASSETS_SCANNED.toLocaleString()} fleet total;
          showing {data.length.toLocaleString()} sample rows with Diff-badges).
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="max-w-md"
          placeholder="Filter by host, tenant, criticality…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          {filtered.length.toLocaleString()} matching · page {table.getState().pagination.pageIndex + 1} /{" "}
          {table.getPageCount()}
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
            {table.getRowModel().rows.map((row) => (
              <TableRow key={row.id}>
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            ))}
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
