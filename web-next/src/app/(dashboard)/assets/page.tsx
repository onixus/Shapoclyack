"use client";

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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fetchAsset, fetchAssets, type AssetStatus, type AssetSummary } from "@/lib/api";

function statusBadge(status: AssetStatus) {
  const map: Record<AssetStatus, string> = {
    active: "bg-emerald-600 hover:bg-emerald-600",
    stale: "bg-amber-500 hover:bg-amber-500 text-slate-900",
    decommissioned: "bg-slate-400 hover:bg-slate-400",
  };
  return <Badge className={map[status]}>{status}</Badge>;
}

export default function AssetsPage() {
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<AssetStatus | "">("");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const assetsQuery = useQuery({
    queryKey: ["assets", { status }],
    queryFn: () => fetchAssets({ status }),
    refetchInterval: 30_000,
  });

  const detailQuery = useQuery({
    queryKey: ["asset", selectedAssetId],
    queryFn: () => fetchAsset(selectedAssetId!),
    enabled: Boolean(selectedAssetId),
  });

  const data = useMemo(() => {
    const rows = assetsQuery.data || [];
    const q = query.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (row) =>
        (row.primary_identifier || "").toLowerCase().includes(q) ||
        row.asset_id.toLowerCase().includes(q),
    );
  }, [assetsQuery.data, query]);

  const columns = useMemo<ColumnDef<AssetSummary>[]>(
    () => [
      {
        accessorKey: "primary_identifier",
        header: "Asset",
        cell: ({ row }) => (
          <div className="space-y-1">
            <p className="font-medium text-slate-900">
              {row.original.primary_identifier || row.original.asset_id}
            </p>
            <p className="text-xs text-muted-foreground">
              {row.original.identifier_count} identifier
              {row.original.identifier_count === 1 ? "" : "s"}
            </p>
          </div>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => statusBadge(row.original.status),
      },
      {
        accessorKey: "first_seen",
        header: "First Seen",
        cell: ({ getValue }) => (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
      {
        accessorKey: "last_seen",
        header: "Last Seen",
        cell: ({ getValue }) => (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
      {
        id: "actions",
        header: "",
        cell: ({ row }) => (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setSelectedAssetId(row.original.asset_id)}
          >
            View
          </Button>
        ),
      },
    ],
    [],
  );

  const table = useReactTable({
    data,
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
          Cross-run asset registry from <code className="text-xs">GET /api/assets</code> — persists
          across scans (first/last seen, status), unlike per-run Runs/Hosts views.
          {assetsQuery.isFetching ? " · refreshing…" : ""}
        </p>
      </div>

      {assetsQuery.error ? (
        <p className="rounded-md border border-rose-200 bg-rose-50 px-3 py-2 text-sm text-rose-800">
          {(assetsQuery.error as Error).message}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-3">
        <Input
          className="max-w-md"
          placeholder="Filter by IP or hostname…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <select
          className="h-9 rounded-md border border-input bg-background px-3 text-sm"
          value={status}
          onChange={(event) => setStatus(event.target.value as AssetStatus | "")}
        >
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="stale">Stale</option>
          <option value="decommissioned">Decommissioned</option>
        </select>
        <p className="text-xs text-muted-foreground">
          {assetsQuery.isLoading
            ? "Loading…"
            : `${data.length.toLocaleString()} asset${data.length === 1 ? "" : "s"} · page ${
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
            {!assetsQuery.isLoading && table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="py-8 text-center text-sm text-muted-foreground"
                >
                  No assets recorded yet — assets are upserted here after a scan completes.
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

      <Dialog
        open={Boolean(selectedAssetId)}
        onOpenChange={(open) => !open && setSelectedAssetId(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Asset detail</DialogTitle>
          </DialogHeader>
          {detailQuery.isLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : detailQuery.error ? (
            <p className="text-sm text-rose-700">{(detailQuery.error as Error).message}</p>
          ) : detailQuery.data ? (
            <div className="space-y-4 text-sm">
              <div className="flex items-center justify-between">
                <code className="text-xs text-muted-foreground">{detailQuery.data.asset_id}</code>
                {statusBadge(detailQuery.data.status)}
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-xs text-muted-foreground">First seen</p>
                  <p>{new Date(detailQuery.data.first_seen).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Last seen</p>
                  <p>{new Date(detailQuery.data.last_seen).toLocaleString()}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Owner</p>
                  <p>{detailQuery.data.owner_email || "—"}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Business unit</p>
                  <p>{detailQuery.data.business_unit || "—"}</p>
                </div>
              </div>
              <div>
                <p className="mb-1 text-xs text-muted-foreground">
                  Identifiers ({detailQuery.data.identifiers.length})
                </p>
                <ul className="space-y-1">
                  {detailQuery.data.identifiers.map((identifier) => (
                    <li
                      key={`${identifier.identifier_type}:${identifier.identifier_value}`}
                      className="flex items-center gap-2"
                    >
                      <Badge variant="secondary">{identifier.identifier_type}</Badge>
                      <span>{identifier.identifier_value}</span>
                    </li>
                  ))}
                </ul>
              </div>
              {Object.keys(detailQuery.data.tags).length > 0 ? (
                <div>
                  <p className="mb-1 text-xs text-muted-foreground">Tags</p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(detailQuery.data.tags).map(([key, value]) => (
                      <Badge key={key} variant="secondary">
                        {key}={value}
                      </Badge>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </div>
  );
}
