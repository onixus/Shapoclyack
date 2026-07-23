"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { useAssets } from "@/hooks/use-assets";
import { type AssetStatus, type AssetSummary } from "@/lib/api";
import { ASSET_CRITICALITY, ASSET_STATUS } from "@/lib/config/statuses";

const STATUS_FILTER_ALL = "all";

function assetDetailHref(assetId: string): string {
  return `/assets/view?assetId=${encodeURIComponent(assetId)}`;
}

export default function AssetsPage() {
  const [status, setStatus] = useState<AssetStatus | "">("");

  const assetsQuery = useAssets({ status });
  const data = assetsQuery.data || [];

  const columns = useMemo<ColumnDef<AssetSummary>[]>(
    () => [
      {
        id: "asset",
        accessorFn: (row) => `${row.primary_identifier || ""} ${row.asset_id}`,
        header: "Asset",
        cell: ({ row }) => (
          <Link href={assetDetailHref(row.original.asset_id)} className="block space-y-1">
            <span className="block font-medium text-sky-700 underline-offset-2 hover:underline">
              {row.original.primary_identifier || row.original.asset_id}
            </span>
            <span className="block text-xs text-muted-foreground">
              {row.original.identifier_count} identifier
              {row.original.identifier_count === 1 ? "" : "s"}
            </span>
          </Link>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge value={row.original.status} map={ASSET_STATUS} />,
      },
      {
        accessorKey: "asset_criticality",
        header: "Criticality",
        cell: ({ row }) =>
          row.original.asset_criticality != null ? (
            <StatusBadge
              value={String(row.original.asset_criticality)}
              map={ASSET_CRITICALITY}
            />
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
      },
      {
        accessorKey: "first_seen",
        header: "First Seen",
        sortingFn: "datetime",
        cell: ({ getValue }) => (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
      {
        accessorKey: "last_seen",
        header: "Last Seen",
        sortingFn: "datetime",
        cell: ({ getValue }) => (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <Button asChild variant="outline" size="sm">
            <Link href={assetDetailHref(row.original.asset_id)}>View</Link>
          </Button>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Assets Inventory</h1>
        <p className="text-sm text-muted-foreground">
          Cross-run asset registry from <code className="text-xs">GET /api/assets</code> — persists
          across scans (first/last seen, status, criticality), unlike per-run Runs/Hosts views.
          {assetsQuery.isFetching ? " · refreshing…" : ""}
        </p>
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={assetsQuery.isLoading}
        error={assetsQuery.error}
        initialSorting={[{ id: "last_seen", desc: true }]}
        searchPlaceholder="Filter by IP or hostname…"
        toolbar={
          <Select
            value={status || STATUS_FILTER_ALL}
            onValueChange={(value) =>
              setStatus(value === STATUS_FILTER_ALL ? "" : (value as AssetStatus))
            }
          >
            <SelectTrigger className="w-48">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={STATUS_FILTER_ALL}>All statuses</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="stale">Stale</SelectItem>
              <SelectItem value="decommissioned">Decommissioned</SelectItem>
            </SelectContent>
          </Select>
        }
        meta={`${data.length.toLocaleString()} asset${data.length === 1 ? "" : "s"}`}
        loadingMessage="Loading assets…"
        emptyMessage="No assets recorded yet — assets are upserted here after a scan completes."
      />
    </div>
  );
}
