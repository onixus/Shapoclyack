"use client";

import Link from "next/link";
import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { type ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { Server, ArrowUpRight, Filter } from "lucide-react";
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
import { usePagination } from "@/hooks/use-pagination";
import { type AssetStatus, type AssetSummary } from "@/lib/api";
import { ASSET_CRITICALITY, ASSET_STATUS } from "@/lib/config/statuses";

const STATUS_FILTER_ALL = "all";

function assetDetailHref(assetId: string): string {
  return `/assets/view?assetId=${encodeURIComponent(assetId)}`;
}

export default function AssetsPage() {
  return (
    <Suspense fallback={<p className="text-sm text-slate-400">Loading asset inventory…</p>}>
      <AssetsInner />
    </Suspense>
  );
}

function AssetsInner() {
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<AssetStatus | "">("");
  const [unowned, setUnowned] = useState(searchParams.get("unowned") === "1");

  // Server-side paging/search/sort (ROADMAP P3.3) — the registry is the one
  // list expected to reach 50k rows, so nothing here is filtered client-side.
  const pagination = usePagination({ sort: "last_seen", order: "desc" });
  const assetsQuery = useAssets({ status, unowned: unowned || undefined }, pagination.params);
  const data = assetsQuery.data?.items ?? [];
  const total = assetsQuery.data?.total ?? 0;

  const columns = useMemo<ColumnDef<AssetSummary>[]>(
    () => [
      {
        id: "asset_id",
        accessorFn: (row) => `${row.primary_identifier || ""} ${row.asset_id}`,
        header: "Asset Identifier",
        cell: ({ row }) => (
          <Link href={assetDetailHref(row.original.asset_id)} className="group space-y-0.5">
            <div className="flex items-center gap-1.5 font-mono font-bold text-sky-400 group-hover:text-sky-300 group-hover:underline">
              <span>{row.original.primary_identifier || row.original.asset_id}</span>
              <ArrowUpRight className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
            </div>
            <span className="block text-[11px] text-slate-400">
              {row.original.identifier_count} identifier
              {row.original.identifier_count === 1 ? "" : "s"}
            </span>
          </Link>
        ),
      },
      {
        accessorKey: "status",
        header: "Lifecycle Status",
        cell: ({ row }) => <StatusBadge value={row.original.status} map={ASSET_STATUS} />,
      },
      {
        accessorKey: "asset_criticality",
        header: "Criticality Level",
        cell: ({ row }) =>
          row.original.asset_criticality != null ? (
            <StatusBadge
              value={String(row.original.asset_criticality)}
              map={ASSET_CRITICALITY}
            />
          ) : (
            <span className="text-xs text-slate-500">Unset</span>
          ),
      },
      {
        accessorKey: "first_seen",
        header: "First Discovered",
        sortingFn: "datetime",
        cell: ({ getValue }) => (
          <span className="text-xs text-slate-400">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
      {
        accessorKey: "last_seen",
        header: "Last Telemetry",
        sortingFn: "datetime",
        cell: ({ getValue }) => (
          <span className="text-xs text-slate-300 font-medium">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <Button asChild variant="outline" size="sm" className="h-7 text-xs border-slate-800 bg-slate-900 text-sky-400 hover:bg-slate-800 hover:text-white">
            <Link href={assetDetailHref(row.original.asset_id)}>Details</Link>
          </Button>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Server className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Global Assets Inventory</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Persistent fleet asset registry across discovery scan runs. Track status, business unit owners, and risk criticality.
            {assetsQuery.isFetching ? " · Refreshing inventory stream…" : ""}
          </p>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={assetsQuery.isLoading}
        error={assetsQuery.error}
        initialSorting={[{ id: "last_seen", desc: true }]}
        searchPlaceholder="Filter by IP range or domain hostname…"
        toolbar={
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-slate-400" />
            <Select
              value={status || STATUS_FILTER_ALL}
              onValueChange={(value) => {
                setStatus(value === STATUS_FILTER_ALL ? "" : (value as AssetStatus));
                // The old offset points into a differently filtered result set.
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-48 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="All statuses" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={STATUS_FILTER_ALL}>All Statuses</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="stale">Stale</SelectItem>
                <SelectItem value="decommissioned">Decommissioned</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={unowned ? "unowned" : STATUS_FILTER_ALL}
              onValueChange={(value) => {
                setUnowned(value === "unowned");
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-48 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="Ownership" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={STATUS_FILTER_ALL}>Any owner</SelectItem>
                <SelectItem value="unowned">No owner</SelectItem>
              </SelectContent>
            </Select>
          </div>
        }
        meta={`${total.toLocaleString()} asset${total === 1 ? "" : "s"} tracked`}
        loadingMessage="Retrieving asset inventory database…"
        emptyMessage="No assets registered yet. Run a discovery scan to populate the asset catalog."
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["last_seen", "first_seen", "status", "asset_criticality", "asset_id"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />
    </div>
  );
}

