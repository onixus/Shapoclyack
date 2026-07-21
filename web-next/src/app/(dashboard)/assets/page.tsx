"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { useAssetDetail, useAssets } from "@/hooks/use-assets";
import { type AssetStatus, type AssetSummary } from "@/lib/api";
import { ASSET_STATUS } from "@/lib/config/statuses";

const STATUS_FILTER_ALL = "all";

export default function AssetsPage() {
  const [status, setStatus] = useState<AssetStatus | "">("");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const assetsQuery = useAssets({ status });
  const detailQuery = useAssetDetail(selectedAssetId);
  const data = assetsQuery.data || [];

  const columns = useMemo<ColumnDef<AssetSummary>[]>(
    () => [
      {
        id: "asset",
        accessorFn: (row) => `${row.primary_identifier || ""} ${row.asset_id}`,
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
        cell: ({ row }) => <StatusBadge value={row.original.status} map={ASSET_STATUS} />,
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
                <StatusBadge value={detailQuery.data.status} map={ASSET_STATUS} />
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
