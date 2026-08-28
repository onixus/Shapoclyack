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
import { useT } from "@/lib/i18n";
import { StatusBadge } from "@/components/status-badge";
import { useAssets } from "@/hooks/use-assets";
import { usePagination } from "@/hooks/use-pagination";
import { type AssetStatus, type AssetSummary } from "@/lib/api";
import { assetRiskLabel } from "@/lib/asset-context";
import {
  ASSET_CRITICALITY,
  ASSET_ENVIRONMENT,
  ASSET_EXPOSURE,
  ASSET_STATUS,
  RISK_LEVEL_STATUS,
} from "@/lib/config/statuses";

const STATUS_FILTER_ALL = "all";

function assetDetailHref(assetId: string): string {
  return `/assets/view?assetId=${encodeURIComponent(assetId)}`;
}

export default function AssetsPage() {
  return (
    <Suspense fallback={<p className="text-sm text-slate-400">…</p>}>
      <AssetsInner />
    </Suspense>
  );
}

function AssetsInner() {
  const t = useT();
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
        header: t("col.asset"),
        cell: ({ row }) => (
          <Link href={assetDetailHref(row.original.asset_id)} className="group space-y-0.5">
            <div className="flex items-center gap-1.5 font-mono font-bold text-sky-400 group-hover:text-sky-300 group-hover:underline">
              <span>{row.original.primary_identifier || row.original.asset_id}</span>
              <ArrowUpRight className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
            </div>
            <span className="block text-[11px] text-slate-400">
              {row.original.identifier_count === 1
                ? t("page.assets.identifierOne", { count: row.original.identifier_count })
                : t("page.assets.identifiers", { count: row.original.identifier_count })}
            </span>
          </Link>
        ),
      },
      {
        accessorKey: "status",
        header: t("col.status"),
        cell: ({ row }) => <StatusBadge value={row.original.status} map={ASSET_STATUS} />,
      },
      {
        accessorKey: "estate_risk",
        header: t("col.assetRisk"),
        cell: ({ row }) => {
          const level = row.original.estate_risk;
          if (level && level in RISK_LEVEL_STATUS) {
            return <StatusBadge value={level} map={RISK_LEVEL_STATUS} />;
          }
          return (
            <span className="text-xs text-slate-500">
              {assetRiskLabel({
                estate_risk: row.original.estate_risk,
                open_total: row.original.open_findings,
              })}
            </span>
          );
        },
      },
      {
        accessorKey: "open_findings",
        header: t("col.open"),
        cell: ({ row }) => (
          <span className="tabular-nums text-slate-200">
            {row.original.open_findings.toLocaleString()}
            {row.original.unassigned_findings > 0 ? (
              <span className="ml-1 text-[11px] text-amber-400">
                · {row.original.unassigned_findings} unassigned
              </span>
            ) : null}
          </span>
        ),
      },
      {
        accessorKey: "owner_email",
        header: t("col.owner"),
        cell: ({ row }) =>
          row.original.owner_email ? (
            <span className="text-xs text-slate-200">{row.original.owner_email}</span>
          ) : (
            <span className="text-xs text-slate-500">{t("common.unassigned")}</span>
          ),
      },
      {
        accessorKey: "business_service",
        header: t("col.service"),
        cell: ({ row }) =>
          row.original.business_service ? (
            <span className="text-xs text-slate-200">{row.original.business_service}</span>
          ) : (
            <span className="text-xs text-slate-500">—</span>
          ),
      },
      {
        accessorKey: "exposure_level",
        header: t("col.exposure"),
        cell: ({ row }) =>
          row.original.exposure_level ? (
            <StatusBadge value={row.original.exposure_level} map={ASSET_EXPOSURE} />
          ) : (
            <span className="text-xs text-slate-500">Unset</span>
          ),
      },
      {
        accessorKey: "environment",
        header: t("col.env"),
        cell: ({ row }) =>
          row.original.environment ? (
            <StatusBadge value={row.original.environment} map={ASSET_ENVIRONMENT} />
          ) : (
            <span className="text-xs text-slate-500">—</span>
          ),
      },
      {
        accessorKey: "asset_criticality",
        header: t("col.criticality"),
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
        header: t("col.firstSeen"),
        sortingFn: "datetime",
        cell: ({ getValue }) => (
          <span className="text-xs text-slate-400">
            {formatDistanceToNow(new Date(String(getValue())), { addSuffix: true })}
          </span>
        ),
      },
      {
        accessorKey: "last_seen",
        header: t("col.lastSeen"),
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
            <Link href={assetDetailHref(row.original.asset_id)}>{t("common.view")}</Link>
          </Button>
        ),
      },
    ],
    [t],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Server className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">{t("page.assets.title")}</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            {t("page.assets.subtitle")}
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
        searchPlaceholder="Filter by IP, hostname, owner or service…"
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
          sortableColumns: [
            "last_seen",
            "first_seen",
            "status",
            "asset_criticality",
            "asset_id",
            "owner_email",
            "business_service",
          ],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />
    </div>
  );
}

