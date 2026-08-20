"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { ArrowUpRight, Radar } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
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
import type { AssetExposureLevel, AssetSummary } from "@/lib/api";
import { ASSET_EXPOSURE_LEVELS, assetRiskLabel } from "@/lib/asset-context";
import {
  ASSET_CRITICALITY,
  ASSET_EXPOSURE,
  ASSET_STATUS,
  RISK_LEVEL_STATUS,
} from "@/lib/config/statuses";
import { assetDetailHref } from "@/lib/vuln-lifecycle";

export default function ExposurePage() {
  const t = useT();
  const [exposure, setExposure] = useState<AssetExposureLevel>("internet");
  const pagination = usePagination({ sort: "last_seen", order: "desc" });
  const assetsQuery = useAssets({ status: "", exposure }, pagination.params);
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
            <div className="flex items-center gap-1.5 font-mono font-bold text-sky-400 group-hover:underline">
              <span>{row.original.primary_identifier || row.original.asset_id}</span>
              <ArrowUpRight className="h-3 w-3 opacity-0 group-hover:opacity-100" />
            </div>
            <span className="block text-[11px] text-slate-400">
              {row.original.business_service || t("common.noService")}
              {row.original.owner_email ? ` · ${row.original.owner_email}` : ` · ${t("common.noOwner")}`}
            </span>
          </Link>
        ),
      },
      {
        accessorKey: "exposure_level",
        header: t("col.declaredExposure"),
        cell: ({ row }) =>
          row.original.exposure_level ? (
            <StatusBadge value={row.original.exposure_level} map={ASSET_EXPOSURE} />
          ) : (
            <span className="text-xs text-slate-500">{t.label("unset")}</span>
          ),
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
          <span className="tabular-nums text-slate-200">{row.original.open_findings}</span>
        ),
      },
      {
        accessorKey: "status",
        header: t("col.status"),
        cell: ({ row }) => <StatusBadge value={row.original.status} map={ASSET_STATUS} />,
      },
      {
        accessorKey: "asset_criticality",
        header: t("col.criticality"),
        cell: ({ row }) =>
          row.original.asset_criticality != null ? (
            <StatusBadge value={String(row.original.asset_criticality)} map={ASSET_CRITICALITY} />
          ) : (
            <span className="text-xs text-slate-500">{t.label("unset")}</span>
          ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <Button asChild variant="outline" size="sm" className="h-7 text-xs border-slate-800">
            <Link href={assetDetailHref(row.original.asset_id)}>{t("common.open")}</Link>
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
            <Radar className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">{t("page.exposure.title")}</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">{t("page.exposure.subtitle")}</p>
        </div>
      </div>

      <Alert className="border-sky-500/30 bg-sky-950/20 text-sky-100">
        <AlertDescription className="text-xs">
          {t("page.exposure.alert")}
        </AlertDescription>
      </Alert>

      <DataTable
        columns={columns}
        data={data}
        isLoading={assetsQuery.isLoading}
        error={assetsQuery.error}
        searchPlaceholder={t("search.assets")}
        toolbar={
          <Select
            value={exposure}
            onValueChange={(value) => {
              setExposure(value as AssetExposureLevel);
              pagination.reset();
            }}
          >
            <SelectTrigger className="w-48 bg-slate-900 border-slate-800 text-slate-200">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
              {ASSET_EXPOSURE_LEVELS.map((value) => (
                <SelectItem key={value} value={value}>
                  {ASSET_EXPOSURE[value].label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
        meta={`${total.toLocaleString()} asset${total === 1 ? "" : "s"} with ${ASSET_EXPOSURE[exposure].label} exposure`}
        loadingMessage="Loading declared exposure…"
        emptyMessage="No assets marked with this exposure yet. Set it on the asset card."
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["last_seen", "first_seen", "status", "asset_criticality", "owner_email"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />
    </div>
  );
}
