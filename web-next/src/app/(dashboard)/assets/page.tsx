"use client";

import Link from "next/link";
import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { type ColumnDef } from "@tanstack/react-table";
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
import { AssetBulkContext } from "@/components/asset/bulk-context";
import { useT } from "@/lib/i18n";
import { pluralForm } from "@/lib/plural";
import { useRelativeTime } from "@/lib/i18n/datetime";
import { StatusBadge } from "@/components/status-badge";
import { useAssets } from "@/hooks/use-assets";
import { useBulkSelection } from "@/hooks/use-bulk-actions";
import { usePagination } from "@/hooks/use-pagination";
import { MAX_BULK_IDS, type AssetStatus, type AssetSummary } from "@/lib/api";
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

/** "2 идентификатора", not "2 идентификаторов". */
function identifierCount(t: ReturnType<typeof useT>, count: number): string {
  const form = pluralForm(count, t.locale);
  if (form === "one") return t("page.assets.identifierOne", { count });
  if (form === "few") return t("page.assets.identifiersFew", { count });
  return t("page.assets.identifiers", { count });
}

export default function AssetsPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">…</p>}>
      <AssetsInner />
    </Suspense>
  );
}

function AssetsInner() {
  const t = useT();
  const searchParams = useSearchParams();
  const [status, setStatus] = useState<AssetStatus | "">("");
  const [unowned, setUnowned] = useState(searchParams.get("unowned") === "1");
  // Selected asset ids (#346), held outside the table for the same reason the
  // findings page holds its own: the list polls and pages under the operator.
  // Cleared on a tenant switch — see ``useBulkSelection``.
  const [selected, setSelected] = useBulkSelection();

  // Server-side paging/search/sort (ROADMAP P3.3) — the registry is the one
  // list expected to reach 50k rows, so nothing here is filtered client-side.
  const pagination = usePagination({
    sort: "last_seen",
    order: "desc",
    search: (searchParams.get("q") || "").trim(),
  });
  const assetsQuery = useAssets({ status, unowned: unowned || undefined }, pagination.params);
  const data = assetsQuery.data?.items ?? [];
  const total = assetsQuery.data?.total ?? 0;

  const ago = useRelativeTime();

  const columns = useMemo<ColumnDef<AssetSummary>[]>(
    () => [
      {
        id: "asset_id",
        accessorFn: (row) => `${row.primary_identifier || ""} ${row.asset_id}`,
        header: t("col.asset"),
        // The domain name heads the row, with the address under it. The API
        // chooses (``primary_identifier``); the two components come along so
        // this can show both without asking again. A host with no name keeps
        // its address in the heading, because that is the only name it has --
        // and then there is nothing to repeat underneath.
        cell: ({ row }) => {
          const asset = row.original;
          const heading = asset.primary_identifier || asset.asset_id;
          const secondary = asset.primary_fqdn && asset.primary_ip ? asset.primary_ip : null;
          return (
            <Link href={assetDetailHref(asset.asset_id)} className="group space-y-0.5">
              <div className="flex items-center gap-1.5 font-mono font-bold text-primary group-hover:underline">
                <span>{heading}</span>
                <ArrowUpRight className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
              </div>
              <span className="block font-mono text-[11px] text-muted-foreground">
                {secondary ?? identifierCount(t, asset.identifier_count)}
              </span>
            </Link>
          );
        },
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
            <span className="text-xs text-muted-foreground">
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
          <span className="tabular-nums text-foreground">
            {row.original.open_findings.toLocaleString()}
            {row.original.unassigned_findings > 0 ? (
              <span className="ml-1 text-[11px] text-amber-600 dark:text-amber-400">
                {" · "}
                {t("page.assets.unassignedSuffix", { count: row.original.unassigned_findings })}
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
            <span className="text-xs text-foreground">{row.original.owner_email}</span>
          ) : (
            <span className="text-xs text-muted-foreground">{t("common.unassigned")}</span>
          ),
      },
      {
        accessorKey: "business_service",
        header: t("col.service"),
        cell: ({ row }) =>
          row.original.business_service ? (
            <span className="text-xs text-foreground">{row.original.business_service}</span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
      },
      {
        accessorKey: "exposure_level",
        header: t("col.exposure"),
        cell: ({ row }) =>
          row.original.exposure_level ? (
            <StatusBadge value={row.original.exposure_level} map={ASSET_EXPOSURE} />
          ) : (
            <span className="text-xs text-muted-foreground">{t("common.unset")}</span>
          ),
      },
      {
        accessorKey: "environment",
        header: t("col.env"),
        cell: ({ row }) =>
          row.original.environment ? (
            <StatusBadge value={row.original.environment} map={ASSET_ENVIRONMENT} />
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
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
            <span className="text-xs text-muted-foreground">{t("common.unset")}</span>
          ),
      },
      {
        accessorKey: "first_seen",
        header: t("col.firstSeen"),
        sortingFn: "datetime",
        cell: ({ getValue }) => (
          <span className="text-xs text-muted-foreground">{ago(String(getValue()))}</span>
        ),
      },
      {
        accessorKey: "last_seen",
        header: t("col.lastSeen"),
        sortingFn: "datetime",
        cell: ({ getValue }) => (
          <span className="text-xs font-medium text-foreground">{ago(String(getValue()))}</span>
        ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <Button asChild variant="outline" size="sm" className="h-7 text-xs">
            <Link href={assetDetailHref(row.original.asset_id)}>{t("common.view")}</Link>
          </Button>
        ),
      },
    ],
    [ago, t],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <Server className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
              {t("page.assets.title")}
            </h1>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
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
        searchPlaceholder={t("page.assets.searchPlaceholder")}
        toolbar={
          <div className="flex items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <Select
              value={status || STATUS_FILTER_ALL}
              onValueChange={(value) => {
                setStatus(value === STATUS_FILTER_ALL ? "" : (value as AssetStatus));
                // The old offset points into a differently filtered result set.
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-48">
                <SelectValue placeholder={t("page.assets.filterAllStatuses")} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={STATUS_FILTER_ALL}>{t("page.assets.filterAllStatuses")}</SelectItem>
                <SelectItem value="active">{t.label("active")}</SelectItem>
                <SelectItem value="stale">{t.label("stale")}</SelectItem>
                <SelectItem value="decommissioned">{t.label("decommissioned")}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={unowned ? "unowned" : STATUS_FILTER_ALL}
              onValueChange={(value) => {
                setUnowned(value === "unowned");
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-48">
                <SelectValue placeholder={t("page.assets.filterOwnership")} />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={STATUS_FILTER_ALL}>{t("page.assets.filterAnyOwner")}</SelectItem>
                <SelectItem value="unowned">{t("page.assets.filterNoOwner")}</SelectItem>
              </SelectContent>
            </Select>
          </div>
        }
        meta={t("page.assets.meta", { count: total.toLocaleString() })}
        loadingMessage={t("page.assets.loading")}
        emptyMessage={t("page.assets.empty")}
        selection={{
          rowId: (row) => row.asset_id,
          selected,
          onChange: setSelected,
          max: MAX_BULK_IDS,
          selectAllLabel: t("page.assets.selectAll"),
          actions: (ids) => (
            <AssetBulkContext ids={ids} onApplied={(remaining) => setSelected(remaining)} />
          ),
        }}
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

