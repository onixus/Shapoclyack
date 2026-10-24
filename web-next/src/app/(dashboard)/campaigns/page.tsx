"use client";

import Link from "next/link";
import { Suspense, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import { type ColumnDef } from "@tanstack/react-table";
import { ListChecks } from "lucide-react";
import { CampaignDetail } from "@/components/campaign/campaign-detail";
import { ProgressBar } from "@/components/campaign/campaign-progress";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { useCampaigns } from "@/hooks/use-campaigns";
import { usePagination } from "@/hooks/use-pagination";
import type { Campaign } from "@/lib/campaigns";
import { CAMPAIGN_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { useRelativeTime } from "@/lib/i18n/datetime";

function CampaignList() {
  const t = useT();
  const ago = useRelativeTime();
  const pagination = usePagination({ sort: "created_at", order: "desc" });
  const query = useCampaigns(pagination.params);
  const rows = query.data?.items ?? [];
  const total = query.data?.total ?? 0;

  const columns = useMemo<ColumnDef<Campaign>[]>(
    () => [
      {
        id: "name",
        header: t("campaign.col.name"),
        enableSorting: false,
        cell: ({ row }) => (
          <Link
            href={`/campaigns?id=${encodeURIComponent(row.original.campaign_id)}`}
            className="space-y-0.5 hover:underline"
          >
            <span className="block font-semibold text-sky-600 dark:text-sky-400">
              {row.original.name}
            </span>
            <span className="block text-[11px] text-muted-foreground">
              {ago(row.original.created_at)}
              {row.original.created_by ? ` · ${row.original.created_by}` : ""}
            </span>
          </Link>
        ),
      },
      {
        id: "status",
        header: t("campaign.col.status"),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="space-y-0.5">
            <StatusBadge value={row.original.status} map={CAMPAIGN_STATUS} />
            {row.original.past_due ? (
              <p className="text-[11px] text-rose-600 dark:text-rose-400">{t("campaign.pastDue")}</p>
            ) : null}
          </div>
        ),
      },
      {
        id: "owner",
        header: t("campaign.col.owner"),
        enableSorting: false,
        cell: ({ row }) => <span className="text-xs">{row.original.owner ?? "—"}</span>,
      },
      {
        id: "due",
        header: t("campaign.col.due"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-xs">
            {row.original.due_at ? new Date(row.original.due_at).toLocaleDateString() : "—"}
          </span>
        ),
      },
      {
        id: "findings",
        header: t("campaign.col.findings"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="text-xs tabular-nums">
            {row.original.progress.total}
            <span className="text-muted-foreground"> · {row.original.progress.assets}</span>
          </span>
        ),
      },
      {
        id: "progress",
        header: t("campaign.col.progress"),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="w-40 space-y-1">
            <ProgressBar progress={row.original.progress} />
            <p className="text-[11px] text-muted-foreground">
              {t("campaign.progress.unresolved", { count: row.original.progress.unresolved })}
            </p>
          </div>
        ),
      },
    ],
    [ago, t],
  );

  return (
    <DataTable
      columns={columns}
      data={rows}
      isLoading={query.isLoading}
      error={query.error}
      emptyMessage={t("campaign.list.empty")}
      loadingMessage={t("campaign.loading")}
      serverPagination={{
        offset: pagination.offset,
        limit: pagination.limit,
        total,
        onOffsetChange: pagination.setOffset,
        search: pagination.search,
        searchRevision: pagination.searchRevision,
        onSearchChange: pagination.setSearch,
        sortableColumns: [],
        sort: pagination.sort,
        order: pagination.order,
        onSortChange: pagination.setSort,
      }}
    />
  );
}

function CampaignsInner() {
  const t = useT();
  const id = (useSearchParams().get("id") || "").trim();
  return (
    <div className="space-y-6">
      {id ? (
        <CampaignDetail id={id} />
      ) : (
        <>
          <div className="border-b border-border pb-4">
            <div className="flex items-center gap-2.5">
              <ListChecks className="h-5 w-5 text-sky-600 dark:text-sky-400" />
              <h1 className="text-2xl font-extrabold tracking-tight">{t("campaign.page.title")}</h1>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{t("campaign.page.subtitle")}</p>
          </div>
          <CampaignList />
        </>
      )}
    </div>
  );
}

export default function CampaignsPage() {
  return (
    <Suspense fallback={<p className="text-sm text-muted-foreground">…</p>}>
      <CampaignsInner />
    </Suspense>
  );
}
