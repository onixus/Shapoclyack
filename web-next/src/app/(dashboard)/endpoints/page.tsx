"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { ArrowUpRight, History, Laptop } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
import { useRelativeTime } from "@/lib/i18n/datetime";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { DataTable } from "@/components/data-table";
import { PatchGapPanel } from "@/components/endpoint/patch-gap-panel";
import { StatusBadge } from "@/components/status-badge";
import { useEndpointDevices, useRecentSoftwareChanges } from "@/hooks/use-endpoint-inventory";
import { useSystemStatus } from "@/hooks/use-system";
import type { EndpointDeviceInfo, EndpointReconciliationStatus } from "@/lib/api";
import { ENDPOINT_RECONCILIATION_STATUS, SOFTWARE_CHANGE_STATUS } from "@/lib/config/statuses";
import { useAuthStore } from "@/lib/auth-store";

const FILTER_ALL = "all";

function assetHref(assetId: string, tenantId: string): string {
  const params = new URLSearchParams({ assetId });
  if (tenantId && tenantId !== "default") params.set("tenantId", tenantId);
  return `/assets/view?${params}`;
}

/** Lightweight cross-device feed of recent software installs/removals/updates
 * (issue #98 Phase 3) — the per-device equivalent lives on the asset's
 * Endpoint/Software tab. */
function RecentChangesFeed({ tenantId }: { tenantId: string }) {
  const t = useT();
  const ago = useRelativeTime();
  const changesQuery = useRecentSoftwareChanges(tenantId, 30);
  const changes = changesQuery.data || [];

  return (
    <div className="rounded-xl border border-border bg-card text-card-foreground">
      <div className="flex items-center gap-2 border-b border-border px-4 py-3">
        <History className="h-4 w-4 text-muted-foreground" />
        <h2 className="text-sm font-bold text-foreground">{t("page.endpoints.recent")}</h2>
      </div>
      <div className="max-h-72 overflow-y-auto">
        {changesQuery.isLoading ? (
          <p className="px-4 py-4 text-xs text-muted-foreground">{t("common.loading")}</p>
        ) : changesQuery.error ? (
          <p className="px-4 py-4 text-xs text-destructive">
            {(changesQuery.error as Error).message}
          </p>
        ) : changes.length === 0 ? (
          <p className="px-4 py-4 text-xs text-muted-foreground">
            {t("page.endpoints.noChanges")}
          </p>
        ) : (
          <ul className="divide-y divide-border">
            {changes.map((change, idx) => (
              <li
                key={`${change.device_id}-${change.snapshot_id}-${change.display_name}-${idx}`}
                className="flex items-center justify-between gap-3 px-4 py-2 text-xs"
              >
                <div className="flex min-w-0 items-center gap-2">
                  <StatusBadge value={change.event_type} map={SOFTWARE_CHANGE_STATUS} />
                  <span className="truncate font-mono text-foreground">{change.display_name}</span>
                  <span className="shrink-0 text-muted-foreground">
                    {t("page.endpoints.changeOn")}
                  </span>
                  {change.asset_id ? (
                    <Link
                      href={assetHref(change.asset_id, tenantId)}
                      className="shrink-0 truncate font-mono text-primary hover:underline"
                    >
                      {change.hostname}
                    </Link>
                  ) : (
                    <span className="shrink-0 truncate font-mono text-muted-foreground">
                      {change.hostname}
                    </span>
                  )}
                </div>
                <span className="shrink-0 text-muted-foreground">{ago(change.observed_at)}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export default function EndpointsPage() {
  const t = useT();
  const [reconFilter, setReconFilter] = useState<string>(FILTER_ALL);
  const [staleOnly, setStaleOnly] = useState(false);

  // Tenant comes from the header switcher (ROADMAP P0) rather than a
  // page-local selector, so every page agrees on which tenant is in view.
  const { activeTenant } = useAuthStore();
  const tenantId = activeTenant ?? "default";

  const staleHours = useSystemStatus().data?.endpoint_inventory.stale_hours ?? 48;

  const devicesQuery = useEndpointDevices(tenantId);
  const raw = useMemo(() => devicesQuery.data || [], [devicesQuery.data]);

  const data = useMemo(() => {
    return raw.filter((d) => {
      if (reconFilter !== FILTER_ALL && d.reconciliation_status !== reconFilter) return false;
      // Staleness is server-derived from OCTO_ENDPOINT_STALE_HOURS (S9).
      if (staleOnly && d.status !== "stale") return false;
      return true;
    });
  }, [raw, reconFilter, staleOnly]);

  const ago = useRelativeTime();

  const columns = useMemo<ColumnDef<EndpointDeviceInfo>[]>(
    () => [
      {
        id: "host",
        accessorFn: (row) => `${row.hostname} ${row.device_id}`,
        header: t("col.hostname"),
        cell: ({ row }) => (
          <div className="space-y-0.5">
            <p className="font-mono font-bold text-foreground">{row.original.hostname || "—"}</p>
            <p className="font-mono text-[10px] text-muted-foreground">{row.original.device_id}</p>
          </div>
        ),
      },
      {
        id: "os",
        accessorFn: (row) => [row.os_name, row.os_version, row.os_arch].filter(Boolean).join(" "),
        header: t("col.os"),
        cell: ({ row }) => {
          const d = row.original;
          const label = [d.os_name, d.os_version].filter(Boolean).join(" ") || "—";
          return (
            <div className="space-y-0.5">
              <p className="text-sm text-foreground">{label}</p>
              <p className="text-[10px] text-muted-foreground">
                {[d.os_family, d.os_arch].filter(Boolean).join(" · ") || "—"}
              </p>
            </div>
          );
        },
      },
      {
        accessorKey: "reconciliation_status",
        header: t("col.correlation"),
        cell: ({ row }) => (
          <StatusBadge
            value={row.original.reconciliation_status}
            map={ENDPOINT_RECONCILIATION_STATUS}
          />
        ),
      },
      {
        id: "asset",
        accessorFn: (row) => row.asset_id || "",
        header: t("col.networkAsset"),
        cell: ({ row }) => {
          const id = row.original.asset_id;
          if (!id) {
            return <span className="text-xs text-muted-foreground">{t("common.notLinked")}</span>;
          }
          return (
            <Link
              href={assetHref(id, tenantId)}
              className="group inline-flex items-center gap-1 font-mono text-xs font-semibold text-primary hover:underline"
            >
              <span className="max-w-[10rem] truncate">{id}</span>
              <ArrowUpRight className="h-3 w-3 opacity-70 group-hover:opacity-100" />
            </Link>
          );
        },
      },
      {
        accessorKey: "agent_version",
        header: t("col.lariska"),
        cell: ({ getValue }) => (
          <code className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-[11px] text-primary">
            {String(getValue() || "—")}
          </code>
        ),
      },
      {
        accessorKey: "last_inventory_at",
        header: t("col.lastInventory"),
        sortingFn: "datetime",
        cell: ({ getValue }) => {
          const v = getValue();
          if (!v) return <span className="text-muted-foreground">{t("common.never")}</span>;
          return <span className="text-xs text-foreground">{ago(String(v))}</span>;
        },
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => {
          const id = row.original.asset_id;
          if (!id) return null;
          return (
            <Button
              asChild
              variant="outline"
              size="sm"
              className="h-7 text-xs"
            >
              <Link href={assetHref(id, tenantId)}>{t("common.openAsset")}</Link>
            </Button>
          );
        },
      },
    ],
    [ago, t, tenantId],
  );

  const linked = raw.filter((d) => d.asset_id).length;
  const conflicts = raw.filter((d) => d.reconciliation_status === "conflict").length;
  const stale = raw.filter((d) => d.status === "stale").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/20 bg-sky-500/10 text-sky-600 dark:text-sky-400 shadow-md">
            <Laptop className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold tracking-tight text-foreground">{t("page.endpoints.title")}</h1>
            <p className="text-xs text-muted-foreground">
              {t("page.endpoints.lariskaHint")}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          <span>
            {t("common.devices", { count: raw.length })}
          </span>
          <span className="font-semibold text-emerald-600 dark:text-emerald-400">
            {t("common.linked", { count: linked })}
          </span>
          {conflicts > 0 ? (
            <span className="font-semibold text-destructive">
              {t("page.endpoints.conflicts", { count: conflicts })}
            </span>
          ) : null}
          {stale > 0 ? (
            <span className="font-semibold text-amber-600 dark:text-amber-400">
              {t("page.endpoints.staleCount", { count: stale })}
            </span>
          ) : null}
          <Button
            variant="outline"
            size="sm"
            onClick={() => setStaleOnly((v) => !v)}
            className={`h-8 text-xs ${
              staleOnly ? "border-amber-500/60 text-amber-600 dark:text-amber-300" : ""
            }`}
          >
            {staleOnly
              ? t("page.endpoints.staleOnly", { hours: staleHours })
              : t("page.endpoints.showStaleOnly")}
          </Button>
          <Select value={reconFilter} onValueChange={setReconFilter}>
            <SelectTrigger className="h-8 w-[160px] text-xs">
              <SelectValue placeholder={t("page.endpoints.filter")} />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={FILTER_ALL}>{t("page.endpoints.filterAllStatuses")}</SelectItem>
              {(Object.keys(ENDPOINT_RECONCILIATION_STATUS) as EndpointReconciliationStatus[]).map(
                (status) => (
                  <SelectItem key={status} value={status}>
                    {t.label(ENDPOINT_RECONCILIATION_STATUS[status].label)}
                  </SelectItem>
                ),
              )}
            </SelectContent>
          </Select>
        </div>
      </div>

      <p className="max-w-3xl text-xs leading-relaxed text-muted-foreground">
        {t("page.endpoints.note", { linked: t.label("linked") })}
      </p>

      <PatchGapPanel tenantId={tenantId} />

      <RecentChangesFeed tenantId={tenantId} />

      <DataTable
        columns={columns}
        data={data}
        isLoading={devicesQuery.isLoading}
        error={devicesQuery.error ? (devicesQuery.error as Error).message : null}
        emptyMessage={
          raw.length > 0
            ? "No endpoints match the current filters."
            : "No Lariska endpoints yet. Install the endpoint agent with a tenant provisioning key."
        }
        searchPlaceholder={t("search.endpoints")}
        meta={
          devicesQuery.isFetching && !devicesQuery.isLoading ? "Refreshing…" : undefined
        }
      />
    </div>
  );
}
