"use client";

import { EndpointDeviceCard } from "@/components/endpoint/endpoint-device-card";
import { EndpointError } from "@/components/endpoint/endpoint-error";
import { SystemTechnicalDetails } from "@/components/system-technical-details";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import {
  endpointText,
  endpointFamily,
  endpointArchitecture,
  endpointReconciliation,
  endpointFreshness,
} from "@/lib/endpoint-presentation";
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
import { SourceCompleteness } from "@/components/endpoint/source-completeness";
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
          <div className="px-4 py-4">
            <EndpointError error={changesQuery.error} message="Failed to load software changes." />
          </div>
        ) : changes.length === 0 ? (
          <p className="px-4 py-4 text-xs text-muted-foreground">{t("page.endpoints.noChanges")}</p>
        ) : (
          <ul className="divide-y divide-border">
            {changes.map((change, idx) => (
              <li
                key={`${change.device_id}-${change.snapshot_id}-${change.display_name}-${idx}`}
                className="flex flex-wrap items-center justify-between gap-3 px-4 py-2 text-xs"
              >
                <div className="flex min-w-0 items-center gap-2">
                  <StatusBadge
                    value={change.event_type}
                    map={SOFTWARE_CHANGE_STATUS}
                    fallback={{
                      label: endpointText(t.locale, "Other state"),
                      variant: "secondary",
                    }}
                  />
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
                <div className="shrink-0 text-muted-foreground">
                  {ago(change.observed_at)}
                  <SystemTechnicalDetails data={change} />
                </div>
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
  const [selectedDevice, setSelectedDevice] = useState<{
    device: EndpointDeviceInfo;
    tenant: string;
  } | null>(null);
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
            <p className="break-all font-mono font-bold text-foreground">
              {row.original.hostname || endpointText(t.locale, "Device name unavailable")}
            </p>
            <SystemTechnicalDetails data={row.original} />
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
              <p className="text-xs text-muted-foreground">
                {[
                  endpointFamily(t.locale, d.os_family),
                  endpointArchitecture(t.locale, d.os_arch),
                ].join(" · ")}
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
            map={
              t.locale === "ru"
                ? Object.fromEntries(
                    Object.entries(ENDPOINT_RECONCILIATION_STATUS).map(([key, style]) => [
                      key,
                      { ...style, label: endpointReconciliation(t.locale, key) },
                    ]),
                  )
                : ENDPOINT_RECONCILIATION_STATUS
            }
            fallback={{
              label: endpointReconciliation(t.locale, row.original.reconciliation_status),
              variant: "secondary",
            }}
          />
        ),
      },
      {
        id: "freshness",
        accessorFn: (row) => row.status,
        header: endpointText(t.locale, "Inventory freshness"),
        cell: ({ row }) => (
          <span>
            {endpointFreshness(t.locale, row.original.status, row.original.last_inventory_at)}
          </span>
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
              <span>{t("common.openAsset")}</span>
              <ArrowUpRight className="h-3 w-3 opacity-70 group-hover:opacity-100" />
            </Link>
          );
        },
      },
      {
        accessorKey: "agent_version",
        header: t("col.lariska"),
        cell: ({ getValue }) => (
          <code className="rounded border border-border bg-muted px-1.5 py-0.5 font-mono text-xs text-primary">
            {String(getValue() || "—")}
          </code>
        ),
      },
      {
        accessorKey: "last_inventory_at",
        header: t("col.lastInventory"),
        sortingFn: "datetime",
        cell: ({ getValue, row }) => {
          const v = getValue();
          if (!v) return <span className="text-muted-foreground">{t("common.never")}</span>;
          return (
            <div>
              <span className="text-xs text-foreground">{ago(String(v))}</span>
              <SourceCompleteness sources={row.original.sources} />
            </div>
          );
        },
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => {
          const id = row.original.asset_id;
          return (
            <div className="flex flex-wrap gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs"
                onClick={() => setSelectedDevice({ device: row.original, tenant: tenantId })}
              >
                {endpointText(t.locale, "Open device card")}
              </Button>
              {id && (
                <Button asChild variant="outline" size="sm" className="h-7 text-xs">
                  <Link href={assetHref(id, tenantId)}>{t("common.openAsset")}</Link>
                </Button>
              )}
            </div>
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
            <h1 className="text-xl font-extrabold tracking-tight text-foreground">
              {t("page.endpoints.title")}
            </h1>
            <p className="text-xs text-muted-foreground">{t("page.endpoints.lariskaHint")}</p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          <span>{t("common.devices", { count: raw.length })}</span>
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
                    {t.locale === "ru"
                      ? endpointReconciliation(t.locale, status)
                      : t.label(ENDPOINT_RECONCILIATION_STATUS[status].label)}
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

      <EndpointError error={devicesQuery.error} message="Failed to load endpoint data." />
      <DataTable
        columns={columns}
        data={data}
        isLoading={devicesQuery.isLoading}
        error={
          t.locale === "ru"
            ? null
            : devicesQuery.error
              ? (devicesQuery.error as Error).message
              : null
        }
        emptyMessage={
          devicesQuery.error
            ? endpointText(t.locale, "Endpoint data unavailable.")
            : raw.length > 0
              ? endpointText(t.locale, "No endpoints match the current filters.")
              : endpointText(
                  t.locale,
                  "No Lariska endpoints yet. Install the endpoint agent with a tenant provisioning key.",
                )
        }
        searchPlaceholder={t("search.endpoints")}
        meta={
          devicesQuery.isFetching && !devicesQuery.isLoading
            ? endpointText(t.locale, "Refreshing…")
            : undefined
        }
      />
      <Dialog
        open={Boolean(selectedDevice && selectedDevice.tenant === tenantId)}
        onOpenChange={(open) => {
          if (!open) setSelectedDevice(null);
        }}
      >
        <DialogContent className="max-h-[90vh] min-w-0 max-w-3xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{endpointText(t.locale, "Device card")}</DialogTitle>
            <DialogDescription>
              {endpointText(
                t.locale,
                "Device inventory and its link to a network asset. Viewing does not change device data.",
              )}
            </DialogDescription>
          </DialogHeader>
          {selectedDevice && selectedDevice.tenant === tenantId && (
            <EndpointDeviceCard device={selectedDevice.device} />
          )}
          <Button variant="outline" onClick={() => setSelectedDevice(null)}>
            {endpointText(t.locale, "Close")}
          </Button>
        </DialogContent>
      </Dialog>
    </div>
  );
}
