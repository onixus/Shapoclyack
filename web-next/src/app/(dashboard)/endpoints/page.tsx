"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow } from "date-fns";
import { ArrowUpRight, Laptop } from "lucide-react";
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
import { useEndpointDevices } from "@/hooks/use-endpoint-inventory";
import type { EndpointDeviceInfo, EndpointReconciliationStatus } from "@/lib/api";
import { ENDPOINT_RECONCILIATION_STATUS } from "@/lib/config/statuses";

const FILTER_ALL = "all";

function assetHref(assetId: string): string {
  return `/assets/view?assetId=${encodeURIComponent(assetId)}`;
}

export default function EndpointsPage() {
  const [reconFilter, setReconFilter] = useState<string>(FILTER_ALL);
  const devicesQuery = useEndpointDevices();
  const raw = useMemo(() => devicesQuery.data || [], [devicesQuery.data]);

  const data = useMemo(() => {
    if (reconFilter === FILTER_ALL) return raw;
    return raw.filter((d) => d.reconciliation_status === reconFilter);
  }, [raw, reconFilter]);

  const columns = useMemo<ColumnDef<EndpointDeviceInfo>[]>(
    () => [
      {
        id: "host",
        accessorFn: (row) => `${row.hostname} ${row.device_id}`,
        header: "Hostname",
        cell: ({ row }) => (
          <div className="space-y-0.5">
            <p className="font-mono font-bold text-slate-100">{row.original.hostname || "—"}</p>
            <p className="font-mono text-[10px] text-slate-500">{row.original.device_id}</p>
          </div>
        ),
      },
      {
        id: "os",
        accessorFn: (row) => [row.os_name, row.os_version, row.os_arch].filter(Boolean).join(" "),
        header: "OS",
        cell: ({ row }) => {
          const d = row.original;
          const label = [d.os_name, d.os_version].filter(Boolean).join(" ") || "—";
          return (
            <div className="space-y-0.5">
              <p className="text-sm text-slate-200">{label}</p>
              <p className="text-[10px] text-slate-500">
                {[d.os_family, d.os_arch].filter(Boolean).join(" · ") || "—"}
              </p>
            </div>
          );
        },
      },
      {
        accessorKey: "reconciliation_status",
        header: "Correlation",
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
        header: "Network asset",
        cell: ({ row }) => {
          const id = row.original.asset_id;
          if (!id) {
            return <span className="text-xs text-slate-500">not linked</span>;
          }
          return (
            <Link
              href={assetHref(id)}
              className="group inline-flex items-center gap-1 font-mono text-xs font-semibold text-sky-400 hover:text-sky-300 hover:underline"
            >
              <span className="max-w-[10rem] truncate">{id}</span>
              <ArrowUpRight className="h-3 w-3 opacity-70 group-hover:opacity-100" />
            </Link>
          );
        },
      },
      {
        accessorKey: "agent_version",
        header: "Lariska",
        cell: ({ getValue }) => (
          <code className="rounded border border-slate-800 bg-slate-950 px-1.5 py-0.5 font-mono text-[11px] text-sky-400">
            {String(getValue() || "—")}
          </code>
        ),
      },
      {
        accessorKey: "last_inventory_at",
        header: "Last inventory",
        sortingFn: "datetime",
        cell: ({ getValue }) => {
          const v = getValue();
          if (!v) return <span className="text-slate-500">never</span>;
          return (
            <span className="text-xs text-slate-300">
              {formatDistanceToNow(new Date(String(v)), { addSuffix: true })}
            </span>
          );
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
              className="h-7 border-slate-800 bg-slate-900 text-xs text-sky-400 hover:bg-slate-800 hover:text-white"
            >
              <Link href={assetHref(id)}>Open asset</Link>
            </Button>
          );
        },
      },
    ],
    [],
  );

  const linked = raw.filter((d) => d.asset_id).length;
  const conflicts = raw.filter((d) => d.reconciliation_status === "conflict").length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/20 bg-sky-500/10 text-sky-400 shadow-md">
            <Laptop className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-xl font-extrabold tracking-tight text-slate-100">Endpoints</h1>
            <p className="text-xs text-slate-400">
              Lariska agents · software inventory correlated to network assets
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
          <span>
            <span className="font-semibold text-slate-200">{raw.length}</span> devices
          </span>
          <span>
            <span className="font-semibold text-emerald-400">{linked}</span> linked
          </span>
          {conflicts > 0 ? (
            <span>
              <span className="font-semibold text-rose-400">{conflicts}</span> conflict
            </span>
          ) : null}
          <Select value={reconFilter} onValueChange={setReconFilter}>
            <SelectTrigger className="h-8 w-[140px] border-slate-800 bg-slate-900 text-xs">
              <SelectValue placeholder="Filter" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={FILTER_ALL}>All statuses</SelectItem>
              {(Object.keys(ENDPOINT_RECONCILIATION_STATUS) as EndpointReconciliationStatus[]).map(
                (s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ),
              )}
            </SelectContent>
          </Select>
        </div>
      </div>

      <p className="max-w-3xl text-xs leading-relaxed text-slate-500">
        Each row is a Lariska-managed host. <strong className="text-slate-400">linked</strong> means
        inventory is attached to a network-scan asset (by hostname / identifiers). Open the asset to
        see Pulse vulns, ports, and installed software together.
      </p>

      <DataTable
        columns={columns}
        data={data}
        isLoading={devicesQuery.isLoading}
        error={devicesQuery.error ? (devicesQuery.error as Error).message : null}
        emptyMessage="No Lariska endpoints yet. Install the agent with a tenant provisioning key."
        searchPlaceholder="Filter hostname, OS, agent…"
        meta={
          devicesQuery.isFetching && !devicesQuery.isLoading ? "Refreshing…" : undefined
        }
      />
    </div>
  );
}
