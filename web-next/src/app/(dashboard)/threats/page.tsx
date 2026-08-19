"use client";

import Link from "next/link";
import { useMemo } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { Siren } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { usePagination } from "@/hooks/use-pagination";
import { useTrackedVulnerabilities } from "@/hooks/use-vulnerabilities";
import type { TrackedVulnerability } from "@/lib/api";
import { RISK_LEVEL_STATUS, SEVERITY_STATUS, VULN_LIFECYCLE_STATUS } from "@/lib/config/statuses";
import { normalizeSeverity } from "@/lib/run-data";
import { assetDetailHref, findingLabel, vulnDetailHref } from "@/lib/vuln-lifecycle";

export default function ThreatsPage() {
  const pagination = usePagination({ sort: "contextual_score", order: "desc" });
  const listQuery = useTrackedVulnerabilities(
    { open_only: true, in_kev: true },
    pagination.params,
  );
  const data = listQuery.data?.items ?? [];
  const total = listQuery.data?.total ?? 0;

  const columns = useMemo<ColumnDef<TrackedVulnerability>[]>(
    () => [
      {
        id: "cve",
        accessorFn: (row) => findingLabel(row),
        header: "Finding",
        cell: ({ row }) => (
          <Link href={vulnDetailHref(row.original.vuln_id, row.original.tenant_id)} className="space-y-0.5">
            <p className="font-mono font-bold text-sky-400 hover:underline">{findingLabel(row.original)}</p>
            <p className="text-[11px] text-slate-400">
              {row.original.exploit_maturity ? row.original.exploit_maturity.replaceAll("_", " ") : "KEV"}
              {row.original.port ? ` · port ${row.original.port}` : ""}
            </p>
          </Link>
        ),
      },
      {
        accessorKey: "severity",
        header: "Severity",
        cell: ({ row }) => (
          <StatusBadge value={normalizeSeverity(row.original.severity)} map={SEVERITY_STATUS} />
        ),
      },
      {
        accessorKey: "risk_level",
        header: "NIST",
        cell: ({ row }) =>
          row.original.risk_level && row.original.risk_level in RISK_LEVEL_STATUS ? (
            <StatusBadge value={row.original.risk_level} map={RISK_LEVEL_STATUS} />
          ) : (
            <span className="text-xs text-slate-500">unset</span>
          ),
      },
      {
        accessorKey: "state",
        header: "Lifecycle",
        cell: ({ row }) => <StatusBadge value={row.original.state} map={VULN_LIFECYCLE_STATUS} />,
      },
      {
        accessorKey: "sla_state",
        header: "SLA",
        cell: ({ row }) => <SlaIndicator slaState={row.original.sla_state} dueAt={row.original.due_at} />,
      },
      {
        id: "asset_id",
        header: "Asset",
        cell: ({ row }) => (
          <Link
            href={assetDetailHref(row.original.asset_id, row.original.tenant_id)}
            className="font-mono text-[11px] text-slate-300 hover:text-sky-300"
          >
            {row.original.asset_id}
          </Link>
        ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <Button asChild variant="outline" size="sm" className="h-7 text-xs border-slate-800">
            <Link href={vulnDetailHref(row.original.vuln_id, row.original.tenant_id)}>Act</Link>
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
            <Siren className="h-5 w-5 text-rose-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Threat intel</h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Open tracked findings currently on CISA KEV, with the latest observation&apos;s
            exploit maturity. This is the working set, not the last scan&apos;s raw list.
          </p>
        </div>
      </div>

      <Alert className="border-rose-500/30 bg-rose-950/20 text-rose-100">
        <AlertDescription className="text-xs">
          KEV membership is copied from the last observation onto the tracked finding, so it
          survives run pruning. Attack-path chaining is not modelled.
        </AlertDescription>
      </Alert>

      <DataTable
        columns={columns}
        data={data}
        isLoading={listQuery.isLoading}
        error={listQuery.error}
        searchPlaceholder="Filter by CVE, script, asset or owner…"
        meta={`${total.toLocaleString()} open KEV finding${total === 1 ? "" : "s"}`}
        loadingMessage="Loading KEV findings…"
        emptyMessage="No open tracked findings are on CISA KEV right now."
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["contextual_score", "severity", "last_seen_at"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />
    </div>
  );
}
