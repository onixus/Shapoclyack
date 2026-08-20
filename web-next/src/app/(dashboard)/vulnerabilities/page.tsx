"use client";

import Link from "next/link";
import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { type ColumnDef } from "@tanstack/react-table";
import { formatDistanceToNow, isValid, parseISO } from "date-fns";
import { ArrowUpRight, Filter, ShieldAlert } from "lucide-react";
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
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { usePagination } from "@/hooks/use-pagination";
import { useTrackedVulnerabilities, useVulnerabilitySummary } from "@/hooks/use-vulnerabilities";
import type { SlaState, TrackedVulnerability, VulnLifecycleState } from "@/lib/api";
import { SEVERITY_STATUS, VULN_LIFECYCLE_STATUS } from "@/lib/config/statuses";
import { normalizeSeverity, SEVERITIES } from "@/lib/run-data";
import {
  assetDetailHref,
  findingLabel,
  SLA_STATES,
  VULN_STATES,
  vulnDetailHref,
} from "@/lib/vuln-lifecycle";

const FILTER_ALL = "all";
const OPEN_WORKING_SET = "open";
const ALL_STATES = "any";

function relativeTime(value: string | null): string {
  if (!value) return "—";
  const parsed = parseISO(value);
  if (!isValid(parsed)) return value;
  return formatDistanceToNow(parsed, { addSuffix: true });
}

function VulnerabilitiesInner() {
  const t = useT();
  const searchParams = useSearchParams();
  const initialAssetId = (searchParams.get("assetId") || "").trim();
  const initialSla = (searchParams.get("sla") || "") as SlaState | "";
  const initialState = (searchParams.get("state") || "") as VulnLifecycleState | "";
  const initialSeverity = (searchParams.get("severity") || "").trim();
  const initialUnassigned = searchParams.get("unassigned") === "1";

  const [scope, setScope] = useState<"open" | "all">(initialState ? "all" : OPEN_WORKING_SET);
  const [state, setState] = useState<VulnLifecycleState | "">(initialState);
  const [severity, setSeverity] = useState(initialSeverity);
  const [sla, setSla] = useState<SlaState | "">(initialSla);
  const [staleDays, setStaleDays] = useState("");
  const [unassigned, setUnassigned] = useState(initialUnassigned);
  const assetId = initialAssetId;

  const pagination = usePagination({ sort: "contextual_score", order: "desc" });
  const filters = {
    state,
    open_only: scope === "open" && !state,
    severity,
    asset_id: assetId || undefined,
    unassigned: unassigned || undefined,
    sla,
    stale_days: staleDays ? Number(staleDays) : undefined,
  };
  const listQuery = useTrackedVulnerabilities(filters, pagination.params);
  const summaryQuery = useVulnerabilitySummary();
  const data = listQuery.data?.items ?? [];
  const total = listQuery.data?.total ?? 0;
  const summary = summaryQuery.data;

  const columns = useMemo<ColumnDef<TrackedVulnerability>[]>(
    () => [
      {
        id: "cve",
        accessorFn: (row) => findingLabel(row),
        header: t("col.finding"),
        cell: ({ row }) => (
          <Link
            href={vulnDetailHref(row.original.vuln_id, row.original.tenant_id)}
            className="group space-y-0.5"
          >
            <div className="flex items-center gap-1.5 font-mono font-bold text-sky-400 group-hover:text-sky-300 group-hover:underline">
              <span>{findingLabel(row.original)}</span>
              <ArrowUpRight className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
            </div>
            <span className="block text-[11px] text-slate-400">
              {row.original.port ? `port ${row.original.port}` : "no port"}
              {row.original.script_id && row.original.cve ? ` · ${row.original.script_id}` : ""}
            </span>
          </Link>
        ),
      },
      {
        accessorKey: "severity",
        header: t("col.severity"),
        cell: ({ row }) => (
          <StatusBadge value={normalizeSeverity(row.original.severity)} map={SEVERITY_STATUS} />
        ),
      },
      {
        accessorKey: "state",
        header: t("col.lifecycle"),
        cell: ({ row }) => <StatusBadge value={row.original.state} map={VULN_LIFECYCLE_STATUS} />,
      },
      {
        accessorKey: "sla_state",
        header: t("col.sla"),
        cell: ({ row }) => (
          <SlaIndicator slaState={row.original.sla_state} dueAt={row.original.due_at} />
        ),
      },
      {
        accessorKey: "assignee",
        header: t("col.owner"),
        cell: ({ row }) =>
          row.original.assignee || row.original.owner_team ? (
            <div className="space-y-0.5">
              <p className="text-xs text-slate-200">{row.original.assignee || "—"}</p>
              {row.original.owner_team ? (
                <p className="text-[11px] text-slate-400">{row.original.owner_team}</p>
              ) : null}
            </div>
          ) : (
            <span className="text-xs text-slate-500">{t("common.unassigned")}</span>
          ),
      },
      {
        id: "asset_id",
        accessorKey: "asset_id",
        header: t("col.asset"),
        cell: ({ row }) => (
          <Link
            href={assetDetailHref(row.original.asset_id, row.original.tenant_id)}
            className="font-mono text-[11px] text-slate-300 hover:text-sky-300 hover:underline"
          >
            {row.original.asset_id}
          </Link>
        ),
      },
      {
        accessorKey: "last_seen_at",
        header: t("col.lastSeen"),
        cell: ({ row }) => (
          <span className="text-xs text-slate-400">{relativeTime(row.original.last_seen_at)}</span>
        ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <Button
            asChild
            variant="outline"
            size="sm"
            className="h-7 text-xs border-slate-800 bg-slate-900 text-sky-400 hover:bg-slate-800 hover:text-white"
          >
            <Link href={vulnDetailHref(row.original.vuln_id, row.original.tenant_id)}>{t("common.view")}</Link>
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
            <ShieldAlert className="h-5 w-5 text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">
              {t("page.vulns.title")}
            </h1>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            {t("page.vulns.subtitle")}
            {listQuery.isFetching ? t("common.refreshing") : ""}
            {assetId ? (
              <>
                {" "}
                Filtered to asset{" "}
                <Link
                  href={assetDetailHref(assetId)}
                  className="font-mono text-sky-400 hover:underline"
                >
                  {assetId}
                </Link>
                .
              </>
            ) : null}
          </p>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Open findings"
          value={summaryQuery.isLoading ? "…" : (summary?.open_total ?? 0)}
          hint={summary ? `${summary.untriaged} still untriaged` : undefined}
          decorationColor="sky"
        />
        <KpiCard
          label="Critical / high (open)"
          value={
            summaryQuery.isLoading
              ? "…"
              : (summary?.by_severity_open.critical ?? 0) + (summary?.by_severity_open.high ?? 0)
          }
          hint={
            summary
              ? `${summary.by_severity_open.critical ?? 0} critical · ${summary.by_severity_open.high ?? 0} high`
              : undefined
          }
          decorationColor="orange"
        />
        <KpiCard
          label="SLA breached"
          value={summaryQuery.isLoading ? "…" : (summary?.breached ?? 0)}
          hint={
            summary?.worst_breached_severity
              ? `worst open: ${summary.worst_breached_severity}`
              : "no open breaches"
          }
          decorationColor="rose"
        />
        <KpiCard
          label="Due soon"
          value={summaryQuery.isLoading ? "…" : (summary?.by_sla.due_soon ?? 0)}
          hint="within 7 days"
          decorationColor="amber"
        />
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={listQuery.isLoading}
        error={listQuery.error}
        initialSorting={[{ id: "contextual_score", desc: true }]}
        searchPlaceholder="Filter by CVE, script, asset or assignee…"
        toolbar={
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="h-4 w-4 text-slate-400" />
            <Select
              value={scope}
              onValueChange={(value) => {
                setScope(value as "open" | "all");
                if (value === "open") setState("");
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-40 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={OPEN_WORKING_SET}>Open only</SelectItem>
                <SelectItem value="all">All findings</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={state || ALL_STATES}
              onValueChange={(value) => {
                setState(value === ALL_STATES ? "" : (value as VulnLifecycleState));
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-44 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="Any state" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={ALL_STATES}>Any state</SelectItem>
                {VULN_STATES.map((item) => (
                  <SelectItem key={item} value={item}>
                    {VULN_LIFECYCLE_STATUS[item].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={severity || FILTER_ALL}
              onValueChange={(value) => {
                setSeverity(value === FILTER_ALL ? "" : value);
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-36 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={FILTER_ALL}>Any severity</SelectItem>
                {SEVERITIES.map((item) => (
                  <SelectItem key={item} value={item}>
                    {item}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={sla || FILTER_ALL}
              onValueChange={(value) => {
                setSla(value === FILTER_ALL ? "" : (value as SlaState));
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-40 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="SLA" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={FILTER_ALL}>Any SLA</SelectItem>
                {SLA_STATES.map((item) => (
                  <SelectItem key={item} value={item}>
                    {item.replace("_", " ")}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={unassigned ? "unassigned" : FILTER_ALL}
              onValueChange={(value) => {
                setUnassigned(value === "unassigned");
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-40 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="Owner" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={FILTER_ALL}>Any owner</SelectItem>
                <SelectItem value="unassigned">{t("common.unassigned")}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={staleDays || FILTER_ALL}
              onValueChange={(value) => {
                setStaleDays(value === FILTER_ALL ? "" : value);
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-40 bg-slate-900 border-slate-800 text-slate-200">
                <SelectValue placeholder="Stale" />
              </SelectTrigger>
              <SelectContent className="bg-slate-900 border-slate-800 text-slate-200">
                <SelectItem value={FILTER_ALL}>Any recency</SelectItem>
                <SelectItem value="14">Stale 14+ days</SelectItem>
                <SelectItem value="30">Stale 30+ days</SelectItem>
                <SelectItem value="90">Stale 90+ days</SelectItem>
              </SelectContent>
            </Select>
          </div>
        }
        meta={`${total.toLocaleString()} finding${total === 1 ? "" : "s"}`}
        loadingMessage="Retrieving tracked vulnerabilities…"
        emptyMessage="No tracked findings match these filters. Findings appear here after a scan observes them against an asset."
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: [
            "cve",
            "severity",
            "state",
            "due_at",
            "last_seen_at",
            "first_seen_at",
            "contextual_score",
          ],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />
    </div>
  );
}

export default function VulnerabilitiesPage() {
  return (
    <Suspense fallback={<p className="text-sm text-slate-400">Loading Vulnerability Center…</p>}>
      <VulnerabilitiesInner />
    </Suspense>
  );
}
