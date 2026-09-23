"use client";

import Link from "next/link";
import { Suspense, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { type ColumnDef } from "@tanstack/react-table";
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
import { VulnerabilityBulkActions } from "@/components/vulnerability/bulk-actions";
import { RetroMatchCard } from "@/components/vulnerability/retro-match-card";
import { useT } from "@/lib/i18n";
import { useRelativeTime } from "@/lib/i18n/datetime";
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
import { SlaIndicator } from "@/components/vulnerability/sla-indicator";
import { useBulkSelection } from "@/hooks/use-bulk-actions";
import { usePagination } from "@/hooks/use-pagination";
import { useTrackedVulnerabilities, useVulnerabilitySummary } from "@/hooks/use-vulnerabilities";
import { MAX_BULK_IDS } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import type {
  SlaState,
  TrackedVulnerability,
  VulnerabilitySource,
  NetworkExposure,
  VulnLifecycleState,
} from "@/lib/api";
import {
  RETRO_MATCH_CONFIDENCE,
  SEVERITY_STATUS,
  VULN_LIFECYCLE_STATUS,
  VULN_SOURCE_STATUS,
} from "@/lib/config/statuses";
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

function VulnerabilitiesInner() {
  const t = useT();
  const ago = useRelativeTime();
  const { canOperate } = useAuthStore();
  const searchParams = useSearchParams();
  const initialAssetId = (searchParams.get("assetId") || "").trim();
  const initialSla = (searchParams.get("sla") || "") as SlaState | "";
  const initialState = (searchParams.get("state") || "") as VulnLifecycleState | "";
  const initialSeverity = (searchParams.get("severity") || "").trim();
  const initialUnassigned = searchParams.get("unassigned") === "1";
  const initialSource = (searchParams.get("source") || "") as VulnerabilitySource | "";
  const initialExposure = (searchParams.get("exposure") || "") as NetworkExposure | "";

  const [scope, setScope] = useState<"open" | "all">(initialState ? "all" : OPEN_WORKING_SET);
  const [state, setState] = useState<VulnLifecycleState | "">(initialState);
  const [severity, setSeverity] = useState(initialSeverity);
  const [sla, setSla] = useState<SlaState | "">(initialSla);
  const [staleDays, setStaleDays] = useState("");
  const [unassigned, setUnassigned] = useState(initialUnassigned);
  const [source, setSource] = useState<VulnerabilitySource | "">(initialSource);
  const [exposure, setExposure] = useState<NetworkExposure | "">(initialExposure);
  // Selected finding ids (#346). Held here rather than in the table so paging,
  // the poll and a filter change do not drop a selection somebody is still
  // building — a tenant switch does, since the ids belong to the tenant they
  // were ticked in. ``useAuthStore``-gated verbs live in the bulk bar itself.
  const [selected, setSelected] = useBulkSelection();
  const assetId = initialAssetId;

  const pagination = usePagination({
    sort: "contextual_score",
    order: "desc",
    search: (searchParams.get("q") || "").trim(),
  });
  const filters = {
    state,
    open_only: scope === "open" && !state,
    severity,
    asset_id: assetId || undefined,
    source,
    network_exposure: exposure,
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
            <div className="flex items-center gap-1.5 font-mono font-bold text-sky-600 dark:text-sky-400 group-hover:text-sky-600 dark:text-sky-300 group-hover:underline">
              <span>{findingLabel(row.original)}</span>
              <ArrowUpRight className="h-3 w-3 opacity-0 transition-opacity group-hover:opacity-100" />
            </div>
            <span className="block text-[11px] text-muted-foreground">
              {/* A software finding has no port by construction: its locator is
                  the installed package and the version that closes it. */}
              {row.original.source === "endpoint_software"
                ? row.original.title || "installed package"
                : row.original.port
                  ? t("vulns.port", { port: row.original.port })
                  : "no port"}
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
        id: "source",
        accessorKey: "source",
        header: t("vuln.source"),
        enableSorting: false,
        cell: ({ row }) => (
          <div className="flex flex-col items-start gap-1">
            <StatusBadge value={row.original.source} map={VULN_SOURCE_STATUS} />
            {/* An inferred finding says how sure the inference is: a vendor's
                statement and a bare NVD range are not the same claim. */}
            {row.original.source === "retro_match" && row.original.match_confidence ? (
              <StatusBadge
                value={row.original.match_confidence}
                map={RETRO_MATCH_CONFIDENCE}
              />
            ) : null}
          </div>
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
              <p className="text-xs text-foreground">{row.original.assignee || "—"}</p>
              {row.original.owner_team ? (
                <p className="text-[11px] text-muted-foreground">{row.original.owner_team}</p>
              ) : null}
            </div>
          ) : (
            <span className="text-xs text-muted-foreground">{t("common.unassigned")}</span>
          ),
      },
      {
        id: "asset_id",
        accessorKey: "asset_id",
        header: t("col.asset"),
        cell: ({ row }) => (
          <Link
            href={assetDetailHref(row.original.asset_id, row.original.tenant_id)}
            className="font-mono text-[11px] text-foreground hover:text-sky-600 dark:text-sky-300 hover:underline"
          >
            {row.original.asset_id}
          </Link>
        ),
      },
      {
        accessorKey: "last_seen_at",
        header: t("col.lastSeen"),
        cell: ({ row }) => (
          <span className="text-xs text-muted-foreground">{ago(row.original.last_seen_at)}</span>
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
            className="h-7 text-xs border-border bg-card text-sky-600 dark:text-sky-400 hover:bg-muted hover:text-foreground"
          >
            <Link href={vulnDetailHref(row.original.vuln_id, row.original.tenant_id)}>{t("common.view")}</Link>
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
            <ShieldAlert className="h-5 w-5 text-sky-600 dark:text-sky-400" />
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
              {t("page.vulns.title")}
            </h1>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {t("page.vulns.subtitle")}
            {listQuery.isFetching ? t("common.refreshing") : ""}
            {assetId ? (
              <>
                {" "}
                Filtered to asset{" "}
                <Link
                  href={assetDetailHref(assetId)}
                  className="font-mono text-sky-600 dark:text-sky-400 hover:underline"
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
          label={t("kpi.openFindings")}
          value={summaryQuery.isLoading ? "…" : (summary?.open_total ?? 0)}
          hint={summary ? t("vulns.hint.untriaged", { count: summary.untriaged }) : undefined}
          decorationColor="sky"
        />
        <KpiCard
          label={t("kpi.critHighOpen")}
          value={
            summaryQuery.isLoading
              ? "…"
              : (summary?.by_severity_open.critical ?? 0) + (summary?.by_severity_open.high ?? 0)
          }
          hint={
            summary
              ? t("vulns.hint.critHigh", {
                  critical: summary.by_severity_open.critical ?? 0,
                  high: summary.by_severity_open.high ?? 0,
                })
              : undefined
          }
          decorationColor="orange"
        />
        <KpiCard
          label={t("kpi.slaBreached")}
          value={summaryQuery.isLoading ? "…" : (summary?.breached ?? 0)}
          hint={
            summary?.worst_breached_severity
              ? t("vulns.hint.worstOpen", {
                  severity: t.label(summary.worst_breached_severity),
                })
              : t("vulns.hint.noBreaches")
          }
          decorationColor="rose"
        />
        <KpiCard
          label={t("kpi.dueSoon")}
          value={summaryQuery.isLoading ? "…" : (summary?.by_sla.due_soon ?? 0)}
          hint={t("vulns.hint.withinSeven")}
          decorationColor="amber"
        />
      </div>

      <RetroMatchCard canOperate={canOperate} />

      <DataTable
        columns={columns}
        data={data}
        isLoading={listQuery.isLoading}
        error={listQuery.error}
        initialSorting={[{ id: "contextual_score", desc: true }]}
        searchPlaceholder={t("search.vulns")}
        toolbar={
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <Select
              value={scope}
              onValueChange={(value) => {
                setScope(value as "open" | "all");
                if (value === "open") setState("");
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-auto min-w-[10rem]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={OPEN_WORKING_SET}>{t("vulns.filter.openOnly")}</SelectItem>
                <SelectItem value="all">{t("ui.allFindings")}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={state || ALL_STATES}
              onValueChange={(value) => {
                setState(value === ALL_STATES ? "" : (value as VulnLifecycleState));
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-auto min-w-[11rem]">
                <SelectValue placeholder={t("select.anyState")} />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={ALL_STATES}>{t("vulns.filter.anyState")}</SelectItem>
                {VULN_STATES.map((item) => (
                  <SelectItem key={item} value={item}>
                    {VULN_LIFECYCLE_STATUS[item].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={source || FILTER_ALL}
              onValueChange={(value) => {
                setSource(value === FILTER_ALL ? "" : (value as VulnerabilitySource));
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-auto min-w-[11rem]">
                <SelectValue placeholder={t("vuln.source")} />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={FILTER_ALL}>{t("vuln.source.any")}</SelectItem>
                <SelectItem value="scan">{t("vuln.source.scan")}</SelectItem>
                <SelectItem value="endpoint_software">
                  {t("vuln.source.endpointSoftware")}
                </SelectItem>
                <SelectItem value="retro_match">{t("vuln.source.retroMatch")}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={exposure || FILTER_ALL}
              onValueChange={(value) => {
                setExposure(value === FILTER_ALL ? "" : (value as NetworkExposure));
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-auto min-w-[11rem]" aria-label={t("vuln.exposure")}>
                <SelectValue placeholder={t("vuln.exposure")} />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={FILTER_ALL}>{t("vuln.exposure.any")}</SelectItem>
                <SelectItem value="external">{t("vuln.exposure.external")}</SelectItem>
                <SelectItem value="internal">{t("vuln.exposure.internal")}</SelectItem>
                <SelectItem value="unknown">{t("vuln.exposure.unknown")}</SelectItem>
              </SelectContent>
            </Select>
            <Select
              value={severity || FILTER_ALL}
              onValueChange={(value) => {
                setSeverity(value === FILTER_ALL ? "" : value);
                pagination.reset();
              }}
            >
              <SelectTrigger className="w-auto min-w-[9rem]">
                <SelectValue placeholder={t("select.severity")} />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={FILTER_ALL}>{t("vulns.filter.anySeverity")}</SelectItem>
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
              <SelectTrigger className="w-auto min-w-[10rem]">
                <SelectValue placeholder={t("select.sla")} />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={FILTER_ALL}>{t("vulns.filter.anySla")}</SelectItem>
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
              <SelectTrigger className="w-auto min-w-[10rem]">
                <SelectValue placeholder={t("select.owner")} />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={FILTER_ALL}>{t("vulns.filter.anyOwner")}</SelectItem>
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
              <SelectTrigger className="w-auto min-w-[10rem]">
                <SelectValue placeholder={t("select.stale")} />
              </SelectTrigger>
              <SelectContent className="bg-card border-border text-foreground">
                <SelectItem value={FILTER_ALL}>{t("vulns.filter.anyRecency")}</SelectItem>
                <SelectItem value="14">Stale 14+ days</SelectItem>
                <SelectItem value="30">Stale 30+ days</SelectItem>
                <SelectItem value="90">Stale 90+ days</SelectItem>
              </SelectContent>
            </Select>
          </div>
        }
        meta={t("vulns.meta", { count: total.toLocaleString() })}
        loadingMessage={t("loading.trackedVulns")}
        emptyMessage={t("empty.trackedFindings")}
        selection={{
          rowId: (row) => row.vuln_id,
          selected,
          onChange: setSelected,
          max: MAX_BULK_IDS,
          selectAllLabel: "Select every finding on this page",
          actions: (ids) => (
            <VulnerabilityBulkActions
              ids={ids}
              // The ids that failed stay selected: an operator whose batch of
              // two hundred skipped three needs to see which three.
              onApplied={(remaining) => setSelected(remaining)}
            />
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
    <Suspense fallback={<p className="text-sm text-muted-foreground">Loading Vulnerability Center…</p>}>
      <VulnerabilitiesInner />
    </Suspense>
  );
}
