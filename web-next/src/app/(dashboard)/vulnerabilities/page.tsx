"use client";

import Link from "next/link";
import { Suspense, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { type ColumnDef } from "@tanstack/react-table";
import { ArrowUpRight, ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Field, FieldGrid } from "@/components/ui/field";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SavedViews } from "@/components/saved-views";
import { pickFilter } from "@/lib/saved-views";
import { DataTable } from "@/components/data-table";
import { VulnerabilityBulkActions } from "@/components/vulnerability/bulk-actions";
import { CreateCampaignDialog } from "@/components/campaign/create-campaign-dialog";
import { ProblemsTable } from "@/components/vulnerability/problems-table";
import { useProblemDrift } from "@/hooks/use-campaigns";
import { selectionFromFilters, type CampaignSelection, type ProblemRow } from "@/lib/campaigns";
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
  FindingType,
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
  const router = useRouter();
  const pathname = usePathname();
  const initialAssetId = (searchParams.get("assetId") || "").trim();
  const initialSla = pickFilter("sla", searchParams.get("sla")) as SlaState | "";
  const initialState = pickFilter("state", searchParams.get("state")) as VulnLifecycleState | "";
  const initialSeverity = pickFilter("severity", searchParams.get("severity"));
  const initialUnassigned = searchParams.get("unassigned") === "1";
  const initialSource = pickFilter("source", searchParams.get("source")) as VulnerabilitySource | "";
  const initialFindingType = pickFilter("findingType", searchParams.get("finding_type")) as FindingType | "";
  const initialDetector = pickFilter("detector", searchParams.get("detector_source"));
  const initialExposure = pickFilter("exposure", searchParams.get("exposure")) as NetworkExposure | "";

  const [scope, setScope] = useState<"open" | "all">(initialState ? "all" : OPEN_WORKING_SET);
  const [state, setState] = useState<VulnLifecycleState | "">(initialState);
  const [severity, setSeverity] = useState<string>(initialSeverity);
  const [sla, setSla] = useState<SlaState | "">(initialSla);
  const [staleDays, setStaleDays] = useState("");
  const [unassigned, setUnassigned] = useState(initialUnassigned);
  const [source, setSource] = useState<VulnerabilitySource | "">(initialSource);
  const [findingType, setFindingType] = useState<FindingType | "">(initialFindingType);
  const [detector, setDetector] = useState<string>(initialDetector);
  const [exposure, setExposure] = useState<NetworkExposure | "">(initialExposure);
  // Selected finding ids (#346). Held here rather than in the table so paging,
  // the poll and a filter change do not drop a selection somebody is still
  // building — a tenant switch does, since the ids belong to the tenant they
  // were ticked in. ``useAuthStore``-gated verbs live in the bulk bar itself.
  const [selected, setSelected] = useBulkSelection();
  const [assetId, setAssetId] = useState(initialAssetId);
  // Problems / Instances (#579). The filters above are shared by both views —
  // they are this component's state, not either table's — so switching never
  // loses them; only the table underneath changes. The view and a problem
  // drill-down live in the URL, so a reload or a shared link lands on the same one.
  const [view, setView] = useState<"problems" | "instances">(
    searchParams.get("view") === "problems" ? "problems" : "instances",
  );
  const initialProblem = (searchParams.get("problem") || "").trim();
  const [drill, setDrill] = useState<{ key: string; instances: number; asOf: string } | null>(
    initialProblem ? { key: initialProblem, instances: -1, asOf: "" } : null,
  );
  const [selectedProblems, setSelectedProblems] = useState<string[]>([]);
  const [campaignSelection, setCampaignSelection] = useState<CampaignSelection | null>(null);

  const pagination = usePagination({
    sort: "contextual_score",
    order: "desc",
    search: (searchParams.get("q") || "").trim(),
  });
  const problemPagination = usePagination({
    sort: "risk",
    order: "desc",
    search: (searchParams.get("q") || "").trim(),
  });
  const sharedFilters = {
    state,
    open_only: scope === "open" && !state,
    severity,
    asset_id: assetId || undefined,
    source,
    finding_type: findingType,
    detector_source: detector,
    network_exposure: exposure,
    unassigned: unassigned || undefined,
    sla,
    stale_days: staleDays ? Number(staleDays) : undefined,
  };
  // The drill-down adds only the problem key to the very same filters, which is
  // what makes it reproduce the aggregate row's selection.
  const filters = { ...sharedFilters, problem_key: drill?.key || undefined };
  const listQuery = useTrackedVulnerabilities(filters, pagination.params, view === "instances");
  const driftQuery = useProblemDrift(drill, sharedFilters, view === "instances");
  const summaryQuery = useVulnerabilitySummary();

  const changeView = (next: "problems" | "instances") => {
    if (next === view) return;
    setView(next);
    // The search box is part of the filters: carry it across.
    if (next === "problems") problemPagination.setSearch(pagination.search);
    else pagination.setSearch(problemPagination.search);
    setSelected([]);
    setSelectedProblems([]);
    const params = new URLSearchParams(searchParams.toString());
    if (next === "problems") params.set("view", "problems");
    else params.delete("view");
    if (next === "problems" || !drill) params.delete("problem");
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  };

  const showInstances = (row: ProblemRow, asOf: string) => {
    setDrill({ key: row.problem_key, instances: row.instances, asOf });
    setView("instances");
    pagination.reset();
    setSelected([]);
    const params = new URLSearchParams(searchParams.toString());
    params.delete("view");
    params.set("problem", row.problem_key);
    router.replace(`${pathname}?${params.toString()}`, { scroll: false });
  };

  const clearDrill = () => {
    setDrill(null);
    pagination.reset();
    const params = new URLSearchParams(searchParams.toString());
    params.delete("problem");
    const query = params.toString();
    router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
  };
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
            <span className="block text-xs text-muted-foreground">
              {/* A software finding has no port by construction: its locator is
                  the installed package and the version that closes it. */}
              {row.original.source === "endpoint_software"
                ? row.original.title || "installed package"
                : row.original.port
                  ? t("vulns.port", { port: row.original.port })
                  : "no port"}
              {row.original.script_id && row.original.cve ? ` · ${row.original.script_id}` : ""}
              {row.original.finding_type && row.original.finding_type !== "cve"
                ? ` · ${row.original.finding_type}` : ""}
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
                <p className="text-xs text-muted-foreground">{row.original.owner_team}</p>
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
            className="font-mono text-xs text-foreground hover:text-sky-600 dark:text-sky-300 hover:underline"
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

  const filterToolbar = (
          <FieldGrid cols="filters" className="w-full basis-full">
            <Field label={t("vulns.filter.scope")} htmlFor="vuln-filter-scope" reserveHint={false}>
              <Select
                value={scope}
                onValueChange={(value) => {
                  setScope(value as "open" | "all");
                  if (value === "open") setState("");
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-scope">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value={OPEN_WORKING_SET}>{t("vulns.filter.openOnly")}</SelectItem>
                  <SelectItem value="all">{t("ui.allFindings")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("vulns.filter.state")} htmlFor="vuln-filter-state" reserveHint={false}>
              <Select
                value={state || ALL_STATES}
                onValueChange={(value) => {
                  setState(value === ALL_STATES ? "" : (value as VulnLifecycleState));
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-state">
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
            </Field>
            <Field label={t("vuln.source")} htmlFor="vuln-filter-source" reserveHint={false}>
              <Select
                value={source || FILTER_ALL}
                onValueChange={(value) => {
                  setSource(value === FILTER_ALL ? "" : (value as VulnerabilitySource));
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-source">
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
            </Field>
            <Field label={t("vuln.findingType")} htmlFor="vuln-filter-finding-type" reserveHint={false}>
              <Select
                value={findingType || FILTER_ALL}
                onValueChange={(value) => {
                  setFindingType(value === FILTER_ALL ? "" : (value as FindingType));
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-finding-type">
                  <SelectValue placeholder={t("vuln.findingType")} />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value={FILTER_ALL}>{t("vulns.filter.anyFindingType")}</SelectItem>
                  <SelectItem value="cve">CVE</SelectItem>
                  <SelectItem value="misconfiguration">Misconfiguration</SelectItem>
                  <SelectItem value="exposure">Exposure</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("vuln.detector")} htmlFor="vuln-filter-detector" reserveHint={false}>
              <Select
                value={detector || FILTER_ALL}
                onValueChange={(value) => {
                  setDetector(value === FILTER_ALL ? "" : value);
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-detector">
                  <SelectValue placeholder={t("vuln.detector")} />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value={FILTER_ALL}>{t("vulns.filter.anyDetector")}</SelectItem>
                  <SelectItem value="nuclei">Nuclei</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("vuln.exposure")} htmlFor="vuln-filter-exposure" reserveHint={false}>
              <Select
                value={exposure || FILTER_ALL}
                onValueChange={(value) => {
                  setExposure(value === FILTER_ALL ? "" : (value as NetworkExposure));
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-exposure">
                  <SelectValue placeholder={t("vuln.exposure")} />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value={FILTER_ALL}>{t("vuln.exposure.any")}</SelectItem>
                  <SelectItem value="external">{t("vuln.exposure.external")}</SelectItem>
                  <SelectItem value="internal">{t("vuln.exposure.internal")}</SelectItem>
                  <SelectItem value="unknown">{t("vuln.exposure.unknown")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("select.severity")} htmlFor="vuln-filter-severity" reserveHint={false}>
              <Select
                value={severity || FILTER_ALL}
                onValueChange={(value) => {
                  setSeverity(value === FILTER_ALL ? "" : value);
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-severity">
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
            </Field>
            <Field label={t("select.sla")} htmlFor="vuln-filter-sla" reserveHint={false}>
              <Select
                value={sla || FILTER_ALL}
                onValueChange={(value) => {
                  setSla(value === FILTER_ALL ? "" : (value as SlaState));
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-sla">
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
            </Field>
            <Field label={t("select.owner")} htmlFor="vuln-filter-owner" reserveHint={false}>
              <Select
                value={unassigned ? "unassigned" : FILTER_ALL}
                onValueChange={(value) => {
                  setUnassigned(value === "unassigned");
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-owner">
                  <SelectValue placeholder={t("select.owner")} />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value={FILTER_ALL}>{t("vulns.filter.anyOwner")}</SelectItem>
                  <SelectItem value="unassigned">{t("common.unassigned")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label={t("select.stale")} htmlFor="vuln-filter-stale" reserveHint={false}>
              <Select
                value={staleDays || FILTER_ALL}
                onValueChange={(value) => {
                  setStaleDays(value === FILTER_ALL ? "" : value);
                  pagination.reset();
                }}
              >
                <SelectTrigger id="vuln-filter-stale">
                  <SelectValue placeholder={t("select.stale")} />
                </SelectTrigger>
                <SelectContent className="bg-card border-border text-foreground">
                  <SelectItem value={FILTER_ALL}>{t("vulns.filter.anyRecency")}</SelectItem>
                  <SelectItem value="14">{t("vulns.filter.stale14")}</SelectItem>
                  <SelectItem value="30">{t("vulns.filter.stale30")}</SelectItem>
                  <SelectItem value="90">{t("vulns.filter.stale90")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </FieldGrid>
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

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div
          role="tablist"
          aria-label={t("vulns.view.label")}
          className="inline-flex rounded-md border border-border bg-card p-0.5"
        >
          {(["problems", "instances"] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              role="tab"
              id={`vulns-tab-${mode}`}
              aria-controls="vulns-panel"
              aria-selected={view === mode}
              onClick={() => changeView(mode)}
              className={
                "rounded px-3 py-1 text-xs font-medium transition-colors " +
                (view === mode
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground")
              }
            >
              {t(mode === "problems" ? "vulns.view.problems" : "vulns.view.instances")}
            </button>
          ))}
        </div>
        <Button asChild variant="outline" size="sm" className="h-8 text-xs">
          <Link href="/campaigns">{t("nav.campaigns")}</Link>
        </Button>
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

      {summary?.cve_findings != null && summary?.non_cve_findings != null ? (
        <p className="text-xs text-muted-foreground">
          All tracked findings: {summary.cve_findings.toLocaleString()} CVE · {summary.non_cve_findings.toLocaleString()} non-CVE
        </p>
      ) : null}

      <RetroMatchCard canOperate={canOperate} />

      <SavedViews page="vulnerabilities" state={{ version: 1, search: pagination.search, sort: pagination.sort ?? null, order: pagination.order, filters: { scope, state, severity, sla, staleDays, unassigned, source, findingType, detector, exposure, assetId } }} onApply={(view) => {
        pagination.setSearch(view.search); pagination.setSort(view.sort ?? undefined, view.order);
        const f = view.filters;
        setScope(f.scope === "all" ? "all" : "open"); setState((f.state || "") as VulnLifecycleState | ""); setSeverity(String(f.severity || "")); setSla((f.sla || "") as SlaState | "");
        setStaleDays(String(f.staleDays || "")); setUnassigned(f.unassigned === true); setSource((f.source || "") as VulnerabilitySource | ""); setFindingType((f.findingType || "") as FindingType | ""); setDetector(String(f.detector || "")); setExposure((f.exposure || "") as NetworkExposure | ""); setAssetId(String(f.assetId || "")); setSelected([]); pagination.reset();
        // Keep ?assetId= in step with the applied view, so a reload or a shared link
        // does not bring back the previous asset filter.
        const params = new URLSearchParams(searchParams.toString());
        if (f.assetId) params.set("assetId", String(f.assetId)); else params.delete("assetId");
        const query = params.toString();
        router.replace(query ? `${pathname}?${query}` : pathname, { scroll: false });
      }} />
      <div role="tabpanel" id="vulns-panel" aria-labelledby={`vulns-tab-${view}`} className="space-y-6">
      {view === "problems" ? (
        <ProblemsTable
          filters={sharedFilters}
          pagination={problemPagination}
          toolbar={filterToolbar}
          selected={selectedProblems}
          onSelectedChange={setSelectedProblems}
          onShowInstances={showInstances}
          selectionActions={
            canOperate
              ? (keys) => (
                  <Button
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() =>
                      setCampaignSelection(selectionFromFilters(keys, [], sharedFilters))
                    }
                  >
                    {t("campaign.create")}
                  </Button>
                )
              : undefined
          }
        />
      ) : null}
      {view === "instances" ? (
        <>
      {drill ? (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-xs">
          <span className="font-mono">{t("problems.drill.chip", { key: drill.key })}</span>
          <Button variant="outline" size="sm" className="h-6 text-xs" onClick={clearDrill}>
            {t("problems.drill.clear")}
          </Button>
          {driftQuery.data?.drift?.differs ? (
            <span role="status" className="text-amber-600 dark:text-amber-400">
              {driftQuery.data.drift.changed_since_as_of > 0
                ? t("problems.drill.drift", {
                    expected: driftQuery.data.drift.expected_instances,
                    actual: driftQuery.data.drift.actual_instances,
                    changed: driftQuery.data.drift.changed_since_as_of,
                  })
                : t("problems.drill.driftNoChange", {
                    expected: driftQuery.data.drift.expected_instances,
                    actual: driftQuery.data.drift.actual_instances,
                  })}
            </span>
          ) : null}
        </div>
      ) : null}
      <DataTable
        columns={columns}
        data={data}
        isLoading={listQuery.isLoading}
        error={listQuery.error}
        initialSorting={[{ id: "contextual_score", desc: true }]}
        searchPlaceholder={t("search.vulns")}
        toolbar={filterToolbar}
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
            <>
              <VulnerabilityBulkActions
                ids={ids}
                // The ids that failed stay selected: an operator whose batch of
                // two hundred skipped three needs to see which three.
                onApplied={(remaining) => setSelected(remaining)}
              />
              {canOperate ? (
                <Button
                  size="sm"
                  className="h-7 text-xs"
                  onClick={() => setCampaignSelection(selectionFromFilters([], ids, undefined))}
                >
                  {t("campaign.create")}
                </Button>
              ) : null}
            </>
          ),
        }}
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          searchRevision: pagination.searchRevision,
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
        </>
      ) : null}
      </div>
      {campaignSelection ? (
        <CreateCampaignDialog
          open
          onOpenChange={(open) => {
            if (!open) setCampaignSelection(null);
          }}
          selection={campaignSelection}
          onCreated={(campaign) => {
            setSelected([]);
            setSelectedProblems([]);
            router.push(`/campaigns?id=${encodeURIComponent(campaign.campaign_id)}`);
          }}
        />
      ) : null}
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
