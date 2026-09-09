"use client";

import { useMemo } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import { KpiCard } from "@/components/kpi-card";
import { useAgentSummary } from "@/hooks/use-agents";
import { useJobCounts, useJobs } from "@/hooks/use-jobs";
import { useScanScope, usePromotedDomains } from "@/hooks/use-scan-scope";
import { useSystemStatus } from "@/hooks/use-system";
import { useVulnerabilitySummary } from "@/hooks/use-vulnerabilities";
import { type JobInfo } from "@/lib/api";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { runDetailHref } from "@/lib/run-data";
import { type ScanSurface } from "@/lib/scan-surface";
import { vulnListHref } from "@/lib/vuln-lifecycle";

/** What the last 50 started jobs say about a surface: how they end. Queue
 * depth is not read from this window — see `useJobCounts`. */
export function summariseJobs(jobs: JobInfo[]) {
  let finished = 0;
  let succeeded = 0;
  let lastCompleted: JobInfo | null = null;
  for (const job of jobs) {
    if (job.status === "succeeded" || job.status === "failed") {
      finished += 1;
      if (job.status === "succeeded") {
        succeeded += 1;
        if (!lastCompleted || (job.finished_at ?? "") > (lastCompleted.finished_at ?? ""))
          lastCompleted = job;
      }
    }
  }
  return { finished, succeeded, lastCompleted };
}

export function SurfaceKpis({
  surface,
  canOperate,
}: {
  surface: ScanSurface | null;
  canOperate: boolean;
}) {
  const t = useT();
  const { user, activeTenant } = useAuthStore();
  const tenantId = activeTenant ?? user?.default_tenant ?? "default";
  const isAdmin = user?.role === "admin";

  const jobsQuery = useJobs(
    canOperate,
    { limit: 50, sort: "started_at", order: "desc" },
    surface ? { surface } : undefined,
  );
  const stats = useMemo(() => summariseJobs(jobsQuery.data?.items ?? []), [jobsQuery.data]);
  const counts = useJobCounts(canOperate, surface ? { surface } : undefined, POLL_INTERVALS.jobs);

  const vulnSummary = useVulnerabilitySummary();
  const exposureKey =
    surface === "external" ? "external" : surface === "internal" ? "internal" : null;
  const openOnSurface = exposureKey
    ? (vulnSummary.data?.by_network_exposure_open?.[exposureKey] ?? null)
    : null;

  const agents = useAgentSummary();
  const system = useSystemStatus();
  const scope = useScanScope(tenantId, isAdmin && surface !== null);
  const promoted = usePromotedDomains(tenantId, isAdmin && surface === "external");

  const scopeCounts = useMemo(() => {
    const kind = surface === "external" ? "domain" : "cidr";
    const entries = (scope.data ?? []).filter((e) => e.kind === kind);
    return {
      allow: entries.filter((e) => e.effect === "allow").length,
      deny: entries.filter((e) => e.effect === "deny").length,
    };
  }, [scope.data, surface]);

  const last = stats.lastCompleted;
  const lastValue = last?.finished_at
    ? formatDistanceToNowStrict(new Date(last.finished_at), { addSuffix: true })
    : t("kpi.scans.noneYet");

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label={t("kpi.scans.running")}
        value={counts.isLoading ? "…" : counts.running}
        hint={
          counts.queued > 0
            ? t("kpi.scans.queued") + `: ${counts.queued}`
            : t("kpi.scans.nothingRunning")
        }
        decorationColor={counts.running > 0 ? "amber" : "slate"}
      />
      <KpiCard
        label={t("kpi.scans.lastCompleted")}
        value={jobsQuery.isLoading ? "…" : lastValue}
        hint={last?.run_id ?? undefined}
        href={last?.run_id ? runDetailHref(last.run_id) : undefined}
        decorationColor="emerald"
      />
      <KpiCard
        label={t("kpi.scans.successRate")}
        value={
          stats.finished > 0 ? `${Math.round((stats.succeeded / stats.finished) * 100)}%` : "—"
        }
        hint={t("kpi.scans.successRateHint", { ok: stats.succeeded, total: stats.finished })}
        decorationColor={stats.finished > 0 && stats.succeeded < stats.finished ? "rose" : "sky"}
      />
      {exposureKey && openOnSurface !== null ? (
        <KpiCard
          label={t("kpi.scans.openFindings")}
          value={openOnSurface}
          hint={t("kpi.scans.openFindingsHint")}
          href={vulnListHref({ networkExposure: exposureKey })}
          decorationColor={openOnSurface > 0 ? "rose" : "emerald"}
        />
      ) : surface === "internal" ? (
        <KpiCard
          label={t("kpi.scans.agentsOnline")}
          value={agents.data ? `${agents.data.online_agents}/${agents.data.total_agents}` : "…"}
          hint={t("kpi.scans.agentsHint", {
            busy: agents.data?.busy_agents ?? 0,
            stale: agents.data?.stale_agents ?? 0,
          })}
          href="/agents"
          decorationColor="blue"
        />
      ) : surface === "external" && isAdmin ? (
        <KpiCard
          label={t("kpi.scans.scopeDomains")}
          value={scope.data ? scopeCounts.allow : "…"}
          hint={
            promoted.data && promoted.data.length > 0
              ? t("kpi.scans.promoted", { count: promoted.data.length })
              : t("kpi.scans.scopeHint", scopeCounts)
          }
          href="/tenants"
          decorationColor="blue"
        />
      ) : (
        <KpiCard
          label={t("kpi.scans.endpoints")}
          value={system.data?.endpoint_inventory.devices_total ?? "—"}
          hint={t("kpi.scans.endpointsHint", {
            stale: system.data?.endpoint_inventory.devices_stale ?? 0,
          })}
          href="/endpoints"
          decorationColor="blue"
        />
      )}
    </div>
  );
}
