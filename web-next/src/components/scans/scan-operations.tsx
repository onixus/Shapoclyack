"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useMemo, useState } from "react";
import { format } from "date-fns";
import {
  ArrowUpRight,
  ChevronDown,
  Globe2,
  Layers,
  Play,
  Plus,
  ShieldCheck,
  Timer,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/page-header";
import { JobsTable } from "@/components/scans/jobs-table";
import { ScanLauncher } from "@/components/scans/scan-launcher";
import { SurfaceKpis } from "@/components/scans/surface-kpis";
import { useJobs } from "@/hooks/use-jobs";
import { usePagination } from "@/hooks/use-pagination";
import { useRuns } from "@/hooks/use-runs";
import { useSystemStatus } from "@/hooks/use-system";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { runDetailHref } from "@/lib/run-data";
import { surfaceHref, type ScanSurface } from "@/lib/scan-surface";
import { cn } from "@/lib/utils";

/** The operations pages exist for the two real surfaces; "mixed" is a label on a job, not a page. */
export type OperationsSurface = Exclude<ScanSurface, "mixed"> | null;

const TABS: Array<{
  surface: OperationsSurface;
  key: "all" | "external" | "internal";
  icon: typeof Play;
}> = [
  { surface: null, key: "all", icon: Play },
  { surface: "external", key: "external", icon: Globe2 },
  { surface: "internal", key: "internal", icon: Layers },
];

/** Segmented switch between the three operations pages. */
export function SurfaceTabs({ current }: { current: OperationsSurface }) {
  const t = useT();
  return (
    <nav
      aria-label={t("surface.filterLabel")}
      className="inline-flex rounded-lg border border-border bg-muted/50 p-1"
    >
      {TABS.map(({ surface, key, icon: Icon }) => {
        const active = surface === current;
        return (
          <Link
            key={key}
            href={surfaceHref(surface)}
            aria-current={active ? "page" : undefined}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-colors",
              active
                ? "bg-card text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {key === "all" ? t("surface.all") : t(`surface.${key}`)}
          </Link>
        );
      })}
    </nav>
  );
}

function RecentRuns({ surface }: { surface: OperationsSurface }) {
  const t = useT();
  const runsQuery = useRuns(undefined, { limit: 6 }, surface ? { surface } : undefined);
  const runs = runsQuery.data?.items ?? [];
  if (runsQuery.isLoading || runs.length === 0) return null;
  const runsHref = surface ? `/runs?surface=${surface}` : "/runs";
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-wider text-foreground">
            {t("page.scans.recentRuns")}
          </h2>
          <p className="text-xs text-muted-foreground">{t("page.scans.recentRunsHint")}</p>
        </div>
        <Link
          href={runsHref}
          className="inline-flex items-center gap-1 text-xs font-semibold text-primary hover:underline"
        >
          {t("page.scans.allRuns")}
          <ArrowUpRight className="h-3 w-3" />
        </Link>
      </div>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {runs.map((run) => {
          const vulns = run.potential_vulnerabilities ?? 0;
          return (
            <Link
              key={run.run_id}
              href={runDetailHref(run.run_id)}
              className="group rounded-xl border border-border bg-card p-4 shadow-sm transition-colors hover:border-primary/40"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono text-xs font-semibold text-primary group-hover:underline">
                  {run.run_id}
                </span>
                {run.profile ? (
                  <Badge variant="secondary" className="font-mono text-[10px]">
                    {run.profile}
                  </Badge>
                ) : null}
              </div>
              <p className="mt-1 text-[11px] text-muted-foreground">
                {run.started_at ? format(new Date(run.started_at), "yyyy-MM-dd HH:mm") : "—"}
              </p>
              <dl className="mt-3 grid grid-cols-3 gap-2 text-center">
                <div>
                  <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    {t("col.aliveHosts")}
                  </dt>
                  <dd className="font-mono text-sm font-bold text-foreground">
                    {(run.alive_hosts ?? 0).toLocaleString()}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    {t("col.openPorts")}
                  </dt>
                  <dd className="font-mono text-sm font-bold text-foreground">
                    {(run.open_host_port_pairs ?? 0).toLocaleString()}
                  </dd>
                </div>
                <div>
                  <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">
                    {t("col.vulns")}
                  </dt>
                  <dd
                    className={cn(
                      "font-mono text-sm font-bold",
                      vulns > 0 ? "text-rose-600 dark:text-rose-400" : "text-foreground",
                    )}
                  >
                    {vulns.toLocaleString()}
                  </dd>
                </div>
              </dl>
            </Link>
          );
        })}
      </div>
    </section>
  );
}

function ScanOperationsInner({ surface }: { surface: OperationsSurface }) {
  const t = useT();
  const router = useRouter();
  const searchParams = useSearchParams();
  const { canOperate, user } = useAuthStore();
  const { data: system } = useSystemStatus();
  // `null` = not decided by the operator yet: open on an empty tenant, closed otherwise.
  const [launcherOpen, setLauncherOpen] = useState<boolean | null>(null);
  const deepLinkedJob = (searchParams.get("job") || "").trim() || null;

  useEffect(() => {
    // `?launch=1` (sidebar quick actions, command palette) opens the form and
    // then drops the flag so a reload does not reopen it.
    if (searchParams.get("launch") === "1") {
      setLauncherOpen(true);
      router.replace(surfaceHref(surface));
    }
  }, [searchParams, router, surface]);

  const pagination = usePagination({ sort: "started_at", order: "desc" });
  const jobsQuery = useJobs(canOperate, pagination.params, surface ? { surface } : undefined);
  const family = surface ?? "all";
  const noJobsYet =
    !jobsQuery.isLoading && (jobsQuery.data?.total ?? 0) === 0 && !pagination.search;
  const showLauncher = canOperate && (launcherOpen ?? noJobsYet);
  const agentMode = system?.runtime.job_execution_mode === "agent";
  const scanStartDisabled = system ? !system.runtime.allow_scan_start : false;
  const isAdmin = user?.role === "admin";

  const header = useMemo(
    () => ({
      icon: family === "external" ? Globe2 : family === "internal" ? Layers : Play,
      tone:
        family === "external"
          ? ("sky" as const)
          : family === "internal"
            ? ("violet" as const)
            : ("slate" as const),
    }),
    [family],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2 rounded-xl border border-border bg-card p-8 text-center">
        <h1 className="text-2xl font-bold tracking-tight text-foreground">
          {t(`page.scans.${family}.title`)}
        </h1>
        <p className="text-xs text-muted-foreground">{t("page.scans.denied")}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        icon={header.icon}
        tone={header.tone}
        title={t(`page.scans.${family}.title`)}
        subtitle={t(`page.scans.${family}.subtitle`)}
        actions={
          <>
            <Button asChild variant="outline" size="sm" className="gap-1.5">
              <Link href="/schedules">
                <Timer className="h-3.5 w-3.5" />
                {t("common.manageSchedules")}
              </Link>
            </Button>
            {isAdmin ? (
              <Button asChild variant="outline" size="sm" className="gap-1.5">
                <Link href="/tenants">
                  <ShieldCheck className="h-3.5 w-3.5" />
                  {t("page.scans.manageScope")}
                </Link>
              </Button>
            ) : null}
            <Button
              type="button"
              size="sm"
              className="gap-1.5 font-semibold"
              disabled={scanStartDisabled}
              aria-expanded={showLauncher}
              onClick={() => setLauncherOpen(!showLauncher)}
            >
              {showLauncher ? (
                <ChevronDown className="h-3.5 w-3.5" />
              ) : (
                <Plus className="h-3.5 w-3.5" />
              )}
              {showLauncher ? t("page.scans.hideLauncher") : t("page.scans.launch")}
            </Button>
          </>
        }
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SurfaceTabs current={surface} />
          <p className="text-[11px] text-muted-foreground">
            {agentMode ? t("page.scans.mode.agent") : t("page.scans.mode.local")}{" "}
            {t("page.scans.scopeHint")}
          </p>
        </div>
      </PageHeader>

      <SurfaceKpis surface={surface} canOperate={canOperate} />

      {showLauncher ? (
        <ScanLauncher surface={surface} onStarted={() => setLauncherOpen(false)} />
      ) : null}

      <section className="space-y-3">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-wider text-foreground">
            {t("page.scans.jobsHeading")}
          </h2>
          <p className="text-xs text-muted-foreground">{t("page.scans.jobsHint")}</p>
        </div>
        <JobsTable
          page={jobsQuery.data}
          isLoading={jobsQuery.isLoading}
          error={jobsQuery.error}
          isFetching={jobsQuery.isFetching}
          pagination={pagination}
          showSurface={surface === null}
          canOperate={canOperate}
          initialJobId={deepLinkedJob}
          onInitialJobClosed={() => router.replace(surfaceHref(surface))}
        />
      </section>

      <RecentRuns surface={surface} />
    </div>
  );
}

/** The operations page for one surface (`null` = every surface). */
export function ScanOperations({ surface }: { surface: OperationsSurface }) {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center gap-2 py-16 text-muted-foreground">
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      }
    >
      <ScanOperationsInner surface={surface} />
    </Suspense>
  );
}
