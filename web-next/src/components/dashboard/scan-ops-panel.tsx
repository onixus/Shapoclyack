"use client";

import Link from "next/link";
import { differenceInDays, formatDistanceToNowStrict } from "date-fns";
import { ArrowUpRight, Globe2, Layers, Play } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useJobCounts } from "@/hooks/use-jobs";
import { useRuns } from "@/hooks/use-runs";
import { useVulnerabilitySummary } from "@/hooks/use-vulnerabilities";
import { useAuthStore } from "@/lib/auth-store";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { useT } from "@/lib/i18n";
import { runDetailHref } from "@/lib/run-data";
import { surfaceHref, type ScanSurface } from "@/lib/scan-surface";
import { cn } from "@/lib/utils";
import { vulnListHref } from "@/lib/vuln-lifecycle";

/** A run older than this is flagged: a surface nobody has looked at for a
 * month is not "clean", it is unobserved. */
const STALE_DAYS = 30;

function SurfaceCard({ surface }: { surface: Exclude<ScanSurface, "mixed"> }) {
  const t = useT();
  const { canOperate } = useAuthStore();
  const runs = useRuns(POLL_INTERVALS.dashboard, { limit: 1 }, { surface });
  const jobs = useJobCounts(canOperate, { surface });
  const last = runs.data?.items[0] ?? null;
  const { running, queued } = jobs;
  const ageDays = last?.started_at ? differenceInDays(new Date(), new Date(last.started_at)) : null;
  const stale = ageDays !== null && ageDays > STALE_DAYS;
  const Icon = surface === "external" ? Globe2 : Layers;
  const tone =
    surface === "external"
      ? "border-sky-500/30 bg-sky-500/10 text-sky-600 dark:text-sky-400"
      : "border-violet-500/30 bg-violet-500/10 text-violet-600 dark:text-violet-400";

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className={cn("flex h-8 w-8 items-center justify-center rounded-lg border", tone)}>
            <Icon className="h-4 w-4" />
          </span>
          <div>
            <p className="text-sm font-bold text-foreground">{t(`surface.${surface}`)}</p>
            <p className="text-[11px] text-muted-foreground">{t(`surface.hint.${surface}`)}</p>
          </div>
        </div>
        {canOperate ? (
          <Button asChild size="sm" variant="outline" className="gap-1.5">
            <Link href={`${surfaceHref(surface)}?launch=1`}>
              <Play className="h-3 w-3 fill-current" />
              {t("dash.ops.launch")}
            </Link>
          </Button>
        ) : null}
      </div>

      <dl className="grid grid-cols-3 gap-2 text-xs">
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
            {t("dash.ops.lastRun")}
          </dt>
          <dd
            className={cn(
              "mt-0.5 font-semibold",
              stale ? "text-amber-600 dark:text-amber-300" : "text-foreground",
            )}
          >
            {runs.isLoading
              ? "…"
              : last?.started_at
                ? formatDistanceToNowStrict(new Date(last.started_at), { addSuffix: true })
                : t("kpi.scans.noneYet")}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
            {t("dash.ops.running")}
          </dt>
          <dd className="mt-0.5 font-mono font-semibold text-foreground">
            {canOperate ? (jobs.isLoading ? "…" : `${running}${queued ? ` +${queued}` : ""}`) : "—"}
          </dd>
        </div>
        <div>
          <dt className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
            {t("dash.ops.findings")}
          </dt>
          <dd
            className={cn(
              "mt-0.5 font-mono font-semibold",
              (last?.potential_vulnerabilities ?? 0) > 0
                ? "text-rose-600 dark:text-rose-400"
                : "text-foreground",
            )}
          >
            {last ? (last.potential_vulnerabilities ?? 0).toLocaleString() : "—"}
          </dd>
        </div>
      </dl>

      <div className="flex items-center justify-between text-[11px]">
        <span className="text-muted-foreground">
          {last
            ? stale
              ? t("dash.ops.stale", { days: STALE_DAYS })
              : last.run_id
            : t("dash.ops.never")}
        </span>
        <span className="flex items-center gap-3">
          {last ? (
            <Link
              href={runDetailHref(last.run_id)}
              className="inline-flex items-center gap-1 font-semibold text-primary hover:underline"
            >
              {t("dash.ops.open")}
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          ) : null}
          {canOperate ? (
            <Link
              href={surfaceHref(surface)}
              className="font-semibold text-primary hover:underline"
            >
              {t(`nav.${surface}Scans`)}
            </Link>
          ) : null}
        </span>
      </div>
    </div>
  );
}

function ExposureSplit() {
  const t = useT();
  const summary = useVulnerabilitySummary();
  const split = summary.data?.by_network_exposure_open;
  if (!split) return null;
  const total = (split.external ?? 0) + (split.internal ?? 0) + (split.unknown ?? 0);
  const rows: Array<{ key: "external" | "internal" | "unknown"; color: string }> = [
    { key: "external", color: "bg-sky-500" },
    { key: "internal", color: "bg-violet-500" },
    { key: "unknown", color: "bg-slate-400" },
  ];
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4 shadow-sm">
      <div>
        <p className="text-sm font-bold text-foreground">{t("dash.ops.exposureSplit")}</p>
        <p className="text-[11px] text-muted-foreground">{t("dash.ops.exposureHint")}</p>
      </div>
      <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
        {total > 0
          ? rows.map(({ key, color }) => (
              <span
                key={key}
                className={cn("h-full", color)}
                style={{ width: `${((split[key] ?? 0) / total) * 100}%` }}
                aria-hidden
              />
            ))
          : null}
      </div>
      <ul className="grid grid-cols-3 gap-2 text-xs">
        {rows.map(({ key, color }) => (
          <li key={key}>
            <Link
              href={vulnListHref({ networkExposure: key })}
              className="group flex flex-col rounded-md p-1 hover:bg-muted"
              title={t(`vuln.exposure.${key}`)}
            >
              <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                <span className={cn("h-2 w-2 rounded-full", color)} aria-hidden />
                {t(`surface.${key}`)}
              </span>
              <span className="font-mono text-base font-bold text-foreground group-hover:text-primary">
                {(split[key] ?? 0).toLocaleString()}
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

/** Dashboard block: are both surfaces being watched, and where do the open
 * findings sit relative to the perimeter. */
export function ScanOpsPanel() {
  const t = useT();
  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-sm font-bold uppercase tracking-wider text-foreground">
          {t("dash.ops.title")}
        </h2>
        <p className="text-xs text-muted-foreground">{t("dash.ops.subtitle")}</p>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <SurfaceCard surface="external" />
        <SurfaceCard surface="internal" />
        <ExposureSplit />
      </div>
    </section>
  );
}
