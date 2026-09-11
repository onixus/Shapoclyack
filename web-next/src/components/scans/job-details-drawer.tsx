"use client";

import Link from "next/link";
import { useState } from "react";
import { format, formatDistanceStrict } from "date-fns";
import { ArrowUpRight, ChevronDown, Cpu, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { StatusBadge } from "@/components/status-badge";
import { SurfaceBadge } from "@/components/scans/surface-badge";
import { useJob } from "@/hooks/use-jobs";
import { type JobInfo } from "@/lib/api";
import { JOB_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { runDetailHref } from "@/lib/run-data";
import { jobSurface } from "@/lib/scan-surface";

function stamp(iso: string | null | undefined): string | null {
  return iso ? format(new Date(iso), "yyyy-MM-dd HH:mm:ss") : null;
}

export function jobDuration(
  job: Pick<JobInfo, "started_at" | "finished_at" | "status">,
): string | null {
  if (!job.started_at) return null;
  const end = job.finished_at
    ? new Date(job.finished_at)
    : job.status === "running"
      ? new Date()
      : null;
  if (!end) return null;
  return formatDistanceStrict(new Date(job.started_at), end);
}

function Row({
  label,
  children,
  hint,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="grid grid-cols-[minmax(0,9rem)_1fr] items-start gap-3 py-1.5 text-xs">
      <dt className="font-semibold text-muted-foreground" title={hint}>
        {label}
      </dt>
      <dd className="min-w-0 break-words text-foreground">{children}</dd>
    </div>
  );
}

function asStringList(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/**
 * Everything the API recorded about one job. Polls while the job moves so a
 * drawer left open follows it from queued to finished.
 */
export function JobDetailsDrawer({
  job,
  jobId,
  open,
  onOpenChange,
}: {
  /** A row already in hand, or … */
  job?: JobInfo | null;
  /** … just an id (deep link `/scans?job=…`), fetched here. */
  jobId?: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  const live = useJob(job?.job_id ?? jobId ?? null, open);
  const current = live.data ?? job ?? null;
  const [showCommand, setShowCommand] = useState(false);

  if (!current) {
    if (!open || !jobId) return null;
    return (
      <Sheet open={open} onOpenChange={onOpenChange}>
        <SheetContent side="right" className="w-full sm:max-w-xl">
          <SheetHeader>
            <SheetTitle className="font-mono text-base">{jobId}</SheetTitle>
            <SheetDescription>
              {live.error instanceof Error ? live.error.message : t("common.loading")}
            </SheetDescription>
          </SheetHeader>
        </SheetContent>
      </Sheet>
    );
  }
  const opts = current.scan_options ?? {};
  const intent = typeof opts.intent === "string" ? opts.intent : null;
  const intentSummary = typeof opts.intent_summary === "string" ? opts.intent_summary : null;
  const promoted = asStringList(opts.promoted_domains);
  const refused = asStringList(opts.promoted_domains_refused);
  const wordlist =
    typeof opts.wordlist_name === "string"
      ? opts.wordlist_name
      : typeof opts.wordlist_id === "string"
        ? opts.wordlist_id
        : null;
  const counts = Object.entries(current.target_counts ?? {}).filter(
    ([, n]) => typeof n === "number" && n > 0,
  );
  const duration = jobDuration(current);
  const command = Array.isArray((current as { command?: unknown }).command)
    ? ((current as { command?: string[] }).command ?? []).join(" ")
    : null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-full overflow-y-auto sm:max-w-xl">
        <SheetHeader className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <SheetTitle className="font-mono text-base">{current.job_id}</SheetTitle>
            <StatusBadge
              value={current.status}
              map={JOB_STATUS}
              showPulse={
                current.status === "running" ||
                current.status === "claimed" ||
                current.status === "cancelling"
              }
            />
            <SurfaceBadge surface={jobSurface(current)} link />
          </div>
          <SheetDescription>{t("jobs.detailsHint")}</SheetDescription>
        </SheetHeader>

        {current.error ? (
          <div className="mt-4 flex items-start gap-2 rounded-lg border border-rose-500/30 bg-rose-500/10 px-3 py-2 text-xs text-rose-800 dark:text-rose-200">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              <p className="font-semibold">{t("jobs.error")}</p>
              <p className="mt-0.5 break-words font-mono">{current.error}</p>
            </div>
          </div>
        ) : null}
        {current.asset_upsert_error ? (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-200">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              <p className="font-semibold">{t("jobs.assetUpsertError")}</p>
              <p className="mt-0.5 break-words font-mono">{current.asset_upsert_error}</p>
            </div>
          </div>
        ) : null}

        <section className="mt-5">
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
            {t("jobs.timeline")}
          </h4>
          <dl className="mt-1 divide-y divide-border/60">
            <Row label={t("jobs.started")}>
              <span className="font-mono">{stamp(current.started_at) ?? t("jobs.notYet")}</span>
            </Row>
            <Row label={t("jobs.finished")}>
              <span className="font-mono">{stamp(current.finished_at) ?? t("jobs.notYet")}</span>
            </Row>
            <Row label={t("jobs.duration")}>{duration ?? "—"}</Row>
            <Row label={t("jobs.attempts")} hint={t("jobs.attemptsHint")}>
              <span
                className={
                  current.attempts && current.attempts > 1
                    ? "font-semibold text-amber-600 dark:text-amber-300"
                    : ""
                }
              >
                {current.attempts ?? 0}
              </span>
            </Row>
            {current.exit_code != null ? (
              <Row label={t("jobs.exitCode")}>
                <span className="font-mono">{current.exit_code}</span>
              </Row>
            ) : null}
          </dl>
        </section>

        <section className="mt-5">
          <h4 className="text-[11px] font-bold uppercase tracking-wider text-muted-foreground">
            {t("jobs.options")}
          </h4>
          <dl className="mt-1 divide-y divide-border/60">
            <Row label={t("col.intent")}>
              <span className="font-mono uppercase">{intent ?? "legacy"}</span>
              <span className="text-muted-foreground"> · {current.mode}</span>
              {intentSummary ? (
                <p className="mt-0.5 text-muted-foreground">{intentSummary}</p>
              ) : null}
            </Row>
            <Row label={t("col.execution")}>
              <span className="inline-flex items-center gap-1">
                <Cpu className="h-3 w-3 text-muted-foreground" />
                {current.execution ?? "local"}
                {current.assigned_agent_id ? (
                  <>
                    <span className="text-muted-foreground">·</span>
                    <Link href="/agents" className="font-mono text-primary hover:underline">
                      {current.assigned_agent_id}
                    </Link>
                  </>
                ) : null}
              </span>
            </Row>
            <Row label={t("jobs.requestedBy")}>{current.requested_by || "—"}</Row>
            {current.tenant_id ? <Row label={t("jobs.tenant")}>{current.tenant_id}</Row> : null}
            {wordlist ? <Row label={t("jobs.wordlist")}>{wordlist}</Row> : null}
            <Row label={t("jobs.targets")}>
              {counts.length === 0 ? (
                <span className="text-muted-foreground">{t("jobs.targetsNone")}</span>
              ) : (
                <span className="flex flex-wrap gap-1.5">
                  {counts.map(([key, n]) => (
                    <Badge key={key} variant="secondary" className="font-mono text-[10px]">
                      {key}: {n}
                    </Badge>
                  ))}
                </span>
              )}
            </Row>
            {promoted.length > 0 ? (
              <Row label={t("jobs.promoted")}>
                <span className="font-mono">{promoted.join(", ")}</span>
              </Row>
            ) : null}
            {refused.length > 0 ? (
              <Row label={t("jobs.promotedRefused")}>
                <span className="font-mono text-amber-700 dark:text-amber-300">
                  {refused.join(", ")}
                </span>
              </Row>
            ) : null}
            <Row label={t("col.run")}>
              {current.run_id ? (
                <span className="flex flex-wrap gap-3">
                  <Link
                    href={runDetailHref(current.run_id)}
                    className="inline-flex items-center gap-1 font-mono text-primary hover:underline"
                  >
                    {current.run_id}
                    <ArrowUpRight className="h-3 w-3" />
                  </Link>
                  <Link
                    href={`${runDetailHref(current.run_id)}&tab=vulns`}
                    className="text-primary hover:underline"
                  >
                    {t("jobs.openFindings")}
                  </Link>
                </span>
              ) : (
                <span className="text-muted-foreground">{t("jobs.noRunYet")}</span>
              )}
            </Row>
          </dl>
        </section>

        {command ? (
          <section className="mt-5">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              className="-ml-2 h-7 gap-1 px-2 text-[11px] font-bold uppercase tracking-wider text-muted-foreground"
              onClick={() => setShowCommand((v) => !v)}
              aria-expanded={showCommand}
            >
              <ChevronDown
                className={`h-3 w-3 transition-transform ${showCommand ? "" : "-rotate-90"}`}
              />
              {t("jobs.command")}
            </Button>
            {showCommand ? (
              <pre className="mt-1 max-h-48 overflow-auto rounded-lg border border-border bg-muted/50 p-3 font-mono text-[11px] leading-relaxed text-foreground">
                {command}
              </pre>
            ) : null}
          </section>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
