"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { ArrowUpRight, Ban, Cpu, Hourglass, Info, TriangleAlert } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { JobDetailsDrawer, jobDuration } from "@/components/scans/job-details-drawer";
import { SurfaceBadge } from "@/components/scans/surface-badge";
import { useCancelJob } from "@/hooks/use-jobs";
import { holdsPermission, useAuthStore } from "@/lib/auth-store";
import type { PaginationState } from "@/hooks/use-pagination";
import { type JobInfo, type Page } from "@/lib/api";
import { JOB_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { runDetailHref } from "@/lib/run-data";
import { jobSurface } from "@/lib/scan-surface";

/** Whether the API will accept a stop for this job.
 *
 * A running scan is cancellable since #360: the request reaches the agent on
 * its next heartbeat. `cancelling` is deliberately not — the stop has already
 * been asked for, and a second click would do nothing but suggest the first
 * one did not land. A local scan that has started is refused by the API with a
 * 409 and its reason; the console does not know the execution mode early
 * enough to hide the button, so the refusal is what says so.
 */
export function isCancellable(job: Pick<JobInfo, "status">): boolean {
  return job.status === "queued" || job.status === "claimed" || job.status === "running";
}

/** A job whose stop was requested and not yet confirmed by its agent. */
export function isStopping(job: Pick<JobInfo, "status">): boolean {
  return job.status === "cancelling";
}

/**
 * The job list shared by the three operations pages. Surface is a column on
 * the unpinned list and omitted on a surfaced one, where every row is the
 * same. Row click opens the full record; the cancel action shows on every job
 * the API will accept a stop for, which since #360 includes one an agent is
 * already running.
 */
export function JobsTable({
  page,
  isLoading,
  error,
  isFetching,
  pagination,
  showSurface,
  canOperate,
  initialJobId,
  onInitialJobClosed,
}: {
  page: Page<JobInfo> | undefined;
  isLoading: boolean;
  error: unknown;
  isFetching?: boolean;
  pagination: PaginationState;
  showSurface: boolean;
  canOperate: boolean;
  /** Open this job's drawer on mount (deep link from the command palette). */
  initialJobId?: string | null;
  onInitialJobClosed?: () => void;
}) {
  const t = useT();
  const jobs = useMemo(() => page?.items ?? [], [page]);
  const [selected, setSelected] = useState<JobInfo | null>(null);
  const [deepLinked, setDeepLinked] = useState<string | null>(initialJobId ?? null);
  const [cancelTarget, setCancelTarget] = useState<JobInfo | null>(null);
  const cancel = useCancelJob();
  // `scan.cancel` since #360, falling back to the rank the button used to be
  // gated on so an API older than #318 (which sends no permission list) keeps
  // showing it to the operators it always did. The API is the boundary either
  // way.
  const canCancel = useAuthStore((s) => canOperate && holdsPermission(s.user, "scan.cancel", true));

  const columns = useMemo<ColumnDef<JobInfo>[]>(() => {
    const cols: ColumnDef<JobInfo>[] = [
      {
        accessorKey: "job_id",
        header: t("col.jobId"),
        cell: ({ row }) => (
          <button
            type="button"
            onClick={() => setSelected(row.original)}
            className="font-mono text-xs font-semibold text-primary hover:underline"
            title={t("jobs.details")}
          >
            {row.original.job_id}
          </button>
        ),
      },
      {
        accessorKey: "status",
        header: t("col.status"),
        cell: ({ row }) => (
          <span className="inline-flex items-center gap-1.5">
            <StatusBadge
              value={row.original.status}
              map={JOB_STATUS}
              showPulse={
                row.original.status === "running" ||
                row.original.status === "claimed" ||
                row.original.status === "cancelling"
              }
            />
            {row.original.asset_upsert_error ? (
              <span
                role="img"
                aria-label={t("jobs.assetUpsertError")}
                title={`${t("jobs.assetUpsertError")}: ${row.original.asset_upsert_error}`}
              >
                <TriangleAlert className="h-3.5 w-3.5 shrink-0 text-amber-500" />
              </span>
            ) : null}
            {row.original.attempts && row.original.attempts > 1 ? (
              <span
                className="font-mono text-[10px] text-amber-600 dark:text-amber-300"
                title={t("jobs.attemptsHint")}
              >
                ×{row.original.attempts}
              </span>
            ) : null}
          </span>
        ),
      },
    ];
    if (showSurface) {
      cols.push({
        id: "surface",
        header: t("col.surface"),
        enableSorting: false,
        cell: ({ row }) => <SurfaceBadge surface={jobSurface(row.original)} link />,
      });
    }
    cols.push(
      {
        accessorKey: "mode",
        header: t("col.intent"),
        cell: ({ row }) => {
          const intentVal = row.original.scan_options?.intent;
          const counts = Object.entries(row.original.target_counts ?? {}).filter(
            ([, n]) => typeof n === "number" && n > 0,
          );
          return (
            <span className="flex flex-col gap-0.5">
              <span className="text-[11px] font-bold uppercase tracking-wider text-foreground">
                {typeof intentVal === "string" && intentVal ? intentVal : "legacy"}
                <span className="font-medium normal-case tracking-normal text-muted-foreground">
                  {" "}
                  · {row.original.mode}
                </span>
              </span>
              {counts.length > 0 ? (
                <span className="font-mono text-[10px] text-muted-foreground">
                  {counts.map(([k, n]) => `${k} ${n}`).join(" · ")}
                </span>
              ) : (
                <span className="text-[10px] text-muted-foreground">{t("jobs.targetsNone")}</span>
              )}
            </span>
          );
        },
      },
      {
        accessorKey: "run_id",
        header: t("col.run"),
        enableSorting: false,
        cell: ({ row }) => {
          const runId = row.original.run_id;
          if (!runId) return <span className="text-muted-foreground">—</span>;
          return (
            <Link
              href={runDetailHref(runId)}
              className="inline-flex items-center gap-1 font-mono text-xs font-semibold text-primary hover:underline"
              title={t("jobs.openRun")}
            >
              <span>{runId}</span>
              <ArrowUpRight className="h-3 w-3" />
            </Link>
          );
        },
      },
      {
        accessorKey: "execution",
        header: t("col.execution"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="inline-flex flex-col text-xs text-foreground">
            <span className="inline-flex items-center gap-1 font-medium">
              <Cpu className="h-3 w-3 text-muted-foreground" />
              {row.original.execution || "local"}
            </span>
            {row.original.assigned_agent_id ? (
              <span className="font-mono text-[10px] text-muted-foreground">
                {row.original.assigned_agent_id}
              </span>
            ) : null}
          </span>
        ),
      },
      {
        accessorKey: "started_at",
        header: t("col.started"),
        cell: ({ row }) => {
          const duration = jobDuration(row.original);
          return row.original.started_at ? (
            <span className="flex flex-col">
              <span className="font-mono text-xs text-foreground">
                {format(new Date(row.original.started_at), "yyyy-MM-dd HH:mm:ss")}
              </span>
              {duration ? (
                <span className="text-[10px] text-muted-foreground">{duration}</span>
              ) : null}
            </span>
          ) : (
            <span className="text-muted-foreground">—</span>
          );
        },
      },
      {
        accessorKey: "requested_by",
        header: t("col.operator"),
        enableSorting: false,
        cell: ({ getValue }) => (
          <span className="text-xs font-semibold text-foreground">{String(getValue() || "—")}</span>
        ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <span className="flex items-center justify-end gap-1">
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-7 w-7 text-muted-foreground hover:text-foreground"
              aria-label={t("jobs.details")}
              title={t("jobs.details")}
              onClick={() => setSelected(row.original)}
            >
              <Info className="h-3.5 w-3.5" />
            </Button>
            {canCancel && isCancellable(row.original) ? (
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="h-7 w-7 text-rose-600 hover:bg-rose-500/10 hover:text-rose-700 dark:text-rose-400"
                aria-label={t("jobs.cancel")}
                title={t("jobs.cancel")}
                onClick={() => setCancelTarget(row.original)}
              >
                <Ban className="h-3.5 w-3.5" />
              </Button>
            ) : null}
            {isStopping(row.original) ? (
              <span
                role="img"
                aria-label={t("jobs.stopping")}
                title={t("jobs.stopping")}
                className="text-amber-600 dark:text-amber-300"
              >
                <Hourglass className="h-3.5 w-3.5" />
              </span>
            ) : null}
          </span>
        ),
      },
    );
    return cols;
  }, [t, showSurface, canCancel]);

  return (
    <>
      <DataTable
        columns={columns}
        data={jobs}
        isLoading={isLoading}
        error={error}
        initialSorting={[{ id: "started_at", desc: true }]}
        searchPlaceholder={t("search.scans")}
        loadingMessage={t("loading.jobs")}
        emptyMessage={t("empty.jobs")}
        meta={`${(page?.total ?? 0).toLocaleString()} jobs${isFetching ? t("common.refreshing") : ""}`}
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: page?.total ?? 0,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
          sortableColumns: ["started_at", "finished_at", "status", "job_id", "mode", "tenant_id"],
          sort: pagination.sort,
          order: pagination.order,
          onSortChange: pagination.setSort,
        }}
      />

      <JobDetailsDrawer
        job={selected}
        jobId={selected ? null : deepLinked}
        open={Boolean(selected) || Boolean(deepLinked)}
        onOpenChange={(open) => {
          if (open) return;
          setSelected(null);
          if (deepLinked) {
            setDeepLinked(null);
            onInitialJobClosed?.();
          }
        }}
      />

      <AlertDialog
        open={Boolean(cancelTarget)}
        onOpenChange={(open) => !open && setCancelTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("jobs.cancelTitle", { id: cancelTarget?.job_id ?? "" })}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs">
              {cancelTarget && cancelTarget.status !== "queued"
                ? t("jobs.cancelBodyRunning")
                : t("jobs.cancelBody")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("jobs.keepJob")}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 text-white hover:bg-rose-500"
              onClick={() => {
                if (cancelTarget) cancel.mutate(cancelTarget.job_id);
                setCancelTarget(null);
              }}
            >
              {t("jobs.cancelConfirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
