"use client";

import { Hourglass } from "lucide-react";
import type { JobInfo } from "@/lib/api";
import { useT } from "@/lib/i18n";

/** The last calendar refusal, refreshed by the queue's next start attempt. */
export function JobMaintenanceWait({ job, compact = false }: { job: JobInfo; compact?: boolean }) {
  const t = useT();
  const value = job.scan_options?.maintenance_wait;
  if (job.status !== "queued" || !value || typeof value !== "object") return null;
  const waiting = value as Record<string, unknown>;
  if (waiting.allowed !== false) return null;
  const reason =
    waiting.reason === "change_freeze"
      ? t("jobs.maintenanceFreeze")
      : waiting.reason === "outside_allowed_window"
        ? t("jobs.maintenanceAllowed")
        : t("jobs.maintenanceBlackout");
  const detail = typeof waiting.detail === "string" ? waiting.detail : "";
  const retry = typeof waiting.retry_at === "string" ? new Date(waiting.retry_at) : null;
  const retryText =
    retry && !Number.isNaN(retry.getTime())
      ? t("jobs.maintenanceRetry", { time: retry.toLocaleString() })
      : t("jobs.maintenanceRetryUnknown");
  const description = [reason, detail, retryText].filter(Boolean).join(". ");
  if (compact) {
    return (
      <span role="img" aria-label={reason} title={description}>
        <Hourglass className="h-3.5 w-3.5 shrink-0 text-amber-500" />
      </span>
    );
  }
  return (
    <div
      role="status"
      className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-200"
    >
      <p className="font-semibold">{reason}</p>
      {detail ? <p className="mt-0.5">{detail}</p> : null}
      <p className="mt-0.5">{retryText}</p>
    </div>
  );
}
