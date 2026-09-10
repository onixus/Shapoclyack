"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  bulkAssetAction,
  bulkVulnerabilityAction,
  newBulkIdempotencyKey,
  type BulkAssetBody,
  type BulkActionReport,
  type BulkVulnerabilityBody,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/**
 * The bulk verbs (#346), shared by the findings and the assets table.
 *
 * Two things these hooks do that a plain mutation would not:
 *
 * **They mint an `Idempotency-Key` per submission.** A bulk request is the one
 * the operator is most likely to retry — it is the slowest, so it is the one
 * that times out — and a retry that applied two hundred transitions a second
 * time would be the worst outcome this feature could have. The key is created
 * inside `mutationFn`, so React Query's own retry of the *same* mutation
 * carries the same key and is deduplicated by the server, while the operator's
 * next, different batch gets a new one.
 *
 * **They report the per-id outcome rather than "done".** The API answers 200
 * with a report even when some ids failed, so a plain `onSuccess` toast saying
 * "updated" would be a lie for the ids that were not. `bulkSummary` is what
 * the toast says instead.
 */
export function bulkSummary(report: BulkActionReport, noun: string): string {
  const plural = report.succeeded === 1 ? noun : `${noun}s`;
  const applied = `${report.succeeded} ${plural} updated`;
  if (report.replayed) {
    // Nothing was applied by this request: the answer is the earlier one.
    return `${applied} (already applied — replayed)`;
  }
  return report.failed > 0 ? `${applied}, ${report.failed} skipped` : applied;
}

/** The distinct reasons ids were skipped, most common first, for the toast's
 * description. The full per-id detail is in the report the caller keeps. */
export function bulkFailureDetail(report: BulkActionReport): string | undefined {
  const failures = report.results.filter((item) => !item.ok);
  if (failures.length === 0) return undefined;
  const counts = new Map<string, number>();
  for (const item of failures) {
    const reason = item.error || item.outcome;
    counts.set(reason, (counts.get(reason) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 3)
    .map(([reason, count]) => (count > 1 ? `${reason} (×${count})` : reason))
    .join("; ");
}

function announce(report: BulkActionReport, noun: string) {
  const summary = bulkSummary(report, noun);
  const detail = bulkFailureDetail(report);
  if (report.failed > 0) {
    toast.warning(summary, { description: detail });
    return;
  }
  toast.success(summary);
}

export function useBulkVulnerabilityAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkVulnerabilityBody) =>
      bulkVulnerabilityAction(body, { idempotencyKey: newBulkIdempotencyKey() }),
    onSuccess: async (report) => {
      announce(report, "finding");
      // Every list, the summary KPIs and the activity feed can all have moved:
      // a batch touches rows on pages the operator is not looking at, so
      // invalidating the queries this row belongs to is not enough.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilities }),
        queryClient.invalidateQueries({ queryKey: queryKeys.vulnerabilitySummary }),
        queryClient.invalidateQueries({ queryKey: ["vulnerabilities", "events"] }),
      ]);
    },
    onError: (err) => {
      toast.error("Bulk action failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useBulkAssetAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: BulkAssetBody) =>
      bulkAssetAction(body, { idempotencyKey: newBulkIdempotencyKey() }),
    onSuccess: async (report) => {
      announce(report, "asset");
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["assets"] }),
        queryClient.invalidateQueries({ queryKey: ["asset"] }),
        queryClient.invalidateQueries({ queryKey: queryKeys.assetSummary }),
      ]);
    },
    onError: (err) => {
      toast.error("Bulk action failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
