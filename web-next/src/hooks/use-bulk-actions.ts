"use client";

import { useEffect, useRef, useState } from "react";
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
import { useAuthStore } from "@/lib/auth-store";
import { queryKeys } from "@/lib/query-keys";

/**
 * The bulk verbs (#346), shared by the findings and the assets table.
 *
 * Two things these hooks do that a plain mutation would not:
 *
 * **They mint an `Idempotency-Key` per submission, not per attempt.** A bulk
 * request is the one the operator is most likely to retry — it is the slowest,
 * so it is the one that times out — and a retry that applied two hundred
 * transitions a second time would be the worst outcome this feature could
 * have. Minting the key where the request is *sent* did nothing for that: the
 * proxy cuts the connection, the operator clicks Apply again, and a fresh UUID
 * is a batch the server has never seen. So the key is held against the body it
 * was minted for and reused until that submission is answered — the same click
 * retried by hand, or by React Query, carries the same key and is deduplicated
 * by the server, while the operator's next, different batch gets a new one.
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

/**
 * One `Idempotency-Key` per submission, keyed by the body it names.
 *
 * The same body gets the same key until that submission is answered, so a
 * retry — React Query's, or the operator clicking Apply again after a timeout
 * — is the *same* request to the server and replays rather than applying the
 * batch twice. A different body is a different batch and gets its own key,
 * which also keeps an edited-then-resubmitted form off the server's 409 for a
 * key reused with a different request. Forgotten on success, so an identical
 * batch submitted again later is deliberate work and not a replay.
 */
function useSubmissionKey() {
  const pending = useRef<{ signature: string; key: string } | null>(null);
  return {
    forBody(body: unknown): string {
      const signature = JSON.stringify(body);
      if (pending.current?.signature !== signature) {
        pending.current = { signature, key: newBulkIdempotencyKey() };
      }
      return pending.current.key;
    },
    settled() {
      pending.current = null;
    },
  };
}

/**
 * The selected ids for a bulk-capable table, dropped when the tenant changes.
 *
 * Selection deliberately survives paging, the poll and a filter change — an
 * operator builds one across pages. A tenant switch is the one change that
 * must not be survived: the ids belong to the tenant they were ticked in, so
 * they come back `not_found` and, at the 200-id ceiling, disable every
 * checkbox on a page of a tenant whose rows are not selected at all.
 */
export function useBulkSelection(): [string[], (ids: string[]) => void] {
  const tenant = useAuthStore((state) => state.activeTenant);
  const [selected, setSelected] = useState<string[]>([]);
  useEffect(() => {
    setSelected([]);
  }, [tenant]);
  return [selected, setSelected];
}

export function useBulkVulnerabilityAction() {
  const queryClient = useQueryClient();
  const submission = useSubmissionKey();
  return useMutation({
    mutationFn: (body: BulkVulnerabilityBody) =>
      bulkVulnerabilityAction(body, { idempotencyKey: submission.forBody(body) }),
    onSuccess: async (report) => {
      submission.settled();
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
  const submission = useSubmissionKey();
  return useMutation({
    mutationFn: (body: BulkAssetBody) =>
      bulkAssetAction(body, { idempotencyKey: submission.forBody(body) }),
    onSuccess: async (report) => {
      submission.settled();
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
