"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  fetchAsset,
  fetchAssetContextEvents,
  fetchAssetSummary,
  fetchAssets,
  importAssets,
  updateAsset,
  type AssetExposureLevel,
  type AssetImportBody,
  type AssetStatus,
  type PageParams,
  type UpdateAssetBody,
} from "@/lib/api";
import { useSubmissionKey } from "@/hooks/use-bulk-actions";
import { POLL_INTERVALS } from "@/lib/config/constants";
import { useT } from "@/lib/i18n";
import { queryKeys } from "@/lib/query-keys";

export function useAssets(
  filters: { status: AssetStatus | ""; unowned?: boolean; exposure?: AssetExposureLevel | "" },
  page?: PageParams,
) {
  return useQuery({
    queryKey: queryKeys.assetsPage(
      { status: filters.status, unowned: filters.unowned, exposure: filters.exposure },
      page,
    ),
    queryFn: () =>
      fetchAssets(
        { status: filters.status, unowned: filters.unowned, exposure: filters.exposure },
        page,
      ),
    refetchInterval: POLL_INTERVALS.assets,
  });
}

export function useAssetSummary() {
  return useQuery({
    queryKey: queryKeys.assetSummary,
    queryFn: fetchAssetSummary,
    refetchInterval: POLL_INTERVALS.assets,
  });
}

export function useAssetDetail(assetId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.asset(assetId ?? "", tenantId),
    queryFn: () => fetchAsset(assetId!, tenantId),
    enabled: Boolean(assetId),
  });
}

export function useAssetContextEvents(assetId: string | null, tenantId = "default") {
  return useQuery({
    queryKey: queryKeys.assetEvents(assetId ?? "", tenantId),
    queryFn: () => fetchAssetContextEvents(assetId!, tenantId, { limit: 50 }),
    enabled: Boolean(assetId),
  });
}

export function useUpdateAsset(assetId: string, tenantId = "default") {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: UpdateAssetBody) => updateAsset(assetId, body),
    onSuccess: async (updated) => {
      queryClient.setQueryData(queryKeys.asset(assetId, tenantId), updated);
      await queryClient.invalidateQueries({ queryKey: ["assets"] });
      await queryClient.invalidateQueries({ queryKey: ["asset", assetId] });
      toast.success("Asset updated");
    },
    onError: (err) => {
      toast.error("Update failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

/**
 * The dry run of a CMDB/AD import (#350). A plain mutation rather than a query:
 * the preview is of one file the operator just picked, and it is never polled
 * or cached under a key — the next file is a different question.
 */
export function useAssetImportPreview() {
  return useMutation({
    mutationFn: (body: Omit<AssetImportBody, "dry_run">) =>
      importAssets({ ...body, dry_run: true }),
  });
}

/**
 * Applying it. Carries an `Idempotency-Key` held against the body, the way the
 * bulk verbs do: an apply that timed out and is clicked again replays the
 * first answer instead of importing the file twice.
 */
export function useAssetImportApply() {
  const queryClient = useQueryClient();
  const submission = useSubmissionKey();
  const t = useT();
  return useMutation({
    mutationFn: (body: Omit<AssetImportBody, "dry_run">) => {
      const full = { ...body, dry_run: false };
      return importAssets(full, { idempotencyKey: submission.forBody(full) });
    },
    onSuccess: async (report) => {
      submission.settled();
      const changed = report.counts.create + report.counts.update;
      toast.success(
        report.replayed
          ? t("assetImport.toast.replayed", { count: changed })
          : t("assetImport.toast.applied", {
              created: report.counts.create,
              updated: report.counts.update,
            }),
      );
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["assets"] }),
        queryClient.invalidateQueries({ queryKey: ["asset"] }),
        queryClient.invalidateQueries({ queryKey: queryKeys.assetSummary }),
      ]);
    },
    onError: (err) => {
      toast.error(t("assetImport.toast.failed"), {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
