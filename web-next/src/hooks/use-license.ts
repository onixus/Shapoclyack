"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { getLicense, uploadLicense } from "@/lib/api";
import { useT } from "@/lib/i18n";
import { queryKeys } from "@/lib/query-keys";

export function useLicense() {
  return useQuery({
    queryKey: queryKeys.license,
    queryFn: getLicense,
  });
}

export function useUploadLicense() {
  const queryClient = useQueryClient();
  const t = useT();
  return useMutation({
    mutationFn: (file: File) => uploadLicense(file),
    onSuccess: async (status) => {
      toast.success(t("page.license.activated"), {
        description: status.customer_name ?? status.license_id ?? undefined,
      });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.license }),
        // Scan-start and feature gates also read system runtime / inventory.
        queryClient.invalidateQueries({ queryKey: queryKeys.system }),
      ]);
    },
    onError: (err) => {
      toast.error(t("page.license.uploadFailed"), {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
