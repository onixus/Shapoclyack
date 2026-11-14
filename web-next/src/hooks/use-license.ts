"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { getLicense, uploadLicense } from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useLicense() {
  return useQuery({
    queryKey: queryKeys.license,
    queryFn: getLicense,
  });
}

export function useUploadLicense() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (file: File) => uploadLicense(file),
    onSuccess: async (status) => {
      toast.success("License activated", {
        description: status.customer_name ?? status.license_id ?? undefined,
      });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.license }),
        // Scan-start and feature gates also read system runtime / inventory.
        queryClient.invalidateQueries({ queryKey: queryKeys.system }),
      ]);
    },
    onError: (err) => {
      toast.error("License upload failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
