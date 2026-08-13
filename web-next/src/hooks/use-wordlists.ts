"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  deleteWordlist,
  fetchWordlists,
  uploadWordlist,
  type WordlistInfo,
  type WordlistKind,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";
import { useAuthStore } from "@/lib/auth-store";

export function useWordlists(enabled: boolean = true) {
  const tenant = useAuthStore((s) => s.activeTenant);
  return useQuery<WordlistInfo[]>({
    queryKey: queryKeys.wordlists(tenant),
    queryFn: fetchWordlists,
    enabled,
  });
}

export function useUploadWordlist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (input: { file: File; kind: WordlistKind; name?: string }) =>
      uploadWordlist(input),
    onSuccess: async (wl) => {
      toast.success("Wordlist saved", {
        description: `${wl.name} — ${wl.line_count} entries`,
      });
      await queryClient.invalidateQueries({ queryKey: ["wordlists"] });
    },
    onError: (err) => {
      toast.error("Upload failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDeleteWordlist() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (wordlistId: string) => deleteWordlist(wordlistId),
    onSuccess: async () => {
      toast.success("Wordlist deleted");
      await queryClient.invalidateQueries({ queryKey: ["wordlists"] });
    },
    onError: (err) => {
      toast.error("Delete failed", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
