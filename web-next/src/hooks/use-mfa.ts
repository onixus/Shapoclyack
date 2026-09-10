"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  confirmTotp,
  disableMfa,
  fetchMfaStatus,
  resetUserMfa,
  setupTotp,
  type MfaSetup,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** The signed-in account's own second-factor state (#315). */
export function useMfaStatus(enabled = true) {
  return useQuery({
    queryKey: queryKeys.mfa,
    queryFn: fetchMfaStatus,
    enabled,
  });
}

/**
 * Start enrolment.
 *
 * Deliberately a mutation and not a query: it *mints* a secret, so a query's
 * refetch-on-focus would hand the user a different secret every time they
 * tabbed back to the page, invalidating the one they had just scanned.
 */
export function useSetupTotp() {
  return useMutation<MfaSetup, Error, void>({
    mutationFn: () => setupTotp(),
    onError: (err) => {
      toast.error("Could not start MFA setup", { description: err.message });
    },
  });
}

/** Confirm a code and turn the factor on. Resolves to the recovery codes. */
export function useConfirmTotp() {
  const queryClient = useQueryClient();
  return useMutation<string[], Error, string>({
    mutationFn: (code: string) => confirmTotp(code),
    onSuccess: async () => {
      toast.success("Two-factor authentication is on");
      await queryClient.invalidateQueries({ queryKey: queryKeys.mfa });
    },
    onError: (err) => {
      toast.error("That code was not accepted", { description: err.message });
    },
  });
}

export function useDisableMfa() {
  const queryClient = useQueryClient();
  return useMutation<
    unknown,
    Error,
    { password: string; code?: string; recoveryCode?: string }
  >({
    mutationFn: ({ password, code, recoveryCode }) =>
      disableMfa({ password, code, recovery_code: recoveryCode }),
    onSuccess: async () => {
      toast.success("Two-factor authentication is off");
      await queryClient.invalidateQueries({ queryKey: queryKeys.mfa });
    },
    onError: (err) => {
      toast.error("Could not turn it off", { description: err.message });
    },
  });
}

/**
 * Clear another account's factor (admin). Ends that account's sessions, which
 * is why the toast says so: an admin who does this to a colleague has also
 * just signed them out of the console.
 */
export function useResetUserMfa() {
  const queryClient = useQueryClient();
  return useMutation<unknown, Error, string>({
    mutationFn: (username: string) => resetUserMfa(username),
    onSuccess: async (_data, username) => {
      toast.success("MFA reset", {
        description: `${username} must enrol again, and their sessions were ended.`,
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: (err) => {
      toast.error("Could not reset MFA", { description: err.message });
    },
  });
}
