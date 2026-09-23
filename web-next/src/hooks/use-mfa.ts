"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  beginKeyRegistration,
  confirmTotp,
  disableMfa,
  fetchMfaStatus,
  fetchWebAuthnKeys,
  finishKeyRegistration,
  resetUserMfa,
  revokeWebAuthnKey,
  setupTotp,
  type MfaSetup,
  type WebAuthnKey,
} from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { queryKeys } from "@/lib/query-keys";
import { createKey } from "@/lib/webauthn";

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
  return useMutation<string[], Error, { code: string; password?: string }>({
    mutationFn: ({ code, password }) => confirmTotp(code, password),
    onSuccess: async () => {
      toast.success("Two-factor authentication is on");
      await queryClient.invalidateQueries({ queryKey: queryKeys.mfa });
      // And re-read the principal: a session that was confined to this page
      // (`mfa_pending`) is not confined any more, and the API decides that per
      // request. Without this the banner stays up and the rest of the console
      // stays 403 on a screen that just said "you are done".
      await useAuthStore.getState().hydrate();
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

/** The signed-in account's own security keys (#315). */
export function useWebAuthnKeys(enabled = true) {
  return useQuery({
    queryKey: queryKeys.webauthnKeys,
    queryFn: fetchWebAuthnKeys,
    enabled,
  });
}

/**
 * Register a new key: options from the API, the browser's create prompt, the
 * attestation back to the API.
 *
 * A stale step-up is not handled here: the options call answers the same 403
 * every step-up route does, and the interceptor raises the prompt for it.
 * After re-verifying, the user presses the button again — nothing is replayed.
 */
export function useRegisterWebAuthnKey() {
  const queryClient = useQueryClient();
  return useMutation<WebAuthnKey, Error, { name: string }>({
    mutationFn: async ({ name }) => {
      const options = await beginKeyRegistration();
      const answer = await createKey(options);
      return finishKeyRegistration(answer, name);
    },
    onSuccess: async () => {
      toast.success("Security key added");
      await queryClient.invalidateQueries({ queryKey: queryKeys.mfa });
      // A session confined by the key policy stays confined until it is
      // re-proved *with* the key; re-reading the principal is what shows that.
      await useAuthStore.getState().hydrate();
    },
    onError: (err) => {
      toast.error("Could not add the security key", { description: err.message });
    },
  });
}

export function useRevokeWebAuthnKey() {
  const queryClient = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (id: string) => revokeWebAuthnKey(id),
    onSuccess: async () => {
      toast.success("Security key removed");
      await queryClient.invalidateQueries({ queryKey: queryKeys.mfa });
    },
    onError: (err) => {
      toast.error("Could not remove the security key", { description: err.message });
    },
  });
}
