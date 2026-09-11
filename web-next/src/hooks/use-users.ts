"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  changeOwnPassword,
  createUser,
  deleteUser,
  fetchAuthEvents,
  fetchProvisioningKeys,
  fetchTenantMembers,
  fetchUsers,
  grantMembership,
  revokeMembership,
  revokeProvisioningKey,
  setUserDisabled,
  setUserEmail,
  setUserPassword,
  setUserRole,
  type AuthEventOutcome,
  type CreateUserBody,
  type PageParams,
  type Role,
  type TenantRoleName,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useUsers(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.users,
    queryFn: fetchUsers,
    enabled,
  });
}

export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateUserBody) => createUser(body),
    onSuccess: async (user) => {
      toast.success("User created", { description: `${user.username} · ${user.role}` });
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: (err) => {
      toast.error("Failed to create user", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useSetUserRole() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ username, role }: { username: string; role: Role }) =>
      setUserRole(username, role),
    onSuccess: async (user) => {
      toast.success("Role updated", { description: `${user.username} is now ${user.role}` });
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: (err) => {
      toast.error("Failed to change the role", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useSetUserEmail() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      username,
      email,
      verified,
    }: {
      username: string;
      email: string | null;
      verified: boolean;
    }) => setUserEmail(username, email, verified),
    onSuccess: async (user) => {
      toast.success("Email updated", { description: user.email ?? user.username });
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: (err) => {
      toast.error("Failed to set the email", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useSetUserDisabled() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ username, disabled }: { username: string; disabled: boolean }) =>
      setUserDisabled(username, disabled),
    onSuccess: async (user) => {
      toast.success(user.disabled ? "Account disabled" : "Account enabled", {
        description: user.username,
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: (err) => {
      toast.error("Failed to change the account state", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useResetUserPassword() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ username, password }: { username: string; password: string }) =>
      setUserPassword(username, password),
    onSuccess: async (user) => {
      toast.success("Password reset", { description: user.username });
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: (err) => {
      toast.error("Failed to reset the password", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDeleteUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (username: string) => deleteUser(username),
    onSuccess: async (_data, username) => {
      toast.success("User deleted", { description: username });
      await queryClient.invalidateQueries({ queryKey: queryKeys.users });
    },
    onError: (err) => {
      toast.error("Failed to delete the user", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

/** Every role, not just admins: this is the one account operation a viewer
 * performs on themselves. */
export function useChangeOwnPassword() {
  return useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) =>
      changeOwnPassword(current, next),
    onSuccess: () => {
      toast.success("Password changed");
    },
    onError: (err) => {
      toast.error("Failed to change the password", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useAuthEvents(enabled: boolean, page?: PageParams, outcome?: AuthEventOutcome) {
  return useQuery({
    queryKey: queryKeys.authEvents(page, outcome),
    queryFn: () => fetchAuthEvents(page, outcome),
    enabled,
  });
}

export function useTenantMembers(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.tenantMembers(tenantId),
    queryFn: () => fetchTenantMembers(tenantId),
    enabled: enabled && Boolean(tenantId),
  });
}

/** One call for both "add a member" and "change their role" — the endpoint is
 * idempotent, so the console does not need to know which one this is. */
export function useGrantMembership(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    // A membership role, not the account's — a different and longer list
    // since #318, served by GET /api/rbac/roles.
    mutationFn: ({ username, role }: { username: string; role: TenantRoleName }) =>
      grantMembership(tenantId, username, role),
    onSuccess: async (membership) => {
      toast.success("Membership granted", {
        description: `${membership.username} · ${membership.role} in ${membership.tenant_id}`,
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.tenantMembers(tenantId) });
    },
    onError: (err) => {
      toast.error("Failed to grant the membership", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useRevokeMembership(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (username: string) => revokeMembership(tenantId, username),
    onSuccess: async (_data, username) => {
      toast.success("Membership revoked", { description: username });
      await queryClient.invalidateQueries({ queryKey: queryKeys.tenantMembers(tenantId) });
    },
    onError: (err) => {
      toast.error("Failed to revoke the membership", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useProvisioningKeys(tenantId: string, enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.provisioningKeys(tenantId),
    queryFn: () => fetchProvisioningKeys(tenantId),
    enabled: enabled && Boolean(tenantId),
  });
}

export function useRevokeProvisioningKey(tenantId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (keyId: string) => revokeProvisioningKey(tenantId, keyId),
    onSuccess: async (key) => {
      toast.success("Provisioning key revoked", { description: key.label || key.key_id });
      await queryClient.invalidateQueries({ queryKey: queryKeys.provisioningKeys(tenantId) });
    },
    onError: (err) => {
      toast.error("Failed to revoke the provisioning key", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
