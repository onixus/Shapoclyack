"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  createWebhook,
  deleteWebhook,
  fetchWebhookDeliveries,
  fetchWebhooks,
  retryWebhookDelivery,
  rotateWebhookSecret,
  testWebhook,
  updateWebhook,
  type CreateWebhookBody,
  type PageParams,
  type UpdateWebhookBody,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

/** `data === null` is the answer for an installation with
 * `OCTO_WEBHOOKS_ENABLED=false`; the page renders that as an empty state, not
 * as a failure, so it is deliberately not turned into a thrown error here. */
export function useWebhooks(enabled: boolean, page?: PageParams) {
  return useQuery({
    queryKey: queryKeys.webhooksPage(page),
    queryFn: () => fetchWebhooks(page),
    enabled,
  });
}

/** Polled: a queued delivery changes state on the dispatcher's tick, not on
 * anything the console does, so a "test" that just went out lands on its own. */
export function useWebhookDeliveries(enabled: boolean, status: string | null, page?: PageParams) {
  return useQuery({
    queryKey: queryKeys.webhookDeliveries(status, page),
    queryFn: () => fetchWebhookDeliveries(page, status ? { status } : undefined),
    refetchInterval: 15_000,
    enabled,
  });
}

export function useCreateWebhook() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateWebhookBody) => createWebhook(body),
    onSuccess: async (subscription) => {
      toast.success("Integration created", { description: subscription.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
    onError: (err) => {
      toast.error("Could not create the integration", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useUpdateWebhook() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ subscriptionId, body }: { subscriptionId: string; body: UpdateWebhookBody }) =>
      updateWebhook(subscriptionId, body),
    onSuccess: async (subscription) => {
      toast.success("Integration updated", { description: subscription.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
    onError: (err) => {
      toast.error("Could not update the integration", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDeleteWebhook() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: deleteWebhook,
    onSuccess: async () => {
      toast.success("Integration deleted");
      await queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
    onError: (err) => {
      toast.error("Could not delete the integration", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

/** The new secret is handed back to the caller, which shows it once. It is
 * deliberately kept out of the toast: a toast outlives the moment the admin is
 * looking at it, and this value is unrecoverable afterwards. */
export function useRotateWebhookSecret() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: rotateWebhookSecret,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
    onError: (err) => {
      toast.error("Could not rotate the signing secret", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useTestWebhook() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: testWebhook,
    onSuccess: async () => {
      toast.success("Test delivery queued", {
        description: "The result appears in Deliveries once the dispatcher runs.",
      });
      await queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
    onError: (err) => {
      toast.error("Could not queue the test delivery", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useRetryWebhookDelivery() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: retryWebhookDelivery,
    onSuccess: async () => {
      toast.success("Delivery requeued");
      await queryClient.invalidateQueries({ queryKey: queryKeys.webhooks });
    },
    onError: (err) => {
      toast.error("Could not requeue the delivery", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
