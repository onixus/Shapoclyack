"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useT } from "@/lib/i18n";
import { toast } from "sonner";
import {
  createSchedule,
  deleteSchedule,
  fetchSchedules,
  updateSchedule,
  type CreateScheduleBody,
  type PageParams,
  type UpdateScheduleBody,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useSchedules(enabled: boolean, page?: PageParams, tenantId?: string) {
  return useQuery({
    queryKey: queryKeys.schedulesPage(tenantId, page),
    queryFn: () => fetchSchedules(tenantId, page),
    enabled,
  });
}

export function useCreateSchedule() {
  const t = useT();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateScheduleBody) => createSchedule(body),
    onSuccess: async (schedule) => {
      toast.success(t("scanCopy.created"), { description: schedule.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.schedules });
    },
    onError: (err) => {
      toast.error(t("scanCopy.createFailed"), {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useUpdateSchedule() {
  const t = useT();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scheduleId, body }: { scheduleId: string; body: UpdateScheduleBody }) =>
      updateSchedule(scheduleId, body),
    onSuccess: async (schedule) => {
      toast.success(t("scanCopy.updated"), { description: schedule.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.schedules });
    },
    onError: (err) => {
      toast.error(t("scanCopy.updateFailed"), {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDeleteSchedule() {
  const t = useT();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scheduleId: string) => deleteSchedule(scheduleId),
    onSuccess: async () => {
      toast.success(t("scanCopy.deleted"));
      await queryClient.invalidateQueries({ queryKey: queryKeys.schedules });
    },
    onError: (err) => {
      toast.error(t("scanCopy.deleteFailed"), {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
