"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  createSchedule,
  deleteSchedule,
  fetchSchedules,
  updateSchedule,
  type CreateScheduleBody,
  type UpdateScheduleBody,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

export function useSchedules(enabled: boolean) {
  return useQuery({
    queryKey: queryKeys.schedules,
    queryFn: () => fetchSchedules(),
    enabled,
  });
}

export function useCreateSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateScheduleBody) => createSchedule(body),
    onSuccess: async (schedule) => {
      toast.success("Schedule created", { description: schedule.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.schedules });
    },
    onError: (err) => {
      toast.error("Failed to create schedule", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useUpdateSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ scheduleId, body }: { scheduleId: string; body: UpdateScheduleBody }) =>
      updateSchedule(scheduleId, body),
    onSuccess: async (schedule) => {
      toast.success("Schedule updated", { description: schedule.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.schedules });
    },
    onError: (err) => {
      toast.error("Failed to update schedule", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}

export function useDeleteSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scheduleId: string) => deleteSchedule(scheduleId),
    onSuccess: async () => {
      toast.success("Schedule deleted");
      await queryClient.invalidateQueries({ queryKey: queryKeys.schedules });
    },
    onError: (err) => {
      toast.error("Failed to delete schedule", {
        description: err instanceof Error ? err.message : undefined,
      });
    },
  });
}
