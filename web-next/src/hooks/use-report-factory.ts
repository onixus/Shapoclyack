"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  createReportSchedule,
  createReportTemplate,
  deleteGeneratedReport,
  deleteReportSchedule,
  deleteReportTemplate,
  fetchBranding,
  fetchGeneratedReports,
  fetchReportSchedules,
  fetchReportTemplates,
  generateReport,
  updateBranding,
  type CreateReportScheduleBody,
  type CreateReportTemplateBody,
  type GenerateReportBody,
  type TenantBrandingInfo,
} from "@/lib/api";
import { queryKeys } from "@/lib/query-keys";

function failed(action: string) {
  return (err: unknown) =>
    toast.error(action, { description: err instanceof Error ? err.message : undefined });
}

export function useBranding() {
  return useQuery({ queryKey: queryKeys.reportBranding, queryFn: fetchBranding });
}

export function useUpdateBranding() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: Partial<Omit<TenantBrandingInfo, "tenant_id">>) => updateBranding(body),
    onSuccess: async () => {
      toast.success("Branding saved");
      await queryClient.invalidateQueries({ queryKey: queryKeys.reportBranding });
    },
    onError: failed("Failed to save branding"),
  });
}

export function useReportTemplates() {
  return useQuery({ queryKey: queryKeys.reportTemplates, queryFn: fetchReportTemplates });
}

export function useCreateReportTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateReportTemplateBody) => createReportTemplate(body),
    onSuccess: async (template) => {
      toast.success("Template created", { description: template.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.reportTemplates });
    },
    onError: failed("Failed to create template"),
  });
}

export function useDeleteReportTemplate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (templateId: string) => deleteReportTemplate(templateId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.reportTemplates });
      // A template delete cascades to its schedules in the database; the list
      // on screen has to follow or it offers a schedule that no longer exists.
      await queryClient.invalidateQueries({ queryKey: queryKeys.reportSchedules });
    },
    onError: failed("Failed to delete template"),
  });
}

export function useReportSchedules() {
  return useQuery({ queryKey: queryKeys.reportSchedules, queryFn: fetchReportSchedules });
}

export function useCreateReportSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: CreateReportScheduleBody) => createReportSchedule(body),
    onSuccess: async (schedule) => {
      toast.success("Schedule created", { description: schedule.name });
      await queryClient.invalidateQueries({ queryKey: queryKeys.reportSchedules });
    },
    onError: failed("Failed to create schedule"),
  });
}

export function useDeleteReportSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (scheduleId: string) => deleteReportSchedule(scheduleId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.reportSchedules });
    },
    onError: failed("Failed to delete schedule"),
  });
}

export function useGeneratedReports(limit = 50) {
  return useQuery({
    queryKey: queryKeys.generatedReports(limit),
    queryFn: () => fetchGeneratedReports(limit),
  });
}

export function useGenerateReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: GenerateReportBody) => generateReport(body),
    onSuccess: async (report) => {
      // A failed render comes back as a row with an error rather than an HTTP
      // error, so success here is not the same as "the report exists".
      if (report.status === "ready") {
        toast.success("Report generated", { description: report.title || report.report_id });
      } else {
        toast.error("Report generation failed", { description: report.error ?? undefined });
      }
      await queryClient.invalidateQueries({ queryKey: ["reports", "generated"] });
    },
    onError: failed("Failed to generate report"),
  });
}

export function useDeleteGeneratedReport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (reportId: string) => deleteGeneratedReport(reportId),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["reports", "generated"] });
    },
    onError: failed("Failed to delete report"),
  });
}
