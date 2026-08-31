"use client";

import { useState } from "react";
import { format } from "date-fns";
import { Download, FileBarChart, Palette, Plus, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useComplianceFrameworks } from "@/hooks/use-compliance";
import {
  useBranding,
  useCreateReportSchedule,
  useCreateReportTemplate,
  useDeleteGeneratedReport,
  useDeleteReportSchedule,
  useDeleteReportTemplate,
  useGenerateReport,
  useGeneratedReports,
  useReportSchedules,
  useReportTemplates,
  useUpdateBranding,
} from "@/hooks/use-report-factory";
import { downloadGeneratedReport, type GeneratedReportInfo } from "@/lib/api";

type Kind = "executive" | "technical" | "compliance";
type Format = "pdf" | "html" | "json";

function Section({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-xl border border-border bg-card">
      <div className="flex items-center gap-2 border-b border-border px-4 py-3">
        {icon}
        <h2 className="text-sm font-bold text-foreground">{title}</h2>
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

function deliverySummary(report: GeneratedReportInfo) {
  if (report.delivery.length === 0) return null;
  const delivered = report.delivery.filter((entry) => entry.status === "delivered").length;
  // Deliberately "2/4", not "sent": the failures are the half worth seeing.
  return `${delivered}/${report.delivery.length} delivered`;
}

export function ReportFactoryPanel() {
  const branding = useBranding();
  const saveBranding = useUpdateBranding();
  const templates = useReportTemplates();
  const createTemplate = useCreateReportTemplate();
  const deleteTemplate = useDeleteReportTemplate();
  const schedules = useReportSchedules();
  const createSchedule = useCreateReportSchedule();
  const deleteSchedule = useDeleteReportSchedule();
  const reports = useGeneratedReports();
  const generate = useGenerateReport();
  const deleteReport = useDeleteGeneratedReport();
  const frameworks = useComplianceFrameworks();

  const [orgName, setOrgName] = useState<string | null>(null);
  const [primaryColor, setPrimaryColor] = useState<string | null>(null);
  const [footerText, setFooterText] = useState<string | null>(null);

  const [templateName, setTemplateName] = useState("");
  const [templateKind, setTemplateKind] = useState<Kind>("executive");
  const [templateFramework, setTemplateFramework] = useState<string>("");

  const [scheduleTemplate, setScheduleTemplate] = useState<string>("");
  const [scheduleName, setScheduleName] = useState("");
  const [scheduleCron, setScheduleCron] = useState("0 6 1 * *");
  const [scheduleFormat, setScheduleFormat] = useState<Format>("pdf");
  const [scheduleRecipient, setScheduleRecipient] = useState("");

  const [generateKind, setGenerateKind] = useState<Kind>("executive");
  const [generateFormat, setGenerateFormat] = useState<Format>("pdf");
  const [generateFramework, setGenerateFramework] = useState<string>("");

  const brandingRow = branding.data;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Section title="Branding" icon={<Palette className="h-4 w-4 text-sky-500" />}>
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="org-name">Organisation name</Label>
            <Input
              id="org-name"
              value={orgName ?? brandingRow?.org_name ?? ""}
              onChange={(event) => setOrgName(event.target.value)}
              placeholder="Acme MSSP"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="primary-color">Primary colour</Label>
            <Input
              id="primary-color"
              value={primaryColor ?? brandingRow?.primary_color ?? ""}
              onChange={(event) => setPrimaryColor(event.target.value)}
              placeholder="#1e3a8a"
            />
          </div>
          <div className="space-y-1 sm:col-span-2">
            <Label htmlFor="footer-text">Footer</Label>
            <Input
              id="footer-text"
              value={footerText ?? brandingRow?.footer_text ?? ""}
              onChange={(event) => setFooterText(event.target.value)}
              placeholder="Confidential — prepared for Acme Ltd"
            />
          </div>
        </div>
        <Button
          className="mt-3"
          size="sm"
          disabled={saveBranding.isPending}
          onClick={() =>
            saveBranding.mutate({
              org_name: orgName ?? brandingRow?.org_name ?? null,
              primary_color: primaryColor ?? brandingRow?.primary_color ?? null,
              footer_text: footerText ?? brandingRow?.footer_text ?? null,
            })
          }
        >
          Save branding
        </Button>
        <p className="mt-2 text-xs text-muted-foreground">
          Applied to every rendered report for this tenant. Admin only.
        </p>
      </Section>

      <Section title="Generate now" icon={<FileBarChart className="h-4 w-4 text-sky-500" />}>
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1">
            <Label>Report</Label>
            <Select value={generateKind} onValueChange={(value) => setGenerateKind(value as Kind)}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="executive">Executive</SelectItem>
                <SelectItem value="technical">Technical</SelectItem>
                <SelectItem value="compliance">Compliance</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1">
            <Label>Format</Label>
            <Select
              value={generateFormat}
              onValueChange={(value) => setGenerateFormat(value as Format)}
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="pdf">PDF</SelectItem>
                <SelectItem value="html">HTML</SelectItem>
                <SelectItem value="json">JSON</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {generateKind === "compliance" ? (
            <div className="space-y-1">
              <Label>Framework</Label>
              <Select value={generateFramework} onValueChange={setGenerateFramework}>
                <SelectTrigger>
                  <SelectValue placeholder="Select" />
                </SelectTrigger>
                <SelectContent>
                  {(frameworks.data ?? []).map((framework) => (
                    <SelectItem key={framework.framework_id} value={framework.framework_id}>
                      {framework.name} {framework.version}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          ) : null}
        </div>
        <Button
          className="mt-3"
          size="sm"
          disabled={
            generate.isPending || (generateKind === "compliance" && !generateFramework)
          }
          onClick={() =>
            generate.mutate({
              kind: generateKind,
              format: generateFormat,
              framework_id: generateKind === "compliance" ? generateFramework : null,
            })
          }
        >
          Generate
        </Button>
      </Section>

      <Section title="Templates" icon={<Plus className="h-4 w-4 text-sky-500" />}>
        <div className="grid gap-3 sm:grid-cols-3">
          <Input
            value={templateName}
            onChange={(event) => setTemplateName(event.target.value)}
            placeholder="Monthly executive"
          />
          <Select value={templateKind} onValueChange={(value) => setTemplateKind(value as Kind)}>
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="executive">Executive</SelectItem>
              <SelectItem value="technical">Technical</SelectItem>
              <SelectItem value="compliance">Compliance</SelectItem>
            </SelectContent>
          </Select>
          {templateKind === "compliance" ? (
            <Select value={templateFramework} onValueChange={setTemplateFramework}>
              <SelectTrigger>
                <SelectValue placeholder="Framework" />
              </SelectTrigger>
              <SelectContent>
                {(frameworks.data ?? []).map((framework) => (
                  <SelectItem key={framework.framework_id} value={framework.framework_id}>
                    {framework.name} {framework.version}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          ) : null}
        </div>
        <Button
          className="mt-3"
          size="sm"
          disabled={
            !templateName ||
            createTemplate.isPending ||
            (templateKind === "compliance" && !templateFramework)
          }
          onClick={() =>
            createTemplate.mutate(
              {
                name: templateName,
                kind: templateKind,
                framework_id: templateKind === "compliance" ? templateFramework : null,
              },
              { onSuccess: () => setTemplateName("") },
            )
          }
        >
          Add template
        </Button>
        <ul className="mt-3 space-y-1 text-xs">
          {(templates.data ?? []).map((template) => (
            <li
              key={template.template_id}
              className="flex items-center justify-between gap-2 rounded border border-border/60 px-2 py-1.5"
            >
              <span className="truncate">
                <span className="font-semibold text-foreground">{template.name}</span>{" "}
                <Badge variant="outline">{template.kind}</Badge>
              </span>
              <Button
                variant="ghost"
                size="icon"
                aria-label={`Delete ${template.name}`}
                onClick={() => deleteTemplate.mutate(template.template_id)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Scheduled delivery" icon={<Plus className="h-4 w-4 text-sky-500" />}>
        <div className="grid gap-3 sm:grid-cols-2">
          <Select value={scheduleTemplate} onValueChange={setScheduleTemplate}>
            <SelectTrigger>
              <SelectValue placeholder="Template" />
            </SelectTrigger>
            <SelectContent>
              {(templates.data ?? []).map((template) => (
                <SelectItem key={template.template_id} value={template.template_id}>
                  {template.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Input
            value={scheduleName}
            onChange={(event) => setScheduleName(event.target.value)}
            placeholder="Monthly to the CISO"
          />
          <Input
            value={scheduleCron}
            onChange={(event) => setScheduleCron(event.target.value)}
            placeholder="0 6 1 * * (UTC)"
          />
          <Select
            value={scheduleFormat}
            onValueChange={(value) => setScheduleFormat(value as Format)}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="pdf">PDF</SelectItem>
              <SelectItem value="html">HTML</SelectItem>
              <SelectItem value="json">JSON</SelectItem>
            </SelectContent>
          </Select>
          <Input
            className="sm:col-span-2"
            value={scheduleRecipient}
            onChange={(event) => setScheduleRecipient(event.target.value)}
            placeholder="ciso@example.com or https://hooks.example.com/reports"
          />
        </div>
        <Button
          className="mt-3"
          size="sm"
          disabled={!scheduleTemplate || !scheduleName || createSchedule.isPending}
          onClick={() =>
            createSchedule.mutate(
              {
                template_id: scheduleTemplate,
                name: scheduleName,
                cron: scheduleCron,
                format: scheduleFormat,
                recipients: scheduleRecipient
                  ? [
                      {
                        transport: scheduleRecipient.startsWith("http") ? "webhook" : "email",
                        target: scheduleRecipient,
                      },
                    ]
                  : [],
              },
              { onSuccess: () => setScheduleRecipient("") },
            )
          }
        >
          Add schedule
        </Button>
        <ul className="mt-3 space-y-1 text-xs">
          {(schedules.data ?? []).map((schedule) => (
            <li
              key={schedule.schedule_id}
              className="flex items-center justify-between gap-2 rounded border border-border/60 px-2 py-1.5"
            >
              <span className="truncate">
                <span className="font-semibold text-foreground">{schedule.name}</span>{" "}
                <span className="font-mono text-muted-foreground">{schedule.cron}</span>{" "}
                <span className="text-muted-foreground">
                  next{" "}
                  {schedule.next_run_at
                    ? format(new Date(schedule.next_run_at), "yyyy-MM-dd HH:mm")
                    : "—"}
                </span>
              </span>
              <Button
                variant="ghost"
                size="icon"
                aria-label={`Delete ${schedule.name}`}
                onClick={() => deleteSchedule.mutate(schedule.schedule_id)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </li>
          ))}
        </ul>
      </Section>

      <Section
        title="Generated reports"
        icon={<FileBarChart className="h-4 w-4 text-sky-500" />}
      >
        <ul className="space-y-1 text-xs lg:col-span-2">
          {(reports.data ?? []).length === 0 ? (
            <li className="text-muted-foreground">Nothing generated yet.</li>
          ) : null}
          {(reports.data ?? []).map((report) => (
            <li
              key={report.report_id}
              className="flex items-center justify-between gap-2 rounded border border-border/60 px-2 py-1.5"
            >
              <span className="min-w-0 truncate">
                <span className="font-semibold text-foreground">
                  {report.title || report.report_id}
                </span>{" "}
                <Badge variant="outline">{report.format}</Badge>{" "}
                <span className="text-muted-foreground">
                  {report.generated_at
                    ? format(new Date(report.generated_at), "yyyy-MM-dd HH:mm")
                    : "—"}
                </span>{" "}
                {report.status === "failed" ? (
                  <span className="text-rose-400">{report.error}</span>
                ) : (
                  <span className="text-muted-foreground">{deliverySummary(report)}</span>
                )}
              </span>
              <span className="flex shrink-0 gap-1">
                {report.status === "ready" ? (
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Download ${report.report_id}`}
                    onClick={() => downloadGeneratedReport(report)}
                  >
                    <Download className="h-3.5 w-3.5" />
                  </Button>
                ) : null}
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Delete ${report.report_id}`}
                  onClick={() => deleteReport.mutate(report.report_id)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </span>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  );
}
