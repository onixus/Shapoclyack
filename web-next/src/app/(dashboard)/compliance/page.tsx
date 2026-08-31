"use client";

import { useEffect, useMemo, useState } from "react";
import { ClipboardCheck, ShieldCheck, ShieldX, MinusCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useComplianceFrameworks, useCompliancePosture } from "@/hooks/use-compliance";
import type { ComplianceControlStatus } from "@/lib/api";

const STATUS_STYLE: Record<ComplianceControlStatus["status"], string> = {
  passed: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
  failed: "border-rose-500/30 bg-rose-500/10 text-rose-400",
  not_assessed: "border-slate-500/30 bg-slate-500/10 text-slate-400",
};

const STATUS_LABEL: Record<ComplianceControlStatus["status"], string> = {
  passed: "Pass",
  failed: "Fail",
  not_assessed: "Not assessed",
};

function StatusIcon({ status }: { status: ComplianceControlStatus["status"] }) {
  if (status === "passed") return <ShieldCheck className="h-4 w-4 text-emerald-400" />;
  if (status === "failed") return <ShieldX className="h-4 w-4 text-rose-400" />;
  return <MinusCircle className="h-4 w-4 text-slate-500" />;
}

function ControlRow({ control }: { control: ComplianceControlStatus }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="border-b border-border/60 last:border-0">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-muted/40"
      >
        <StatusIcon status={control.status} />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-bold text-foreground">
              {control.control_id}
            </span>
            <span className="text-sm text-foreground">{control.title}</span>
          </span>
          <span className="mt-1 block text-xs text-muted-foreground">{control.rationale}</span>
        </span>
        <span className="flex shrink-0 items-center gap-2">
          {control.failing_count > 0 ? (
            <Badge variant="outline" className="border-rose-500/30 text-rose-400">
              {control.failing_count} failing
            </Badge>
          ) : null}
          {control.accepted_count > 0 ? (
            <Badge variant="outline" className="border-amber-500/30 text-amber-400">
              {control.accepted_count} accepted
            </Badge>
          ) : null}
          <Badge variant="outline" className={STATUS_STYLE[control.status]}>
            {STATUS_LABEL[control.status]}
          </Badge>
        </span>
      </button>
      {open ? (
        <div className="border-t border-border/60 bg-muted/20 px-4 py-3 text-xs">
          {control.status === "not_assessed" ? (
            <p className="text-muted-foreground">
              Not assessed: {control.not_assessed_reason}. A control with no evidence is reported
              as unknown rather than as a pass.
            </p>
          ) : control.evidence.length === 0 ? (
            <p className="text-muted-foreground">
              No failing evidence. Findings below {control.severity_floor} severity are not counted
              against this control.
            </p>
          ) : (
            <ul className="space-y-1">
              {control.evidence.map((item) => (
                <li key={`${item.kind}-${item.ref_id}`} className="flex flex-wrap gap-2">
                  <span className="font-mono text-foreground">{item.label}</span>
                  <span className="text-muted-foreground">{item.detail}</span>
                  <span className="text-muted-foreground">({item.signals.join(", ")})</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}
    </li>
  );
}

export default function CompliancePage() {
  const frameworksQuery = useComplianceFrameworks();
  const frameworks = useMemo(() => frameworksQuery.data ?? [], [frameworksQuery.data]);
  const [frameworkId, setFrameworkId] = useState<string | null>(null);

  useEffect(() => {
    if (!frameworkId && frameworks.length > 0) setFrameworkId(frameworks[0].framework_id);
  }, [frameworks, frameworkId]);

  const postureQuery = useCompliancePosture(frameworkId);
  const posture = postureQuery.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-foreground">
            <ClipboardCheck className="h-5 w-5 text-sky-500" />
            Compliance posture
          </h1>
          <p className="text-sm text-muted-foreground">
            Controls assessed from this tenant&apos;s own findings, asset context and endpoint
            inventory.
          </p>
        </div>
        <Select value={frameworkId ?? ""} onValueChange={setFrameworkId}>
          <SelectTrigger className="w-72">
            <SelectValue placeholder="Framework" />
          </SelectTrigger>
          <SelectContent>
            {frameworks.map((framework) => (
              <SelectItem key={framework.framework_id} value={framework.framework_id}>
                {framework.name} {framework.version}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {postureQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : postureQuery.error ? (
        <p className="text-sm text-rose-400">{(postureQuery.error as Error).message}</p>
      ) : posture ? (
        <>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">
                Assessed controls passing
              </p>
              <p className="mt-1 text-2xl font-bold text-foreground">
                {posture.controls_passed}/{posture.controls_assessed}
                {posture.coverage_score !== null ? (
                  <span className="ml-2 text-base text-muted-foreground">
                    {posture.coverage_score}%
                  </span>
                ) : null}
              </p>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Failing</p>
              <p className="mt-1 text-2xl font-bold text-rose-400">{posture.controls_failed}</p>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Not assessed</p>
              <p className="mt-1 text-2xl font-bold text-slate-400">
                {posture.controls_not_assessed}
              </p>
            </div>
            <div className="rounded-xl border border-border bg-card p-4">
              <p className="text-xs uppercase tracking-wide text-muted-foreground">Evidence base</p>
              <p className="mt-1 text-sm text-foreground">
                {posture.open_findings} open findings · {posture.asset_count} assets
              </p>
            </div>
          </div>

          {/* The scope note is not decoration: without it a coverage score is
              read as a compliance percentage for the whole standard. */}
          <p className="rounded-lg border border-amber-500/20 bg-amber-500/5 px-4 py-3 text-xs text-muted-foreground">
            <span className="font-semibold text-amber-500">Scope: </span>
            {posture.scope_note} The score is the share of assessed controls that pass, not a
            statement of compliance with {posture.name} {posture.version}.
          </p>

          <div className="rounded-xl border border-border bg-card">
            <ul>
              {posture.controls.map((control) => (
                <ControlRow key={control.control_id} control={control} />
              ))}
            </ul>
          </div>
        </>
      ) : null}
    </div>
  );
}
