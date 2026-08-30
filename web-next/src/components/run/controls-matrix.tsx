"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  FileText,
  Activity,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  fetchRunControls,
  type ControlItem,
  type ControlStatus,
  type OrgProfileControlsSummary,
} from "@/lib/api";

function StatusBadge({ status }: { status: ControlStatus }) {
  switch (status) {
    case "ok":
      return (
        <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40 gap-1 font-mono">
          <ShieldCheck className="h-3.5 w-3.5" />
          OK
        </Badge>
      );
    case "weak":
      return (
        <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/40 gap-1 font-mono">
          <AlertTriangle className="h-3.5 w-3.5" />
          WEAK
        </Badge>
      );
    case "fail":
      return (
        <Badge className="bg-rose-500/20 text-rose-300 border-rose-500/40 gap-1 font-mono">
          <ShieldAlert className="h-3.5 w-3.5" />
          FAIL
        </Badge>
      );
    case "error":
      return (
        <Badge className="bg-rose-950/60 text-rose-400 border-rose-800 gap-1 font-mono">
          <AlertTriangle className="h-3.5 w-3.5" />
          ERROR
        </Badge>
      );
    default:
      return (
        <Badge variant="outline" className="text-slate-400 border-slate-700 bg-slate-800/40 gap-1 font-mono">
          <ShieldQuestion className="h-3.5 w-3.5" />
          NOT CHECKED
        </Badge>
      );
  }
}

function RiskBadge({ risk }: { risk: string }) {
  const normalized = risk.toLowerCase();
  if (normalized.includes("very_high") || normalized.includes("critical")) {
    return <Badge className="bg-rose-600/30 text-rose-300 border-rose-500/40">Critical / Very High</Badge>;
  }
  if (normalized.includes("high")) {
    return <Badge className="bg-rose-500/20 text-rose-300 border-rose-500/30">High Risk</Badge>;
  }
  if (normalized.includes("moderate") || normalized.includes("medium")) {
    return <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/30">Moderate Risk</Badge>;
  }
  if (normalized.includes("low")) {
    return <Badge className="bg-blue-500/20 text-blue-300 border-blue-500/30">Low Risk</Badge>;
  }
  if (normalized.includes("very_low")) {
    return <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/30">Very Low Risk</Badge>;
  }
  return <Badge variant="outline" className="text-slate-500 border-slate-700">Unassessed</Badge>;
}

function SeverityPills({ counts }: { counts: Record<string, number> }) {
  const c = counts.critical || 0;
  const h = counts.high || 0;
  const m = counts.medium || 0;
  const l = counts.low || 0;
  return (
    <div className="flex items-center gap-1.5 font-mono text-xs">
      {c > 0 && <span className="rounded bg-rose-500/20 px-1.5 py-0.5 font-bold text-rose-300">C:{c}</span>}
      {h > 0 && <span className="rounded bg-orange-500/20 px-1.5 py-0.5 font-bold text-orange-300">H:{h}</span>}
      {m > 0 && <span className="rounded bg-amber-500/20 px-1.5 py-0.5 font-medium text-amber-300">M:{m}</span>}
      {l > 0 && <span className="rounded bg-blue-500/20 px-1.5 py-0.5 text-blue-300">L:{l}</span>}
      {c === 0 && h === 0 && m === 0 && l === 0 && <span className="text-slate-500">0 findings</span>}
    </div>
  );
}

function ControlRow({ control }: { control: ControlItem }) {
  const [expanded, setExpanded] = useState(false);
  const hasFindings = control.top_findings && control.top_findings.length > 0;

  return (
    <div className="border-b border-slate-800/60 last:border-0 hover:bg-slate-900/40 transition-colors">
      <div
        className="flex flex-col md:flex-row md:items-center justify-between p-4 gap-3 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start md:items-center gap-3">
          <Button
            variant="ghost"
            size="sm"
            className="h-6 w-6 p-0 text-slate-400 hover:text-slate-100 shrink-0 mt-0.5 md:mt-0"
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
          >
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </Button>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-semibold text-slate-100 text-sm">{control.title}</span>
              <span className="text-xs text-slate-500 font-mono">({control.control})</span>
              <Badge variant="outline" className="text-xs border-slate-700 text-slate-400 uppercase">
                Impact: {control.impact}
              </Badge>
            </div>
            <p className="text-xs text-slate-400 mt-1">{control.why || "No details reported"}</p>
          </div>
        </div>

        <div className="flex items-center gap-4 ml-9 md:ml-0 flex-wrap">
          <SeverityPills counts={control.findings_by_severity || {}} />
          <RiskBadge risk={control.risk_level || "unassessed"} />
          <StatusBadge status={control.status} />
        </div>
      </div>

      {expanded && (
        <div className="px-6 pb-4 pt-2 bg-slate-950/40 space-y-3 text-xs border-t border-slate-800/40">
          <div className="flex items-center gap-4 text-slate-400">
            <div>
              <span className="text-slate-500">Coverage: </span>
              <span className="font-mono text-slate-200 font-medium">
                {control.coverage?.checked ?? 0} / {control.coverage?.total ?? 0} targets
              </span>
            </div>
            {control.evidence && control.evidence.length > 0 && (
              <div className="flex items-center gap-1.5">
                <FileText className="h-3.5 w-3.5 text-slate-500" />
                <span className="text-slate-500">Evidence:</span>
                <span className="font-mono text-slate-300">{control.evidence.join(", ")}</span>
              </div>
            )}
          </div>

          {hasFindings ? (
            <div className="space-y-2">
              <span className="font-semibold text-slate-300 block">Top Findings / Observations:</span>
              <div className="space-y-1.5">
                {control.top_findings.map((f, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 bg-slate-900/60 p-2 rounded border border-slate-800 font-mono text-xs"
                  >
                    <span className="font-bold text-slate-200 shrink-0">{f.id}</span>
                    {f.domain && <span className="text-sky-400 shrink-0">[{f.domain}]</span>}
                    <span className="text-slate-400 grow">{f.detail || ""}</span>
                    <Badge variant="outline" className="text-[10px] uppercase border-slate-700 py-0 px-1 shrink-0">
                      {f.severity}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="text-slate-500 italic">No specific findings listed for this control.</p>
          )}
        </div>
      )}
    </div>
  );
}

export function ControlsMatrix({ runId }: { runId: string }) {
  const { data, isLoading, error } = useQuery<OrgProfileControlsSummary>({
    queryKey: ["run-controls", runId],
    queryFn: () => fetchRunControls(runId),
    enabled: Boolean(runId),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12 text-slate-400 gap-2 font-mono text-xs">
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-sky-400 border-t-transparent" />
        Evaluating security controls matrix…
      </div>
    );
  }

  if (error || !data) {
    return (
      <Card className="border-slate-800 bg-slate-900/60">
        <CardContent className="py-8 text-center text-slate-400 text-xs">
          <ShieldQuestion className="h-8 w-8 text-slate-500 mx-auto mb-2" />
          Controls matrix telemetry is not available for this run (stage unconfigured or artifacts absent).
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Overview Posture Card */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/80 p-5 shadow-lg backdrop-blur">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-sky-400" />
              <h2 className="text-base font-bold text-slate-100">Organization Security Posture Matrix</h2>
            </div>
            <p className="text-xs text-slate-400">
              Evaluated across 6 foundational external attack surface controls according to NIST SP 800-30 Rev. 1.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <span className="text-[11px] text-slate-400 uppercase tracking-wider block">Overall Verdict</span>
              <div className="mt-0.5">
                <StatusBadge status={data.overall_verdict} />
              </div>
            </div>
            <div className="text-right border-l border-slate-800 pl-3">
              <span className="text-[11px] text-slate-400 uppercase tracking-wider block">NIST Risk Level</span>
              <div className="mt-0.5">
                <RiskBadge risk={data.overall_risk} />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Controls Table Card */}
      <Card className="border-slate-800/80 bg-slate-900/80 shadow-md">
        <CardHeader className="py-3.5 px-4 border-b border-slate-800/80">
          <CardTitle className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Evaluated Security Controls ({data.controls?.length || 0})
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="divide-y divide-slate-800/60">
            {data.controls?.map((control) => (
              <ControlRow key={control.control} control={control} />
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
