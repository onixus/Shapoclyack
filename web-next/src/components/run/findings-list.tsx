"use client";

import { useState } from "react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { StatusBadge } from "@/components/status-badge";
import type { RunReportTruncation } from "@/hooks/use-run-report";
import type { Vulnerability } from "@/lib/api";
import { FINDINGS_GROUP_PREVIEW, VULN_FETCH_LIMIT } from "@/lib/config/constants";
import { SEVERITY_STATUS } from "@/lib/config/statuses";
import { SEVERITIES, formatLocation, type Severity } from "@/lib/run-data";

export function FindingsList({
  grouped,
  truncation,
}: {
  grouped: Record<Severity, Vulnerability[]>;
  truncation: RunReportTruncation;
}) {
  const [expanded, setExpanded] = useState<Partial<Record<Severity, boolean>>>({});
  const totalShown = SEVERITIES.reduce((n, sev) => n + grouped[sev].length, 0);

  return (
    <div className="space-y-4">
      {truncation.isTruncated ? (
        <Alert variant="warning" className="border-amber-500/30 bg-amber-950/40 text-amber-200">
          <AlertDescription className="text-xs">
            Showing {truncation.shown.toLocaleString()} of{" "}
            {truncation.total != null
              ? truncation.total.toLocaleString()
              : `${VULN_FETCH_LIMIT.toLocaleString()}+`}{" "}
            findings — the API returns at most {VULN_FETCH_LIMIT.toLocaleString()} per run. Narrow
            by host or port (Hosts/Ports tabs) to see the rest.
          </AlertDescription>
        </Alert>
      ) : null}

      {SEVERITIES.filter((sev) => grouped[sev].length > 0).map((sev) => {
        const items = grouped[sev];
        const isExpanded = Boolean(expanded[sev]);
        const visible = isExpanded ? items : items.slice(0, FINDINGS_GROUP_PREVIEW);
        return (
          <section key={sev} className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-900/80 shadow-lg backdrop-blur">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-4 py-3 bg-slate-950/40">
              <div className="flex items-center gap-2">
                <StatusBadge value={sev} map={SEVERITY_STATUS} />
                <span className="font-mono text-xs text-slate-400">
                  {visible.length < items.length
                    ? `${visible.length} of ${items.length.toLocaleString()} shown`
                    : `${items.length.toLocaleString()} findings`}
                </span>
              </div>
            </div>
            <ul className="divide-y divide-slate-800/60">
              {visible.map((item, index) => (
                <li
                  key={`${item.host}-${item.port}-${item.cve}-${index}`}
                  className="px-4 py-3 text-xs hover:bg-slate-800/40 transition-colors"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="font-mono font-bold text-slate-100">
                        {item.cve || item.script_id || "finding"}
                        {item.port ? (
                          <span className="ml-2 text-sky-400 font-normal">:{item.port}</span>
                        ) : null}
                      </p>
                      <p className="font-mono text-[11px] text-slate-400 mt-0.5">
                        {item.host || "unknown host"}
                        {formatLocation(item) ? ` · ${formatLocation(item)}` : ""}
                      </p>
                    </div>
                    <span className="font-mono text-[11px] font-semibold text-slate-300">
                      {item.cvss4 != null
                        ? `CVSS4 ${item.cvss4}`
                        : item.cvss != null
                          ? `CVSS ${item.cvss}`
                          : sev.toUpperCase()}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
            {items.length > FINDINGS_GROUP_PREVIEW ? (
              <div className="border-t border-slate-800/80 px-4 py-2.5 bg-slate-950/40">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800 text-xs font-semibold"
                  onClick={() => setExpanded((prev) => ({ ...prev, [sev]: !isExpanded }))}
                >
                  {isExpanded ? "Show less" : `Show all ${items.length.toLocaleString()} findings`}
                </Button>
              </div>
            ) : null}
          </section>
        );
      })}

      {totalShown === 0 ? (
        <p className="py-8 text-center text-xs text-slate-400">No findings for the current filters.</p>
      ) : null}
    </div>
  );
}
