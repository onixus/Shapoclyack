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
          <section key={sev} className="overflow-hidden rounded-xl border border-border bg-card shadow-lg backdrop-blur">
            <div className="flex items-center justify-between border-b border-border px-4 py-3 bg-muted">
              <div className="flex items-center gap-2">
                <StatusBadge value={sev} map={SEVERITY_STATUS} />
                <span className="font-mono text-xs text-muted-foreground">
                  {visible.length < items.length
                    ? `${visible.length} of ${items.length.toLocaleString()} shown`
                    : `${items.length.toLocaleString()} findings`}
                </span>
              </div>
            </div>
            <ul className="divide-y divide-border">
              {visible.map((item, index) => (
                <li
                  key={`${item.host}-${item.port}-${item.cve}-${index}`}
                  className="px-4 py-3 text-xs hover:bg-muted transition-colors"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="flex flex-wrap items-center gap-2 font-mono font-bold text-foreground">
                        {item.cve || item.script_id || "finding"}
                        {item.port ? (
                          <span className="text-sky-600 dark:text-sky-400 font-normal">:{item.port}</span>
                        ) : null}
                        {item.requires_confirmation ? (
                          <span
                            className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-amber-600 dark:text-amber-300"
                            title="The scanner could not confirm this finding — treat it as triage signal, not a confirmed vulnerability."
                          >
                            unconfirmed
                          </span>
                        ) : null}
                        {item.in_kev ? (
                          <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-rose-600 dark:text-rose-300">
                            KEV
                          </span>
                        ) : null}
                      </p>
                      <p className="font-mono text-[11px] text-muted-foreground mt-0.5">
                        {item.host || "unknown host"}
                        {formatLocation(item) ? ` · ${formatLocation(item)}` : ""}
                      </p>
                      {item.risk_explanation ? (
                        <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
                          {item.risk_explanation}
                        </p>
                      ) : null}
                    </div>
                    <div className="text-right">
                      <span className="font-mono text-[11px] font-semibold text-foreground">
                        {item.cvss4 != null
                          ? `CVSS4 ${item.cvss4}`
                          : item.cvss != null
                            ? `CVSS ${item.cvss}`
                            : sev.toUpperCase()}
                      </span>
                      {item.contextual_score != null ? (
                        <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                          risk {item.contextual_score.toFixed(1)}
                          {item.cisa_decision ? ` · ${item.cisa_decision}` : ""}
                        </p>
                      ) : null}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
            {items.length > FINDINGS_GROUP_PREVIEW ? (
              <div className="border-t border-border px-4 py-2.5 bg-muted">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="border-border bg-card text-foreground hover:bg-muted text-xs font-semibold"
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
        <p className="py-8 text-center text-xs text-muted-foreground">No findings for the current filters.</p>
      ) : null}
    </div>
  );
}
