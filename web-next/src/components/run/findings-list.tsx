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
        <Alert variant="warning">
          <AlertDescription>
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
          <section key={sev} className="rounded-lg border bg-white">
            <div className="flex items-center justify-between border-b px-4 py-3">
              <div className="flex items-center gap-2">
                <StatusBadge value={sev} map={SEVERITY_STATUS} />
                <span className="text-sm text-muted-foreground">
                  {visible.length < items.length
                    ? `${visible.length} of ${items.length.toLocaleString()} shown`
                    : `${items.length.toLocaleString()} findings`}
                </span>
              </div>
            </div>
            <ul className="divide-y">
              {visible.map((item, index) => (
                <li
                  key={`${item.host}-${item.port}-${item.cve}-${index}`}
                  className="px-4 py-3 text-sm"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="font-medium text-slate-900">
                        {item.cve || item.script_id || "finding"}
                        {item.port ? (
                          <span className="ml-2 text-muted-foreground">:{item.port}</span>
                        ) : null}
                      </p>
                      <p className="text-muted-foreground">
                        {item.host || "unknown host"}
                        {formatLocation(item) ? ` · ${formatLocation(item)}` : ""}
                      </p>
                    </div>
                    <span className="text-xs tabular-nums text-muted-foreground">
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
              <div className="border-t px-4 py-3">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
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
        <p className="text-sm text-muted-foreground">No findings for the current filters.</p>
      ) : null}
    </div>
  );
}
