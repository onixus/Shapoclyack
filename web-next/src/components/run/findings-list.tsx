"use client";
import { runText } from "@/lib/run-presentation";

import { OriginalRunData } from "@/components/run/original-data";
import { RiskExplanation } from "@/components/vulnerability/risk-explanation";
import { CisaDecision } from "@/components/vulnerability/cisa-decision";
import { vulnerabilityName, vulnerabilityText } from "@/lib/vulnerability-presentation";
import { useState } from "react";
import { FindingEvidencePanel } from "@/components/finding-evidence";
import { useT } from "@/lib/i18n";
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
  const t = useT();
  const [expanded, setExpanded] = useState<Partial<Record<Severity, boolean>>>({});
  const totalShown = SEVERITIES.reduce((n, sev) => n + grouped[sev].length, 0);

  return (
    <div className="space-y-4">
      {truncation.isTruncated ? (
        <Alert
          variant="warning"
          className="border-amber-500/30 bg-amber-50 dark:bg-amber-950/40 text-amber-800 dark:text-amber-200"
        >
          <AlertDescription className="text-xs">
            {runText(
              t.locale,
              "Showing {shown} of {total} findings — the API returns at most {limit} per run. Narrow by host or port (Hosts/Ports tabs) to see the rest.",
              {
                shown: truncation.shown.toLocaleString(),
                total:
                  truncation.total != null
                    ? truncation.total.toLocaleString()
                    : `${VULN_FETCH_LIMIT.toLocaleString()}+`,
                limit: VULN_FETCH_LIMIT.toLocaleString(),
              },
            )}
          </AlertDescription>
        </Alert>
      ) : null}

      {SEVERITIES.filter((sev) => grouped[sev].length > 0).map((sev) => {
        const items = grouped[sev];
        const isExpanded = Boolean(expanded[sev]);
        const visible = isExpanded ? items : items.slice(0, FINDINGS_GROUP_PREVIEW);
        return (
          <section key={sev} className="overflow-hidden rounded-xl border border-border bg-card">
            <div className="flex items-center justify-between border-b border-border px-4 py-3 bg-muted">
              <div className="flex items-center gap-2">
                <StatusBadge value={sev} map={SEVERITY_STATUS} />
                <span className="font-mono text-xs text-muted-foreground">
                  {visible.length < items.length
                    ? runText(t.locale, "{shown} of {total} shown", {
                        shown: visible.length,
                        total: items.length.toLocaleString(),
                      })
                    : runText(t.locale, "{count} findings", {
                        count: items.length.toLocaleString(),
                      })}
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
                        {vulnerabilityName(
                          {
                            cve: item.cve,
                            script_id: item.script_id,
                            title: (item as Vulnerability & { title?: string }).title || "",
                          },
                          t.locale,
                        )}
                        {item.port ? (
                          <span className="text-sky-600 dark:text-sky-400 font-normal">
                            :{item.port}
                          </span>
                        ) : null}
                        {item.requires_confirmation ? (
                          <span
                            className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 text-overline font-semibold uppercase text-amber-600 dark:text-amber-300"
                            title={runText(
                              t.locale,
                              "The scanner could not confirm this finding — treat it as triage signal, not a confirmed vulnerability.",
                            )}
                          >
                            {runText(t.locale, "unconfirmed")}
                          </span>
                        ) : null}
                        {item.in_kev ? (
                          <span className="rounded border border-rose-500/30 bg-rose-500/10 px-1.5 py-0.5 text-overline font-semibold uppercase text-rose-600 dark:text-rose-300">
                            KEV
                          </span>
                        ) : null}
                      </p>
                      <p className="font-mono text-xs text-muted-foreground mt-0.5">
                        {item.host || runText(t.locale, "unknown host")}
                        {formatLocation(item) ? ` · ${formatLocation(item)}` : ""}
                      </p>
                      {item.finding_type && item.finding_type !== "cve" ? (
                        <p className="mt-1 text-muted-foreground">
                          {vulnerabilityText(t.locale, item.finding_type)} ·{" "}
                          {vulnerabilityText(t.locale, item.detector_source || "scan")}
                        </p>
                      ) : null}
                      {item.remediation ? (
                        <p className="mt-1 text-foreground">
                          {runText(t.locale, "Remediation")}:{" "}
                          {t.locale === "ru" && !/[А-Яа-яЁё]/.test(item.remediation)
                            ? "Исходная рекомендация сканера приведена в технических данных. Перед исправлением проверьте её применимость к этому сервису."
                            : item.remediation}
                        </p>
                      ) : null}
                      {t.locale === "ru" ? (
                        <OriginalRunData
                          data={{
                            script_id: item.script_id,
                            title: (item as Vulnerability & { title?: string }).title,
                            finding_type: item.finding_type,
                            detector_source: item.detector_source,
                            severity: item.severity,
                            remediation: item.remediation,
                            finding_class: item.finding_class,
                            confidence: item.confidence,
                          }}
                        />
                      ) : null}
                      {item.finding_evidence ? (
                        <FindingEvidencePanel evidence={item.finding_evidence} />
                      ) : null}
                      {item.risk_explanation ? (
                        <RiskExplanation text={item.risk_explanation} />
                      ) : null}
                    </div>
                    <div className="text-right">
                      <span className="font-mono text-xs font-semibold text-foreground">
                        {item.cvss4 != null
                          ? `CVSS4 ${item.cvss4}`
                          : item.cvss != null
                            ? `CVSS ${item.cvss}`
                            : t.label(sev)}
                      </span>
                      {item.contextual_score != null ? (
                        <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                          {runText(t.locale, "risk")} {item.contextual_score.toFixed(1)}
                          {t.locale === "en" && item.cisa_decision
                            ? ` · ${item.cisa_decision}`
                            : ""}
                        </p>
                      ) : null}
                      {t.locale === "ru" && item.cisa_decision ? (
                        <CisaDecision value={item.cisa_decision} />
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
                  {isExpanded
                    ? runText(t.locale, "Show less")
                    : runText(t.locale, "Show all {count} findings", {
                        count: items.length.toLocaleString(),
                      })}
                </Button>
              </div>
            ) : null}
          </section>
        );
      })}

      {totalShown === 0 ? (
        <p className="py-8 text-center text-xs text-muted-foreground">
          {t("ui.noFindingsForTheCurrentFilters")}
        </p>
      ) : null}
    </div>
  );
}
