"use client";
import { useT } from "@/lib/i18n";
export function ScanTechnicalDetails({
  intent,
  mode,
  execution,
  backend,
  id,
  cron,
  interval,
  summary,
}: {
  intent?: unknown;
  mode?: string;
  execution?: string | null;
  backend?: string;
  id?: string;
  cron?: string | null;
  interval?: number | null;
  summary?: string | null;
}) {
  const t = useT();
  const rows = [
    [t("scanCopy.id"), id],
    [
      t("scanCopy.intent"),
      intent === undefined ? undefined : typeof intent === "string" && intent ? intent : "legacy",
    ],
    [t("scanCopy.mode"), mode],
    [t("scanCopy.execution"), execution],
    [t("scanCopy.backend"), backend],
    [t("scanCopy.cron"), cron],
    [t("scanCopy.interval"), interval],
    [t("scanCopy.technical"), summary],
  ];
  return (
    <details className="mt-2 min-w-0 text-xs text-muted-foreground">
      <summary className="cursor-pointer">{t("scanCopy.technical")}</summary>
      <dl className="mt-2 space-y-1 break-words">
        {rows
          .filter(([, v]) => v !== undefined && v !== null && v !== "")
          .map(([k, v], i) => (
            <div key={i}>
              <dt>{k}</dt>
              <dd className="font-mono whitespace-pre-wrap">{v}</dd>
            </div>
          ))}
      </dl>
    </details>
  );
}
