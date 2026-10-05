"use client";

import { useT } from "@/lib/i18n";
import { useRelativeTime } from "@/lib/i18n/datetime";
import type { EndpointSourceState } from "@/lib/api";

/** Receipt freshness does not imply that every collector produced a full set. */
export function SourceCompleteness({ sources = [] }: { sources?: EndpointSourceState[] }) {
  const t = useT();
  const ago = useRelativeTime();
  const degraded = sources.filter((source) => source.status !== "complete");
  if (degraded.length === 0) return null;
  return (
    <ul
      className="mt-1 space-y-1 text-[11px] text-amber-700 dark:text-amber-400"
      aria-label={t("endpoint.sources.degraded")}
    >
      {degraded.map((source) => (
        <li key={source.source} title={source.diagnostic_code || undefined}>
          <span className="font-mono">{source.source}</span>
          {" · "}
          {t(`endpoint.sources.${source.status}`)}
          {" · "}
          {t("endpoint.sources.lastComplete")}{" "}
          {source.last_complete_at ? ago(source.last_complete_at) : t("common.never")}
        </li>
      ))}
    </ul>
  );
}
