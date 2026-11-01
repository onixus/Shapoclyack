"use client";

import { SystemTechnicalDetails } from "@/components/system-technical-details";
import { endpointSource, endpointText } from "@/lib/endpoint-presentation";
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
      className="mt-1 space-y-1 text-xs text-amber-700 dark:text-amber-400"
      aria-label={t("endpoint.sources.degraded")}
    >
      {degraded.map((source) => (
        <li
          key={source.source}
          title={t.locale !== "ru" ? source.diagnostic_code || undefined : undefined}
        >
          <span className="font-mono">{endpointSource(t.locale, source.source)}</span>
          {" · "}
          {["complete", "partial", "failed", "not_applicable"].includes(source.status)
            ? t(`endpoint.sources.${source.status}`)
            : endpointText(t.locale, "Source state unknown")}
          {" · "}
          {t("endpoint.sources.lastComplete")}{" "}
          {source.last_complete_at ? ago(source.last_complete_at) : t("common.never")}
          {t.locale === "ru" && (
            <>
              {source.diagnostic_code && (
                <p>
                  {endpointText(
                    t.locale,
                    [
                      "permission_denied",
                      "timeout",
                      "command_not_found",
                      "collector_failed",
                    ].includes(source.diagnostic_code)
                      ? source.diagnostic_code
                      : "Collector diagnostic available",
                  )}
                </p>
              )}
              <SystemTechnicalDetails data={source} />
            </>
          )}
        </li>
      ))}
    </ul>
  );
}
