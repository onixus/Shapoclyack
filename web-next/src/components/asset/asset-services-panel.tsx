"use client";

import { Network } from "lucide-react";
import { StatusBadge } from "@/components/status-badge";
import { useAssetServices } from "@/hooks/use-retro-match";
import type { AssetServiceInfo } from "@/lib/api";
import {
  ASSET_SERVICE_MATCH_STATUS,
  ASSET_SERVICE_NOT_MATCHED,
  SEVERITY_STATUS,
} from "@/lib/config/statuses";
import { useT, type MsgKey } from "@/lib/i18n";
import { useRelativeTime } from "@/lib/i18n/datetime";
import { normalizeSeverity } from "@/lib/run-data";

/** Why a listener could not be assessed, keyed by `match_status`. */
const REASON_KEY: Record<string, MsgKey> = {
  unknown_product: "services.reason.unknown_product",
  no_version: "services.reason.no_version",
  too_old: "services.reason.too_old",
  no_dataset: "services.reason.no_dataset",
};

/**
 * The listeners scans fingerprinted on one asset, with the retro matcher's
 * verdict on each (docs/retro-cve-matching.md).
 *
 * Every row says whether it was assessed at all. A listener whose product is
 * not in the NVD data, or whose version the scan never recorded, has no CVEs
 * for the opposite reason a patched one does, and the table must not let the
 * two look alike. Possible CVEs — NVD says affected, a visible distribution may
 * have backported the fix — are listed on the row, collapsed, because they are
 * deliberately not tracked findings.
 */
export function AssetServicesPanel({
  assetId,
  tenantId = "default",
}: {
  assetId: string;
  tenantId?: string;
}) {
  const t = useT();
  const ago = useRelativeTime();
  const servicesQuery = useAssetServices(assetId, tenantId);
  const services = servicesQuery.data ?? [];

  return (
    <div className="space-y-3" data-testid="asset-services-panel">
      <div className="flex items-center gap-2">
        <Network className="h-4 w-4 text-muted-foreground" />
        <h3 className="text-sm font-bold text-foreground">{t("services.title")}</h3>
        <span className="text-[11px] text-muted-foreground">{t("services.subtitle")}</span>
      </div>

      {servicesQuery.isLoading ? (
        <p className="text-xs text-muted-foreground">{t("services.loading")}</p>
      ) : servicesQuery.error ? (
        <p className="text-xs text-rose-600 dark:text-rose-400">
          {(servicesQuery.error as Error).message}
        </p>
      ) : services.length === 0 ? (
        <p className="text-xs text-muted-foreground">{t("services.empty")}</p>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border bg-card">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-border bg-muted font-bold uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="px-3.5 py-3">{t("services.col.port")}</th>
                <th className="px-3.5 py-3">{t("services.col.service")}</th>
                <th className="px-3.5 py-3">{t("services.col.product")}</th>
                <th className="px-3.5 py-3">{t("services.col.cpe")}</th>
                <th className="px-3.5 py-3">{t("services.col.lastSeen")}</th>
                <th className="px-3.5 py-3">{t("services.col.status")}</th>
                <th className="px-3.5 py-3">{t("services.col.cves")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {services.map((service) => (
                <ServiceRow key={service.id} service={service} ago={ago} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-[11px] text-muted-foreground">{t("services.footnote")}</p>
    </div>
  );
}

function ServiceRow({
  service,
  ago,
}: {
  service: AssetServiceInfo;
  ago: (value: string | null) => string;
}) {
  const t = useT();
  const status = service.match_status;
  const reason = status
    ? REASON_KEY[status]
      ? t(REASON_KEY[status])
      : undefined
    : t("services.reason.pending");
  const counts = service.match_counts ?? {};
  const product = [service.product, service.version].filter(Boolean).join(" ");

  return (
    <tr className="align-top transition-colors hover:bg-muted">
      <td className="px-3.5 py-3 font-mono font-semibold text-foreground">
        {service.port}/{service.protocol}
      </td>
      <td className="px-3.5 py-3 text-foreground">{service.service || "—"}</td>
      <td className="px-3.5 py-3">
        <p className="font-mono text-foreground">{product || "—"}</p>
        {service.banner && service.banner !== product ? (
          <p className="max-w-[18rem] truncate text-[10px] text-muted-foreground" title={service.banner}>
            {service.banner}
          </p>
        ) : null}
      </td>
      <td className="px-3.5 py-3 font-mono text-[11px] text-muted-foreground">
        {service.cpe.length ? service.cpe.map((cpe) => <p key={cpe}>{cpe}</p>) : "—"}
      </td>
      <td className="px-3.5 py-3 text-muted-foreground">{ago(service.last_seen_at)}</td>
      <td className="px-3.5 py-3">
        <span title={reason}>
          {status ? (
            <StatusBadge value={status} map={ASSET_SERVICE_MATCH_STATUS} />
          ) : (
            <StatusBadge value="" map={{}} fallback={ASSET_SERVICE_NOT_MATCHED} />
          )}
        </span>
        {reason && status !== "matched" ? (
          <p className="mt-1 max-w-[16rem] text-[10px] text-muted-foreground">{reason}</p>
        ) : null}
      </td>
      <td className="px-3.5 py-3">
        {status === "matched" ? (
          <div className="space-y-1">
            <div className="flex flex-wrap gap-x-2 gap-y-0.5 text-[11px]">
              <Count
                label={t("services.counts.vulnerable")}
                value={counts.vulnerable ?? 0}
                className="text-rose-600 dark:text-rose-400"
              />
              <Count label={t("services.counts.fixed")} value={counts.fixed ?? 0} />
              <Count label={t("services.counts.notAffected")} value={counts.not_affected ?? 0} />
              <Count
                label={t("services.counts.possible")}
                value={counts.possible ?? 0}
                className="text-amber-700 dark:text-amber-300"
              />
              <Count
                label={t("services.counts.unfixed")}
                value={counts.unfixed ?? 0}
                className="text-amber-700 dark:text-amber-300"
              />
            </div>
            {service.possible_cves.length ? (
              <details className="text-[11px]">
                <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                  {t("services.possibleList")}
                </summary>
                <ul className="mt-1 space-y-0.5">
                  {service.possible_cves.map((possible) => (
                    <li key={possible.cve} className="flex items-center gap-1.5">
                      <span className="font-mono text-foreground">{possible.cve}</span>
                      <StatusBadge
                        value={normalizeSeverity(possible.severity)}
                        map={SEVERITY_STATUS}
                      />
                      {possible.cvss != null ? (
                        <span className="tabular-nums text-muted-foreground">{possible.cvss}</span>
                      ) : null}
                      <span className="text-muted-foreground">
                        {possible.verdict === "unfixed"
                          ? t("services.verdict.unfixed")
                          : t("services.verdict.possible")}
                      </span>
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </div>
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </td>
    </tr>
  );
}

function Count({
  label,
  value,
  className,
}: {
  label: string;
  value: number;
  className?: string;
}) {
  return (
    <span className={value > 0 && className ? className : "text-muted-foreground"}>
      {label} <span className="font-semibold tabular-nums">{value}</span>
    </span>
  );
}
