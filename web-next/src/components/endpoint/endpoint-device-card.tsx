"use client";
import { useT } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";
import type { EndpointDeviceInfo } from "@/lib/api";
import {
  endpointText,
  endpointArchitecture,
  endpointFamily,
  endpointReconciliation,
  endpointFreshness,
} from "@/lib/endpoint-presentation";
import { SystemTechnicalDetails } from "@/components/system-technical-details";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ENDPOINT_RECONCILIATION_STATUS, ASSET_STATUS } from "@/lib/config/statuses";
import { SourceCompleteness } from "./source-completeness";
export function EndpointDeviceCard({ device }: { device: EndpointDeviceInfo }) {
  const t = useT();
  const when = useAbsoluteTime();
  const e = (s: string) => endpointText(t.locale, s);
  const recon = ENDPOINT_RECONCILIATION_STATUS[device.reconciliation_status];
  return (
    <section
      className="min-w-0 space-y-4 rounded-xl border border-border bg-card p-5 text-xs"
      aria-label={e("Device card")}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-2">
        <div className="min-w-0">
          <h2 className="text-sm font-bold text-foreground">{t("asset.endpointTitle")}</h2>
          <p className="mt-1 break-all font-mono text-muted-foreground">
            {device.hostname || e("Device name unavailable")}
          </p>
        </div>
        <StatusBadge
          value={device.reconciliation_status}
          map={
            t.locale === "ru"
              ? {
                  [device.reconciliation_status]: {
                    ...recon,
                    label: endpointReconciliation(t.locale, device.reconciliation_status),
                  },
                }
              : ENDPOINT_RECONCILIATION_STATUS
          }
        />
      </div>
      {device.reconciliation_status === "conflict" && (
        <Alert variant="destructive">
          <AlertDescription>{t("asset.endpointConflict")}</AlertDescription>
        </Alert>
      )}
      {device.status === "stale" && device.last_inventory_at != null && (
        <Alert>
          <AlertDescription>{t("asset.endpointStale")}</AlertDescription>
        </Alert>
      )}
      <dl className="grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-2">
        {[
          [
            t("col.os"),
            [device.os_name, device.os_version].filter(Boolean).join(" ") ||
              e("Operating system not specified"),
          ],
          [t("asset.field.architecture"), endpointArchitecture(t.locale, device.os_arch)],
          [t("asset.field.agentVersion"), device.agent_version || "—"],
          [t("asset.field.lastInventory"), when(device.last_inventory_at, t("common.never"))],
          [e("First seen"), when(device.first_seen, t("common.never"))],
          [e("Last seen"), when(device.last_seen, t("common.never"))],
        ].map(([label, value]) => (
          <div key={label} className="min-w-0">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="break-words">{value}</dd>
          </div>
        ))}
        <div>
          <dt className="text-muted-foreground">{e("Inventory freshness")}</dt>
          <dd>
            <StatusBadge
              value={device.status}
              map={
                t.locale === "ru"
                  ? {
                      [device.status]: {
                        ...ASSET_STATUS[device.status],
                        label: endpointFreshness(t.locale, device.status, device.last_inventory_at),
                      },
                    }
                  : ASSET_STATUS
              }
            />
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">{e("OS family")}</dt>
          <dd>{endpointFamily(t.locale, device.os_family)}</dd>
        </div>
      </dl>
      <SourceCompleteness sources={device.sources} />
      <SystemTechnicalDetails data={device} />
    </section>
  );
}
