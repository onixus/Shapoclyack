"use client";

import { useLegalHolds } from "@/hooks/use-retention";
import { useT } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";

/**
 * Every hold in force across tenants, oldest first (#332).
 *
 * Rendered for platform admins only, and the API refuses anybody else: it
 * carries each hold's reason and author, which the held tenant itself is not
 * shown. It answers what an auditor asks first — what is on hold, since when,
 * by whom and why — without opening every tenant's page.
 */
export function LegalHoldRegister() {
  const t = useT();
  const when = useAbsoluteTime();
  const { data, isLoading, error } = useLegalHolds(true);

  return (
    <section className="space-y-3">
      <div className="space-y-1">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {t("retention.register.title")}
        </p>
        <p className="text-[11px] text-muted-foreground">{t("retention.register.hint")}</p>
      </div>
      {error ? (
        <p className="text-sm text-rose-500" role="alert">
          {error instanceof Error ? error.message : t("retention.register.loadFailed")}
        </p>
      ) : isLoading || !data ? null : data.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("retention.register.empty")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-muted-foreground">
              <tr>
                <th className="py-2 pr-4">{t("retention.register.col.tenant")}</th>
                <th className="py-2 pr-4">{t("retention.register.col.since")}</th>
                <th className="py-2 pr-4">{t("retention.register.col.by")}</th>
                <th className="py-2">{t("retention.register.col.reason")}</th>
              </tr>
            </thead>
            <tbody>
              {data.map((hold) => (
                <tr key={hold.tenant_id} className="border-t border-border/60 align-top">
                  <td className="py-2 pr-4 font-medium text-foreground">{hold.tenant_id}</td>
                  <td className="py-2 pr-4 tabular-nums">{hold.set_at ? when(hold.set_at) : "—"}</td>
                  <td className="py-2 pr-4">{hold.set_by ?? "—"}</td>
                  <td className="py-2">{hold.reason ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
