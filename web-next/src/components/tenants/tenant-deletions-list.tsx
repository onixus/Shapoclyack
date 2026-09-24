"use client";

import { StatusBadge } from "@/components/status-badge";
import { useTenantDeletions } from "@/hooks/use-tenant-lifecycle";
import { type TenantDeletion } from "@/lib/api";
import { TENANT_DELETION_STATUS } from "@/lib/config/statuses";
import { useT } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";

/** `store n` per store of a completed purge's tombstone, empty stores left out. */
export function outcomeSummary(deletion: TenantDeletion): { removed: string; skipped: string[] } {
  const outcome = deletion.outcome ?? {};
  const stores = (outcome.stores ?? {}) as Record<string, Record<string, unknown>>;
  const removed = Object.entries(stores)
    .map(([store, counts]) => {
      const total = Object.values(counts ?? {}).reduce<number>(
        (sum, value) => sum + (typeof value === "number" ? value : 0),
        0,
      );
      return [store, total] as const;
    })
    .filter(([, total]) => total > 0)
    .map(([store, total]) => `${store} ${total}`)
    .join(" · ");
  const skipped = Object.keys((outcome.skipped ?? {}) as Record<string, unknown>);
  return { removed, skipped };
}

/**
 * The deletion journal (#325): every request, what became of it, and for a
 * completed purge what each store gave up. The one place the console still
 * shows a tenant after it is gone — and the list to re-apply after restoring a
 * backup taken before it. Platform admins only, like the API behind it.
 */
export function TenantDeletionsList() {
  const t = useT();
  const when = useAbsoluteTime();
  const { data, isLoading, error } = useTenantDeletions(true);

  return (
    <section className="space-y-2">
      <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
        {t("deletions.title")}
      </p>
      <p className="text-[11px] text-muted-foreground">{t("deletions.hint")}</p>
      {error ? (
        <p className="text-sm text-rose-500" role="alert">
          {error instanceof Error ? error.message : t("deletions.loadFailed")}
        </p>
      ) : isLoading || !data ? null : data.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("deletions.empty")}</p>
      ) : (
        <table className="w-full text-left text-xs" aria-label={t("deletions.title")}>
          <thead>
            <tr className="text-[11px] uppercase tracking-wider text-muted-foreground">
              <th className="pb-1 pr-3 font-semibold">{t("deletions.col.tenant")}</th>
              <th className="pb-1 pr-3 font-semibold">{t("deletions.col.state")}</th>
              <th className="pb-1 pr-3 font-semibold">{t("deletions.col.requested")}</th>
              <th className="pb-1 pr-3 font-semibold">{t("deletions.col.approved")}</th>
              <th className="pb-1 pr-3 font-semibold">{t("deletions.col.finished")}</th>
              <th className="pb-1 font-semibold">{t("deletions.col.outcome")}</th>
            </tr>
          </thead>
          <tbody>
            {data.map((deletion) => {
              const { removed, skipped } = outcomeSummary(deletion);
              return (
                <tr key={deletion.deletion_id} className="border-t border-border align-top">
                  <td className="py-1.5 pr-3 font-mono text-foreground">{deletion.tenant_id}</td>
                  <td className="py-1.5 pr-3">
                    <StatusBadge value={deletion.state} map={TENANT_DELETION_STATUS} />
                  </td>
                  <td className="py-1.5 pr-3 text-muted-foreground">
                    {t("deletions.by", {
                      who: deletion.requested_by,
                      when: when(deletion.requested_at),
                    })}
                  </td>
                  <td className="py-1.5 pr-3 text-muted-foreground">
                    {deletion.approved_by
                      ? t("deletions.by", {
                          who: deletion.approved_by,
                          when: when(deletion.approved_at),
                        })
                      : "—"}
                  </td>
                  <td className="py-1.5 pr-3 text-muted-foreground">
                    {when(deletion.completed_at ?? deletion.cancelled_at)}
                  </td>
                  <td className="py-1.5 text-muted-foreground">
                    {removed ? <p className="text-foreground">{removed}</p> : null}
                    {skipped.length ? (
                      <p>{t("deletions.skipped", { stores: skipped.join(", ") })}</p>
                    ) : null}
                    {deletion.state !== "completed" && deletion.last_error ? (
                      <p className="text-rose-500">{deletion.last_error}</p>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
