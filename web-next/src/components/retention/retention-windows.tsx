"use client";

import { useEffect, useMemo, useState } from "react";
import { RotateCcw, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useResetRetentionPolicy, useUpdateRetentionPolicy } from "@/hooks/use-retention";
import { type RetentionCategory, type RetentionPolicy } from "@/lib/api";
import { useT, type MsgKey, type Translate } from "@/lib/i18n";
import { useAbsoluteTime } from "@/lib/i18n/datetime";

/** The console's name for each category. A category this build does not know
 * — a newer API — falls back to the API's own description rather than
 * disappearing: every category is listed, because a missing one reads as
 * "not kept". */
const CATEGORY_LABELS: Record<string, MsgKey> = {
  runs: "retention.category.runs",
  screenshots: "retention.category.screenshots",
  reports: "retention.category.reports",
  endpoint_snapshots: "retention.category.endpointSnapshots",
  endpoint_changes: "retention.category.endpointChanges",
  risk_snapshots: "retention.category.riskSnapshots",
  webhook_deliveries: "retention.category.webhookDeliveries",
  workflow_markers: "retention.category.workflowMarkers",
  audit_events: "retention.category.auditEvents",
};

export function categoryLabel(category: RetentionCategory, t: Translate) {
  const key = CATEGORY_LABELS[category.category];
  return key ? t(key) : category.description;
}

export function daysLabel(days: number, t: Translate) {
  return days > 0 ? t("retention.days", { count: days }) : t("retention.forever");
}

/** `""` is "inherit the platform default"; anything else is what was typed. */
type Draft = Record<string, string>;

function draftOf(policy: RetentionPolicy): Draft {
  return Object.fromEntries(
    policy.categories.map((item) => [
      item.category,
      item.override_days === null ? "" : String(item.override_days),
    ]),
  );
}

/** Why a typed value would be refused, or null. The same bounds the API
 * enforces — it is the authority and says so in its 422 — checked here so an
 * admin sees the floor before pressing Save rather than after. */
function rowError(category: RetentionCategory, raw: string, t: Translate): string | null {
  const value = raw.trim();
  if (!value) return null;
  if (!/^\d+$/.test(value)) return t("retention.notInteger");
  const days = Number(value);
  if (days < category.min_days || days > category.max_days) {
    return t("retention.outOfBounds", { min: category.min_days, max: category.max_days });
  }
  return null;
}

/**
 * One tenant's retention windows, category by category (#332).
 *
 * A whole-document editor because the API is one: a category left empty goes
 * back to the platform default on Save, so the editor is seeded from what is
 * stored *now* and an admin changing one row cannot silently drop another.
 */
export function RetentionWindows({
  tenantId,
  policy,
  canManage,
}: {
  tenantId: string;
  policy: RetentionPolicy;
  canManage: boolean;
}) {
  const t = useT();
  const when = useAbsoluteTime();
  const update = useUpdateRetentionPolicy(tenantId);
  const reset = useResetRetentionPolicy(tenantId);

  const baseline = useMemo(() => draftOf(policy), [policy]);
  const signature = JSON.stringify([baseline, policy.note]);
  const [draft, setDraft] = useState<Draft>(baseline);
  const [note, setNote] = useState(policy.note);

  // Reseed when the stored policy changes underneath the editor (a save, a
  // reset, another admin); a refetch that returns the same document must not
  // throw away edits in progress, hence the signature.
  useEffect(() => {
    setDraft(baseline);
    setNote(policy.note);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature]);

  const errors = policy.categories
    .map((item) => rowError(item, draft[item.category] ?? "", t))
    .filter((message): message is string => message !== null);
  const dirty =
    note.trim() !== policy.note ||
    policy.categories.some(
      (item) => (draft[item.category] ?? "").trim() !== (baseline[item.category] ?? ""),
    );
  const hasOverrides = policy.categories.some((item) => item.source === "tenant");

  function save() {
    const overrides = Object.fromEntries(
      policy.categories.map((item) => {
        const value = (draft[item.category] ?? "").trim();
        return [item.category, value ? Number(value) : null];
      }),
    );
    update.mutate({ overrides, note: note.trim() });
  }

  return (
    <section className="space-y-3">
      <div className="space-y-1">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          {t("retention.windows")}
        </p>
        <p className="text-[11px] text-muted-foreground">{t("retention.windowsHint")}</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-xs uppercase text-muted-foreground">
            <tr>
              <th className="py-2 pr-4">{t("retention.col.category")}</th>
              <th className="py-2 pr-4">{t("retention.col.default")}</th>
              <th className="py-2 pr-4">{t("retention.col.bounds")}</th>
              <th className="py-2 pr-4">{t("retention.col.override")}</th>
              <th className="py-2">{t("retention.col.effective")}</th>
            </tr>
          </thead>
          <tbody>
            {policy.categories.map((item) => {
              const label = categoryLabel(item, t);
              const error = rowError(item, draft[item.category] ?? "", t);
              return (
                <tr key={item.category} className="border-t border-border/60 align-top">
                  <td className="py-2 pr-4">
                    <p className="font-medium text-foreground">{label}</p>
                    <p className="text-[11px] text-muted-foreground">{item.description}</p>
                  </td>
                  <td className="py-2 pr-4 tabular-nums">{daysLabel(item.default_days, t)}</td>
                  <td className="py-2 pr-4 tabular-nums text-muted-foreground">
                    {t("retention.bounds", { min: item.min_days, max: item.max_days })}
                  </td>
                  <td className="py-2 pr-4">
                    {canManage ? (
                      <div className="space-y-1">
                        <Input
                          aria-label={t("retention.overrideFor", { category: label })}
                          inputMode="numeric"
                          className="h-8 w-28"
                          placeholder={t("retention.inherit")}
                          value={draft[item.category] ?? ""}
                          onChange={(event) =>
                            setDraft((current) => ({
                              ...current,
                              [item.category]: event.target.value,
                            }))
                          }
                        />
                        {error ? (
                          <p className="text-[11px] text-rose-500" role="alert">
                            {error}
                          </p>
                        ) : null}
                      </div>
                    ) : (
                      <span className="tabular-nums">
                        {item.override_days === null
                          ? t("retention.inherit")
                          : daysLabel(item.override_days, t)}
                      </span>
                    )}
                  </td>
                  <td className="py-2 font-medium tabular-nums">
                    {daysLabel(item.effective_days, t)}
                    {item.out_of_bounds ? (
                      <p
                        className="text-[11px] font-normal text-amber-600 dark:text-amber-400"
                        title={t("retention.storedOutOfBoundsHint", {
                          days: item.override_days ?? 0,
                          min: item.min_days,
                          max: item.max_days,
                        })}
                      >
                        {t("retention.storedOutOfBounds")}
                      </p>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {policy.updated_at ? (
        <p className="text-[11px] text-muted-foreground">
          {t("retention.updatedBy", { who: policy.updated_by || "—", when: when(policy.updated_at) })}
        </p>
      ) : null}

      {canManage ? (
        <div className="space-y-3">
          <Input
            aria-label={t("retention.note")}
            placeholder={t("retention.notePlaceholder")}
            value={note}
            maxLength={500}
            onChange={(event) => setNote(event.target.value)}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              className="gap-2 bg-sky-600 text-foreground hover:bg-sky-500"
              disabled={!dirty || errors.length > 0 || update.isPending}
              onClick={save}
            >
              <Save className="h-4 w-4" />
              {update.isPending ? t("retention.saving") : t("retention.save")}
            </Button>
            <Button
              type="button"
              variant="outline"
              className="gap-2 border-border"
              disabled={!hasOverrides || reset.isPending}
              onClick={() => reset.mutate()}
            >
              <RotateCcw className="h-4 w-4" />
              {t("retention.reset")}
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
