"use client";
import { useT } from "@/lib/i18n";
import { SystemTechnicalDetails } from "@/components/system-technical-details";
import { groupState, groupValue } from "@/lib/asset-group-presentation";
import { useGroupText } from "@/lib/asset-group-presentation";

import Link from "next/link";
import axios from "axios";
import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { useAuthStore } from "@/lib/auth-store";
import { can } from "@/lib/authz";
import {
  ASSET_DATA_CLASSIFICATIONS,
  ASSET_ENVIRONMENTS,
  CONTEXT_FIELD_LABELS,
} from "@/lib/asset-context";
import {
  assetGroupsApi,
  GROUP_FIELDS,
  parseRuleValue,
  ruleOperators,
  type AssetGroup,
  type GroupContext,
  type GroupDraft,
  type GroupField,
  type GroupPreview,
  type GroupRule,
  type RuleOperator,
} from "@/lib/asset-groups";

const selectClass =
  "h-10 min-w-0 w-full max-w-full rounded-md border border-input bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";
const newLeaf = (): GroupRule => ({ field: "ip", op: "cidr", value: "" });
const blankDraft = (): GroupDraft => ({
  name: "",
  description: "",
  enabled: true,
  priority: 100,
  rules: { all: [newLeaf()] },
  context: {},
});
const ruleLabels: Record<string, string> = {
  ...CONTEXT_FIELD_LABELS,
  os_family: "Confirmed endpoint OS",
};
const contextOptions: Record<string, readonly string[]> = {
  environment: ASSET_ENVIRONMENTS,
  data_classification: ASSET_DATA_CLASSIFICATIONS,
  asset_criticality: ["0", "1", "2", "3", "4"],
};
function describe(value: unknown): string {
  return value == null ? "—" : typeof value === "string" ? value : JSON.stringify(value);
}
function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
function observed(value: unknown): string {
  return Array.isArray(value)
    ? value.map((item) => (item == null ? "unknown" : String(item))).join(", ") || "unknown"
    : value == null
      ? "unknown"
      : String(value);
}
function OsEvidence({ value }: { value: unknown }) {
  const g = useGroupText();
  const t = useT();
  const evidence = asRecord(value);
  if (!evidence) return null;
  const observations = Array.isArray(evidence.observations) ? evidence.observations : [];
  if (t.locale === "ru")
    return (
      <div className="mt-1 border-l border-border pl-3 text-xs text-muted-foreground">
        <p>
          Источник: подтверждённый инвентарь устройства · {groupState(t.locale, evidence.state)} ·
          срок актуальности: {groupValue(t.locale, "freshness_hours", evidence.freshness_hours)} ч.
        </p>
        {evidence.observations_truncated ? (
          <p>Часть связанных устройств не показана. Неполные данные не подтверждают совпадение.</p>
        ) : null}
        <SystemTechnicalDetails data={evidence} />
      </div>
    );
  return (
    <div className="mt-1 border-l border-border pl-3 text-xs text-muted-foreground">
      <p>
        {" "}
        {g("Source: authenticated endpoint inventory ·")} {String(evidence.state ?? g("unknown"))}{" "}
        {g("· freshness limit")} {observed(evidence.freshness_hours)} {g("hours")}{" "}
      </p>
      {evidence.observations_truncated ? (
        <p>
          {" "}
          {g(
            "Additional linked devices were omitted; incomplete evidence never confirms a match.",
          )}{" "}
        </p>
      ) : null}
      {observations.map((item, index) => {
        const snapshot = asRecord(item);
        return (
          <p key={index}>
            {" "}
            {g("Device")} {observed(snapshot?.device_id)} {g("· snapshot")}{" "}
            {observed(snapshot?.snapshot_id)} · {observed(snapshot?.family)} {g("· collected")}{" "}
            {observed(snapshot?.collected_at)} {g("· received")} {observed(snapshot?.received_at)}{" "}
            {g("· reconciliation")} {observed(snapshot?.reconciliation_status)}
          </p>
        );
      })}
    </div>
  );
}
function Reasons({ value }: { value: unknown }) {
  const g = useGroupText();
  const t = useT();
  const reasons = Array.isArray(value) ? value : [];
  if (!reasons.length) return <p> {g("No matching conditions recorded.")} </p>;
  if (t.locale === "ru")
    return (
      <ul className="list-inside list-disc space-y-2">
        {reasons.map((reason, index) => {
          const row = asRecord(reason);
          const field = String(row?.field ?? "Condition");
          return (
            <li key={index} className="break-words">
              {row ? (
                <>
                  {g(
                    ruleLabels[field] ??
                      { ip: "ip", fqdn: "fqdn", status: "status" }[field] ??
                      "Condition",
                  )}{" "}
                  {row.negate ? "НЕ " : ""}
                  {g(String(row.op ?? ""))} {groupValue(t.locale, field, row.value)}; наблюдаемое
                  значение: {groupValue(t.locale, field, row.actual)};{" "}
                  {groupState(t.locale, row.result ?? "evaluated")}
                  {row.actual_truncated ? " (данные показаны не полностью)" : ""}
                </>
              ) : (
                "Объяснение условия доступно в технических данных."
              )}
              <SystemTechnicalDetails data={reason} />
              {field === "os_family" && <OsEvidence value={row?.evidence} />}
            </li>
          );
        })}
      </ul>
    );
  return (
    <ul className="list-inside list-disc space-y-1">
      {reasons.map((reason, index) => {
        const row = asRecord(reason);
        if (!row) return <li key={index}>{describe(reason)}</li>;
        const field = String(row.field ?? g("Condition"));
        return (
          <li key={index}>
            {g(ruleLabels[field] ?? field)} {row.negate ? g("NOT ") : ""}
            {String(row.op ?? "")} {observed(row.value)} {g("; observed:")} {observed(row.actual)};{" "}
            {String(row.result ?? g("evaluated")).replaceAll("_", " ")}
            {row.actual_truncated ? g(" (evidence truncated)") : ""}
            {field === "os_family" && <OsEvidence value={row.evidence} />}
          </li>
        );
      })}
    </ul>
  );
}
function Changes({ value }: { value: unknown }) {
  const g = useGroupText();
  const t = useT();
  const changes = asRecord(value);
  if (!changes || !Object.keys(changes).length) return <p> {g("No context changes.")} </p>;
  if (t.locale === "ru")
    return (
      <ul className="list-inside list-disc">
        {Object.entries(changes).map(([field, change]) => {
          const row = asRecord(change);
          return (
            <li key={field}>
              {g(ruleLabels[field] ?? "Context")}: {groupValue(t.locale, field, row?.old)} →{" "}
              {groupValue(t.locale, field, row?.new)}
              {row?.release ? " (снять значение, заданное правилом)" : ""}
              <SystemTechnicalDetails data={{ field, ...row }} />
            </li>
          );
        })}
      </ul>
    );
  return (
    <ul className="list-inside list-disc">
      {Object.entries(changes).map(([field, change]) => {
        const row = asRecord(change);
        return (
          <li key={field}>
            {g(ruleLabels[field] ?? field)}: {observed(row?.old)} → {observed(row?.new)}
            {row?.release ? g(" (release rule-owned value)") : ""}
            {row?.group_id ? g(` · group ${row.group_id}`) : ""}
            {row?.version != null ? g(` · rule v${row.version}`) : ""}
          </li>
        );
      })}
    </ul>
  );
}
function Conflicts({ value }: { value: unknown }) {
  const g = useGroupText();
  const t = useT();
  const conflicts = Array.isArray(value) ? value : [];
  if (!conflicts.length) return <p> {g("No conflicts.")} </p>;
  if (t.locale === "ru")
    return (
      <ul className="list-inside list-disc">
        {conflicts.map((conflict, index) => {
          const row = asRecord(conflict);
          return (
            <li key={index}>
              {g(ruleLabels[String(row?.field)] ?? "Context")}:{" "}
              {groupState(t.locale, row?.reason ?? "conflict")}
              <SystemTechnicalDetails data={conflict} />
            </li>
          );
        })}
      </ul>
    );
  return (
    <ul className="list-inside list-disc">
      {conflicts.map((conflict, index) => {
        const row = asRecord(conflict);
        const field = String(row?.field ?? g("Context"));
        return (
          <li key={index}>
            {g(ruleLabels[field] ?? field)}:{" "}
            {String(row?.reason ?? g("conflict")).replaceAll("_", " ")}
            {row?.group_ids ? g(` · groups ${observed(row.group_ids)}`) : ""}
          </li>
        );
      })}
    </ul>
  );
}
function ErrorMessage({ error }: { error: unknown }) {
  const g = useGroupText();
  const t = useT();
  const detail = axios.isAxiosError(error) ? error.response?.data?.detail : undefined;
  if (error && t.locale === "ru") {
    const original = detail
      ? describe(detail)
      : error instanceof Error
        ? error.message
        : String(error);
    const translated = g(original);
    return (
      <div role="alert" className="text-sm text-destructive">
        {translated === original
          ? "Не удалось выполнить действие. Подробности ошибки сохранены ниже."
          : translated}
        <SystemTechnicalDetails data={{ error: original }} />
      </div>
    );
  }
  return error ? (
    <p role="alert" className="text-sm text-destructive">
      {detail ? describe(detail) : error instanceof Error ? error.message : String(error)}
    </p>
  ) : null;
}
function Field({ title, children }: { title: string; children: ReactNode }) {
  return (
    <label className="grid min-w-0 gap-1.5 text-sm font-medium">
      {title}
      {children}
    </label>
  );
}
function Pager({
  offset,
  total,
  hasMore,
  onChange,
  pending = false,
  label,
}: {
  offset: number;
  total: number;
  hasMore: boolean;
  onChange: (value: number) => void;
  pending?: boolean;
  label?: string;
}) {
  const g = useGroupText();
  const t = useT();
  return (
    <div className="flex flex-wrap items-center gap-3 text-sm">
      <span>
        {total === 0
          ? "0"
          : offset >= total
            ? g("No rows on this page")
            : g(`${offset + 1}–${Math.min(offset + 20, total)}`)}{" "}
        / {total}
      </span>
      <Button
        variant="outline"
        disabled={pending || offset === 0}
        onClick={() => onChange(Math.max(0, offset - 20))}
      >
        {" "}
        {t.locale === "ru" ? (
          `Предыдущая страница${label ? " проверок" : ""}`
        ) : (
          <>Previous {label ? `${label} ` : ""}page</>
        )}{" "}
      </Button>
      <Button
        variant="outline"
        disabled={pending || !hasMore}
        onClick={() => onChange(offset + 20)}
      >
        {" "}
        {t.locale === "ru" ? (
          `Следующая страница${label ? " проверок" : ""}`
        ) : (
          <>Next {label ? `${label} ` : ""}page</>
        )}{" "}
      </Button>
    </div>
  );
}
export function normalizeGroupRules(rule: GroupRule): GroupRule {
  if ("all" in rule) {
    if (!rule.all.length) throw new Error("AND must contain a condition.");
    return { ...rule, all: rule.all.map(normalizeGroupRules) };
  }
  if ("any" in rule) {
    if (!rule.any.length) throw new Error("OR must contain a condition.");
    return { ...rule, any: rule.any.map(normalizeGroupRules) };
  }
  if (rule.field.startsWith("tag:") && !rule.field.slice(4).trim())
    throw new Error("Enter a tag key.");
  return {
    ...rule,
    value: parseRuleValue(
      rule.field,
      rule.op,
      Array.isArray(rule.value) ? rule.value.join(",") : String(rule.value),
    ),
  };
}
export function GroupRuleEditor({
  rule,
  onChange,
  path = "1",
  depth = 0,
}: {
  rule: GroupRule;
  onChange: (rule: GroupRule) => void;
  path?: string;
  depth?: number;
}) {
  const g = useGroupText();
  if ("all" in rule || "any" in rule) {
    const children = "all" in rule ? rule.all : rule.any;
    const join = "all" in rule ? "all" : "any";
    const update = (next: GroupRule[]) =>
      onChange(join === "all" ? { ...rule, all: next } : { ...rule, any: next });
    return (
      <fieldset className="min-w-0 space-y-3 rounded-md border border-border p-3">
        <legend className="max-w-full break-words px-1 text-sm font-semibold">
          {" "}
          {g("Conditions")} {path}
        </legend>
        <Field title={g(`Match mode ${path}`)}>
          <select
            className={selectClass}
            value={join}
            onChange={(event) =>
              onChange(
                event.target.value === "all"
                  ? { all: children, negate: rule.negate }
                  : { any: children, negate: rule.negate },
              )
            }
          >
            <option value="all"> {g("AND — every condition")} </option>
            <option value="any"> {g("OR — any condition")} </option>
          </select>
        </Field>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={rule.negate ?? false}
            onChange={(event) => onChange({ ...rule, negate: event.target.checked })}
          />{" "}
          {g("Negate group")} {path}
        </label>
        {children.map((child, index) => (
          <div className="space-y-2" key={index}>
            <GroupRuleEditor
              rule={child}
              path={`${path}.${index + 1}`}
              depth={depth + 1}
              onChange={(next) => update(children.map((item, i) => (i === index ? next : item)))}
            />
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={children.length === 1}
              onClick={() => update(children.filter((_, i) => i !== index))}
            >
              {" "}
              {g("Remove condition")} {path}.{index + 1}
            </Button>
          </div>
        ))}
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={children.length >= 20}
            onClick={() => update([...children, newLeaf()])}
          >
            {" "}
            {g("Add condition")} {path}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={depth >= 3 || children.length >= 20}
            onClick={() => update([...children, { any: [newLeaf()] }])}
          >
            {" "}
            {g("Add nested group")} {path}
          </Button>
        </div>
      </fieldset>
    );
  }
  const isTag = rule.field.startsWith("tag:");
  return (
    <fieldset className="grid gap-3 rounded border border-border p-3 sm:grid-cols-3">
      <legend className="px-1 text-xs">
        {" "}
        {g("Condition")} {path}
      </legend>
      <Field title={g(`Field ${path}`)}>
        <select
          className={selectClass}
          value={isTag ? "tag" : rule.field}
          onChange={(event) => {
            const field = (
              event.target.value === "tag" ? "tag:" : event.target.value
            ) as GroupField;
            onChange({ field, op: ruleOperators(field)[0], value: "" });
          }}
        >
          {GROUP_FIELDS.map((field) => (
            <option key={field} value={field}>
              {g(ruleLabels[field] ?? field)}
            </option>
          ))}
          <option value="tag"> {g("Tag")} </option>
        </select>
      </Field>
      {isTag && (
        <Field title={g(`Tag key ${path}`)}>
          <Input
            value={rule.field.slice(4)}
            maxLength={128}
            onChange={(event) => onChange({ ...rule, field: `tag:${event.target.value}` })}
          />
        </Field>
      )}
      <Field title={g(`Operator ${path}`)}>
        <select
          className={selectClass}
          value={rule.op}
          onChange={(event) =>
            onChange({ ...rule, op: event.target.value as RuleOperator, value: "" })
          }
        >
          {ruleOperators(rule.field).map((op) => (
            <option value={op} key={op}>
              {g(op)}
            </option>
          ))}
        </select>
      </Field>
      <Field
        title={g(
          `Value ${path}${rule.op === "in" || rule.op === "not_in" ? " (comma separated)" : ""}`,
        )}
      >
        {rule.field === "os_family" && rule.op !== "in" && rule.op !== "not_in" ? (
          <select
            required
            className={selectClass}
            value={String(rule.value)}
            onChange={(event) => onChange({ ...rule, value: event.target.value })}
          >
            <option value=""> {g("Select OS family")} </option>
            {["windows", "linux", "macos"].map((family) => (
              <option value={family} key={family}>
                {g(family)}
              </option>
            ))}
          </select>
        ) : (
          <Input
            required
            value={Array.isArray(rule.value) ? rule.value.join(",") : rule.value}
            inputMode={rule.field === "asset_criticality" ? "numeric" : "text"}
            onChange={(event) => onChange({ ...rule, value: event.target.value })}
          />
        )}
      </Field>
      {rule.field === "os_family" && (
        <p className="text-xs text-muted-foreground sm:col-span-3">
          {" "}
          {g(
            "Only authenticated, linked endpoint inventory confirms OS family. All linked devices must agree and be fresh (default 48 hours). Missing, stale, conflicting or incomplete evidence stays unknown, including negated rules. Accepted families: windows, linux, macos.",
          )}{" "}
        </p>
      )}
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={rule.negate ?? false}
          onChange={(event) => onChange({ ...rule, negate: event.target.checked })}
        />{" "}
        {g("Negate condition")} {path}
      </label>
    </fieldset>
  );
}
function Preview({ result }: { result: GroupPreview }) {
  const g = useGroupText();
  return (
    <section
      className="space-y-3 rounded-md border border-border p-4"
      aria-label={g("Dry-run results")}
      aria-live="polite"
    >
      <p className="font-semibold">
        {result.has_more
          ? g("Incomplete preview — continue before saving or applying")
          : g("Preview complete")}
      </p>
      <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-3">
        {[
          ["Evaluated", result.evaluated],
          ["Matched", result.matched],
          ["Entrants", result.entrants],
          ["Exits", result.exits],
          ["Assets with changes", result.changed ?? result.changes],
          ["Conflicts", result.conflicts],
        ].map(([label, value]) => (
          <div key={label}>
            <dt className="text-muted-foreground">{g(String(label))}</dt>
            <dd className="font-mono">{value ?? g("Unavailable")}</dd>
          </div>
        ))}
      </dl>
      <p className="text-xs text-muted-foreground">
        {" "}
        {g(
          "Context changes resolve priorities across all active groups. Higher priority wins; equal-priority contradictions do not write. Manual context remains protected. Membership does not grant permission to scan. Explanations show the current batch (up to 100 assets); counts include all previewed batches.",
        )}{" "}
      </p>
      <div
        className="max-h-64 space-y-2 overflow-auto"
        tabIndex={0}
        aria-label={g("Preview asset explanations")}
      >
        {result.items.map((item) => (
          <details className="rounded border p-2 text-sm" key={item.asset_id}>
            <summary className="cursor-pointer font-mono">
              {item.asset_id} · {item.matched ? g("matches") : g("does not match")}
              {item.entrant ? g(" · entering") : ""}
              {item.exited ? g(" · leaving") : ""}
            </summary>
            <div className="space-y-1 break-words pt-2">
              <p className="font-medium"> {g("Why")} </p>
              <Reasons value={item.reasons} />
              <p className="font-medium"> {g("Context changes")} </p>
              <Changes value={item.changes} />
              <p className="font-medium"> {g("Conflicts")} </p>
              <Conflicts value={item.conflicts} />
            </div>
          </details>
        ))}
      </div>
    </section>
  );
}
function addPreview(previous: GroupPreview | undefined, next: GroupPreview): GroupPreview {
  if (!previous) return next;
  const count = (field: "entrants" | "exits" | "changed" | "conflicts") =>
    previous[field] == null || next[field] == null ? undefined : previous[field]! + next[field]!;
  return {
    ...next,
    evaluated: previous.evaluated + next.evaluated,
    matched: previous.matched + next.matched,
    entrants: count("entrants"),
    exits: count("exits"),
    changed: count("changed"),
    conflicts: count("conflicts"),
    items: next.items,
  };
}
function GroupEditor({
  group,
  onClose,
  onSaved,
}: {
  group?: AssetGroup;
  onClose: () => void;
  onSaved: () => void;
}) {
  const g = useGroupText();
  const t = useT();
  const [draft, setDraft] = useState<GroupDraft>(() =>
    group
      ? {
          name: group.name,
          description: group.description,
          enabled: group.enabled,
          priority: group.priority,
          rules: group.rules,
          context: group.context,
        }
      : blankDraft(),
  );
  const [error, setError] = useState<unknown>();
  const [preview, setPreview] = useState<{ key: string; result: GroupPreview }>();
  const key = JSON.stringify(draft);
  const currentPreview = preview?.key === key ? preview.result : undefined;
  const normalized = () => ({
    ...draft,
    name: draft.name.trim(),
    rules: normalizeGroupRules(draft.rules),
  });
  const previewMutation = useMutation({
    mutationFn: async () => {
      const requestKey = key;
      const next = await assetGroupsApi.preview(
        normalized(),
        group?.id,
        currentPreview?.has_more ? (currentPreview.next_asset_id ?? undefined) : undefined,
      );
      return {
        key: requestKey,
        result: addPreview(currentPreview?.has_more ? currentPreview : undefined, next),
      };
    },
    onSuccess: (next) => {
      setPreview(next);
      setError(undefined);
    },
    onError: (failure) => {
      setPreview(undefined);
      setError(failure);
    },
  });
  const save = useMutation({
    mutationFn: () => assetGroupsApi.save(normalized(), group?.id),
    onSuccess: onSaved,
    onError: setError,
  });
  const changeContext = (field: string, value: string) => {
    const context: GroupContext = { ...draft.context };
    if (!value) delete context[field as keyof GroupContext];
    else Object.assign(context, { [field]: field === "asset_criticality" ? Number(value) : value });
    setDraft({ ...draft, context });
  };
  function submit(event: FormEvent) {
    event.preventDefault();
    setError(undefined);
    previewMutation.mutate();
  }
  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open && !save.isPending) onClose();
      }}
    >
      <DialogContent className="max-h-[90vh] min-w-0 max-w-4xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {group ? g(`Edit ${group.name} · v${group.version}`) : g("Create dynamic group")}
          </DialogTitle>
          <DialogDescription>
            {" "}
            {g(
              "Unknown values never match, including negated conditions. Preview is read-only; saving schedules reevaluation.",
            )}{" "}
          </DialogDescription>
        </DialogHeader>
        <form className="space-y-4" onSubmit={submit}>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field title={g("Group name")}>
              <Input
                required
                maxLength={160}
                value={draft.name}
                onChange={(event) => setDraft({ ...draft, name: event.target.value })}
              />
            </Field>
            <Field title={g("Priority (higher wins)")}>
              <Input
                type="number"
                required
                min={0}
                max={10000}
                value={draft.priority}
                onChange={(event) => setDraft({ ...draft, priority: Number(event.target.value) })}
              />
            </Field>
          </div>
          <Field title={g("Description")}>
            <Textarea
              maxLength={2000}
              value={draft.description}
              onChange={(event) => setDraft({ ...draft, description: event.target.value })}
            />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })}
            />{" "}
            {g("Enabled")}{" "}
          </label>
          <GroupRuleEditor rule={draft.rules} onChange={(rules) => setDraft({ ...draft, rules })} />
          {t.locale === "ru" && (
            <SystemTechnicalDetails data={{ rules: draft.rules, context: draft.context }} />
          )}
          <fieldset className="space-y-3 rounded-md border p-3">
            <legend className="max-w-full break-words px-1 text-sm font-semibold">
              {" "}
              {g("Context assignments")}{" "}
            </legend>
            <p className="text-xs text-muted-foreground">
              {" "}
              {g(
                "Blank fields remain unmanaged. Exposure remains explicitly declared and cannot be assigned by a group.",
              )}{" "}
            </p>
            <div className="grid gap-3 sm:grid-cols-2">
              {Object.entries(CONTEXT_FIELD_LABELS)
                .filter(([field]) => field !== "exposure_level")
                .map(([field, label]) => (
                  <Field key={field} title={g(label)}>
                    {contextOptions[field] ? (
                      <select
                        className={selectClass}
                        value={draft.context[field as keyof GroupContext] ?? ""}
                        onChange={(event) => changeContext(field, event.target.value)}
                      >
                        <option value=""> {g("Leave unmanaged")} </option>
                        {contextOptions[field].map((option) => (
                          <option value={option} key={option}>
                            {groupValue(t.locale, field, option)}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <Input
                        type={field === "owner_email" ? "email" : "text"}
                        maxLength={320}
                        value={draft.context[field as keyof GroupContext] ?? ""}
                        onChange={(event) => changeContext(field, event.target.value)}
                      />
                    )}
                  </Field>
                ))}
            </div>
          </fieldset>
          <ErrorMessage error={error} />
          {currentPreview && <Preview result={currentPreview} />}
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              variant="outline"
              disabled={previewMutation.isPending || save.isPending}
            >
              {previewMutation.isPending
                ? g("Evaluating…")
                : currentPreview?.has_more
                  ? g("Continue preview")
                  : g("Preview dry-run")}
            </Button>
            <Button
              type="button"
              disabled={
                !currentPreview ||
                currentPreview.has_more ||
                previewMutation.isPending ||
                save.isPending
              }
              onClick={() => save.mutate()}
            >
              {save.isPending ? g("Saving…") : g("Save group")}
            </Button>
            <Button type="button" variant="ghost" disabled={save.isPending} onClick={onClose}>
              {" "}
              {g("Cancel")}{" "}
            </Button>
          </div>
          {!currentPreview && (
            <p className="text-xs text-muted-foreground">
              {" "}
              {g(
                "Preview the current draft before saving. Changing a field invalidates the preview.",
              )}{" "}
            </p>
          )}
        </form>
      </DialogContent>
    </Dialog>
  );
}
function GroupDetails({
  group,
  tenant,
  scope,
  editable,
  onChanged,
}: {
  group: AssetGroup;
  tenant: string | null;
  scope: string;
  editable: boolean;
  onChanged: () => void;
}) {
  const g = useGroupText();
  const t = useT();
  const [offset, setOffset] = useState(0);
  const [evaluationOffset, setEvaluationOffset] = useState(0);
  const [preview, setPreview] = useState<GroupPreview>();
  const [applied, setApplied] = useState<GroupPreview>();
  const [error, setError] = useState<unknown>();
  const members = useQuery({
    queryKey: ["asset-groups", scope, group.id, "members", offset],
    queryFn: () => assetGroupsApi.members(group.id, offset),
  });
  const evaluations = useQuery({
    queryKey: ["asset-groups", scope, group.id, "evaluations", evaluationOffset],
    queryFn: () => assetGroupsApi.evaluations(group.id, evaluationOffset),
    refetchInterval: 10000,
  });
  const dryRun = useMutation({
    mutationFn: () =>
      assetGroupsApi.preview(
        group,
        group.id,
        preview?.has_more ? (preview.next_asset_id ?? undefined) : undefined,
      ),
    onSuccess: (next) => {
      setPreview(addPreview(preview?.has_more ? preview : undefined, next));
      setError(undefined);
      setApplied(undefined);
    },
    onError: (failure) => {
      setPreview(undefined);
      setError(failure);
    },
  });
  const apply = useMutation({
    mutationFn: () =>
      assetGroupsApi.recalculate(
        group.id,
        applied?.has_more ? (applied.next_asset_id ?? undefined) : undefined,
      ),
    onSuccess: (next) => {
      setApplied(addPreview(applied?.has_more ? applied : undefined, next));
      setError(undefined);
      onChanged();
      if (!next.has_more) setPreview(undefined);
    },
    onError: setError,
  });
  const lastSuccess = evaluations.data?.items.find(
    (item) => item.status === "success" || item.status === "completed",
  );
  const currentEvaluation =
    (group.latest_evaluation?.version === group.version ? group.latest_evaluation : undefined) ??
    evaluations.data?.items.find((item) => item.version === group.version);
  return (
    <section
      className="space-y-4 rounded-lg border border-border p-4"
      aria-label={g(`Group ${group.name}`)}
    >
      <h2 className="text-lg font-semibold">
        {group.name} {g("· v")}
        {t.locale === "ru" ? " " : ""}
        {group.version}
      </h2>
      <p className="text-sm text-muted-foreground">
        {" "}
        {g("Last successful evaluation:")}{" "}
        {group.last_success_at ?? lastSuccess?.completed_at ?? g("Not available")}
      </p>
      <p className="text-sm" role="status">
        {" "}
        {g("Current rule v")}
        {t.locale === "ru" ? " " : ""}
        {group.version}:{" "}
        {currentEvaluation
          ? groupState(t.locale, currentEvaluation.status)
          : g("awaiting evaluation")}{" "}
        {g(". Last success above may belong to an earlier rule version.")}{" "}
      </p>
      <ErrorMessage
        error={
          currentEvaluation && !evaluations.data?.items.includes(currentEvaluation)
            ? currentEvaluation.error
            : undefined
        }
      />
      <h3 className="font-semibold"> {g("Evaluation history")} </h3>
      <ErrorMessage error={members.error ?? evaluations.error ?? error} />
      {evaluations.isLoading && <p role="status"> {g("Loading evaluations…")} </p>}
      {evaluations.data?.items.map((item, index) => (
        <div key={item.id ?? item.evaluation_id ?? index} className="rounded border p-2 text-sm">
          <p>
            {" "}
            {g("Evaluation")} {item.id ?? item.evaluation_id} {g("· version")} {item.version ?? "—"}{" "}
            · {groupState(t.locale, item.status)}
            {item.report?.has_more || item.status === "partial" ? g(" · INCOMPLETE") : ""}
          </p>
          <p>
            {item.completed_at ?? item.started_at ?? g("Time unavailable")} {g("· evaluated")}{" "}
            {item.report?.evaluated ?? item.evaluated ?? "—"} {g("· matched")}{" "}
            {item.report?.matched ?? item.matched ?? "—"}
          </p>
          {t.locale === "ru" && <SystemTechnicalDetails data={item} />}
          {item.error && (
            <p role="alert" className="text-destructive">
              {t.locale === "ru"
                ? "Не удалось завершить проверку. Причина сохранена в технических данных."
                : item.error}
            </p>
          )}
        </div>
      ))}
      {evaluations.data && (
        <Pager
          offset={evaluationOffset}
          total={evaluations.data.total}
          hasMore={evaluations.data.has_more}
          onChange={setEvaluationOffset}
          pending={evaluations.isFetching}
          label="evaluations"
        />
      )}
      {editable && (
        <div className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            disabled={dryRun.isPending || apply.isPending}
            onClick={() => dryRun.mutate()}
          >
            {dryRun.isPending
              ? g("Evaluating…")
              : preview?.has_more
                ? g("Continue recalculation preview")
                : g("Preview recalculation")}
          </Button>
          <Button
            disabled={
              apply.isPending ||
              dryRun.isPending ||
              (!applied?.has_more && (!preview || preview.has_more))
            }
            onClick={() => apply.mutate()}
          >
            {apply.isPending
              ? g("Recalculating…")
              : applied?.has_more
                ? g("Continue recalculation")
                : g("Apply recalculation")}
          </Button>
        </div>
      )}
      {preview && <Preview result={preview} />}
      {applied && (
        <div role="status" className="text-sm">
          {applied.has_more
            ? g("Recalculation incomplete — continue the next batch.")
            : g("Recalculation completed.")}{" "}
          {g("Evaluated")} {applied.evaluated} {g("; changed")} {applied.changed ?? "—"}{" "}
          {g("; conflicts")} {applied.conflicts ?? "—"}.
        </div>
      )}
      <h3 className="font-semibold"> {g("Explained members")} </h3>
      {members.isLoading && <p role="status"> {g("Loading members…")} </p>}
      {members.data?.items.map((member) => (
        <details key={member.asset_id} className="rounded border p-2 text-sm">
          <summary className="cursor-pointer">
            {member.asset_id} {g("· rule v")}
            {t.locale === "ru" ? " " : ""}
            {member.version}
            {member.version !== group.version
              ? g(" · previous rule version, awaiting reevaluation")
              : ""}
          </summary>
          <div className="break-words py-2">
            <Reasons value={member.reasons} />
          </div>
          <p>
            {" "}
            {g("Evaluated")} {member.evaluated_at}
          </p>
          <Link
            className="text-primary underline"
            href={`/assets/view?assetId=${encodeURIComponent(member.asset_id)}${tenant ? `&tenantId=${encodeURIComponent(tenant)}` : ""}`}
          >
            {" "}
            {g("Open asset")}{" "}
          </Link>
        </details>
      ))}
      {members.data?.total === 0 && (
        <p className="text-sm text-muted-foreground"> {g("No evaluated members.")} </p>
      )}
      {members.data && (
        <Pager
          offset={offset}
          total={members.data.total}
          hasMore={members.data.has_more}
          onChange={setOffset}
          pending={members.isFetching}
        />
      )}
    </section>
  );
}
export function AssetGroups() {
  const activeTenant = useAuthStore((state) => state.activeTenant);
  const user = useAuthStore((state) => state.user);
  const tenant = activeTenant ?? user?.scoped_tenant ?? user?.default_tenant ?? null;
  const scope = JSON.stringify([user?.username ?? null, tenant]);
  return <ScopedAssetGroups key={scope} tenant={tenant} scope={scope} />;
}
function ScopedAssetGroups({ tenant, scope }: { tenant: string | null; scope: string }) {
  const g = useGroupText();
  const t = useT();
  const user = useAuthStore((state) => state.user);
  const editable = can(user, { minRole: "operator" });
  const client = useQueryClient();
  const [offset, setOffset] = useState(0);
  const [editor, setEditor] = useState<AssetGroup | "new" | null>(null);
  const [selected, setSelected] = useState<AssetGroup | null>(null);
  const [deleting, setDeleting] = useState<AssetGroup | null>(null);
  const groups = useQuery({
    queryKey: ["asset-groups", scope, "list", offset],
    queryFn: () => assetGroupsApi.list(offset),
    refetchInterval: 15000,
    enabled: Boolean(user),
  });
  const invalidate = () => {
    void client.invalidateQueries({ queryKey: ["asset-groups", scope] });
    void client.invalidateQueries({ queryKey: ["assets"] });
    void client.invalidateQueries({ queryKey: ["asset"] });
  };
  const remove = useMutation({
    mutationFn: (id: string) => assetGroupsApi.remove(id),
    onSuccess: () => {
      setDeleting(null);
      setSelected(null);
      invalidate();
    },
  });
  const selectedDetail = useQuery({
    queryKey: ["asset-groups", scope, "selected", selected?.id],
    queryFn: () => assetGroupsApi.get(selected!.id),
    enabled: Boolean(selected),
    refetchInterval: 10000,
  });
  const current = selected
    ? {
        ...selected,
        ...groups.data?.items.find((item) => item.id === selected.id),
        ...selectedDetail.data,
      }
    : null;
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {" "}
        {g("Tenant:")} {tenant ?? g("Resolved by server")}
      </p>
      {editable && <Button onClick={() => setEditor("new")}> {g("Create group")} </Button>}
      <ErrorMessage error={groups.error ?? selectedDetail.error ?? remove.error} />
      {groups.isLoading && <p role="status"> {g("Loading groups…")} </p>}
      {groups.data?.items.map((group) => (
        <article
          key={group.id}
          className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border p-4"
        >
          <div>
            <h2 className="font-semibold">
              {group.name} {g("· v")}
              {t.locale === "ru" ? " " : ""}
              {group.version}
            </h2>
            <p className="text-sm text-muted-foreground">
              {group.enabled ? g("Enabled") : g("Disabled")} {g("· priority")} {group.priority} ·{" "}
              {group.member_count} {g("members")}{" "}
            </p>
            <p className="break-words text-sm">{group.description}</p>
            {t.locale === "ru" && <SystemTechnicalDetails data={group} />}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => setSelected(group)}>
              {" "}
              {g("Members & evaluations:")} {group.name}
            </Button>
            {editable && (
              <>
                <Button variant="outline" onClick={() => setEditor(group)}>
                  {" "}
                  {g("Edit")} {group.name}
                </Button>
                <Button variant="ghost" onClick={() => setDeleting(group)}>
                  {" "}
                  {g("Delete")} {group.name}
                </Button>
              </>
            )}
          </div>
        </article>
      ))}
      {groups.data?.total === 0 && (
        <p className="text-sm text-muted-foreground"> {g("No dynamic groups in this tenant.")} </p>
      )}
      {groups.data && (
        <Pager
          offset={offset}
          total={groups.data.total}
          hasMore={groups.data.has_more}
          onChange={setOffset}
          pending={groups.isFetching}
        />
      )}
      {current && (
        <GroupDetails
          key={`${current.id}:${current.version}`}
          group={current}
          tenant={tenant}
          scope={scope}
          editable={editable}
          onChanged={invalidate}
        />
      )}
      {editable && editor && (
        <GroupEditor
          group={editor === "new" ? undefined : editor}
          onClose={() => setEditor(null)}
          onSaved={() => {
            setEditor(null);
            invalidate();
          }}
        />
      )}
      <AlertDialog
        open={editable && Boolean(deleting)}
        onOpenChange={(open) => {
          if (!open && !remove.isPending) setDeleting(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {" "}
              {g("Delete")} {deleting?.name}?
            </AlertDialogTitle>
            <AlertDialogDescription>
              {" "}
              {g(
                "Membership will be retired. Rule-owned values are restored safely on reevaluation; manual and later changes are preserved. Historical audit records remain.",
              )}{" "}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <ErrorMessage error={remove.error} />
          <AlertDialogFooter>
            <AlertDialogCancel disabled={remove.isPending}> {g("Cancel")} </AlertDialogCancel>
            <AlertDialogAction
              disabled={remove.isPending}
              onClick={(event) => {
                event.preventDefault();
                if (deleting) remove.mutate(deleting.id);
              }}
            >
              {remove.isPending ? g("Deleting…") : g("Delete group")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
