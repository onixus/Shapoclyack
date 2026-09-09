"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { format } from "date-fns";
import { Plus, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { StatusBadge } from "@/components/status-badge";
import {
  scanScopeSignature,
  usePromotedDomains,
  useReplaceScanScope,
  useScanScope,
} from "@/hooks/use-scan-scope";
import { type ScanScopeEffect, type ScanScopeEntry, type ScanScopeKind } from "@/lib/api";
import { SCAN_SCOPE_EFFECT } from "@/lib/config/statuses";
import { useT, type Translate } from "@/lib/i18n";

const EFFECTS: ScanScopeEffect[] = ["allow", "deny"];
const KINDS: ScanScopeKind[] = ["cidr", "domain"];

/** The explicit any-value wildcard, spelled the way the API spells it. */
const WILDCARD = "*";

/** A row being edited. `key` is local identity only — the server assigns ids,
 * and a PUT replaces the rows rather than updating them one by one. */
type DraftRow = {
  key: string;
  effect: ScanScopeEffect;
  kind: ScanScopeKind;
  value: string;
  note: string;
};

function toDraft(entry: ScanScopeEntry, index: number): DraftRow {
  return {
    key: `stored-${entry.id}-${index}`,
    effect: entry.effect,
    kind: entry.kind,
    value: entry.value,
    note: entry.note,
  };
}

/** What is actually sent, and therefore what "changed" is measured on: a row
 * whose only edit is trailing whitespace is not a scope change. */
function normalize(rows: DraftRow[]) {
  return rows.map((row) => ({
    effect: row.effect,
    kind: row.kind,
    value: row.value.trim(),
    note: row.note.trim(),
  }));
}

function looksLikeIpv4(address: string) {
  const octets = address.split(".");
  return octets.length === 4 && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255);
}

function looksLikeIpv6(address: string) {
  // The colon is what separates an IPv6 literal from a word that happens to be
  // spelled out of hex digits — "beef" is not an address. The last group may
  // be a dotted IPv4 tail, which is how a mapped address is written.
  if (!address.includes(":")) return false;
  const groups = address.split(":");
  const head = looksLikeIpv4(groups[groups.length - 1]) ? groups.slice(0, -1) : groups;
  return head.every((group) => group === "" || /^[0-9a-fA-F]{1,4}$/.test(group));
}

/** Shape only, and only as a hint: the API is the authority on a value
 * (`_validated` normalises it and refuses what it cannot parse), so this is
 * cheap enough to be wrong — it exists to catch a domain typed into a `cidr`
 * row before it costs a round trip. It takes the forms the API takes,
 * IPv4-mapped ones (`::ffff:169.254.169.254`) included, and refuses what no
 * parser would read (`999.1.1.1`, a /99 on an IPv4 address). */
function looksLikeCidr(value: string) {
  const slash = value.indexOf("/");
  const address = slash === -1 ? value : value.slice(0, slash);
  const v4 = looksLikeIpv4(address);
  if (!v4 && !looksLikeIpv6(address)) return false;
  if (slash === -1) return true;
  const prefix = value.slice(slash + 1);
  return /^\d{1,3}$/.test(prefix) && Number(prefix) <= (v4 ? 32 : 128);
}

/** What the editor thinks is odd about a row — a warning, never a refusal.
 * The API decides what is accepted and says so in its 422, and a check that
 * blocked the request would have made this file the authority on a vocabulary
 * it only approximates. */
function rowWarning(row: DraftRow, t: Translate): string | null {
  const value = row.value.trim();
  if (!value || value === WILDCARD) return null;
  if (row.kind === "cidr" && !looksLikeCidr(value)) return t("scanScope.warnCidr");
  if (row.kind === "domain" && /\s/.test(value)) return t("scanScope.warnDomain");
  return null;
}

/** The only thing the editor refuses to send: an empty value is not an entry,
 * and the request would be a 422 nobody learns anything from. */
function blockingErrors(rows: DraftRow[], t: Translate): string[] {
  return rows.flatMap((row, index) =>
    row.value.trim() ? [] : [t("scanScope.errValueRequired", { row: index + 1 })],
  );
}

function formatDate(value: string | null) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : format(parsed, "yyyy-MM-dd HH:mm");
}

/**
 * Approve what one tenant is allowed to scan (#226), from the console instead
 * of from curl.
 *
 * The editor is a whole-scope editor because the API is: a scope is evaluated
 * as a set — deny beats allow — so there is no per-entry update that is safe
 * to enforce halfway, and `PUT` replaces everything. That makes two things
 * load-bearing here: the editor is seeded from what is approved *now*, so an
 * admin fixing one line does not silently drop the rest, and an empty list is
 * offered with a warning rather than refused, because "this tenant scans
 * nothing" is a decision someone is entitled to make.
 */
export function ScanScopePanel({ tenantId }: { tenantId: string }) {
  const t = useT();
  const { data: entries, isLoading, error } = useScanScope(tenantId);
  const promotedQuery = usePromotedDomains(tenantId);
  const replaceMutation = useReplaceScanScope(tenantId);

  const baseline = useMemo(() => (entries ?? []).map(toDraft), [entries]);
  const [rows, setRows] = useState<DraftRow[]>(baseline);
  const nextKey = useRef(0);

  // Reseed when the approved scope arrives or changes underneath the editor,
  // which covers the refused-because-somebody-else-approved path: the mutation
  // puts the scope it found into the cache, and the editor starts again from
  // it. A save of one's own reseeds from the response instead — see `approve`.
  const baselineSignature = scanScopeSignature(baseline);
  useEffect(() => {
    setRows((entries ?? []).map(toDraft));
    // The signature is the dependency on purpose: a refetch returning an equal
    // scope must not throw away edits in progress.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [baselineSignature]);

  const errors = blockingErrors(rows, t);
  const dirty = scanScopeSignature(normalize(rows)) !== baselineSignature;
  const promoted = promotedQuery.data ?? [];

  function approve() {
    replaceMutation.mutate(
      { entries: normalize(rows), baseline: baselineSignature },
      {
        // Unconditionally, from the response: what the server stored is not
        // what was sent — it normalises values (10.0.0.5/24 comes back as
        // 10.0.0.0/24) and collapses duplicates — and it can come back equal
        // to the scope the editor started from, which is exactly the case a
        // reseed driven by a changed signature would sit out.
        onSuccess: (saved) => setRows(saved.map(toDraft)),
      },
    );
  }

  function addRow() {
    nextKey.current += 1;
    setRows((current) => [
      ...current,
      { key: `draft-${nextKey.current}`, effect: "allow", kind: "cidr", value: "", note: "" },
    ]);
  }

  function patchRow(key: string, patch: Partial<DraftRow>) {
    setRows((current) => current.map((row) => (row.key === key ? { ...row, ...patch } : row)));
  }

  return (
    <section className="space-y-6">
      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {t("scanScope.current")}
        </p>
        {error ? (
          <p className="text-sm text-rose-500" role="alert">
            {error instanceof Error ? error.message : t("scanScope.loadFailed")}
          </p>
        ) : isLoading ? (
          <p className="text-sm text-muted-foreground">{t("scanScope.loading")}</p>
        ) : (entries ?? []).length === 0 ? (
          <p className="text-sm text-amber-500">{t("scanScope.currentEmpty")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="py-2 pr-4">{t("scanScope.col.effect")}</th>
                  <th className="py-2 pr-4">{t("scanScope.col.kind")}</th>
                  <th className="py-2 pr-4">{t("scanScope.col.value")}</th>
                  <th className="py-2 pr-4">{t("scanScope.col.note")}</th>
                  <th className="py-2 pr-4">{t("scanScope.col.approvedBy")}</th>
                  <th className="py-2">{t("scanScope.col.approvedAt")}</th>
                </tr>
              </thead>
              <tbody>
                {(entries ?? []).map((entry) => (
                  <tr key={entry.id} className="border-t border-border/60">
                    <td className="py-2 pr-4">
                      <StatusBadge value={entry.effect} map={SCAN_SCOPE_EFFECT} />
                    </td>
                    <td className="py-2 pr-4">{t.label(entry.kind)}</td>
                    <td className="py-2 pr-4 font-mono text-xs">{entry.value}</td>
                    <td className="py-2 pr-4 text-muted-foreground">{entry.note || "—"}</td>
                    <td className="py-2 pr-4">{entry.approved_by || "—"}</td>
                    <td className="py-2 tabular-nums">{formatDate(entry.approved_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {t("scanScope.editor")}
        </p>
        <ul className="space-y-1 text-[11px] text-slate-500">
          <li>{t("scanScope.ruleDeny")}</li>
          <li>{t("scanScope.ruleAllow")}</li>
          <li>{t("scanScope.ruleEmpty")}</li>
        </ul>

        <div className="space-y-2">
          {rows.map((row, index) => {
            const warning = rowWarning(row, t);
            return (
              <div key={row.key} className="space-y-1">
                <div className="grid gap-2 sm:grid-cols-[7rem_7rem_1fr_1fr_auto] sm:items-center">
                  <select
                    aria-label={`${t("scanScope.col.effect")} ${index + 1}`}
                    className="h-9 rounded-md border border-input bg-background px-2 text-sm"
                    value={row.effect}
                    onChange={(event) =>
                      patchRow(row.key, { effect: event.target.value as ScanScopeEffect })
                    }
                  >
                    {EFFECTS.map((effect) => (
                      <option key={effect} value={effect}>
                        {t.label(effect)}
                      </option>
                    ))}
                  </select>
                  <select
                    aria-label={`${t("scanScope.col.kind")} ${index + 1}`}
                    className="h-9 rounded-md border border-input bg-background px-2 text-sm"
                    value={row.kind}
                    onChange={(event) => patchRow(row.key, { kind: event.target.value as ScanScopeKind })}
                  >
                    {KINDS.map((kind) => (
                      <option key={kind} value={kind}>
                        {t.label(kind)}
                      </option>
                    ))}
                  </select>
                  <Input
                    aria-label={`${t("scanScope.col.value")} ${index + 1}`}
                    value={row.value}
                    placeholder={t("scanScope.valuePlaceholder")}
                    onChange={(event) => patchRow(row.key, { value: event.target.value })}
                  />
                  <Input
                    aria-label={`${t("scanScope.col.note")} ${index + 1}`}
                    value={row.note}
                    placeholder={t("scanScope.notePlaceholder")}
                    onChange={(event) => patchRow(row.key, { note: event.target.value })}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="border-slate-800"
                    aria-label={`${t("scanScope.removeRow")} ${index + 1}`}
                    onClick={() => setRows((current) => current.filter((item) => item.key !== row.key))}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
                {warning ? (
                  <p className="text-xs text-amber-500" role="status">
                    {warning}
                  </p>
                ) : null}
              </div>
            );
          })}
        </div>

        <Button
          type="button"
          variant="outline"
          size="sm"
          className="gap-2 border-slate-800"
          onClick={addRow}
        >
          <Plus className="h-3.5 w-3.5" />
          {t("scanScope.addRow")}
        </Button>

        {rows.length === 0 ? (
          <p className="rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-sm" role="alert">
            {t("scanScope.emptyWarning")}
          </p>
        ) : null}

        {errors.length > 0 ? (
          <ul className="space-y-1 text-sm text-rose-500" role="alert">
            {errors.map((message) => (
              <li key={message}>{message}</li>
            ))}
          </ul>
        ) : null}
        <p className="text-[11px] text-slate-500">{t("scanScope.serverAuthority")}</p>

        <Button
          type="button"
          className="gap-2 bg-sky-600 text-white hover:bg-sky-500"
          disabled={!dirty || errors.length > 0 || replaceMutation.isPending}
          onClick={approve}
        >
          <ShieldCheck className="h-4 w-4" />
          {replaceMutation.isPending ? t("scanScope.approving") : t("scanScope.approve")}
        </Button>
      </div>

      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {t("scanScope.promoted")}
        </p>
        <p className="text-[11px] text-slate-500">{t("scanScope.promotedHint")}</p>
        {promotedQuery.error ? (
          <p className="text-sm text-rose-500" role="alert">
            {promotedQuery.error instanceof Error
              ? promotedQuery.error.message
              : t("scanScope.promotedFailed")}
          </p>
        ) : promoted.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("scanScope.promotedEmpty")}</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="py-2 pr-4">{t("scanScope.col.domain")}</th>
                  <th className="py-2 pr-4">{t("scanScope.col.promotedBy")}</th>
                  <th className="py-2">{t("scanScope.col.promotedAt")}</th>
                </tr>
              </thead>
              <tbody>
                {promoted.map((item) => (
                  <tr key={item.domain} className="border-t border-border/60">
                    <td className="py-2 pr-4 font-mono text-xs">{item.domain}</td>
                    <td className="py-2 pr-4">{item.promoted_by || "—"}</td>
                    <td className="py-2 tabular-nums">{formatDate(item.promoted_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
