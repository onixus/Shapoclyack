"use client";

import { FormEvent, useMemo, useState } from "react";
import { format } from "date-fns";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useRoleCatalogue } from "@/hooks/use-rbac";
import { useGrantMembership, useRevokeMembership, useTenantMembers } from "@/hooks/use-users";
import { type RoleInfo, type TenantRoleName } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { withinAuthority } from "@/lib/authz";
import { useT } from "@/lib/i18n";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-background px-2 text-sm";

function formatMoment(value: string | null | undefined) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : format(parsed, "yyyy-MM-dd HH:mm");
}

/** The grantable roles for one tenant, in an order a human can read: the
 * three ranked ones first, then the separation-of-duties roles, then anything
 * this tenant defined for itself. `platform-admin` is never in the answer —
 * the API refuses it as a membership role — but it is filtered here too so a
 * future catalogue change cannot put it in a dropdown. */
export function grantableRoles(catalogue: RoleInfo[]): RoleInfo[] {
  const order = ["viewer", "operator", "admin"];
  return [...catalogue]
    .filter((role) => role.role_id !== "platform-admin")
    .sort((a, b) => {
      const ia = order.indexOf(a.role_id);
      const ib = order.indexOf(b.role_id);
      if (ia !== ib) return (ia < 0 ? order.length : ia) - (ib < 0 ? order.length : ib);
      if (a.builtin !== b.builtin) return a.builtin ? -1 : 1;
      return a.role_id.localeCompare(b.role_id);
    });
}

/**
 * Who may act in one tenant, and with which role (ROADMAP P0, #318).
 *
 * Shared by the platform's *Users & access* page, which picks the tenant, and
 * the tenant's own *Roles & members* page, which works in the active one. It
 * used to live inside the first, behind the account's **global** admin role —
 * so the tenant's own admin, whom `tenant.member.manage` lets the API serve,
 * could not reach the screen that exercises it.
 *
 * `canManage` is `tenant.member.manage` in that tenant. Without it the list is
 * read-only. With it, the roles offered are the ones the API will let this
 * principal grant (`withinAuthority`): a member manager defined below admin is
 * not shown `admin`, rather than shown it and refused.
 */
export function TenantMembersPanel({
  tenantId,
  canManage,
}: {
  tenantId: string;
  canManage: boolean;
}) {
  const t = useT();
  const user = useAuthStore((state) => state.user);
  const { data = [], isLoading, error } = useTenantMembers(tenantId, Boolean(tenantId));
  const grant = useGrantMembership(tenantId);
  const revoke = useRevokeMembership(tenantId);
  // The role table lives on the server (#318). Before this the editor offered
  // viewer/operator/admin from a literal, so `auditor`, `scan-operator`,
  // `scope-approver`, `token-admin` and `risk-approver` existed in the API,
  // in migration 0049 and in the docs, and could not be granted from the
  // console at all — and neither could a role the tenant defined.
  const catalogueQuery = useRoleCatalogue(tenantId, Boolean(tenantId));
  const roles = useMemo(() => grantableRoles(catalogueQuery.data ?? []), [catalogueQuery.data]);
  const offered = useMemo(
    () => roles.filter((role) => withinAuthority(user, role.rank, role.permissions)),
    [roles, user],
  );
  const offeredIds = new Set(offered.map((role) => role.role_id));
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<TenantRoleName>("viewer");
  const selected = roles.find((entry) => entry.role_id === role);

  async function onGrant(event: FormEvent) {
    event.preventDefault();
    if (!username.trim()) return;
    try {
      await grant.mutateAsync({ username: username.trim(), role });
      setUsername("");
    } catch {
      // Reported by the mutation; the name stays so a typo can be fixed.
    }
  }

  return (
    <section className="space-y-4 rounded-xl border border-border bg-card p-5">
      <p className="text-sm text-muted-foreground">{t("users.membership.note")}</p>

      {canManage ? (
        <form className="grid gap-3 sm:grid-cols-4 sm:items-end" onSubmit={onGrant}>
          <div className="grid gap-1.5 sm:col-span-2">
            <Label htmlFor="membership-username">{t("users.membership.grantTitle")}</Label>
            <Input
              id="membership-username"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="analyst"
              required
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="membership-role">{t("users.membership.role")}</Label>
            <select
              id="membership-role"
              className={SELECT_CLASS}
              value={role}
              disabled={catalogueQuery.isLoading}
              onChange={(event) => setRole(event.target.value)}
            >
              {offered.map((entry) => (
                <option key={entry.role_id} value={entry.role_id}>
                  {entry.role_id}
                </option>
              ))}
            </select>
          </div>
          <Button type="submit" disabled={grant.isPending || !tenantId}>
            {t("users.membership.grant")}
          </Button>
          {/* What the role does, in the platform's own words: the catalogue
              publishes a description for exactly this, and "auditor" means
              nothing to whoever is about to grant it. */}
          {selected ? (
            <p className="text-xs text-muted-foreground sm:col-span-4">{selected.description}</p>
          ) : null}
          {catalogueQuery.error ? (
            <p className="text-xs text-rose-500 sm:col-span-4" role="alert">
              {t("users.membership.catalogueFailed")}
            </p>
          ) : null}
          <p className="text-xs text-muted-foreground sm:col-span-4">
            {t("users.membership.grantHint")}
          </p>
        </form>
      ) : null}

      {error ? (
        <p className="text-sm text-rose-500" role="alert">
          {error instanceof Error ? error.message : null}
        </p>
      ) : null}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">{t("users.membership.loading")}</p>
      ) : data.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("users.membership.empty")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-muted-foreground">
              <tr>
                <th className="py-2 pr-4">{t("users.membership.username")}</th>
                <th className="py-2 pr-4">{t("users.membership.role")}</th>
                <th className="py-2 pr-4">{t("users.membership.granted")}</th>
                <th className="py-2 pr-4">{t("users.membership.grantedBy")}</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {data.map((member) => {
                // A member whose current role is above this principal cannot
                // be changed or revoked by it — the API refuses both — so the
                // row is shown as it is rather than as a control.
                const current = roles.find((entry) => entry.role_id === member.role);
                const editable =
                  canManage &&
                  (current === undefined ||
                    withinAuthority(user, current.rank, current.permissions));
                return (
                  <tr key={member.username} className="border-t border-border/60">
                    <td className="py-2 pr-4 font-mono font-medium">{member.username}</td>
                    <td className="py-2 pr-4">
                      {editable ? (
                        <select
                          aria-label={t("users.roleFor", { username: member.username })}
                          className={SELECT_CLASS}
                          value={member.role}
                          disabled={grant.isPending}
                          onChange={(event) =>
                            grant.mutate({
                              username: member.username,
                              role: event.target.value,
                            })
                          }
                        >
                          {offered.map((entry) => (
                            <option key={entry.role_id} value={entry.role_id}>
                              {entry.role_id}
                            </option>
                          ))}
                          {/* A role the catalogue no longer lists — one a
                              tenant deleted, or a newer replica wrote — still
                              has to be shown as what it is, or the select
                              renders blank and the first edit silently
                              demotes somebody. */}
                          {offeredIds.has(member.role) ? null : (
                            <option value={member.role}>{member.role}</option>
                          )}
                        </select>
                      ) : (
                        <span className="font-mono">{member.role}</span>
                      )}
                    </td>
                    <td className="py-2 pr-4 tabular-nums">{formatMoment(member.created_at)}</td>
                    <td className="py-2 pr-4">{member.created_by ?? "—"}</td>
                    <td className="py-2">
                      {editable ? (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={revoke.isPending}
                          onClick={() => revoke.mutate(member.username)}
                        >
                          {t("users.action.revoke")}
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
