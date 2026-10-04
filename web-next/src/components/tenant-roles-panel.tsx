"use client";

import { FormEvent, useMemo, useState } from "react";
import { Pencil, Plus, Trash2 } from "lucide-react";
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
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { grantableRoles } from "@/components/tenant-members-panel";
import {
  useCreateTenantRole,
  useDeleteTenantRole,
  usePermissionCatalogue,
  useRoleCatalogue,
  useUpdateTenantRole,
} from "@/hooks/use-rbac";
import { type PermissionInfo, type RoleInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { tenantRank, withinAuthority } from "@/lib/authz";
import { useT, type Translate } from "@/lib/i18n";
import type { MsgKey } from "@/lib/i18n/messages";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-background px-2 text-sm";
const RANKS: { rank: number; key: MsgKey }[] = [
  { rank: 1, key: "roles.rank.1" },
  { rank: 2, key: "roles.rank.2" },
  { rank: 3, key: "roles.rank.3" },
];
/** Mirror of `APPROVAL_PERMISSIONS` / `separation_of_duties_conflict` in
 * `api/core/permissions.py`, so the dialog says why before the API does. */
const APPROVALS = ["scan_scope.approve", "vulnerability.exception.approve"];

function separationConflict(rank: number, permissions: string[], t: Translate): string | null {
  if (!permissions.some((key) => APPROVALS.includes(key))) return null;
  if (rank > 1) return t("roles.sod.rank");
  if (permissions.includes("tenant.member.manage")) return t("roles.sod.members");
  return null;
}

/**
 * The roles this tenant defined for itself (#318): a name, a rank and an
 * explicit permission set, granted on the members panel next to it.
 *
 * `canManage` is `tenant.member.manage` in the tenant — the people who grant
 * memberships decide what there is to grant. What the dialog offers is what
 * the API accepts from *this* principal (`withinAuthority`): no rank above its
 * own, no permission it does not hold, and never one only the platform holds
 * (`tenant_grantable`). The API refuses all three regardless; offering them
 * would be offering a choice that cannot work.
 */
export function TenantRolesPanel({
  tenantId,
  canManage,
}: {
  tenantId: string;
  canManage: boolean;
}) {
  const t = useT();
  const user = useAuthStore((state) => state.user);
  const catalogueQuery = useRoleCatalogue(tenantId, Boolean(tenantId));
  const permissionsQuery = usePermissionCatalogue(canManage);
  const roles = useMemo(() => grantableRoles(catalogueQuery.data ?? []), [catalogueQuery.data]);
  const custom = roles.filter((role) => !role.builtin);
  const [editing, setEditing] = useState<RoleInfo | "new" | null>(null);
  const [deleting, setDeleting] = useState<RoleInfo | null>(null);

  return (
    <section className="space-y-4 rounded-xl border border-border bg-card p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h2 className="text-base font-semibold">{t("roles.title")}</h2>
          <p className="text-sm text-muted-foreground">{t("roles.note")}</p>
        </div>
        {canManage ? (
          <Button size="sm" onClick={() => setEditing("new")}>
            <Plus className="mr-1 h-4 w-4" />
            {t("roles.new")}
          </Button>
        ) : null}
      </div>

      {catalogueQuery.error ? (
        <p className="text-sm text-rose-500" role="alert">
          {catalogueQuery.error instanceof Error ? catalogueQuery.error.message : null}
        </p>
      ) : catalogueQuery.isLoading ? (
        <p className="text-sm text-muted-foreground">{t("roles.loading")}</p>
      ) : custom.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("roles.empty")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-muted-foreground">
              <tr>
                <th className="py-2 pr-4">{t("roles.col.role")}</th>
                <th className="py-2 pr-4">{t("roles.col.rank")}</th>
                <th className="py-2 pr-4">{t("roles.col.permissions")}</th>
                <th className="py-2 pr-4">{t("roles.col.members")}</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {custom.map((role) => {
                // A role above this principal can be neither edited nor
                // deleted by it; the API refuses both with 403.
                const mine = canManage && withinAuthority(user, role.rank, role.permissions);
                return (
                  <tr key={role.role_id} className="border-t border-border/60 align-top">
                    <td className="py-2 pr-4">
                      <div className="font-mono font-medium">{role.role_id}</div>
                      {role.description ? (
                        <div className="text-xs text-muted-foreground">{role.description}</div>
                      ) : null}
                    </td>
                    <td className="py-2 pr-4">{t(`roles.rank.${role.rank}` as MsgKey)}</td>
                    <td className="py-2 pr-4">
                      {role.permissions.length === 0 ? (
                        <span className="text-muted-foreground">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {role.permissions.map((key) => (
                            <code key={key} className="rounded bg-muted px-1.5 py-0.5 text-xs">
                              {key}
                            </code>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="py-2 pr-4 tabular-nums">{role.member_count ?? 0}</td>
                    <td className="py-2">
                      {mine ? (
                        <div className="flex gap-1">
                          <Button
                            variant="outline"
                            size="sm"
                            aria-label={t("roles.edit", { role: role.role_id })}
                            onClick={() => setEditing(role)}
                          >
                            <Pencil className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            aria-label={t("roles.delete", { role: role.role_id })}
                            onClick={() => setDeleting(role)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {editing !== null ? (
        <RoleDialog
          t={t}
          tenantId={tenantId}
          role={editing === "new" ? null : editing}
          catalogue={permissionsQuery.data ?? []}
          onClose={() => setEditing(null)}
        />
      ) : null}
      {deleting !== null ? (
        <DeleteRoleDialog
          t={t}
          tenantId={tenantId}
          role={deleting}
          roles={roles}
          onClose={() => setDeleting(null)}
        />
      ) : null}
    </section>
  );
}

function RoleDialog({
  t,
  tenantId,
  role,
  catalogue,
  onClose,
}: {
  t: Translate;
  tenantId: string;
  role: RoleInfo | null;
  catalogue: PermissionInfo[];
  onClose: () => void;
}) {
  const user = useAuthStore((state) => state.user);
  const create = useCreateTenantRole(tenantId);
  const update = useUpdateTenantRole(tenantId);
  const [name, setName] = useState(role?.role_id ?? "");
  const [description, setDescription] = useState(role?.description ?? "");
  const [rank, setRank] = useState(role?.rank ?? 1);
  const [chosen, setChosen] = useState<string[]>(role?.permissions ?? []);
  const ceiling = user?.is_platform_admin ? 3 : tenantRank(user);
  // Only what a tenant role may carry at all, and of that only what this
  // principal may hand out. A permission the role already has but the
  // principal could not grant never reaches this dialog: the edit button is
  // hidden for such a role.
  const grantable = catalogue.filter(
    (entry) => entry.tenant_grantable && withinAuthority(user, 1, [entry.permission_key]),
  );
  const conflict = separationConflict(rank, chosen, t);
  const pending = create.isPending || update.isPending;

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const body = {
      role_id: name.trim().toLowerCase(),
      description: description.trim(),
      rank,
      permissions: [...chosen].sort(),
    };
    try {
      if (role === null) {
        await create.mutateAsync(body);
      } else {
        await update.mutateAsync({
          roleId: role.role_id,
          body: body.role_id === role.role_id ? { ...body, role_id: undefined } : body,
        });
      }
      onClose();
    } catch {
      // Reported by the mutation; the dialog stays open so the input survives.
    }
  }

  function toggle(key: string, on: boolean) {
    setChosen((current) =>
      on
        ? current.includes(key)
          ? current
          : [...current, key]
        : current.filter((entry) => entry !== key),
    );
  }

  return (
    <Dialog open onOpenChange={(open) => (open ? null : onClose())}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-xl">
        <form onSubmit={onSubmit} className="space-y-4">
          <DialogHeader>
            <DialogTitle>
              {role === null ? t("roles.dialog.createTitle") : t("roles.dialog.editTitle")}
            </DialogTitle>
            <DialogDescription>
              {role !== null && (role.member_count ?? 0) > 0
                ? t("roles.dialog.editHint", { count: role.member_count ?? 0 })
                : t("roles.dialog.createHint")}
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="role-name">{t("roles.dialog.name")}</Label>
            <Input
              id="role-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="soc-lead"
              required
              minLength={2}
              maxLength={48}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="role-description">{t("roles.dialog.description")}</Label>
            <Input
              id="role-description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              maxLength={200}
            />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="role-rank">{t("roles.dialog.rank")}</Label>
            <select
              id="role-rank"
              className={SELECT_CLASS}
              value={rank}
              onChange={(event) => setRank(Number(event.target.value))}
            >
              {RANKS.filter((entry) => entry.rank <= ceiling).map((entry) => (
                <option key={entry.rank} value={entry.rank}>
                  {t(entry.key)}
                </option>
              ))}
            </select>
            <p className="text-xs text-muted-foreground">{t("roles.dialog.rankHint")}</p>
          </div>
          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">{t("roles.dialog.permissions")}</legend>
            {grantable.length === 0 ? (
              <p className="text-xs text-muted-foreground">{t("roles.dialog.noPermissions")}</p>
            ) : (
              grantable.map((entry) => (
                <label
                  key={entry.permission_key}
                  className="flex items-start gap-2 text-sm"
                  htmlFor={`perm-${entry.permission_key}`}
                >
                  <Checkbox
                    id={`perm-${entry.permission_key}`}
                    checked={chosen.includes(entry.permission_key)}
                    onCheckedChange={(value) => toggle(entry.permission_key, value === true)}
                  />
                  <span>
                    <code className="text-xs">{entry.permission_key}</code>
                    <span className="block text-xs text-muted-foreground">{entry.description}</span>
                  </span>
                </label>
              ))
            )}
          </fieldset>
          {conflict ? (
            <p className="text-xs text-rose-500" role="alert">
              {conflict}
            </p>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t("roles.dialog.cancel")}
            </Button>
            <Button type="submit" disabled={pending || Boolean(conflict) || !name.trim()}>
              {t("roles.dialog.save")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteRoleDialog({
  t,
  tenantId,
  role,
  roles,
  onClose,
}: {
  t: Translate;
  tenantId: string;
  role: RoleInfo;
  roles: RoleInfo[];
  onClose: () => void;
}) {
  const user = useAuthStore((state) => state.user);
  const remove = useDeleteTenantRole(tenantId);
  const held = role.member_count ?? 0;
  // Where the holders go is the deleter's grant, so it is held to the same
  // ceiling as any other grant.
  const targets = roles.filter(
    (entry) =>
      entry.role_id !== role.role_id && withinAuthority(user, entry.rank, entry.permissions),
  );
  const [reassignTo, setReassignTo] = useState("");

  async function onConfirm() {
    try {
      await remove.mutateAsync({
        roleId: role.role_id,
        reassignTo: held > 0 ? reassignTo : undefined,
      });
      onClose();
    } catch {
      // Reported by the mutation.
    }
  }

  return (
    <AlertDialog open onOpenChange={(open) => (open ? null : onClose())}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>
            {t("roles.deleteDialog.title", { role: role.role_id })}
          </AlertDialogTitle>
          <AlertDialogDescription>
            {held > 0
              ? t("roles.deleteDialog.held", { count: held })
              : t("roles.deleteDialog.unheld")}
          </AlertDialogDescription>
        </AlertDialogHeader>
        {held > 0 ? (
          <div className="grid gap-1.5">
            <Label htmlFor="role-reassign">{t("roles.deleteDialog.reassign")}</Label>
            <select
              id="role-reassign"
              className={SELECT_CLASS}
              value={reassignTo}
              onChange={(event) => setReassignTo(event.target.value)}
            >
              <option value="">—</option>
              {targets.map((entry) => (
                <option key={entry.role_id} value={entry.role_id}>
                  {entry.role_id}
                </option>
              ))}
            </select>
          </div>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel>{t("roles.dialog.cancel")}</AlertDialogCancel>
          <AlertDialogAction
            disabled={remove.isPending || (held > 0 && !reassignTo)}
            onClick={(event) => {
              event.preventDefault();
              void onConfirm();
            }}
          >
            {t("roles.deleteDialog.confirm")}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
