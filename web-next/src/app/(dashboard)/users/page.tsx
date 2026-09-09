"use client";

import Link from "next/link";
import { FormEvent, useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { KeyRound, Mail, RotateCcw, Trash2, UserCog, UserPlus } from "lucide-react";
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DataTable } from "@/components/data-table";
import { KpiCard } from "@/components/kpi-card";
import { StatusBadge } from "@/components/status-badge";
import { usePagination } from "@/hooks/use-pagination";
import { useTenants } from "@/hooks/use-tenants";
import {
  useAuthEvents,
  useChangeOwnPassword,
  useCreateUser,
  useDeleteUser,
  useGrantMembership,
  useProvisioningKeys,
  useResetUserPassword,
  useRevokeMembership,
  useRevokeProvisioningKey,
  useSetUserDisabled,
  useSetUserEmail,
  useSetUserRole,
  useTenantMembers,
  useUsers,
} from "@/hooks/use-users";
import { type AuthEventInfo, type AuthEventOutcome, type Role, type UserInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import {
  ACCOUNT_STATUS,
  AUTH_EVENT_OUTCOME,
  PROVISIONING_KEY_STATUS,
  USER_ROLE_STATUS,
} from "@/lib/config/statuses";
import { useT, type Translate } from "@/lib/i18n";

const ROLES: Role[] = ["viewer", "operator", "admin"];
const OUTCOMES: AuthEventOutcome[] = ["success", "failure", "locked", "denied", "trust_change"];

const SELECT_CLASS = "h-9 rounded-md border border-input bg-background px-2 text-sm";

function formatMoment(value: string | null | undefined) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : format(parsed, "yyyy-MM-dd HH:mm");
}

/**
 * Users & access (#156, #157).
 *
 * Everything here except the last tab is platform-admin work, and the tabs are
 * hidden from everyone else — presentation only: the API is what refuses, and
 * a viewer who reaches this route by hand still gets nothing but their own
 * password form, which is the one account operation their role owns.
 */
export default function UsersPage() {
  const t = useT();
  const { user } = useAuthStore();
  const isAdmin = user?.role === "admin";

  // Membership and provisioning keys are both per tenant, and an admin working
  // on one account usually wants both for the same tenant — so the choice is
  // made once for the page rather than once per tab.
  const { data: tenants = [] } = useTenants(Boolean(isAdmin));
  const [tenantId, setTenantId] = useState("");
  const selectedTenant = tenantId || tenants[0]?.tenant_id || "";

  const { data: users = [] } = useUsers(Boolean(isAdmin));
  const admins = users.filter((account) => account.role === "admin").length;
  const disabled = users.filter((account) => account.disabled).length;
  const passwordless = users.filter((account) => !account.has_password).length;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-sky-500/20 bg-sky-500/10 text-sky-500 shadow-sm">
            <UserCog className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">
              {t("page.users.title")}
            </h1>
            <p className="text-xs text-muted-foreground">{t("page.users.subtitle")}</p>
          </div>
        </div>
        {isAdmin ? <CreateUserDialog t={t} /> : null}
      </div>

      {isAdmin ? (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          <KpiCard
            label={t("users.kpi.accounts")}
            value={users.length}
            hint={t("users.kpi.accountsHint")}
            decorationColor="sky"
          />
          <KpiCard
            label={t("users.kpi.admins")}
            value={admins}
            hint={t("users.kpi.adminsHint")}
            decorationColor="amber"
          />
          <KpiCard
            label={t("users.kpi.disabled")}
            value={disabled}
            hint={t("users.kpi.disabledHint")}
            decorationColor="slate"
          />
          <KpiCard
            label={t("users.kpi.noPassword")}
            value={passwordless}
            hint={t("users.kpi.noPasswordHint")}
            decorationColor="rose"
          />
        </div>
      ) : null}

      <Tabs defaultValue={isAdmin ? "users" : "account"} className="space-y-4">
        <TabsList className="flex-wrap">
          {isAdmin ? (
            <>
              <TabsTrigger value="users">{t("users.tab.users")}</TabsTrigger>
              <TabsTrigger value="membership">{t("users.tab.membership")}</TabsTrigger>
              <TabsTrigger value="keys">{t("users.tab.keys")}</TabsTrigger>
              <TabsTrigger value="audit">{t("users.tab.audit")}</TabsTrigger>
            </>
          ) : null}
          <TabsTrigger value="account">{t("users.tab.account")}</TabsTrigger>
        </TabsList>

        {isAdmin ? (
          <>
            <TabsContent value="users">
              <UsersTab t={t} signedInAs={user?.username ?? ""} />
            </TabsContent>
            <TabsContent value="membership" className="space-y-4">
              <TenantPicker
                t={t}
                tenants={tenants.map((tenant) => ({
                  tenantId: tenant.tenant_id,
                  name: tenant.name,
                }))}
                value={selectedTenant}
                onChange={setTenantId}
              />
              <MembershipTab t={t} tenantId={selectedTenant} />
            </TabsContent>
            <TabsContent value="keys" className="space-y-4">
              <TenantPicker
                t={t}
                tenants={tenants.map((tenant) => ({
                  tenantId: tenant.tenant_id,
                  name: tenant.name,
                }))}
                value={selectedTenant}
                onChange={setTenantId}
              />
              <ProvisioningKeysTab t={t} tenantId={selectedTenant} />
            </TabsContent>
            <TabsContent value="audit">
              <AuditTab t={t} />
            </TabsContent>
          </>
        ) : null}

        <TabsContent value="account">
          <OwnPasswordTab t={t} username={user?.username ?? ""} role={user?.role ?? "viewer"} />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function TenantPicker({
  t,
  tenants,
  value,
  onChange,
}: {
  t: Translate;
  tenants: { tenantId: string; name: string }[];
  value: string;
  onChange: (tenantId: string) => void;
}) {
  if (tenants.length === 0) {
    return <p className="text-sm text-muted-foreground">{t("users.tenantPicker.none")}</p>;
  }
  return (
    <div className="flex items-center gap-2">
      <Label htmlFor="users-tenant">{t("users.tenantPicker")}</Label>
      <select
        id="users-tenant"
        className={SELECT_CLASS}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      >
        {tenants.map((tenant) => (
          <option key={tenant.tenantId} value={tenant.tenantId}>
            {tenant.name} ({tenant.tenantId})
          </option>
        ))}
      </select>
    </div>
  );
}

function CreateUserDialog({ t }: { t: Translate }) {
  const create = useCreateUser();
  const [open, setOpen] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmailValue] = useState("");
  const [role, setRole] = useState<Role>("viewer");

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      // Email travels in the same request: the API sets it in the account's
      // own transaction, so a refused address leaves no half-created user.
      await create.mutateAsync({
        username: username.trim(),
        password,
        role,
        email: email.trim() || null,
      });
      setOpen(false);
      setUsername("");
      setPassword("");
      setEmailValue("");
      setRole("viewer");
    } catch {
      // The mutations surface the refusal; the form keeps what was typed so a
      // rejected username or password can be corrected in place.
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button className="gap-2">
          <UserPlus className="h-4 w-4" />
          {t("users.action.create")}
        </Button>
      </DialogTrigger>
      <DialogContent>
        <form onSubmit={onSubmit}>
          <DialogHeader>
            <DialogTitle>{t("users.create.title")}</DialogTitle>
            <DialogDescription>{t("users.create.description")}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-1.5">
              <Label htmlFor="create-user-username">{t("users.create.username")}</Label>
              <Input
                id="create-user-username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                required
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="create-user-password">{t("users.create.password")}</Label>
              <Input
                id="create-user-password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="create-user-role">{t("users.create.role")}</Label>
              <select
                id="create-user-role"
                className={SELECT_CLASS}
                value={role}
                onChange={(event) => setRole(event.target.value as Role)}
              >
                {ROLES.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="create-user-email">{t("users.create.email")}</Label>
              <Input
                id="create-user-email"
                type="email"
                value={email}
                onChange={(event) => setEmailValue(event.target.value)}
              />
              <p className="text-xs text-muted-foreground">{t("users.create.emailHint")}</p>
            </div>
            {create.isError ? (
              <p className="text-sm text-destructive" role="alert">
                {create.error instanceof Error ? create.error.message : null}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              {t("users.action.cancel")}
            </Button>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? t("users.create.submitting") : t("users.create.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function UsersTab({ t, signedInAs }: { t: Translate; signedInAs: string }) {
  const { data = [], isLoading, error } = useUsers(true);
  const setRole = useSetUserRole();
  const setDisabled = useSetUserDisabled();
  const remove = useDeleteUser();
  const [resetTarget, setResetTarget] = useState<UserInfo | null>(null);
  const [emailTarget, setEmailTarget] = useState<UserInfo | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<UserInfo | null>(null);

  const columns = useMemo<ColumnDef<UserInfo>[]>(
    () => [
      {
        accessorKey: "username",
        header: t("users.col.username"),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <span className="font-mono font-semibold text-foreground">{row.original.username}</span>
            {row.original.username === signedInAs ? (
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                {t("users.you")}
              </span>
            ) : null}
            {row.original.sso_linked ? (
              <span className="rounded border border-border bg-muted px-1.5 py-0.5 text-[10px] font-semibold text-muted-foreground">
                {t("users.ssoLinked")}
              </span>
            ) : null}
          </div>
        ),
      },
      {
        accessorKey: "role",
        header: t("users.col.role"),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <StatusBadge value={row.original.role} map={USER_ROLE_STATUS} />
            <select
              aria-label={t("users.roleFor", { username: row.original.username })}
              className={SELECT_CLASS}
              value={row.original.role}
              disabled={setRole.isPending}
              onChange={(event) =>
                setRole.mutate({
                  username: row.original.username,
                  role: event.target.value as Role,
                })
              }
            >
              {ROLES.map((value) => (
                <option key={value} value={value}>
                  {value}
                </option>
              ))}
            </select>
          </div>
        ),
      },
      {
        accessorKey: "email",
        header: t("users.col.email"),
        cell: ({ row }) =>
          row.original.email ? (
            <div className="flex items-center gap-2">
              <span className="text-sm text-foreground">{row.original.email}</span>
              {row.original.email_verified ? (
                <span className="text-[10px] uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                  {t("users.emailVerified")}
                </span>
              ) : null}
            </div>
          ) : (
            <span className="text-sm text-muted-foreground">{t("users.emailUnset")}</span>
          ),
      },
      {
        id: "tenants",
        header: t("users.col.tenants"),
        enableSorting: false,
        cell: ({ row }) =>
          row.original.is_platform_admin ? (
            <span className="text-xs text-muted-foreground">{t("users.tenantsAdmin")}</span>
          ) : (row.original.tenants ?? []).length > 0 ? (
            <span className="flex flex-wrap gap-1">
              {(row.original.tenants ?? []).map((tenant) => (
                <span
                  key={tenant}
                  className="rounded-full border border-border bg-muted px-2 py-0.5 font-mono text-[10px] text-foreground"
                >
                  {tenant}
                </span>
              ))}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">{t("users.tenantsNone")}</span>
          ),
      },
      {
        id: "status",
        accessorFn: (account) => (account.disabled ? "disabled" : "active"),
        header: t("users.col.status"),
        cell: ({ row }) => (
          <div className="flex items-center gap-2">
            <StatusBadge
              value={row.original.disabled ? "disabled" : "active"}
              map={ACCOUNT_STATUS}
            />
            {row.original.has_password ? null : (
              <span className="text-[10px] uppercase tracking-wider text-amber-600 dark:text-amber-400">
                {t("users.noPassword")}
              </span>
            )}
          </div>
        ),
      },
      {
        accessorKey: "created_at",
        header: t("users.col.created"),
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {formatMoment(row.original.created_at)}
          </span>
        ),
      },
      {
        id: "actions",
        header: t("users.col.actions"),
        enableSorting: false,
        cell: ({ row }) => {
          const account = row.original;
          const isSelf = account.username === signedInAs;
          return (
            <div className="flex flex-wrap items-center gap-1.5">
              <Button variant="ghost" size="sm" onClick={() => setResetTarget(account)}>
                <RotateCcw className="mr-1.5 h-3.5 w-3.5" />
                {t("users.action.resetPassword")}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setEmailTarget(account)}>
                <Mail className="mr-1.5 h-3.5 w-3.5" />
                {t("users.action.setEmail")}
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={setDisabled.isPending}
                onClick={() =>
                  setDisabled.mutate({
                    username: account.username,
                    disabled: !account.disabled,
                  })
                }
              >
                {account.disabled ? t("users.action.enable") : t("users.action.disable")}
              </Button>
              {/* No delete for the signed-in account: the API refuses it with a
                  409, and offering a button whose only outcome is that refusal
                  is worse than not offering it. */}
              {isSelf ? (
                <span className="text-xs text-muted-foreground">{t("users.delete.selfHint")}</span>
              ) : (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-destructive hover:bg-destructive/10"
                  onClick={() => setDeleteTarget(account)}
                >
                  <Trash2 className="mr-1.5 h-3.5 w-3.5" />
                  {t("users.action.delete")}
                </Button>
              )}
            </div>
          );
        },
      },
    ],
    [t, signedInAs, setRole, setDisabled],
  );

  return (
    <>
      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        searchPlaceholder={t("users.search")}
        loadingMessage={t("users.loading")}
        emptyMessage={t("users.empty")}
        meta={t("users.meta", { total: data.length })}
      />

      <ResetPasswordDialog t={t} account={resetTarget} onClose={() => setResetTarget(null)} />
      <SetEmailDialog t={t} account={emailTarget} onClose={() => setEmailTarget(null)} />

      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(open) => !open && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("users.delete.title", { username: deleteTarget?.username ?? "" })}
            </AlertDialogTitle>
            <AlertDialogDescription>{t("users.delete.description")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("users.action.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-rose-600 text-white hover:bg-rose-500"
              onClick={() => {
                if (deleteTarget) remove.mutate(deleteTarget.username);
                setDeleteTarget(null);
              }}
            >
              {t("users.action.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

function ResetPasswordDialog({
  t,
  account,
  onClose,
}: {
  t: Translate;
  account: UserInfo | null;
  onClose: () => void;
}) {
  const reset = useResetUserPassword();
  const [password, setPassword] = useState("");

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!account) return;
    try {
      await reset.mutateAsync({ username: account.username, password });
      setPassword("");
      onClose();
    } catch {
      // Reported by the mutation; the typed password stays so a refusal about
      // its length can be answered without retyping the rest.
    }
  }

  return (
    <Dialog open={account !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent>
        <form onSubmit={onSubmit}>
          <DialogHeader>
            <DialogTitle>
              {t("users.reset.title", { username: account?.username ?? "" })}
            </DialogTitle>
            <DialogDescription>{t("users.reset.description")}</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5 py-4">
            <Label htmlFor="reset-user-password">{t("users.reset.password")}</Label>
            <Input
              id="reset-user-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              required
            />
            {reset.isError ? (
              <p className="text-sm text-destructive" role="alert">
                {reset.error instanceof Error ? reset.error.message : null}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t("users.action.cancel")}
            </Button>
            <Button type="submit" disabled={reset.isPending}>
              {t("users.reset.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function SetEmailDialog({
  t,
  account,
  onClose,
}: {
  t: Translate;
  account: UserInfo | null;
  onClose: () => void;
}) {
  const setEmail = useSetUserEmail();
  const [email, setEmailValue] = useState("");
  const [verified, setVerified] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);

  // Seed the form from the account the dialog was opened for, once per account
  // rather than on every render — otherwise typing would be overwritten.
  if (account && editing !== account.username) {
    setEditing(account.username);
    setEmailValue(account.email ?? "");
    setVerified(account.email_verified);
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!account) return;
    try {
      await setEmail.mutateAsync({
        username: account.username,
        email: email.trim() || null,
        verified,
      });
      setEditing(null);
      onClose();
    } catch {
      // Reported by the mutation.
    }
  }

  return (
    <Dialog
      open={account !== null}
      onOpenChange={(open) => {
        if (!open) {
          setEditing(null);
          onClose();
        }
      }}
    >
      <DialogContent>
        <form onSubmit={onSubmit}>
          <DialogHeader>
            <DialogTitle>
              {t("users.email.title", { username: account?.username ?? "" })}
            </DialogTitle>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-1.5">
              <Label htmlFor="set-user-email">{t("users.email.address")}</Label>
              <Input
                id="set-user-email"
                type="email"
                value={email}
                onChange={(event) => setEmailValue(event.target.value)}
              />
            </div>
            <div className="flex items-start gap-2">
              <input
                id="set-user-email-verified"
                type="checkbox"
                className="mt-1 h-4 w-4 rounded border-border"
                checked={verified}
                onChange={(event) => setVerified(event.target.checked)}
              />
              <div>
                <Label htmlFor="set-user-email-verified">{t("users.email.verified")}</Label>
                <p className="text-xs text-muted-foreground">{t("users.email.verifiedHint")}</p>
              </div>
            </div>
            {setEmail.isError ? (
              <p className="text-sm text-destructive" role="alert">
                {setEmail.error instanceof Error ? setEmail.error.message : null}
              </p>
            ) : null}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t("users.action.cancel")}
            </Button>
            <Button type="submit" disabled={setEmail.isPending}>
              {t("users.email.submit")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function MembershipTab({ t, tenantId }: { t: Translate; tenantId: string }) {
  const { data = [], isLoading, error } = useTenantMembers(tenantId, Boolean(tenantId));
  const grant = useGrantMembership(tenantId);
  const revoke = useRevokeMembership(tenantId);
  const [username, setUsername] = useState("");
  const [role, setRole] = useState<Role>("viewer");

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
            onChange={(event) => setRole(event.target.value as Role)}
          >
            {ROLES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <Button type="submit" disabled={grant.isPending || !tenantId}>
          {t("users.membership.grant")}
        </Button>
        <p className="text-xs text-muted-foreground sm:col-span-4">
          {t("users.membership.grantHint")}
        </p>
      </form>

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
              {data.map((member) => (
                <tr key={member.username} className="border-t border-border/60">
                  <td className="py-2 pr-4 font-mono font-medium">{member.username}</td>
                  <td className="py-2 pr-4">
                    <select
                      aria-label={t("users.roleFor", { username: member.username })}
                      className={SELECT_CLASS}
                      value={member.role}
                      disabled={grant.isPending}
                      onChange={(event) =>
                        grant.mutate({
                          username: member.username,
                          role: event.target.value as Role,
                        })
                      }
                    >
                      {ROLES.map((value) => (
                        <option key={value} value={value}>
                          {value}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td className="py-2 pr-4 tabular-nums">{formatMoment(member.created_at)}</td>
                  <td className="py-2 pr-4">{member.created_by ?? "—"}</td>
                  <td className="py-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={revoke.isPending}
                      onClick={() => revoke.mutate(member.username)}
                    >
                      {t("users.action.revoke")}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ProvisioningKeysTab({ t, tenantId }: { t: Translate; tenantId: string }) {
  const { data = [], isLoading, error } = useProvisioningKeys(tenantId, Boolean(tenantId));
  const revoke = useRevokeProvisioningKey(tenantId);

  return (
    <section className="space-y-4 rounded-xl border border-border bg-card p-5">
      <p className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
        <KeyRound className="h-4 w-4" />
        {t("users.keys.createHint")}
        <Link
          href="/agents"
          className="font-semibold text-primary underline-offset-2 hover:underline"
        >
          {t("users.keys.createLink")}
        </Link>
      </p>

      {error ? (
        <p className="text-sm text-rose-500" role="alert">
          {error instanceof Error ? error.message : null}
        </p>
      ) : null}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">{t("users.keys.loading")}</p>
      ) : data.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("users.keys.empty")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-muted-foreground">
              <tr>
                <th className="py-2 pr-4">{t("users.keys.label")}</th>
                <th className="py-2 pr-4">{t("users.keys.created")}</th>
                <th className="py-2 pr-4">{t("users.keys.lastUsed")}</th>
                <th className="py-2 pr-4">{t("users.keys.status")}</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {data.map((key) => (
                <tr key={key.key_id} className="border-t border-border/60">
                  <td className="py-2 pr-4">
                    <span className="font-medium">{key.label || "—"}</span>
                    <span className="ml-2 font-mono text-[10px] text-muted-foreground">
                      {key.key_id}
                    </span>
                  </td>
                  <td className="py-2 pr-4 tabular-nums">{formatMoment(key.created_at)}</td>
                  <td className="py-2 pr-4 tabular-nums">{formatMoment(key.last_used_at)}</td>
                  <td className="py-2 pr-4">
                    <StatusBadge
                      value={key.revoked_at ? "revoked" : "active"}
                      map={PROVISIONING_KEY_STATUS}
                    />
                  </td>
                  <td className="py-2">
                    {key.revoked_at ? null : (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={revoke.isPending}
                        onClick={() => revoke.mutate(key.key_id)}
                      >
                        {t("users.action.revoke")}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function AuditTab({ t }: { t: Translate }) {
  // The endpoint is newest-first and takes no sort, so the table offers none.
  const pagination = usePagination();
  const [outcome, setOutcome] = useState<AuthEventOutcome | "">("");
  const { data, isLoading, error } = useAuthEvents(true, pagination.params, outcome || undefined);
  const events = data?.items ?? [];

  const columns = useMemo<ColumnDef<AuthEventInfo>[]>(
    () => [
      {
        accessorKey: "occurred_at",
        header: t("users.audit.time"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {formatMoment(row.original.occurred_at)}
          </span>
        ),
      },
      {
        accessorKey: "username",
        header: t("users.audit.username"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs font-semibold text-foreground">
            {row.original.username || "—"}
          </span>
        ),
      },
      {
        accessorKey: "outcome",
        header: t("users.audit.outcome"),
        enableSorting: false,
        cell: ({ row }) => <StatusBadge value={row.original.outcome} map={AUTH_EVENT_OUTCOME} />,
      },
      {
        accessorKey: "client_ip",
        header: t("users.audit.ip"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.client_ip || "—"}
          </span>
        ),
      },
      {
        accessorKey: "reason",
        header: t("users.audit.reason"),
        enableSorting: false,
        cell: ({ row }) => <span className="text-xs">{row.original.reason || "—"}</span>,
      },
      {
        accessorKey: "detail",
        header: t("users.audit.detail"),
        enableSorting: false,
        cell: ({ row }) => (
          <span className="font-mono text-xs text-muted-foreground">
            {row.original.detail || "—"}
          </span>
        ),
      },
    ],
    [t],
  );

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">{t("users.audit.note")}</p>
      <DataTable
        columns={columns}
        data={events}
        isLoading={isLoading}
        error={error}
        searchPlaceholder={t("users.audit.search")}
        loadingMessage={t("users.audit.loading")}
        emptyMessage={t("users.audit.empty")}
        meta={t("users.audit.meta", { total: data?.total ?? 0 })}
        toolbar={
          <select
            aria-label={t("users.audit.outcome")}
            className={SELECT_CLASS}
            value={outcome}
            onChange={(event) => {
              setOutcome(event.target.value as AuthEventOutcome | "");
              pagination.reset();
            }}
          >
            <option value="">{t("users.audit.allOutcomes")}</option>
            {OUTCOMES.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        }
        serverPagination={{
          offset: pagination.offset,
          limit: pagination.limit,
          total: data?.total ?? 0,
          onOffsetChange: pagination.setOffset,
          search: pagination.search,
          onSearchChange: pagination.setSearch,
        }}
      />
    </div>
  );
}

function OwnPasswordTab({ t, username, role }: { t: Translate; username: string; role: Role }) {
  const change = useChangeOwnPassword();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const mismatch = confirm.length > 0 && next !== confirm;

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (mismatch) return;
    try {
      await change.mutateAsync({ current, next });
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch {
      // The mutation reports it — including the one status the API answers both
      // "wrong current password" and "account is gone" with.
    }
  }

  return (
    <section className="max-w-md space-y-4 rounded-xl border border-border bg-card p-5">
      <div className="space-y-1">
        <h2 className="text-lg font-semibold text-foreground">{t("users.account.title")}</h2>
        <p className="text-sm text-muted-foreground">
          {t("users.account.description", { username, role })}
        </p>
      </div>
      <form className="space-y-3" onSubmit={onSubmit}>
        <div className="grid gap-1.5">
          <Label htmlFor="own-password-current">{t("users.account.current")}</Label>
          <Input
            id="own-password-current"
            type="password"
            value={current}
            onChange={(event) => setCurrent(event.target.value)}
            required
          />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="own-password-new">{t("users.account.new")}</Label>
          <Input
            id="own-password-new"
            type="password"
            value={next}
            onChange={(event) => setNext(event.target.value)}
            required
          />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="own-password-confirm">{t("users.account.confirm")}</Label>
          <Input
            id="own-password-confirm"
            type="password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            required
          />
        </div>
        {mismatch ? (
          <p className="text-sm text-destructive" role="alert">
            {t("users.account.mismatch")}
          </p>
        ) : null}
        {change.isError ? (
          <p className="text-sm text-destructive" role="alert">
            {change.error instanceof Error ? change.error.message : null}
          </p>
        ) : null}
        <Button type="submit" disabled={change.isPending || mismatch}>
          {change.isPending ? t("users.account.submitting") : t("users.account.submit")}
        </Button>
      </form>
    </section>
  );
}
