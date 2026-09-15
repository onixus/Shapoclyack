"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Building, Copy, Plus, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
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
import { DataTable } from "@/components/data-table";
import { ScanScopePanel } from "@/components/scan-scope-panel";
import { StatusBadge } from "@/components/status-badge";
import { useCreateTenantWithKey, useTenantPosture, useTenants } from "@/hooks/use-tenants";
import { type TenantInfo, type TenantPosture } from "@/lib/api";
import { RISK_LEVEL_STATUS, TENANT_STATUS } from "@/lib/config/statuses";
import { useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useAuthStore } from "@/lib/auth-store";
import { holdsGlobalRole } from "@/lib/authz";

export default function TenantsPage() {
  const t = useT();
  const { user, selectTenant } = useAuthStore();
  // Both listings behind this page hang off `require_role` on the account's
  // global role — they resolve their own tenant set and are not scoped to one
  // tenant — so this is the one page that must *not* read the tenant role.
  const canList = holdsGlobalRole(user, "operator");
  const isAdmin = holdsGlobalRole(user, "admin");
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [createdTenantId, setCreatedTenantId] = useState<string | null>(null);
  // The tenant whose scan scope is being approved, or null for "the dialog is
  // closed". Held here rather than per row so closing it drops the editor
  // state with it (#226).
  const [scopeTenant, setScopeTenant] = useState<TenantInfo | null>(null);

  const { data = [], isLoading, error, isFetching } = useTenants(canList);
  const postureQuery = useTenantPosture(canList);
  const posture = postureQuery.data ?? [];
  const createMutation = useCreateTenantWithKey();
  const queryClient = useQueryClient();
  const router = useRouter();

  const postureColumns = useMemo<ColumnDef<TenantPosture>[]>(
    () => [
      {
        accessorKey: "name",
        header: t("col.customer"),
        cell: ({ row }) => (
          <div>
            <p className="font-semibold text-foreground">{row.original.name}</p>
            <p className="font-mono text-[10px] text-muted-foreground">{row.original.tenant_id}</p>
          </div>
        ),
      },
      {
        accessorKey: "estate_risk",
        header: t("col.estateRisk"),
        cell: ({ row }) =>
          row.original.estate_risk && row.original.estate_risk in RISK_LEVEL_STATUS ? (
            <StatusBadge value={row.original.estate_risk} map={RISK_LEVEL_STATUS} />
          ) : (
            <span className="text-xs text-muted-foreground">{row.original.open_total === 0 ? t("common.none") : t("common.unset")}</span>
          ),
      },
      {
        accessorKey: "open_total",
        header: t("col.open"),
        cell: ({ row }) => <span className="tabular-nums text-foreground">{row.original.open_total}</span>,
      },
      {
        accessorKey: "breached",
        header: t("col.sla"),
        cell: ({ row }) => <span className="tabular-nums text-foreground">{row.original.breached}</span>,
      },
      {
        accessorKey: "unassigned",
        header: t("col.unassigned"),
        cell: ({ row }) => <span className="tabular-nums text-foreground">{row.original.unassigned}</span>,
      },
      {
        accessorKey: "in_kev_open",
        header: t("col.kev"),
        cell: ({ row }) => <span className="tabular-nums text-foreground">{row.original.in_kev_open}</span>,
      },
      {
        accessorKey: "unowned_assets",
        header: t("col.unowned"),
        cell: ({ row }) => <span className="tabular-nums text-foreground">{row.original.unowned_assets}</span>,
      },
      {
        accessorKey: "declared_internet_assets",
        header: t("col.declaredInternet"),
        cell: ({ row }) => (
          <span className="tabular-nums text-foreground">{row.original.declared_internet_assets}</span>
        ),
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        cell: ({ row }) => (
          <Button
            variant="outline"
            size="sm"
            className="h-7 text-xs border-border"
            onClick={() => {
              selectTenant(row.original.tenant_id);
              queryClient.clear();
              router.push("/");
            }}
          >
            {t("common.open")}
          </Button>
        ),
      },
    ],
    [queryClient, router, selectTenant, t],
  );

  const columns = useMemo<ColumnDef<TenantInfo>[]>(
    () => [
      {
        id: "name",
        accessorFn: (tenant) => `${tenant.name} ${tenant.tenant_id}`,
        header: t("col.tenant"),
        cell: ({ row }) => (
          <div>
            <p className="font-semibold text-foreground">{row.original.name}</p>
            <p className="font-mono text-[10px] text-muted-foreground">{row.original.tenant_id}</p>
          </div>
        ),
      },
      {
        accessorKey: "status",
        header: t("col.status"),
        cell: ({ row }) => <StatusBadge value={row.original.status} map={TENANT_STATUS} />,
      },
      {
        accessorKey: "created_at",
        header: t("col.provisioned"),
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.created_at ? (
            <span className="font-mono text-xs text-foreground">
              {format(new Date(row.original.created_at), "yyyy-MM-dd HH:mm")}
            </span>
          ) : (
            "—"
          ),
      },
      ...(isAdmin
        ? [
            {
              id: "scan-scope",
              header: "",
              enableSorting: false,
              cell: ({ row }) => (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-border text-xs"
                  onClick={() => setScopeTenant(row.original)}
                >
                  <ShieldCheck className="h-3.5 w-3.5" />
                  {t("scanScope.action")}
                </Button>
              ),
            } satisfies ColumnDef<TenantInfo>,
          ]
        : []),
    ],
    [isAdmin, t],
  );

  if (!canList) {
    return (
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">{t("page.tenants.title")}</h1>
        <p className="text-xs text-muted-foreground">
          {t("page.tenants.denied")}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-600 dark:text-sky-400 border border-sky-500/20 shadow-md">
            <Building className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-foreground">{t("page.tenants.title")}</h1>
            <p className="text-xs text-muted-foreground">
              {t("page.tenants.subtitle")}
              {isFetching ? t("common.refreshing") : ""}
            </p>
          </div>
        </div>
        {isAdmin ? (
          <Dialog
            open={open}
            onOpenChange={(next) => {
              setOpen(next);
              if (!next) {
                setName("");
                setGeneratedKey(null);
                setCreatedTenantId(null);
              }
            }}
          >
            <DialogTrigger asChild>
              <Button className="gap-2 bg-sky-600 hover:bg-sky-500 text-foreground shadow-md">
                <Plus className="h-4 w-4" />
                {t("common.createTenant")}
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-card border-border text-foreground">
              <DialogHeader>
                <DialogTitle className="text-foreground">Provision New Tenant</DialogTitle>
                <DialogDescription className="text-xs text-muted-foreground">
                  Creates a tenant environment and issues a one-time agent provisioning key.
                </DialogDescription>
              </DialogHeader>
              {!generatedKey ? (
                <div className="space-y-3 py-2">
                  <div className="grid gap-2">
                    <Label htmlFor="tenant-name" className="text-xs font-semibold text-foreground">Tenant Name</Label>
                    <Input
                      id="tenant-name"
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                      placeholder="e.g. Contoso External Attack Surface"
                      className="bg-muted border-border text-foreground placeholder:text-muted-foreground"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-3 rounded-lg border border-border bg-muted p-3.5 text-xs">
                  <p className="font-semibold text-foreground">
                    Provisioning key for <code className="text-sky-600 dark:text-sky-400">{createdTenantId}</code>
                  </p>
                  <code className="block break-all rounded bg-card border border-border p-2 font-mono text-[11px] text-amber-600 dark:text-amber-300">
                    {generatedKey}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="gap-2 border-border bg-card text-foreground hover:bg-muted"
                    onClick={() => void navigator.clipboard.writeText(generatedKey)}
                  >
                    <Copy className="h-3.5 w-3.5" />
                    Copy Provisioning Key
                  </Button>
                </div>
              )}
              <DialogFooter>
                {!generatedKey ? (
                  <Button
                    type="button"
                    className="bg-sky-600 hover:bg-sky-500 text-foreground"
                    onClick={() =>
                      createMutation.mutate(name.trim(), {
                        onSuccess: ({ tenant, key }) => {
                          setCreatedTenantId(tenant.tenant_id);
                          setGeneratedKey(key.key || null);
                        },
                      })
                    }
                    disabled={!name.trim() || createMutation.isPending}
                  >
                    {createMutation.isPending ? "Generating…" : "Generate Provisioning Key"}
                  </Button>
                ) : (
                  <Button type="button" className="bg-muted text-foreground hover:bg-slate-700" onClick={() => setOpen(false)}>
                    Done
                  </Button>
                )}
              </DialogFooter>
            </DialogContent>
          </Dialog>
        ) : null}
      </div>

      <div className="space-y-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Customer posture
        </p>
        <p className="text-[11px] text-muted-foreground">
          Worst open NIST risk first. Declared internet is operator-set exposure, not a scan
          measurement.
        </p>
        <DataTable
          columns={postureColumns}
          data={posture}
          isLoading={postureQuery.isLoading}
          error={postureQuery.error}
          searchPlaceholder={t("search.tenants")}
          meta={t("meta.customers", { count: posture.length })}
          loadingMessage={t("loading.tenantPosture")}
          emptyMessage={t("empty.tenantsInScope")}
        />
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        searchPlaceholder={t("search.tenants")}
        meta={t("meta.tenants", { count: data.length })}
        loadingMessage={t("loading.tenantTelemetry")}
        emptyMessage={t("empty.tenants")}
      />

      <Dialog open={scopeTenant !== null} onOpenChange={(next) => (next ? null : setScopeTenant(null))}>
        <DialogContent className="max-w-4xl border-border bg-card text-foreground">
          <DialogHeader>
            <DialogTitle className="text-foreground">
              {t("scanScope.dialogTitle", { tenant: scopeTenant?.name ?? "" })}
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              {t("scanScope.dialogDescription")}
            </DialogDescription>
          </DialogHeader>
          {scopeTenant ? (
            <div className="max-h-[70vh] overflow-y-auto pr-1">
              <ScanScopePanel tenantId={scopeTenant.tenant_id} />
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      {!isAdmin ? (
        <p className="text-xs text-muted-foreground">
          Provisioning new tenants and issuing security keys requires admin privilege.
          {" "}
          {t("scanScope.denied")}
        </p>
      ) : null}
    </div>
  );
}

