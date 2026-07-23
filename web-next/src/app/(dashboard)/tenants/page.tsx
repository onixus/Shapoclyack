"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Building, Copy, Plus } from "lucide-react";
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
import { DataTable } from "@/components/data-table";
import { StatusBadge } from "@/components/status-badge";
import { useCreateTenantWithKey, useTenants } from "@/hooks/use-tenants";
import { type TenantInfo } from "@/lib/api";
import { TENANT_STATUS } from "@/lib/config/statuses";
import { useAuthStore } from "@/lib/auth-store";

export default function TenantsPage() {
  const { user, canOperate } = useAuthStore();
  const isAdmin = user?.role === "admin";
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [createdTenantId, setCreatedTenantId] = useState<string | null>(null);

  const { data = [], isLoading, error, isFetching } = useTenants(canOperate);
  const createMutation = useCreateTenantWithKey();

  const columns = useMemo<ColumnDef<TenantInfo>[]>(
    () => [
      {
        id: "name",
        accessorFn: (tenant) => `${tenant.name} ${tenant.tenant_id}`,
        header: "Tenant Name & ID",
        cell: ({ row }) => (
          <div>
            <p className="font-semibold text-slate-100">{row.original.name}</p>
            <p className="font-mono text-[10px] text-slate-400">{row.original.tenant_id}</p>
          </div>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => <StatusBadge value={row.original.status} map={TENANT_STATUS} />,
      },
      {
        accessorKey: "created_at",
        header: "Provisioned Date",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.created_at ? (
            <span className="font-mono text-xs text-slate-300">
              {format(new Date(row.original.created_at), "yyyy-MM-dd HH:mm")}
            </span>
          ) : (
            "—"
          ),
      },
    ],
    [],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-100">Tenants</h1>
        <p className="text-xs text-slate-400">
          Operator or admin role required to manage tenant organizations.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-sky-500/10 text-sky-400 border border-sky-500/20 shadow-md">
            <Building className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight text-slate-100">Multi-Tenant Management</h1>
            <p className="text-xs text-slate-400">
              MSSP customer environments and agent provisioning key registry.
              {isFetching ? " · Refreshing tenant list…" : ""}
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
              <Button className="gap-2 bg-sky-600 hover:bg-sky-500 text-white shadow-md">
                <Plus className="h-4 w-4" />
                Create New Tenant
              </Button>
            </DialogTrigger>
            <DialogContent className="bg-slate-900 border-slate-800 text-slate-100">
              <DialogHeader>
                <DialogTitle className="text-slate-100">Provision New Tenant</DialogTitle>
                <DialogDescription className="text-xs text-slate-400">
                  Creates a tenant environment and issues a one-time agent provisioning key.
                </DialogDescription>
              </DialogHeader>
              {!generatedKey ? (
                <div className="space-y-3 py-2">
                  <div className="grid gap-2">
                    <Label htmlFor="tenant-name" className="text-xs font-semibold text-slate-300">Tenant Name</Label>
                    <Input
                      id="tenant-name"
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                      placeholder="e.g. Contoso External Attack Surface"
                      className="bg-slate-950 border-slate-800 text-slate-100 placeholder:text-slate-600"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-3 rounded-lg border border-slate-800 bg-slate-950 p-3.5 text-xs">
                  <p className="font-semibold text-slate-200">
                    Provisioning key for <code className="text-sky-400">{createdTenantId}</code>
                  </p>
                  <code className="block break-all rounded bg-slate-900 border border-slate-800 p-2 font-mono text-[11px] text-amber-300">
                    {generatedKey}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="gap-2 border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800"
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
                    className="bg-sky-600 hover:bg-sky-500 text-white"
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
                  <Button type="button" className="bg-slate-800 text-slate-200 hover:bg-slate-700" onClick={() => setOpen(false)}>
                    Done
                  </Button>
                )}
              </DialogFooter>
            </DialogContent>
          </Dialog>
        ) : null}
      </div>

      <DataTable
        columns={columns}
        data={data}
        isLoading={isLoading}
        error={error}
        searchPlaceholder="Filter tenant names or IDs…"
        meta={`${data.length} tenant${data.length === 1 ? "" : "s"}`}
        loadingMessage="Retrieving tenant telemetry…"
        emptyMessage="No tenant organizations provisioned."
      />

      {!isAdmin ? (
        <p className="text-xs text-slate-400">
          Provisioning new tenants and issuing security keys requires admin privilege.
        </p>
      ) : null}
    </div>
  );
}

