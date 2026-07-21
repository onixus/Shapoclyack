"use client";

import { useMemo, useState } from "react";
import { type ColumnDef } from "@tanstack/react-table";
import { format } from "date-fns";
import { Copy, Plus } from "lucide-react";
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
        header: "Tenant Name",
        cell: ({ row }) => (
          <div>
            <p className="font-medium text-slate-900">{row.original.name}</p>
            <p className="text-xs text-muted-foreground">{row.original.tenant_id}</p>
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
        header: "Created",
        sortingFn: "datetime",
        cell: ({ row }) =>
          row.original.created_at
            ? format(new Date(row.original.created_at), "yyyy-MM-dd HH:mm")
            : "—",
      },
    ],
    [],
  );

  if (!canOperate) {
    return (
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Tenants</h1>
        <p className="text-sm text-muted-foreground">
          Operator or admin role required to list tenants.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Tenants</h1>
          <p className="text-sm text-muted-foreground">
            Live MSSP tenants from <code className="text-xs">GET /api/tenants</code>
            {isFetching ? " · refreshing…" : ""}
          </p>
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
              <Button className="gap-2">
                <Plus className="h-4 w-4" />
                Create New Tenant
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Create New Tenant</DialogTitle>
                <DialogDescription>
                  Creates a tenant via the API and issues a one-time provisioning key.
                </DialogDescription>
              </DialogHeader>
              {!generatedKey ? (
                <div className="space-y-3 py-2">
                  <div className="grid gap-2">
                    <Label htmlFor="tenant-name">Tenant name</Label>
                    <Input
                      id="tenant-name"
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                      placeholder="e.g. Contoso External Attack Surface"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-3 rounded-md border bg-slate-50 p-3 text-sm">
                  <p className="font-medium text-slate-900">
                    Provisioning key for <code>{createdTenantId}</code>
                  </p>
                  <code className="block break-all rounded bg-white p-2 text-xs">
                    {generatedKey}
                  </code>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="gap-2"
                    onClick={() => void navigator.clipboard.writeText(generatedKey)}
                  >
                    <Copy className="h-3.5 w-3.5" />
                    Copy key
                  </Button>
                </div>
              )}
              <DialogFooter>
                {!generatedKey ? (
                  <Button
                    type="button"
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
                    {createMutation.isPending ? "Creating…" : "Generate Provisioning Key"}
                  </Button>
                ) : (
                  <Button type="button" onClick={() => setOpen(false)}>
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
        searchPlaceholder="Filter tenants…"
        meta={`${data.length} tenant${data.length === 1 ? "" : "s"}`}
        loadingMessage="Loading tenants…"
        emptyMessage="No tenants yet."
      />

      {!isAdmin ? (
        <p className="text-xs text-muted-foreground">
          Creating tenants and provisioning keys requires the admin role.
        </p>
      ) : null}
    </div>
  );
}
