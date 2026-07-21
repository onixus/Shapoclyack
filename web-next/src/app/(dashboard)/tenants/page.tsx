"use client";

import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import { format } from "date-fns";
import { Copy, Plus } from "lucide-react";
import { Badge } from "@/components/ui/badge";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { createProvisioningKey, createTenant, fetchTenants, type TenantInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";

function statusBadge(status: TenantInfo["status"]) {
  if (status === "active") {
    return <Badge className="bg-emerald-600 hover:bg-emerald-600">active</Badge>;
  }
  return <Badge variant="secondary">disabled</Badge>;
}

export default function TenantsPage() {
  const { user, canOperate } = useAuthStore();
  const isAdmin = user?.role === "admin";
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [createdTenantId, setCreatedTenantId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const {
    data = [],
    isLoading,
    error,
    isFetching,
  } = useQuery({
    queryKey: ["tenants"],
    queryFn: fetchTenants,
    enabled: canOperate,
  });

  const createMutation = useMutation({
    mutationFn: async (tenantName: string) => {
      const tenant = await createTenant({ name: tenantName });
      const key = await createProvisioningKey(tenant.tenant_id, "web-next");
      return { tenant, key };
    },
    onSuccess: async ({ tenant, key }) => {
      setCreatedTenantId(tenant.tenant_id);
      setGeneratedKey(key.key || null);
      setFormError(null);
      await queryClient.invalidateQueries({ queryKey: ["tenants"] });
    },
    onError: (err) => {
      setFormError(err instanceof Error ? err.message : "Failed to create tenant");
    },
  });

  const columns = useMemo<ColumnDef<TenantInfo>[]>(
    () => [
      {
        accessorKey: "name",
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
        cell: ({ row }) => statusBadge(row.original.status),
      },
      {
        accessorKey: "created_at",
        header: "Created",
        cell: ({ row }) =>
          row.original.created_at
            ? format(new Date(row.original.created_at), "yyyy-MM-dd HH:mm")
            : "—",
      },
    ],
    [],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return data;
    return data.filter(
      (t) => t.name.toLowerCase().includes(q) || t.tenant_id.toLowerCase().includes(q),
    );
  }, [data, query]);

  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

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
                setFormError(null);
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
                  <label className="grid gap-2 text-sm font-medium">
                    Tenant name
                    <Input
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                      placeholder="e.g. Contoso External Attack Surface"
                    />
                  </label>
                  {formError ? <p className="text-sm text-rose-600">{formError}</p> : null}
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
                    onClick={() => createMutation.mutate(name.trim())}
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

      <div className="flex items-center gap-3">
        <Input
          className="max-w-sm"
          placeholder="Filter tenants…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <p className="text-xs text-muted-foreground">{filtered.length} tenants</p>
      </div>

      {error ? (
        <p className="text-sm text-rose-600">
          {error instanceof Error ? error.message : "Failed to load tenants"}
        </p>
      ) : null}

      <div className="rounded-lg border bg-white">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead key={header.id}>
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-muted-foreground">
                  Loading tenants…
                </TableCell>
              </TableRow>
            ) : table.getRowModel().rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={columns.length} className="text-muted-foreground">
                  No tenants yet.
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => (
                <TableRow key={row.id}>
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      {!isAdmin ? (
        <p className="text-xs text-muted-foreground">
          Creating tenants and provisioning keys requires the admin role.
        </p>
      ) : null}
    </div>
  );
}
