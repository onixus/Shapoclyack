"use client";

import { useMemo, useState } from "react";
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
import { MOCK_TENANTS, type Tenant } from "@/lib/mock-data";

function statusBadge(status: Tenant["status"]) {
  if (status === "active") return <Badge className="bg-emerald-600 hover:bg-emerald-600">active</Badge>;
  if (status === "paused") return <Badge variant="secondary">paused</Badge>;
  return <Badge variant="outline">provisioning</Badge>;
}

function makeProvisioningKey(name: string) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "tenant";
  const rand = Math.random().toString(36).slice(2, 10);
  return `pk_${slug}_${rand}`;
}

export default function TenantsPage() {
  const [tenants, setTenants] = useState(MOCK_TENANTS);
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [generatedKey, setGeneratedKey] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  const columns = useMemo<ColumnDef<Tenant>[]>(
    () => [
      {
        accessorKey: "name",
        header: "Tenant Name",
        cell: ({ row }) => (
          <div>
            <p className="font-medium text-slate-900">{row.original.name}</p>
            <p className="text-xs text-muted-foreground">{row.original.id}</p>
          </div>
        ),
      },
      {
        accessorKey: "status",
        header: "Status",
        cell: ({ row }) => statusBadge(row.original.status),
      },
      {
        accessorKey: "agentCount",
        header: "Agent Count",
        cell: ({ getValue }) => <span className="tabular-nums">{String(getValue())}</span>,
      },
      {
        accessorKey: "assetCount",
        header: "Assets",
        cell: ({ getValue }) => (
          <span className="tabular-nums">{Number(getValue()).toLocaleString()}</span>
        ),
      },
      {
        id: "actions",
        header: "Actions",
        cell: ({ row }) => (
          <div className="flex gap-2">
            <Button variant="outline" size="sm">
              View
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={() =>
                setTenants((prev) =>
                  prev.map((t) =>
                    t.id === row.original.id
                      ? {
                          ...t,
                          status: t.status === "paused" ? "active" : "paused",
                        }
                      : t,
                  ),
                )
              }
            >
              {row.original.status === "paused" ? "Resume" : "Pause"}
            </Button>
          </div>
        ),
      },
    ],
    [],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return tenants;
    return tenants.filter(
      (t) => t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q),
    );
  }, [tenants, query]);

  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  function createTenant() {
    const key = makeProvisioningKey(name);
    const id = `ten_${Date.now().toString(36)}`;
    setTenants((prev) => [
      {
        id,
        name: name.trim() || "Untitled tenant",
        status: "provisioning",
        agentCount: 0,
        assetCount: 0,
        createdAt: new Date().toISOString(),
      },
      ...prev,
    ]);
    setGeneratedKey(key);
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">Tenants</h1>
          <p className="text-sm text-muted-foreground">
            MSSP isolation units and provisioning keys (Phase 2 roadmap).
          </p>
        </div>
        <Dialog
          open={open}
          onOpenChange={(next) => {
            setOpen(next);
            if (!next) {
              setName("");
              setGeneratedKey(null);
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
                Creates a tenant record and generates a one-time Provisioning Key for agent
                enrollment.
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
              </div>
            ) : (
              <div className="space-y-3 rounded-md border bg-slate-50 p-3 text-sm">
                <p className="font-medium text-slate-900">Provisioning Key generated</p>
                <code className="block break-all rounded bg-white p-2 text-xs">{generatedKey}</code>
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
                <Button type="button" onClick={createTenant} disabled={!name.trim()}>
                  Generate Provisioning Key
                </Button>
              ) : (
                <Button type="button" onClick={() => setOpen(false)}>
                  Done
                </Button>
              )}
            </DialogFooter>
          </DialogContent>
        </Dialog>
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
            {table.getRowModel().rows.map((row) => (
              <TableRow key={row.id}>
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <p className="text-xs text-muted-foreground">
        Created sample:{" "}
        {format(new Date(tenants[0]?.createdAt || Date.now()), "yyyy-MM-dd HH:mm")} UTC
      </p>
    </div>
  );
}
