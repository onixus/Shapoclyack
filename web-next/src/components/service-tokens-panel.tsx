"use client";

import { FormEvent, useState } from "react";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  useCreateServiceToken,
  useRevokeServiceToken,
  useServiceTokens,
} from "@/hooks/use-service-tokens";
import { type Role, type ServiceTokenInfo } from "@/lib/api";

const ROLES: Role[] = ["viewer", "operator", "admin"];

function formatDate(value: string | null) {
  if (!value) return "—";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "—" : parsed.toISOString().slice(0, 10);
}

/**
 * List, issue and revoke this tenant's service tokens (ROADMAP Track E).
 *
 * The created token is shown once, in a panel that says so, because that is
 * the truth of the API: only a hash is stored and the plaintext is
 * unrecoverable the moment this component drops it. It is never written to
 * localStorage and never put in a toast — both outlive the moment the admin is
 * looking at the screen.
 */
export function ServiceTokensPanel({
  tenantId,
  isAdmin,
}: {
  tenantId: string;
  isAdmin: boolean;
}) {
  const { data = [], isLoading, error } = useServiceTokens(tenantId, isAdmin);
  const createMutation = useCreateServiceToken(tenantId);
  const revokeMutation = useRevokeServiceToken(tenantId);

  const [name, setName] = useState("");
  const [scopes, setScopes] = useState("runs:read");
  const [role, setRole] = useState<Role>("viewer");
  const [issued, setIssued] = useState<ServiceTokenInfo | null>(null);

  if (!isAdmin) {
    return (
      <p className="text-sm text-muted-foreground">
        Service tokens are managed by a platform administrator.
      </p>
    );
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    const parsed = scopes
      .split(/[\s,]+/)
      .map((scope) => scope.trim())
      .filter(Boolean);
    if (!name.trim() || parsed.length === 0) return;
    try {
      const created = await createMutation.mutateAsync({ name: name.trim(), scopes: parsed, role });
      setIssued(created);
      setName("");
    } catch {
      // The mutation records the failure; awaiting it without a catch would
      // additionally surface an unhandled rejection. The form keeps what the
      // operator typed so a rejected scope can be corrected in place.
    }
  }

  return (
    <section className="space-y-6">
      <form className="grid gap-3 sm:grid-cols-4 sm:items-end" onSubmit={onSubmit}>
        <div className="grid gap-1.5">
          <Label htmlFor="service-token-name">Name</Label>
          <Input
            id="service-token-name"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="ci-pipeline"
            required
          />
        </div>
        <div className="grid gap-1.5 sm:col-span-2">
          <Label htmlFor="service-token-scopes">Scopes</Label>
          <Input
            id="service-token-scopes"
            value={scopes}
            onChange={(event) => setScopes(event.target.value)}
            placeholder="runs:read vulnerabilities:read"
          />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="service-token-role">Role</Label>
          <select
            id="service-token-role"
            className="h-9 rounded-md border border-input bg-background px-2 text-sm"
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
        <Button type="submit" className="sm:col-span-4" disabled={createMutation.isPending}>
          <KeyRound className="mr-2 h-4 w-4" />
          {createMutation.isPending ? "Issuing…" : "Issue token"}
        </Button>
      </form>

      {issued?.token ? (
        <div
          role="alert"
          className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4"
        >
          <p className="text-sm font-semibold">Copy this token now — it is shown only once.</p>
          <code className="block break-all rounded bg-background/60 p-2 font-mono text-xs">
            {issued.token}
          </code>
          <Button variant="outline" size="sm" onClick={() => setIssued(null)}>
            I have copied it
          </Button>
        </div>
      ) : null}

      {createMutation.isError ? (
        <p className="text-sm text-destructive" role="alert">
          {createMutation.error instanceof Error
            ? createMutation.error.message
            : "Failed to create the service token"}
        </p>
      ) : null}
      {error ? (
        <p className="text-sm text-rose-500">
          {error instanceof Error ? error.message : "Failed to load service tokens"}
        </p>
      ) : null}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading service tokens…</p>
      ) : data.length === 0 ? (
        <p className="text-sm text-muted-foreground">No service tokens issued for this tenant.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-muted-foreground">
              <tr>
                <th className="py-2 pr-4">Name</th>
                <th className="py-2 pr-4">Prefix</th>
                <th className="py-2 pr-4">Role</th>
                <th className="py-2 pr-4">Scopes</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2 pr-4">Expires</th>
                <th className="py-2 pr-4">Last used</th>
                <th className="py-2" />
              </tr>
            </thead>
            <tbody>
              {data.map((token) => (
                <tr key={token.token_id} className="border-t border-border/60">
                  <td className="py-2 pr-4 font-medium">{token.name}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{token.token_prefix}</td>
                  <td className="py-2 pr-4">{token.role}</td>
                  <td className="py-2 pr-4 font-mono text-xs">{token.scopes.join(" ")}</td>
                  <td className="py-2 pr-4">{token.status}</td>
                  <td className="py-2 pr-4 tabular-nums">{formatDate(token.expires_at)}</td>
                  <td className="py-2 pr-4 tabular-nums">{formatDate(token.last_used_at)}</td>
                  <td className="py-2">
                    {token.status === "active" ? (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => revokeMutation.mutate(token.token_id)}
                        disabled={revokeMutation.isPending}
                      >
                        Revoke
                      </Button>
                    ) : null}
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
