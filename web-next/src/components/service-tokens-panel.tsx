"use client";

import { FormEvent, useState } from "react";
import { useT } from "@/lib/i18n";
import { KeyRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Field, FieldGrid, fieldHintId } from "@/components/ui/field";
import {
  useCreateServiceToken,
  useRevokeServiceToken,
  useRotateServiceToken,
  useServiceTokens,
} from "@/hooks/use-service-tokens";
import { type Role, type ServiceTokenInfo } from "@/lib/api";
import { useAuthStore } from "@/lib/auth-store";
import { tenantRank } from "@/lib/authz";

/** What a service token's role may be: the three ranked ones, which is what
 * `api/services/service_tokens.py` accepts — a token is a credential, not a
 * separation of duties, so the specialist roles are not issuable. Their ranks
 * are here because the ceiling below compares against the issuer's. */
const TOKEN_ROLES: { role: Role; rank: number }[] = [
  { role: "viewer", rank: 1 },
  { role: "operator", rank: 2 },
  { role: "admin", rank: 3 },
];

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
 *
 * `canManage` is `tenant.credential.manage` in the selected tenant (#318), not
 * the global admin role: the tenant's own admin and a `token-admin` hold it,
 * and telling either of them that their credentials "are managed by a platform
 * administrator" was false the moment tenant self-service landed.
 */
export function ServiceTokensPanel({
  tenantId,
  canManage,
}: {
  tenantId: string;
  canManage: boolean;
}) {
  const t = useT();
  const { data = [], isLoading, error } = useServiceTokens(tenantId, canManage);
  const createMutation = useCreateServiceToken(tenantId);
  const revokeMutation = useRevokeServiceToken(tenantId);
  const rotateMutation = useRotateServiceToken(tenantId);
  // The issuance ceiling, shown rather than discovered (#318 review). A
  // `token-admin` holds `tenant.credential.manage` at rank 1, so the server
  // refuses the `operator` and `admin` options with a 403 — offering them was
  // offering a choice that could not work. The platform admin has no ceiling,
  // for the reason the service gives: it already holds everything everywhere.
  const user = useAuthStore((state) => state.user);
  const ceiling = user?.is_platform_admin ? 3 : tenantRank(user);
  const issuable = TOKEN_ROLES.filter((entry) => entry.rank <= ceiling);

  const [name, setName] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [noticeDays, setNoticeDays] = useState(7);
  const [graceSeconds, setGraceSeconds] = useState(3600);
  const [scopes, setScopes] = useState("runs:read");
  const [role, setRole] = useState<Role>("viewer");
  const [issued, setIssued] = useState<ServiceTokenInfo | null>(null);

  if (!canManage) {
    return (
      <p className="text-sm text-muted-foreground">
        Managing this tenant&apos;s service tokens needs the <code>tenant.credential.manage</code>{" "}
        permission — its admin or a token-admin.
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
      const created = await createMutation.mutateAsync({
        name: name.trim(),
        scopes: parsed,
        role,
        allowed_cidrs: cidrs.split(/[\s,]+/).filter(Boolean),
        expiry_notice_days: noticeDays,
      });
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
      <form className="space-y-4" onSubmit={onSubmit}>
        <FieldGrid cols={3}>
          <Field label="Name" htmlFor="service-token-name">
            <Input
              id="service-token-name"
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="ci-pipeline"
              required
            />
          </Field>
          <Field label={t("ui.scopes")} htmlFor="service-token-scopes" className="lg:col-span-2">
            <Input
              id="service-token-scopes"
              value={scopes}
              onChange={(event) => setScopes(event.target.value)}
              placeholder="runs:read vulnerabilities:read"
            />
          </Field>
          <Field
            label="Role"
            htmlFor="service-token-role"
            hint={
              issuable.length < TOKEN_ROLES.length
                ? "A token cannot be stronger than the hand issuing it, so your role in this tenant caps this list."
                : undefined
            }
          >
            <select
              id="service-token-role"
              aria-describedby={fieldHintId("service-token-role")}
              className="h-9 w-full rounded-md border border-control bg-background px-3 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
              value={role}
              onChange={(event) => setRole(event.target.value as Role)}
            >
              {issuable.map((entry) => (
                <option key={entry.role} value={entry.role}>
                  {entry.role}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label="Allowed source networks"
            htmlFor="service-token-cidrs"
            hint="Leave empty to allow every source address."
          >
            <Input
              id="service-token-cidrs"
              aria-describedby={fieldHintId("service-token-cidrs")}
              value={cidrs}
              onChange={(event) => setCidrs(event.target.value)}
              placeholder="192.0.2.0/24, 2001:db8::/32"
            />
          </Field>
          <Field label="Expiry notice (days)" htmlFor="service-token-notice">
            <Input
              id="service-token-notice"
              type="number"
              min={0}
              max={3650}
              value={noticeDays}
              onChange={(event) => setNoticeDays(Number(event.target.value))}
            />
          </Field>
        </FieldGrid>
        <Button type="submit" disabled={createMutation.isPending}>
          <KeyRound className="mr-2 h-4 w-4" />
          {createMutation.isPending ? "Issuing…" : "Issue token"}
        </Button>
      </form>

      <FieldGrid cols={3}>
        <Field
          label="Rotation overlap (seconds)"
          htmlFor="service-token-grace"
          hint="The previous token works during this window. Zero ends its access immediately."
        >
          <Input
            id="service-token-grace"
            aria-describedby={fieldHintId("service-token-grace")}
            type="number"
            min={0}
            max={604800}
            value={graceSeconds}
            onChange={(event) => setGraceSeconds(Number(event.target.value))}
          />
        </Field>
      </FieldGrid>

      {issued?.token ? (
        <div
          role="alert"
          className="space-y-2 rounded-lg border border-amber-500/40 bg-amber-500/10 p-4"
        >
          <p className="text-sm font-semibold">{t("ui.copyThisTokenNowItIs")}</p>
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
        <p className="text-sm text-muted-foreground">{t("ui.noServiceTokensIssuedForThis")}</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-muted text-xs text-muted-foreground font-medium">
              <tr>
                <th className="py-2 pr-4">Name</th>
                <th className="py-2 pr-4">{t("ui.prefix")}</th>
                <th className="py-2 pr-4">Role</th>
                <th className="py-2 pr-4">{t("ui.scopes")}</th>
                <th className="py-2 pr-4">{t("ui.status")}</th>
                <th className="py-2 pr-4">Source networks</th>
                <th className="py-2 pr-4">{t("ui.expires")}</th>
                <th className="py-2 pr-4">{t("ui.lastUsed")}</th>
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
                  <td className="py-2 pr-4">
                    {token.status}
                    {token.rotated_from_id ? (
                      <span className="block text-xs">Replaces {token.rotated_from_id}</span>
                    ) : null}
                    {token.rotation_expires_at ? (
                      <span className="block text-xs">
                        Overlap ends {new Date(token.rotation_expires_at).toISOString()}
                      </span>
                    ) : null}
                  </td>
                  <td className="py-2 pr-4 text-xs">
                    {token.allowed_cidrs?.join(", ") || "Any source"}
                  </td>
                  <td className="py-2 pr-4 tabular-nums">{formatDate(token.expires_at)}</td>
                  <td className="py-2 pr-4 tabular-nums">{formatDate(token.last_used_at)}</td>
                  <td className="py-2">
                    {token.status === "active" && !token.rotation_expires_at ? (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={
                          rotateMutation.isPending ||
                          !Number.isInteger(graceSeconds) ||
                          graceSeconds < 0 ||
                          graceSeconds > 604800
                        }
                        onClick={async () => {
                          try {
                            setIssued(
                              await rotateMutation.mutateAsync({
                                tokenId: token.token_id,
                                graceSeconds,
                              }),
                            );
                          } catch {
                            /* The mutation surfaces the error. */
                          }
                        }}
                      >
                        Rotate
                      </Button>
                    ) : null}
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
