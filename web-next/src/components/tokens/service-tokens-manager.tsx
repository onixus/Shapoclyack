"use client";

import { useEffect, useState } from "react";
import {
  CreateServiceTokenResponse,
  createServiceToken,
  fetchAvailableScopes,
  fetchServiceTokens,
  revokeServiceToken,
  ServiceTokenMetadata,
} from "@/lib/api";
import { useT } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function ServiceTokensManager() {
  const t = useT();
  const [tokens, setTokens] = useState<ServiceTokenMetadata[]>([]);
  const [scopesList, setScopesList] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Create Modal State
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState<"viewer" | "operator" | "admin">("operator");
  const [selectedScopes, setSelectedScopes] = useState<string[]>(["scans:read", "assets:read"]);
  const [expiryDays, setExpiryDays] = useState<number | null>(90);
  const [creating, setCreating] = useState(false);

  // Secret Modal State
  const [newSecret, setNewSecret] = useState<CreateServiceTokenResponse | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    loadData();
  }, []);

  async function loadData() {
    setLoading(true);
    setError(null);
    try {
      const [tokenData, availableScopes] = await Promise.all([
        fetchServiceTokens(),
        fetchAvailableScopes().catch(() => [
          "scans:read",
          "scans:write",
          "assets:read",
          "assets:write",
          "vulns:read",
          "vulns:write",
          "leaks:read",
          "tokens:manage",
          "system:read",
          "reports:read",
        ]),
      ]);
      setTokens(tokenData);
      setScopesList(availableScopes);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load service tokens");
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setCreating(true);
    setError(null);
    try {
      const created = await createServiceToken({
        name: name.trim(),
        role,
        scopes: selectedScopes,
        expires_days: expiryDays,
      });
      setNewSecret(created);
      setCreateOpen(false);
      setName("");
      setSelectedScopes(["scans:read", "assets:read"]);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create service token");
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(tokenId: string) {
    if (!window.confirm(t("tokens.revokeConfirm"))) return;
    try {
      await revokeServiceToken(tokenId);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke token");
    }
  }

  function toggleScope(scope: string) {
    setSelectedScopes((prev) =>
      prev.includes(scope) ? prev.filter((s) => s !== scope) : [...prev, scope],
    );
  }

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
        <div>
          <h2 className="text-xl font-semibold tracking-tight text-slate-100">{t("tokens.title")}</h2>
          <p className="text-sm text-slate-400">{t("tokens.subtitle")}</p>
        </div>
        <Button
          onClick={() => setCreateOpen(true)}
          className="bg-sky-600 hover:bg-sky-500 text-white"
        >
          {t("tokens.createBtn")}
        </Button>
      </div>

      {error ? (
        <div className="rounded-lg border border-rose-800/50 bg-rose-950/40 p-4 text-sm text-rose-300">
          {error}
        </div>
      ) : null}

      {/* Tokens Table */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 backdrop-blur">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="border-b border-slate-800 bg-slate-950/50 text-xs uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-4 py-3">{t("tokens.name")}</th>
              <th className="px-4 py-3">Prefix</th>
              <th className="px-4 py-3">{t("tokens.role")}</th>
              <th className="px-4 py-3">{t("tokens.scopes")}</th>
              <th className="px-4 py-3">{t("tokens.status")}</th>
              <th className="px-4 py-3">{t("tokens.expiry")}</th>
              <th className="px-4 py-3">{t("tokens.lastUsed")}</th>
              <th className="px-4 py-3 text-right">{t("common.actions")}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {loading ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                  {t("common.loading")}
                </td>
              </tr>
            ) : tokens.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                  {t("table.empty")}
                </td>
              </tr>
            ) : (
              tokens.map((tok) => {
                const isRevoked = tok.revoked_at !== null;
                const isExpired = tok.expires_at !== null && new Date(tok.expires_at) < new Date();
                const isActive = !isRevoked && !isExpired;

                return (
                  <tr key={tok.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-100">{tok.name}</td>
                    <td className="px-4 py-3 font-mono text-xs text-sky-400">shk_{tok.key_prefix}_••••</td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center rounded-md bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-300">
                        {tok.role}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {tok.scopes?.length ? (
                          tok.scopes.map((sc) => (
                            <span
                              key={sc}
                              className="rounded bg-sky-950/60 border border-sky-800/40 px-1.5 py-0.5 text-[11px] font-mono text-sky-300"
                            >
                              {sc}
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-slate-500">{t("common.none")}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      {isActive ? (
                        <span className="inline-flex items-center rounded-full bg-emerald-950/80 px-2.5 py-0.5 text-xs font-medium text-emerald-400 border border-emerald-800/40">
                          {t("tokens.active")}
                        </span>
                      ) : isRevoked ? (
                        <span className="inline-flex items-center rounded-full bg-rose-950/80 px-2.5 py-0.5 text-xs font-medium text-rose-400 border border-rose-800/40">
                          {t("tokens.revoked")}
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded-full bg-amber-950/80 px-2.5 py-0.5 text-xs font-medium text-amber-400 border border-amber-800/40">
                          {t("tokens.expired")}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {tok.expires_at ? new Date(tok.expires_at).toLocaleDateString() : "Never"}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">
                      {tok.last_used_at ? new Date(tok.last_used_at).toLocaleDateString() : "Never"}
                    </td>
                    <td className="px-4 py-3 text-right">
                      {isActive ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleRevoke(tok.id)}
                          className="border-rose-900/60 bg-rose-950/30 text-rose-400 hover:bg-rose-900/50 hover:text-rose-200"
                        >
                          {t("tokens.revoke")}
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Create Token Dialog Modal */}
      {createOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg space-y-5 rounded-xl border border-slate-800 bg-slate-900 p-6 text-slate-100 shadow-2xl">
            <h3 className="text-lg font-semibold text-slate-100">{t("tokens.createBtn")}</h3>
            <form onSubmit={handleCreate} className="space-y-4">
              <label className="grid gap-1.5 text-sm">
                <span className="text-slate-300">{t("tokens.name")}</span>
                <Input
                  className="border-slate-700 bg-slate-950 text-slate-100"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g. GitHub Actions CI Token"
                  required
                />
              </label>

              <div className="grid grid-cols-2 gap-4">
                <label className="grid gap-1.5 text-sm">
                  <span className="text-slate-300">{t("tokens.role")}</span>
                  <select
                    className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 py-1 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-sky-500"
                    value={role}
                    onChange={(e) => setRole(e.target.value as "viewer" | "operator" | "admin")}
                  >
                    <option value="viewer">viewer</option>
                    <option value="operator">operator</option>
                    <option value="admin">admin</option>
                  </select>
                </label>

                <label className="grid gap-1.5 text-sm">
                  <span className="text-slate-300">{t("tokens.expiry")}</span>
                  <select
                    className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 py-1 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-sky-500"
                    value={expiryDays ?? "never"}
                    onChange={(e) =>
                      setExpiryDays(e.target.value === "never" ? null : Number(e.target.value))
                    }
                  >
                    <option value="30">30 days</option>
                    <option value="60">60 days</option>
                    <option value="90">90 days</option>
                    <option value="365">1 year (365 days)</option>
                    <option value="never">Never (No expiry)</option>
                  </select>
                </label>
              </div>

              <div className="space-y-2">
                <span className="text-sm text-slate-300">{t("tokens.scopes")}</span>
                <div className="grid grid-cols-2 gap-2 max-h-44 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                  {scopesList.map((sc) => (
                    <label key={sc} className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={selectedScopes.includes(sc)}
                        onChange={() => toggleScope(sc)}
                        className="rounded border-slate-700 bg-slate-900 text-sky-500 focus:ring-sky-400"
                      />
                      <span className="font-mono">{sc}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setCreateOpen(false)}
                  disabled={creating}
                >
                  {t("common.cancel")}
                </Button>
                <Button type="submit" disabled={creating} className="bg-sky-600 hover:bg-sky-500 text-white">
                  {creating ? t("common.loading") : t("common.create")}
                </Button>
              </div>
            </form>
          </div>
        </div>
      ) : null}

      {/* Token Generated Secret Dialog Modal */}
      {newSecret ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
          <div className="w-full max-w-lg space-y-4 rounded-xl border border-sky-800/80 bg-slate-900 p-6 text-slate-100 shadow-2xl">
            <div className="space-y-1">
              <h3 className="text-lg font-semibold text-emerald-400">
                {t("tokens.createdTitle")}
              </h3>
              <p className="text-xs text-amber-300/90 font-medium">
                ⚠️ {t("tokens.copyWarning")}
              </p>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="font-mono text-sm break-all select-all text-sky-300">
                {newSecret.token}
              </p>
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-emerald-400 font-medium">
                {copied ? `✓ ${t("tokens.copied")}` : ""}
              </span>
              <div className="flex gap-2">
                <Button
                  onClick={() => copyToClipboard(newSecret.token)}
                  className="bg-sky-600 hover:bg-sky-500 text-white"
                >
                  {t("tokens.copyBtn")}
                </Button>
                <Button variant="outline" onClick={() => setNewSecret(null)}>
                  {t("common.close")}
                </Button>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
