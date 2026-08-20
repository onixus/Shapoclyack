"use client";

import { useQueryClient } from "@tanstack/react-query";
import { Building2, Check, ChevronDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";

/** Label for the "no explicit tenant" choice. A platform admin acts across the
 * whole fleet there; everyone else falls back to the tenant the server derives
 * from their memberships. */
function fallbackLabel(
  isPlatformAdmin: boolean,
  defaultTenant: string,
  allTenantsLabel: string,
): string {
  return isPlatformAdmin ? allTenantsLabel : defaultTenant;
}

export function TenantSwitcher() {
  const t = useT();
  const { user, activeTenant, selectTenant } = useAuthStore();
  const queryClient = useQueryClient();

  if (!user) return null;

  // An API older than P0 answers /auth/me without any tenant context, so fall
  // back to the same defaults the server itself would resolve to.
  const tenants = user.tenants ?? [];
  const defaultTenant = user.default_tenant || "default";
  const isPlatformAdmin = user.is_platform_admin ?? user.role === "admin";
  const current = activeTenant ?? fallbackLabel(isPlatformAdmin, defaultTenant, t("tenant.all"));

  function choose(tenantId: string | null) {
    if (tenantId === activeTenant) return;
    selectTenant(tenantId);
    // Every cached list was fetched in the previous tenant's scope, so drop the
    // whole cache rather than trying to enumerate the affected query keys.
    queryClient.clear();
  }

  // A member of exactly one tenant has nothing to switch between — show the
  // tenant as a plain chip instead of a dead dropdown.
  if (!isPlatformAdmin && tenants.length <= 1) {
    return (
      <div className="hidden items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-xs text-slate-300 sm:flex">
        <Building2 className="h-3.5 w-3.5 text-sky-400" />
        <span className="text-slate-400">{t("tenant.label")}</span>
        <span className="font-semibold text-slate-200">{current}</span>
      </div>
    );
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          className="hidden gap-1.5 border-slate-800 bg-slate-900/60 px-2.5 text-xs text-slate-300 hover:bg-slate-800 hover:text-white sm:flex"
        >
          <Building2 className="h-3.5 w-3.5 text-sky-400" />
          <span className="text-slate-400">{t("tenant.label")}</span>
          <span className="font-semibold text-slate-200">{current}</span>
          <ChevronDown className="h-3.5 w-3.5 text-slate-500" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent
        align="end"
        className="max-h-80 w-56 overflow-y-auto border-slate-800 bg-slate-900 text-slate-100 shadow-xl shadow-slate-950"
      >
        <DropdownMenuLabel className="text-xs font-normal text-slate-400">
          {t("tenant.actIn")}
        </DropdownMenuLabel>
        <DropdownMenuItem
          onClick={() => choose(null)}
          className="cursor-pointer text-xs text-slate-300 focus:bg-slate-800 focus:text-slate-100"
        >
          <Check
            className={cn("mr-2 h-3.5 w-3.5", activeTenant ? "opacity-0" : "text-sky-400")}
          />
          {fallbackLabel(isPlatformAdmin, defaultTenant, t("tenant.all"))}
        </DropdownMenuItem>
        {tenants.length > 0 && <DropdownMenuSeparator className="bg-slate-800" />}
        {tenants.map((tenantId) => (
          <DropdownMenuItem
            key={tenantId}
            onClick={() => choose(tenantId)}
            className="cursor-pointer text-xs text-slate-300 focus:bg-slate-800 focus:text-slate-100"
          >
            <Check
              className={cn(
                "mr-2 h-3.5 w-3.5",
                activeTenant === tenantId ? "text-sky-400" : "opacity-0",
              )}
            />
            <span className="truncate font-mono">{tenantId}</span>
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
