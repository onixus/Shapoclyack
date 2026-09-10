"use client";

import { KeyRound } from "lucide-react";
import { ServiceTokensPanel } from "@/components/service-tokens-panel";
import { holdsPermission, useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

export default function ServiceTokensPage() {
  const t = useT();
  const { user, activeTenant } = useAuthStore();
  // `tenant.credential.manage` in the tenant selected below, not the global
  // admin role (#318): the tenant's own admin and a `token-admin` hold it and
  // the route accepts them, so gating on the global role refused the page to
  // the very people it is for. The fallback keeps it for a platform admin on
  // an API that predates the permission list.
  const canManage = holdsPermission(
    user,
    "tenant.credential.manage",
    user?.role === "admin",
  );
  // The panel is per tenant, so it needs one named: a platform admin viewing
  // the fleet has no tenant selected, and issuing "for everything" is not a
  // thing this credential can be.
  const tenantId = activeTenant ?? user?.default_tenant ?? "default";

  return (
    <div className="space-y-6 p-6">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <KeyRound className="h-5 w-5" />
          {t("nav.serviceTokens")}
        </h1>
        <p className="text-sm text-muted-foreground">
          Non-interactive API credentials for <span className="font-mono">{tenantId}</span>. Each
          token is confined to this tenant, to a role, and to the scopes it is issued with. The
          secret is shown once and cannot be read back.
        </p>
      </header>
      <ServiceTokensPanel tenantId={tenantId} canManage={canManage} />
    </div>
  );
}
