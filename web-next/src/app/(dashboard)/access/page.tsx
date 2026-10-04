"use client";

import { UserCheck } from "lucide-react";
import { TenantMembersPanel } from "@/components/tenant-members-panel";
import { TenantRolesPanel } from "@/components/tenant-roles-panel";
import { holdsPermission, useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

/**
 * Roles and members of the tenant the switcher is on (#318).
 *
 * The tenant's own page for what `/users` does for the whole platform: who
 * may act here, with which role, and the roles this tenant defined. Gated on
 * `tenant.member.read` / `tenant.member.manage` **in the active tenant** —
 * never on the account's global role, which is what kept the tenant admin out
 * of the membership screen while the API served it. The fallbacks keep it for
 * a platform admin on an API that predates the permission list.
 */
export default function AccessPage() {
  const t = useT();
  const { user, activeTenant } = useAuthStore();
  const isPlatformAdmin = user?.role === "admin";
  const canRead = holdsPermission(user, "tenant.member.read", isPlatformAdmin);
  const canManage = holdsPermission(user, "tenant.member.manage", isPlatformAdmin);
  const tenantId = activeTenant ?? user?.default_tenant ?? "default";

  return (
    <div className="space-y-6 p-6">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-xl font-semibold">
          <UserCheck className="h-5 w-5" />
          {t("nav.access")}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t("access.subtitle", { tenant: tenantId })}
        </p>
      </header>
      {canRead ? (
        <>
          <TenantRolesPanel tenantId={tenantId} canManage={canManage} />
          <TenantMembersPanel tenantId={tenantId} canManage={canManage} />
        </>
      ) : (
        <p className="text-sm text-muted-foreground">{t("access.denied")}</p>
      )}
    </div>
  );
}
