"use client";

import { Archive } from "lucide-react";
import { PageHeader } from "@/components/page-header";
import { DataSubjectPanel } from "@/components/retention/data-subject-panel";
import { LegalHoldPanel } from "@/components/retention/legal-hold-panel";
import { RetentionWindows } from "@/components/retention/retention-windows";
import { useRetentionPolicy } from "@/hooks/use-retention";
import { holdsPermission, useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

/**
 * How long this tenant's data is kept, whether it is on legal hold, and — for
 * a platform admin — the data-subject requests for console accounts (#332).
 *
 * Three authorities, gated here the way the API gates them: reading is
 * `tenant.retention.read` (the tenant's admin and auditor), editing the
 * windows is `tenant.retention.manage` (the tenant's admin, within bounds the
 * platform configured), and the hold and the account requests are the
 * platform admin's. All of it is presentation: the API enforces each on the
 * request itself.
 */
export default function RetentionPage() {
  const t = useT();
  const { user, activeTenant } = useAuthStore();
  // The permission list is what #318 made the answer; the fallback keeps the
  // page for a platform admin on an API that predates it.
  const canRead = holdsPermission(user, "tenant.retention.read", user?.role === "admin");
  const canManage = holdsPermission(user, "tenant.retention.manage", user?.role === "admin");
  const isPlatformAdmin = Boolean(user?.is_platform_admin);
  // Per tenant, so one has to be named: a platform admin on the fleet view has
  // none selected, and "every tenant's retention" is not one document.
  const tenantId = activeTenant ?? user?.default_tenant ?? "default";
  const { data, isLoading, error } = useRetentionPolicy(tenantId, canRead);

  return (
    <div className="space-y-6">
      <PageHeader
        icon={Archive}
        title={t("retention.title")}
        subtitle={t("retention.subtitle", { tenant: tenantId })}
        tone="slate"
      />
      {!canRead ? (
        <p className="text-sm text-muted-foreground">{t("retention.denied")}</p>
      ) : error ? (
        <p className="text-sm text-rose-500" role="alert">
          {error instanceof Error ? error.message : t("retention.loadFailed")}
        </p>
      ) : isLoading || !data ? (
        <p className="text-sm text-muted-foreground">{t("retention.loading")}</p>
      ) : (
        <>
          <LegalHoldPanel tenantId={tenantId} hold={data.legal_hold} canManage={isPlatformAdmin} />
          <RetentionWindows tenantId={tenantId} policy={data} canManage={canManage} />
        </>
      )}
      {isPlatformAdmin ? <DataSubjectPanel currentUsername={user?.username ?? ""} /> : null}
    </div>
  );
}
