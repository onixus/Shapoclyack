"use client";

import { OperatorSettings } from "@/components/operator/operator-settings";
import { Bot } from "lucide-react";
import { PageHeader } from "@/components/page-header";
import { OperatorConsole } from "@/components/operator/operator-console";
import { useAuthStore } from "@/lib/auth-store";
import { useT } from "@/lib/i18n";

export default function OperatorPage() {
  const t = useT();
  const { user, activeTenant, canOperate } = useAuthStore();
  // A platform administrator's fleet view is never an operator scope.
  const tenant = activeTenant ?? (user?.is_platform_admin ? null : user?.default_tenant);
  return (
    <div className="space-y-6">
      <PageHeader icon={Bot} title={t("nav.operator")} subtitle={t("nav.hint.operator")} />
      {user?.is_platform_admin && <OperatorSettings key={user.username} actor={user.username} />}
      {tenant && user ? (
        <OperatorConsole
          key={`${tenant}:${user.username}`}
          tenant={tenant}
          actor={user.username}
          canOperate={canOperate}
        />
      ) : (
        <p role="status" className="rounded-lg border bg-card p-6 text-sm">
          {t.locale === "ru"
            ? "Выберите конкретный тенант в верхней панели."
            : "Select a specific tenant in the top bar."}
        </p>
      )}
    </div>
  );
}
